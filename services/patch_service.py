"""Deterministic in-memory patch preparation with policy and grounding checks."""

from __future__ import annotations

from collections import defaultdict
import difflib
import hashlib
from pathlib import Path
import time

from orchestrator.policy_engine import PolicyEngine
from schemas.blue_team import CodeFinding, SourceReadResult
from schemas.common import PolicyReasonCode
from schemas.logging import AuditExecutionStatus, AuditPolicyDecision
from schemas.patches import PatchProposal, PreparedFileChange, PreparedPatch
from schemas.verification import PolicyDecision
from services.audit_service import AuditService
from services.target_registry import TargetRegistry


class PatchServiceError(RuntimeError):
    """Raised when an untrusted patch proposal cannot be prepared safely."""


class PatchServiceBlocked(PatchServiceError):
    """Raised when deterministic policy blocks patch preparation."""

    def __init__(self, decision: PolicyDecision) -> None:
        super().__init__(decision.message)
        self.decision = decision


class PatchGroundingError(PatchServiceError):
    """Raised when a proposed exact-text edit is ambiguous or ungrounded."""


class PatchService:
    """Prepare policy-approved unified diffs entirely in memory."""

    def __init__(
        self,
        *,
        registry: TargetRegistry,
        policy_engine: PolicyEngine,
        audit_service: AuditService,
        project_root: Path,
    ) -> None:
        self.registry = registry
        self.policy_engine = policy_engine
        self.audit_service = audit_service
        self.project_root = project_root.resolve(strict=False)

    def prepare_patch(
        self,
        *,
        proposal: PatchProposal,
        code_finding: CodeFinding,
        source_context: SourceReadResult,
    ) -> PreparedPatch:
        """Validate and prepare one patch without writing any generated content."""
        started = time.monotonic()
        try:
            return self._prepare_patch(
                proposal=proposal,
                code_finding=code_finding,
                source_context=source_context,
                started=started,
            )
        except (PatchGroundingError, PatchServiceBlocked) as exc:
            self._record_prepare(
                run_id=proposal.run_id,
                target=proposal.target_id,
                status=AuditExecutionStatus.BLOCKED,
                duration_ms=self._elapsed_ms(started),
                error_code=(
                    "patch-grounding-blocked"
                    if isinstance(exc, PatchGroundingError)
                    else "patch-policy-blocked"
                ),
            )
            raise
        except Exception:
            self._record_prepare(
                run_id=proposal.run_id,
                target=proposal.target_id,
                status=AuditExecutionStatus.FAILED,
                duration_ms=self._elapsed_ms(started),
                error_code="patch-prepare-failed",
            )
            raise

    def _prepare_patch(
        self,
        *,
        proposal: PatchProposal,
        code_finding: CodeFinding,
        source_context: SourceReadResult,
        started: float,
    ) -> PreparedPatch:
        if proposal.run_id != code_finding.run_id or proposal.run_id != source_context.run_id:
            raise PatchGroundingError("patch run_id must match code finding and source context")
        if proposal.target_id != source_context.target_id:
            raise PatchGroundingError("patch target_id must match source context")

        snippets_for_file = tuple(
            snippet for snippet in source_context.snippets if snippet.file_path == code_finding.file_path
        )
        if not snippets_for_file:
            raise PatchGroundingError("code finding file is absent from supplied patch context")
        grouped: dict[str, list] = defaultdict(list)
        for change in proposal.changes:
            if change.file_path != code_finding.file_path:
                raise PatchGroundingError(
                    "source edits are restricted to the validated CodeFinding file"
                )
            grouped[str(change.file_path)].append(change)

        prepared_files: list[PreparedFileChange] = []
        diffs: list[str] = []
        inserted_lines = 0
        deleted_lines = 0

        for file_path, changes in sorted(grouped.items()):
            self._require_patch_path(proposal.run_id, proposal.target_id, file_path)
            candidate = (self.project_root / file_path).resolve(strict=False)
            if not candidate.is_file():
                raise PatchGroundingError("proposed source file does not exist")
            original = candidate.read_text(encoding="utf-8")

            located: list[tuple[int, int, object]] = []
            for change in changes:
                if not any(
                    change.original_content in snippet.content
                    for snippet in snippets_for_file
                ):
                    raise PatchGroundingError(
                        "proposed original_content was not supplied in one bounded source snippet"
                    )
                if original.count(change.original_content) != 1:
                    raise PatchGroundingError(
                        "proposed original_content must occur exactly once in the current file"
                    )
                start = original.index(change.original_content)
                end = start + len(change.original_content)
                located.append((start, end, change))

            located.sort(key=lambda item: item[0])
            for previous, current in zip(located, located[1:]):
                if current[0] < previous[1]:
                    raise PatchGroundingError("proposed source edits must not overlap")

            replacement = original
            for start, end, change in reversed(located):
                replacement = replacement[:start] + change.replacement_content + replacement[end:]

            file_diff, added, removed = self._build_diff(
                file_path=file_path,
                original=original,
                replacement=replacement,
                is_new_file=False,
            )
            diffs.append(file_diff)
            inserted_lines += added
            deleted_lines += removed
            prepared_files.append(
                PreparedFileChange(
                    file_path=file_path,
                    original_sha256=self._sha256(original),
                    replacement_sha256=self._sha256(replacement),
                    replacement_content=replacement,
                    is_new_file=False,
                )
            )

        generated_test_path: str | None = None
        if proposal.proposed_security_test is not None:
            test = proposal.proposed_security_test
            if test.target_file != code_finding.file_path:
                raise PatchGroundingError(
                    "generated security test target_file must match the CodeFinding file"
                )
            generated_test_root = self._generated_test_root(proposal.target_id)
            generated_test_path = (
                generated_test_root / f"{test.test_name}.py"
            ).as_posix()
            self._require_patch_path(
                proposal.run_id,
                proposal.target_id,
                generated_test_path,
            )
            test_candidate = (self.project_root / generated_test_path).resolve(strict=False)
            if test_candidate.exists():
                raise PatchGroundingError("derived generated-test path already exists")
            test_content = test.proposed_test_content.rstrip() + "\n"
            file_diff, added, removed = self._build_diff(
                file_path=generated_test_path,
                original="",
                replacement=test_content,
                is_new_file=True,
            )
            diffs.append(file_diff)
            inserted_lines += added
            deleted_lines += removed
            prepared_files.append(
                PreparedFileChange(
                    file_path=generated_test_path,
                    original_sha256=self._sha256(""),
                    replacement_sha256=self._sha256(test_content),
                    replacement_content=test_content,
                    is_new_file=True,
                )
            )

        unified_diff = "\n".join(item.rstrip("\n") for item in diffs).rstrip() + "\n"
        total_diff_bytes = len(unified_diff.encode("utf-8"))
        size_decision = self.policy_engine.validate_patch_size(
            target_id=proposal.target_id,
            files_changed=len(prepared_files),
            inserted_lines=inserted_lines,
            deleted_lines=deleted_lines,
            total_diff_bytes=total_diff_bytes,
        )
        self._record_policy(
            run_id=proposal.run_id,
            operation="patch_size_validation",
            target=proposal.target_id,
            decision=size_decision,
        )
        if not size_decision.allowed:
            raise PatchServiceBlocked(size_decision)

        result = PreparedPatch(
            run_id=proposal.run_id,
            target_id=proposal.target_id,
            attempt_number=proposal.attempt_number,
            files=tuple(prepared_files),
            unified_diff=unified_diff,
            diff_sha256=self._sha256(unified_diff),
            files_changed=len(prepared_files),
            inserted_lines=inserted_lines,
            deleted_lines=deleted_lines,
            total_diff_bytes=total_diff_bytes,
            generated_test_path=generated_test_path,
        )
        self._record_prepare(
            run_id=proposal.run_id,
            target=proposal.target_id,
            status=AuditExecutionStatus.SUCCEEDED,
            duration_ms=self._elapsed_ms(started),
            evidence_reference=result.diff_sha256,
        )
        return result


    def _generated_test_root(self, target_id: str) -> Path:
        target = self.registry.get_target(target_id)
        candidates = tuple(
            Path(str(root))
            for root in target.writable_patch_roots
            if Path(str(root)).as_posix().endswith("/tests/generated")
        )
        if len(candidates) != 1:
            raise PatchGroundingError(
                "target must define exactly one generated security-test writable root"
            )
        return candidates[0]

    def _require_patch_path(self, run_id: str, target_id: str, file_path: str) -> None:
        decision = self.policy_engine.validate_patch_path(
            target_id=target_id,
            relative_path=file_path,
        )
        self._record_policy(
            run_id=run_id,
            operation="patch_path_validation",
            target=file_path,
            decision=decision,
        )
        if not decision.allowed:
            raise PatchServiceBlocked(decision)

    def _record_policy(
        self,
        *,
        run_id: str,
        operation: str,
        target: str,
        decision: PolicyDecision,
    ) -> None:
        self.audit_service.record(
            run_id=run_id,
            component="patch_service",
            actor_type="deterministic_service",
            operation=operation,
            target=target,
            policy_decision=(
                AuditPolicyDecision.ALLOWED if decision.allowed else AuditPolicyDecision.BLOCKED
            ),
            policy_reason=decision.reason_code,
            execution_status=(
                AuditExecutionStatus.AUTHORIZED if decision.allowed else AuditExecutionStatus.BLOCKED
            ),
            error_code=None if decision.allowed else "policy-blocked",
        )

    def _record_prepare(
        self,
        *,
        run_id: str,
        target: str,
        status: AuditExecutionStatus,
        duration_ms: int,
        evidence_reference: str | None = None,
        error_code: str | None = None,
    ) -> None:
        self.audit_service.record(
            run_id=run_id,
            component="patch_service",
            actor_type="deterministic_service",
            operation="patch_prepare",
            target=target,
            policy_decision=AuditPolicyDecision.NOT_APPLICABLE,
            execution_status=status,
            duration_ms=duration_ms,
            evidence_reference=evidence_reference,
            error_code=error_code,
        )

    @staticmethod
    def _build_diff(
        *,
        file_path: str,
        original: str,
        replacement: str,
        is_new_file: bool,
    ) -> tuple[str, int, int]:
        original_lines = original.splitlines()
        replacement_lines = replacement.splitlines()
        diff_lines = list(
            difflib.unified_diff(
                original_lines,
                replacement_lines,
                fromfile="/dev/null" if is_new_file else f"a/{file_path}",
                tofile=f"b/{file_path}",
                lineterm="",
            )
        )
        if not diff_lines:
            raise PatchGroundingError("prepared edit produced no diff")
        inserted = sum(1 for line in diff_lines if line.startswith("+") and not line.startswith("+++"))
        deleted = sum(1 for line in diff_lines if line.startswith("-") and not line.startswith("---"))
        return "\n".join(diff_lines) + "\n", inserted, deleted

    @staticmethod
    def _sha256(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    @staticmethod
    def _elapsed_ms(started: float) -> int:
        return max(0, int((time.monotonic() - started) * 1000))
