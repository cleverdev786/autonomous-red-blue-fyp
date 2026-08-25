"""Deterministic, policy-controlled source context for Blue Team analysis."""

from __future__ import annotations

import re
from pathlib import Path
import time

from orchestrator.policy_engine import PolicyEngine
from schemas.blue_team import SourceReadResult, SourceSnippet
from schemas.common import PolicyReasonCode
from schemas.logging import AuditExecutionStatus, AuditPolicyDecision
from services.audit_service import AuditService
from services.target_registry import TargetRegistry


_MAX_FILES_SCANNED = 32
_MAX_SOURCE_FILE_BYTES = 100_000
_MAX_SNIPPETS = 6
_CONTEXT_LINES_BEFORE = 3
_CONTEXT_LINES_AFTER = 36
_MAX_SNIPPET_CHARS = 6000
_MAX_TOTAL_CONTEXT_CHARS = 24_000
_FUNCTION_PATTERN = re.compile(r"^\s*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")


class SourceReaderError(RuntimeError):
    """Raised when bounded source context cannot be produced safely."""


class SourceReadBlocked(SourceReaderError):
    """Raised when a requested source read violates deterministic restrictions."""

    def __init__(self, reason_code: PolicyReasonCode, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


class SourceReader:
    """Read only bounded Python source beneath the registered target app root."""

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

    def read_relevant(
        self,
        *,
        run_id: str,
        target_id: str,
        route_names: tuple[str, ...],
    ) -> SourceReadResult:
        """Select bounded function snippets using only neutral route names."""
        target = self.registry.get_target(target_id)
        normalized_routes = tuple(sorted(set(route_names)))
        app_root_relative = Path(str(target.source_root)) / "app"
        app_root = (self.project_root / app_root_relative).resolve(strict=False)

        snippets: list[SourceSnippet] = []
        total_chars = 0
        scanned = 0

        if not app_root.exists():
            raise SourceReaderError("registered application source root does not exist")

        for candidate in sorted(app_root.rglob("*.py")):
            if scanned >= _MAX_FILES_SCANNED or len(snippets) >= _MAX_SNIPPETS:
                break
            scanned += 1

            relative_path = candidate.relative_to(self.project_root).as_posix()
            text = self._read_authorized_text(
                run_id=run_id,
                target_id=target_id,
                relative_path=relative_path,
            )
            lines = text.splitlines()

            for index, line in enumerate(lines):
                match = _FUNCTION_PATTERN.match(line)
                if match is None:
                    continue
                function_name = match.group(1).lower()
                matching_route = next(
                    (
                        route
                        for route in normalized_routes
                        if route.lower() in function_name
                    ),
                    None,
                )
                if matching_route is None:
                    continue

                start_index = max(0, index - _CONTEXT_LINES_BEFORE)
                end_index = min(len(lines), index + _CONTEXT_LINES_AFTER + 1)
                content = "\n".join(lines[start_index:end_index]).strip()
                if not content:
                    continue
                content = content[:_MAX_SNIPPET_CHARS]

                if total_chars + len(content) > _MAX_TOTAL_CONTEXT_CHARS:
                    break

                snippets.append(
                    SourceSnippet(
                        file_path=relative_path,
                        start_line=start_index + 1,
                        end_line=start_index + len(content.splitlines()),
                        content=content,
                    )
                )
                total_chars += len(content)
                if len(snippets) >= _MAX_SNIPPETS:
                    break

        return SourceReadResult(
            run_id=run_id,
            target_id=target_id,
            route_names=normalized_routes,
            snippets=tuple(snippets),
        )

    def read_file(
        self,
        *,
        run_id: str,
        target_id: str,
        relative_path: str,
        start_line: int = 1,
        max_lines: int = 40,
    ) -> SourceSnippet:
        """Read one explicitly requested bounded application Python source range."""
        if start_line < 1:
            raise ValueError("start_line must be >= 1")
        if max_lines < 1 or max_lines > 100:
            raise ValueError("max_lines must be between 1 and 100")

        text = self._read_authorized_text(
            run_id=run_id,
            target_id=target_id,
            relative_path=relative_path,
        )
        lines = text.splitlines()
        if start_line > len(lines):
            raise SourceReaderError("start_line is beyond the source file")

        selected = lines[start_line - 1 : start_line - 1 + max_lines]
        content = "\n".join(selected).strip()
        if not content:
            raise SourceReaderError("requested source range is empty")
        content = content[:_MAX_SNIPPET_CHARS]
        return SourceSnippet(
            file_path=relative_path,
            start_line=start_line,
            end_line=start_line + len(content.splitlines()) - 1,
            content=content,
        )

    def _read_authorized_text(
        self,
        *,
        run_id: str,
        target_id: str,
        relative_path: str,
    ) -> str:
        started = time.monotonic()
        decision = self.policy_engine.validate_source_read(
            target_id=target_id,
            relative_path=relative_path,
        )
        if not decision.allowed:
            self._record(
                run_id=run_id,
                relative_path=relative_path,
                policy_decision=AuditPolicyDecision.BLOCKED,
                policy_reason=decision.reason_code,
                execution_status=AuditExecutionStatus.BLOCKED,
                duration_ms=self._elapsed_ms(started),
                error_code="source-read-policy-blocked",
            )
            raise SourceReadBlocked(decision.reason_code, decision.message)

        target = self.registry.get_target(target_id)
        supplied = Path(relative_path)
        app_root = (
            self.project_root / Path(str(target.source_root)) / "app"
        ).resolve(strict=False)
        candidate = (self.project_root / supplied).resolve(strict=False)

        try:
            candidate.relative_to(app_root)
        except ValueError as exc:
            reason = (
                PolicyReasonCode.SYMLINK_ESCAPE
                if self._lexically_inside_app(supplied, target.source_root)
                else PolicyReasonCode.SOURCE_PATH_NOT_ALLOWED
            )
            message = "Blue source reads are restricted to the registered application app/ root."
            self._record(
                run_id=run_id,
                relative_path=relative_path,
                policy_decision=AuditPolicyDecision.BLOCKED,
                policy_reason=reason,
                execution_status=AuditExecutionStatus.BLOCKED,
                duration_ms=self._elapsed_ms(started),
                error_code="source-read-app-root-blocked",
            )
            raise SourceReadBlocked(reason, message) from exc

        if candidate.suffix.lower() != ".py":
            reason = PolicyReasonCode.SOURCE_PATH_NOT_ALLOWED
            message = "Blue source reads are restricted to Python application source files."
            self._record(
                run_id=run_id,
                relative_path=relative_path,
                policy_decision=AuditPolicyDecision.BLOCKED,
                policy_reason=reason,
                execution_status=AuditExecutionStatus.BLOCKED,
                duration_ms=self._elapsed_ms(started),
                error_code="source-read-type-blocked",
            )
            raise SourceReadBlocked(reason, message)

        try:
            size = candidate.stat().st_size
            if not candidate.is_file():
                raise SourceReaderError("approved source path is not a regular file")
            if size > _MAX_SOURCE_FILE_BYTES:
                raise SourceReaderError("approved source file exceeds the bounded read limit")
            text = candidate.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            self._record(
                run_id=run_id,
                relative_path=relative_path,
                policy_decision=AuditPolicyDecision.ALLOWED,
                policy_reason=decision.reason_code,
                execution_status=AuditExecutionStatus.FAILED,
                duration_ms=self._elapsed_ms(started),
                error_code="source-read-failed",
            )
            if isinstance(exc, SourceReaderError):
                raise
            raise SourceReaderError("approved source file could not be read") from exc

        self._record(
            run_id=run_id,
            relative_path=relative_path,
            policy_decision=AuditPolicyDecision.ALLOWED,
            policy_reason=decision.reason_code,
            execution_status=AuditExecutionStatus.SUCCEEDED,
            duration_ms=self._elapsed_ms(started),
        )
        return text

    @staticmethod
    def _lexically_inside_app(path: Path, source_root: str) -> bool:
        app_root = Path(str(source_root)) / "app"
        try:
            path.relative_to(app_root)
        except ValueError:
            return False
        return True

    def _record(
        self,
        *,
        run_id: str,
        relative_path: str,
        policy_decision: AuditPolicyDecision,
        policy_reason: PolicyReasonCode,
        execution_status: AuditExecutionStatus,
        duration_ms: int,
        error_code: str | None = None,
    ) -> None:
        self.audit_service.record(
            run_id=run_id,
            component="source_reader",
            actor_type="deterministic_service",
            operation="source_read",
            target=relative_path,
            policy_decision=policy_decision,
            policy_reason=policy_reason,
            execution_status=execution_status,
            duration_ms=duration_ms,
            error_code=error_code,
        )

    @staticmethod
    def _elapsed_ms(started: float) -> int:
        return max(0, int((time.monotonic() - started) * 1000))
