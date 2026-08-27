"""Restricted deterministic local Git operations for isolated patch attempts."""

from __future__ import annotations

import hashlib
from pathlib import Path
import time
from typing import Iterable

try:
    from git import InvalidGitRepositoryError, NoSuchPathError, Repo
    from git.exc import GitCommandError
except ModuleNotFoundError:  # pragma: no cover - project dependency verified on development host
    Repo = None  # type: ignore[assignment]

    class InvalidGitRepositoryError(Exception):
        pass

    class NoSuchPathError(Exception):
        pass

    class GitCommandError(Exception):
        pass

from orchestrator.policy_engine import PolicyEngine
from schemas.common import PatchDecision, PolicyReasonCode
from schemas.git import GitPolicyConfig, PatchBranchResult
from schemas.logging import AuditExecutionStatus, AuditPolicyDecision
from schemas.patches import PreparedPatch
from services.audit_service import AuditService


_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


class GitServiceError(RuntimeError):
    """Base error for deterministic Git-service failures."""

    def __init__(self, message: str, *, error_code: str = "git-service-error") -> None:
        super().__init__(message)
        self.error_code = error_code


class GitServiceBlocked(GitServiceError):
    """Raised when deterministic Git safety policy blocks an operation."""


class _GitAuditRecorder:
    """Small adapter that keeps Git audit records consistent."""

    def __init__(self, audit_service: AuditService) -> None:
        self.audit_service = audit_service

    def success(
        self,
        *,
        run_id: str,
        operation: str,
        target: str,
        started: float,
        evidence_reference: str | None = None,
    ) -> None:
        self.audit_service.record(
            run_id=run_id,
            component="git_service",
            actor_type="deterministic_service",
            operation=operation,
            target=target,
            policy_decision=AuditPolicyDecision.ALLOWED,
            policy_reason=PolicyReasonCode.ALLOWED,
            execution_status=AuditExecutionStatus.SUCCEEDED,
            duration_ms=_elapsed_ms(started),
            evidence_reference=evidence_reference,
        )

    def blocked(
        self,
        *,
        run_id: str,
        operation: str,
        target: str,
        error_code: str,
        started: float,
    ) -> None:
        self.audit_service.record(
            run_id=run_id,
            component="git_service",
            actor_type="deterministic_service",
            operation=operation,
            target=target,
            policy_decision=AuditPolicyDecision.BLOCKED,
            policy_reason=PolicyReasonCode.PROHIBITED_OPERATION,
            execution_status=AuditExecutionStatus.BLOCKED,
            duration_ms=_elapsed_ms(started),
            error_code=error_code,
        )

    def failed(
        self,
        *,
        run_id: str,
        operation: str,
        target: str,
        error_code: str,
        started: float,
    ) -> None:
        self.audit_service.record(
            run_id=run_id,
            component="git_service",
            actor_type="deterministic_service",
            operation=operation,
            target=target,
            policy_decision=AuditPolicyDecision.NOT_APPLICABLE,
            execution_status=AuditExecutionStatus.FAILED,
            duration_ms=_elapsed_ms(started),
            error_code=error_code,
        )


def _active_branch(repo: Repo) -> str:
    try:
        return repo.active_branch.name
    except TypeError as exc:
        raise GitServiceBlocked(
            "detached HEAD is not allowed for patch automation",
            error_code="git-detached-head",
        ) from exc


def _changed_paths(repo: Repo) -> tuple[str, ...]:
    paths: set[str] = set(repo.untracked_files)
    for diff in repo.index.diff(repo.head.commit):
        if diff.a_path:
            paths.add(diff.a_path)
        if diff.b_path:
            paths.add(diff.b_path)
    for diff in repo.index.diff(None):
        if diff.a_path:
            paths.add(diff.a_path)
        if diff.b_path:
            paths.add(diff.b_path)
    return tuple(sorted(paths))


def _unstaged_paths(repo: Repo) -> tuple[str, ...]:
    paths: set[str] = set(repo.untracked_files)
    for diff in repo.index.diff(None):
        if diff.a_path:
            paths.add(diff.a_path)
        if diff.b_path:
            paths.add(diff.b_path)
    return tuple(sorted(paths))


def _staged_git_diff(repo: Repo, paths: Iterable[str]) -> str:
    try:
        return repo.git.diff(
            "--cached",
            "--no-ext-diff",
            "--no-color",
            "--no-renames",
            "--",
            *tuple(paths),
        )
    except GitCommandError as exc:
        raise GitServiceError(
            "failed to inspect bounded staged Git diff",
            error_code="git-diff-inspection-failed",
        ) from exc


def _blob_bytes(repo: Repo, commit_sha: str, relative_path: str) -> bytes | None:
    try:
        blob = repo.commit(commit_sha).tree / relative_path
    except KeyError:
        return None
    return blob.data_stream.read()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _elapsed_ms(started: float) -> int:
    return max(0, int((time.monotonic() - started) * 1000))


class _PreparedPatchMaterializer:
    """Exact-path PreparedPatch preflight, write, inspection, and rollback."""

    def __init__(self, *, repository_root: Path, policy_engine: PolicyEngine) -> None:
        self.repository_root = repository_root
        self.policy_engine = policy_engine

    def materialize(
        self,
        *,
        repo: Repo,
        prepared_patch: PreparedPatch,
        base_commit: str,
    ) -> tuple[str, str, tuple[str, ...]]:
        expected_paths = tuple(item.file_path for item in prepared_patch.files)
        originals = self.preflight(prepared_patch)
        writes_started = False
        try:
            writes_started = True
            self.write_files(prepared_patch)
            repo.index.add(list(expected_paths))
            return self.inspect(repo=repo, expected_paths=expected_paths)
        except Exception:
            if writes_started:
                self.rollback(repo=repo, base_commit=base_commit, originals=originals)
            raise

    def preflight(self, prepared_patch: PreparedPatch) -> dict[str, bytes | None]:
        actual_diff_hash = hashlib.sha256(
            prepared_patch.unified_diff.encode("utf-8")
        ).hexdigest()
        if actual_diff_hash != prepared_patch.diff_sha256:
            raise GitServiceBlocked(
                "PreparedPatch diff hash does not match its unified diff",
                error_code="git-prepared-diff-hash-mismatch",
            )

        expected_paths = tuple(item.file_path for item in prepared_patch.files)
        if len(expected_paths) != len(set(expected_paths)):
            raise GitServiceBlocked(
                "PreparedPatch contains duplicate file paths",
                error_code="git-duplicate-patch-path",
            )

        originals: dict[str, bytes | None] = {}
        for item in prepared_patch.files:
            decision = self.policy_engine.validate_patch_path(
                target_id=prepared_patch.target_id,
                relative_path=item.file_path,
            )
            if not decision.allowed:
                raise GitServiceBlocked(
                    f"prepared path {item.file_path!r} no longer passes patch policy",
                    error_code="git-patch-path-blocked",
                )

            path = self.repository_root / item.file_path
            if path.is_symlink():
                raise GitServiceBlocked(
                    f"prepared path {item.file_path!r} is a symlink",
                    error_code="git-patch-symlink-blocked",
                )
            if _sha256_text(item.replacement_content) != item.replacement_sha256:
                raise GitServiceBlocked(
                    f"replacement hash mismatch for {item.file_path!r}",
                    error_code="git-replacement-hash-mismatch",
                )

            if item.is_new_file:
                if item.original_sha256 != _EMPTY_SHA256:
                    raise GitServiceBlocked(
                        f"new file {item.file_path!r} has a non-empty original hash",
                        error_code="git-new-file-original-hash-invalid",
                    )
                if path.exists():
                    raise GitServiceBlocked(
                        f"new prepared file {item.file_path!r} already exists",
                        error_code="git-new-file-collision",
                    )
                originals[item.file_path] = None
                continue

            if not path.is_file():
                raise GitServiceBlocked(
                    f"prepared source file {item.file_path!r} does not exist",
                    error_code="git-source-file-missing",
                )
            current = path.read_bytes()
            if hashlib.sha256(current).hexdigest() != item.original_sha256:
                raise GitServiceBlocked(
                    f"prepared source file {item.file_path!r} changed since preparation",
                    error_code="git-source-hash-mismatch",
                )
            originals[item.file_path] = current

        return originals

    def write_files(self, prepared_patch: PreparedPatch) -> None:
        for item in prepared_patch.files:
            path = self.repository_root / item.file_path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(item.replacement_content, encoding="utf-8")
            if hashlib.sha256(path.read_bytes()).hexdigest() != item.replacement_sha256:
                raise GitServiceError(
                    f"written replacement hash mismatch for {item.file_path!r}",
                    error_code="git-written-hash-mismatch",
                )

    @staticmethod
    def inspect(
        *,
        repo: Repo,
        expected_paths: tuple[str, ...],
    ) -> tuple[str, str, tuple[str, ...]]:
        changed_paths = _changed_paths(repo)
        if set(changed_paths) != set(expected_paths):
            raise GitServiceError(
                "Git changed-path set differs from PreparedPatch paths",
                error_code="git-unexpected-changed-paths",
            )
        if _unstaged_paths(repo):
            raise GitServiceError(
                "patch materialization left unstaged changes",
                error_code="git-unstaged-after-materialization",
            )

        git_diff = _staged_git_diff(repo, expected_paths)
        if not git_diff.strip():
            raise GitServiceError(
                "materialized patch produced an empty Git diff",
                error_code="git-empty-patch-diff",
            )
        return (
            git_diff,
            hashlib.sha256(git_diff.encode("utf-8")).hexdigest(),
            tuple(sorted(changed_paths)),
        )

    def rollback(
        self,
        *,
        repo: Repo,
        base_commit: str,
        originals: dict[str, bytes | None],
    ) -> None:
        paths = tuple(originals)
        for relative_path, original in originals.items():
            path = self.repository_root / relative_path
            if original is None:
                if path.exists() or path.is_symlink():
                    path.unlink()
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(original)
        if paths:
            repo.git.reset(base_commit, "--", *paths)


class GitService:
    """Apply only prepared patches using a narrow local Git capability."""

    def __init__(
        self,
        *,
        repository_root: Path,
        git_policy: GitPolicyConfig,
        policy_engine: PolicyEngine,
        audit_service: AuditService,
    ) -> None:
        self.repository_root = repository_root.resolve(strict=False)
        self.git_policy = git_policy
        self.policy_engine = policy_engine
        self.audit_service = audit_service
        self._audit = _GitAuditRecorder(audit_service)
        self._materializer = _PreparedPatchMaterializer(
            repository_root=self.repository_root,
            policy_engine=policy_engine,
        )

    def verify_clean_baseline(
        self,
        *,
        run_id: str,
        expected_base_commit: str | None = None,
    ) -> str:
        """Require configured baseline, clean tree, and optional exact base SHA."""
        started = time.monotonic()
        try:
            repo = self._repo()
            branch = _active_branch(repo)
            if branch != self.git_policy.baseline_branch:
                raise GitServiceBlocked(
                    f"current branch {branch!r} is not configured baseline "
                    f"{self.git_policy.baseline_branch!r}",
                    error_code="git-wrong-baseline-branch",
                )
            if repo.is_dirty(untracked_files=True):
                raise GitServiceBlocked(
                    "baseline repository must be clean before creating a patch branch",
                    error_code="git-dirty-baseline",
                )
            base_commit = repo.head.commit.hexsha
            if expected_base_commit is not None and base_commit != expected_base_commit:
                raise GitServiceBlocked(
                    "baseline HEAD does not match the expected commit",
                    error_code="git-base-commit-mismatch",
                )
        except GitServiceBlocked as exc:
            self._audit.blocked(
                run_id=run_id,
                operation="git_baseline_validation",
                target=str(self.repository_root),
                error_code=exc.error_code,
                started=started,
            )
            raise

        self._audit.success(
            run_id=run_id,
            operation="git_baseline_validation",
            target=self.git_policy.baseline_branch,
            evidence_reference=base_commit,
            started=started,
        )
        return base_commit

    def create_patch_branch(
        self,
        *,
        prepared_patch: PreparedPatch,
        base_commit: str,
    ) -> str:
        """Create and checkout the deterministic branch for one patch attempt."""
        started = time.monotonic()
        branch_name = self.git_policy.branch_name(
            run_id=prepared_patch.run_id,
            attempt_number=prepared_patch.attempt_number,
        )
        try:
            repo = self._repo()
            if _active_branch(repo) != self.git_policy.baseline_branch:
                raise GitServiceBlocked(
                    "patch branch creation requires the configured baseline branch",
                    error_code="git-branch-create-off-baseline",
                )
            if repo.is_dirty(untracked_files=True):
                raise GitServiceBlocked(
                    "patch branch creation requires a clean repository",
                    error_code="git-dirty-before-branch",
                )
            if repo.head.commit.hexsha != base_commit:
                raise GitServiceBlocked(
                    "repository HEAD changed after baseline validation",
                    error_code="git-base-commit-drift",
                )
            try:
                repo.git.check_ref_format("--branch", branch_name)
            except GitCommandError as exc:
                raise GitServiceBlocked(
                    "generated patch branch is not a valid Git branch name",
                    error_code="git-branch-name-invalid",
                ) from exc
            if any(head.name == branch_name for head in repo.heads):
                raise GitServiceBlocked(
                    f"patch branch {branch_name!r} already exists",
                    error_code="git-branch-collision",
                )
            repo.create_head(branch_name, repo.commit(base_commit)).checkout()
            if _active_branch(repo) != branch_name:
                raise GitServiceError(
                    "created patch branch was not checked out",
                    error_code="git-branch-checkout-failed",
                )
        except GitServiceBlocked as exc:
            self._audit.blocked(
                run_id=prepared_patch.run_id,
                operation="git_branch_creation",
                target=branch_name,
                error_code=exc.error_code,
                started=started,
            )
            raise
        except Exception as exc:
            self._audit.failed(
                run_id=prepared_patch.run_id,
                operation="git_branch_creation",
                target=branch_name,
                error_code="git-branch-creation-failed",
                started=started,
            )
            if isinstance(exc, GitServiceError):
                raise
            raise GitServiceError(
                "failed to create isolated patch branch",
                error_code="git-branch-creation-failed",
            ) from exc

        self._audit.success(
            run_id=prepared_patch.run_id,
            operation="git_branch_creation",
            target=branch_name,
            evidence_reference=base_commit,
            started=started,
        )
        return branch_name

    def materialize_prepared_patch(
        self,
        *,
        prepared_patch: PreparedPatch,
        branch_name: str,
        base_commit: str,
    ) -> tuple[str, str, tuple[str, ...]]:
        """Write and stage exactly the approved PreparedPatch files on its branch."""
        started = time.monotonic()
        try:
            repo = self._repo()
            self._require_patch_branch_state(
                repo=repo,
                branch_name=branch_name,
                base_commit=base_commit,
            )
            git_diff, git_diff_sha256, changed_paths = self._materializer.materialize(
                repo=repo,
                prepared_patch=prepared_patch,
                base_commit=base_commit,
            )
        except GitServiceBlocked as exc:
            self._audit.blocked(
                run_id=prepared_patch.run_id,
                operation="git_patch_materialization",
                target=branch_name,
                error_code=exc.error_code,
                started=started,
            )
            raise
        except Exception as exc:
            error_code = (
                exc.error_code
                if isinstance(exc, GitServiceError)
                else "git-materialization-failed"
            )
            self._audit.failed(
                run_id=prepared_patch.run_id,
                operation="git_patch_materialization",
                target=branch_name,
                error_code=error_code,
                started=started,
            )
            if isinstance(exc, GitServiceError):
                raise
            raise GitServiceError(
                "failed while materializing PreparedPatch",
                error_code="git-materialization-failed",
            ) from exc

        self._audit.success(
            run_id=prepared_patch.run_id,
            operation="git_patch_materialization",
            target=branch_name,
            evidence_reference=prepared_patch.diff_sha256,
            started=started,
        )
        self._audit.success(
            run_id=prepared_patch.run_id,
            operation="git_diff_inspection",
            target=branch_name,
            evidence_reference=git_diff_sha256,
            started=started,
        )
        return git_diff, git_diff_sha256, changed_paths

    def verify_materialized_patch(
        self,
        *,
        prepared_patch: PreparedPatch,
        branch_result: PatchBranchResult,
    ) -> str:
        """Revalidate the exact staged patch branch before executing patched code."""
        started = time.monotonic()
        try:
            if (
                prepared_patch.run_id != branch_result.run_id
                or prepared_patch.target_id != branch_result.target_id
                or prepared_patch.attempt_number != branch_result.attempt_number
            ):
                raise GitServiceBlocked(
                    "PreparedPatch identity does not match PatchBranchResult",
                    error_code="git-verification-identity-mismatch",
                )
            if prepared_patch.diff_sha256 != branch_result.prepared_diff_sha256:
                raise GitServiceBlocked(
                    "PreparedPatch diff hash does not match recorded branch evidence",
                    error_code="git-verification-prepared-diff-drift",
                )
            expected_paths = tuple(sorted(item.file_path for item in prepared_patch.files))
            if expected_paths != tuple(sorted(branch_result.changed_paths)):
                raise GitServiceBlocked(
                    "PreparedPatch paths do not match recorded branch evidence",
                    error_code="git-verification-path-drift",
                )

            repo = self._repo()
            self._require_commit_state(repo=repo, branch_result=branch_result)
            current_diff = _staged_git_diff(repo, branch_result.changed_paths)
            current_hash = hashlib.sha256(current_diff.encode("utf-8")).hexdigest()
            if current_hash != branch_result.git_diff_sha256:
                raise GitServiceBlocked(
                    "staged Git diff changed before patch verification",
                    error_code="git-verification-diff-drift",
                )

            for item in prepared_patch.files:
                path = self.repository_root / item.file_path
                if path.is_symlink() or not path.is_file():
                    raise GitServiceBlocked(
                        f"materialized verification path {item.file_path!r} is not a regular file",
                        error_code="git-verification-file-missing",
                    )
                actual = hashlib.sha256(path.read_bytes()).hexdigest()
                if actual != item.replacement_sha256:
                    raise GitServiceBlocked(
                        f"materialized replacement hash drifted for {item.file_path!r}",
                        error_code="git-verification-file-hash-drift",
                    )
        except GitServiceBlocked as exc:
            self._audit.blocked(
                run_id=branch_result.run_id,
                operation="git_materialized_patch_verification",
                target=branch_result.branch_name,
                error_code=exc.error_code,
                started=started,
            )
            raise
        except Exception as exc:
            error_code = (
                exc.error_code if isinstance(exc, GitServiceError)
                else "git-verification-inspection-failed"
            )
            self._audit.failed(
                run_id=branch_result.run_id,
                operation="git_materialized_patch_verification",
                target=branch_result.branch_name,
                error_code=error_code,
                started=started,
            )
            if isinstance(exc, GitServiceError):
                raise
            raise GitServiceError(
                "failed to verify materialized patch branch",
                error_code="git-verification-inspection-failed",
            ) from exc

        self._audit.success(
            run_id=branch_result.run_id,
            operation="git_materialized_patch_verification",
            target=branch_result.branch_name,
            evidence_reference=current_hash,
            started=started,
        )
        return current_hash

    def restore_baseline(
        self,
        *,
        prepared_patch: PreparedPatch,
        branch_name: str,
        base_commit: str,
    ) -> None:
        """Restore known patch paths, then return to the unchanged baseline branch."""
        started = time.monotonic()
        expected_paths = tuple(item.file_path for item in prepared_patch.files)
        try:
            repo = self._repo()
            active = _active_branch(repo)
            if active != branch_name:
                raise GitServiceBlocked(
                    f"restore requires active patch branch {branch_name!r}, found {active!r}",
                    error_code="git-restore-wrong-branch",
                )
            if branch_name == self.git_policy.baseline_branch:
                raise GitServiceBlocked(
                    "restore cannot treat the baseline branch as a patch branch",
                    error_code="git-restore-baseline-protected",
                )

            dirty = set(_changed_paths(repo))
            unexpected = dirty.difference(expected_paths)
            if unexpected:
                raise GitServiceBlocked(
                    "unrelated dirty files prevent safe baseline restoration",
                    error_code="git-restore-unrelated-dirty",
                )

            if dirty:
                originals = {
                    path: _blob_bytes(repo, base_commit, path)
                    for path in expected_paths
                }
                self._materializer.rollback(
                    repo=repo,
                    base_commit=base_commit,
                    originals=originals,
                )

            if repo.is_dirty(untracked_files=True):
                raise GitServiceBlocked(
                    "patch branch is not clean after exact-path restoration",
                    error_code="git-restore-not-clean",
                )

            baseline = self._baseline_head(repo)
            if baseline.commit.hexsha != base_commit:
                raise GitServiceBlocked(
                    "baseline branch moved during patch attempt",
                    error_code="git-baseline-moved",
                )
            baseline.checkout()
            if repo.head.commit.hexsha != base_commit or repo.is_dirty(untracked_files=True):
                raise GitServiceError(
                    "baseline restoration verification failed",
                    error_code="git-restore-verification-failed",
                )
        except GitServiceBlocked as exc:
            self._audit.blocked(
                run_id=prepared_patch.run_id,
                operation="git_restore_baseline",
                target=branch_name,
                error_code=exc.error_code,
                started=started,
            )
            raise
        except Exception as exc:
            error_code = (
                exc.error_code if isinstance(exc, GitServiceError) else "git-restore-failed"
            )
            self._audit.failed(
                run_id=prepared_patch.run_id,
                operation="git_restore_baseline",
                target=branch_name,
                error_code=error_code,
                started=started,
            )
            if isinstance(exc, GitServiceError):
                raise
            raise GitServiceError(
                "failed to restore baseline safely",
                error_code="git-restore-failed",
            ) from exc

        self._audit.success(
            run_id=prepared_patch.run_id,
            operation="git_restore_baseline",
            target=self.git_policy.baseline_branch,
            evidence_reference=base_commit,
            started=started,
        )

    def commit_accepted_patch(
        self,
        *,
        branch_result: PatchBranchResult,
        decision: PatchDecision,
    ) -> str:
        """Create a local patch-branch commit only after explicit trusted acceptance."""
        started = time.monotonic()
        try:
            if decision != PatchDecision.ACCEPTED:
                raise GitServiceBlocked(
                    "only an explicit accepted PatchDecision can create a patch commit",
                    error_code="git-commit-not-accepted",
                )

            repo = self._repo()
            self._require_commit_state(repo=repo, branch_result=branch_result)
            current_diff = _staged_git_diff(repo, branch_result.changed_paths)
            current_hash = hashlib.sha256(current_diff.encode("utf-8")).hexdigest()
            if current_hash != branch_result.git_diff_sha256:
                raise GitServiceBlocked(
                    "staged Git diff changed since branch materialization",
                    error_code="git-commit-diff-drift",
                )

            baseline = self._baseline_head(repo)
            if baseline.commit.hexsha != branch_result.base_commit:
                raise GitServiceBlocked(
                    "baseline branch moved before accepted commit",
                    error_code="git-baseline-moved",
                )

            message = (
                f"Patch attempt {branch_result.run_id} "
                f"attempt {branch_result.attempt_number}"
            )
            commit = repo.index.commit(message)
            if baseline.commit.hexsha != branch_result.base_commit:
                raise GitServiceError(
                    "baseline branch changed while committing patch attempt",
                    error_code="git-baseline-mutated",
                )
        except GitServiceBlocked as exc:
            self._audit.blocked(
                run_id=branch_result.run_id,
                operation="git_accepted_patch_commit",
                target=branch_result.branch_name,
                error_code=exc.error_code,
                started=started,
            )
            raise
        except Exception as exc:
            error_code = (
                exc.error_code if isinstance(exc, GitServiceError) else "git-commit-failed"
            )
            self._audit.failed(
                run_id=branch_result.run_id,
                operation="git_accepted_patch_commit",
                target=branch_result.branch_name,
                error_code=error_code,
                started=started,
            )
            if isinstance(exc, GitServiceError):
                raise
            raise GitServiceError(
                "failed to create accepted local patch commit",
                error_code="git-commit-failed",
            ) from exc

        self._audit.success(
            run_id=branch_result.run_id,
            operation="git_accepted_patch_commit",
            target=branch_result.branch_name,
            evidence_reference=commit.hexsha,
            started=started,
        )
        return commit.hexsha

    def _repo(self) -> Repo:
        if Repo is None:
            raise GitServiceError(
                "GitPython is required for Milestone 13 Git automation",
                error_code="gitpython-unavailable",
            )
        try:
            return Repo(self.repository_root)
        except (InvalidGitRepositoryError, NoSuchPathError) as exc:
            raise GitServiceBlocked(
                f"{self.repository_root} is not an approved local Git repository",
                error_code="git-repository-invalid",
            ) from exc

    def _baseline_head(self, repo: Repo):
        baseline = next(
            (head for head in repo.heads if head.name == self.git_policy.baseline_branch),
            None,
        )
        if baseline is None:
            raise GitServiceBlocked(
                "configured baseline branch does not exist",
                error_code="git-baseline-branch-missing",
            )
        return baseline

    def _require_patch_branch_state(
        self,
        *,
        repo: Repo,
        branch_name: str,
        base_commit: str,
    ) -> None:
        active = _active_branch(repo)
        if active != branch_name:
            raise GitServiceBlocked(
                f"patch materialization requires branch {branch_name!r}, found {active!r}",
                error_code="git-materialize-wrong-branch",
            )
        if active == self.git_policy.baseline_branch:
            raise GitServiceBlocked(
                "generated patch materialization on baseline is prohibited",
                error_code="git-baseline-write-blocked",
            )
        if repo.head.commit.hexsha != base_commit:
            raise GitServiceBlocked(
                "patch branch HEAD no longer matches recorded base commit",
                error_code="git-patch-head-drift",
            )
        if repo.is_dirty(untracked_files=True):
            raise GitServiceBlocked(
                "patch branch must be clean before materialization",
                error_code="git-dirty-patch-branch",
            )

    def _require_commit_state(
        self,
        *,
        repo: Repo,
        branch_result: PatchBranchResult,
    ) -> None:
        if _active_branch(repo) != branch_result.branch_name:
            raise GitServiceBlocked(
                "accepted patch commit requires the recorded patch branch",
                error_code="git-commit-wrong-branch",
            )
        if branch_result.branch_name == self.git_policy.baseline_branch:
            raise GitServiceBlocked(
                "accepted patch commit cannot run on the baseline branch",
                error_code="git-commit-baseline-protected",
            )
        if repo.head.commit.hexsha != branch_result.base_commit:
            raise GitServiceBlocked(
                "patch branch HEAD changed before accepted commit",
                error_code="git-commit-head-drift",
            )

        for relative_path in branch_result.changed_paths:
            decision = self.policy_engine.validate_patch_path(
                target_id=branch_result.target_id,
                relative_path=relative_path,
            )
            if not decision.allowed:
                raise GitServiceBlocked(
                    f"recorded patch path {relative_path!r} no longer passes patch policy",
                    error_code="git-commit-patch-path-blocked",
                )

        if set(_changed_paths(repo)) != set(branch_result.changed_paths):
            raise GitServiceBlocked(
                "changed paths no longer match the recorded patch attempt",
                error_code="git-commit-path-drift",
            )
        if _unstaged_paths(repo):
            raise GitServiceBlocked(
                "accepted patch commit refuses unstaged modifications",
                error_code="git-commit-unstaged-changes",
            )
