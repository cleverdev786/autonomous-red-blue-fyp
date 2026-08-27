"""Milestone 13 restricted Git branch-isolation tests using temporary repositories only."""

from __future__ import annotations

import difflib
import hashlib
from pathlib import Path

import pytest

pytest.importorskip("git")
from git import Repo

from orchestrator.patch_branch_flow import PatchBranchFlow, PatchBranchFlowError
from orchestrator.policy_engine import PolicyEngine
from schemas.common import PatchDecision, WorkflowState
from schemas.git import GitPolicyConfig
from schemas.patches import (
    PatchGenerationResult,
    PatchProposal,
    PreparedFileChange,
    PreparedPatch,
    ProposedFileChange,
)
from services.audit_service import AuditService
from services.git_service import GitService, GitServiceBlocked, GitServiceError
from services.target_registry import TargetRegistry


ROOT = Path(__file__).resolve().parents[1]
TARGET_ID = "vulnerable-store"
SOURCE_FILE = "dummy_apps/vulnerable_store/app/example.py"
GENERATED_FILE = "dummy_apps/vulnerable_store/tests/generated/test_generated_example.py"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


def _sha_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _unified_diff(path: str, before: str, after: str, *, new_file: bool = False) -> str:
    before_lines = [] if new_file else before.splitlines(keepends=True)
    after_lines = after.splitlines(keepends=True)
    return "".join(
        difflib.unified_diff(
            before_lines,
            after_lines,
            fromfile="/dev/null" if new_file else f"a/{path}",
            tofile=f"b/{path}",
        )
    )


def _init_repo(tmp_path: Path) -> tuple[Repo, Path, str, str]:
    root = tmp_path / "repo"
    source = root / SOURCE_FILE
    generated_dir = root / "dummy_apps/vulnerable_store/tests/generated"
    source.parent.mkdir(parents=True)
    generated_dir.mkdir(parents=True)
    before = "def vulnerable(value: str) -> str:\n    return value\n"
    source.write_text(before, encoding="utf-8")
    (generated_dir / ".gitkeep").write_text("", encoding="utf-8")
    (root / ".gitignore").write_text("data/*\n!data/.gitkeep\n", encoding="utf-8")

    repo = Repo.init(root)
    with repo.config_writer() as writer:
        writer.set_value("user", "name", "FYP Test")
        writer.set_value("user", "email", "fyp-test@example.invalid")
    repo.index.add(
        [
            SOURCE_FILE,
            "dummy_apps/vulnerable_store/tests/generated/.gitkeep",
            ".gitignore",
        ]
    )
    commit = repo.index.commit("baseline")
    repo.active_branch.rename("main")
    return repo, root, commit.hexsha, before


def _registry() -> TargetRegistry:
    return TargetRegistry.from_directories(
        targets_dir=ROOT / "config" / "targets",
        security_tests_dir=ROOT / "config" / "security_tests",
    )


def _service(repo_root: Path, audit_root: Path) -> GitService:
    registry = _registry()
    return GitService(
        repository_root=repo_root,
        git_policy=GitPolicyConfig(
            baseline_branch="main",
            patch_branch_prefix="agent-patch",
        ),
        policy_engine=PolicyEngine(registry=registry, project_root=repo_root),
        audit_service=AuditService(project_root=audit_root),
    )


def _prepared_patch(
    *,
    run_id: str = "git-run",
    attempt_number: int = 1,
    before: str,
    include_generated: bool = False,
) -> PreparedPatch:
    after = "def vulnerable(value: str) -> str:\n    return value.strip()\n"
    source_diff = _unified_diff(SOURCE_FILE, before, after)
    files = [
        PreparedFileChange(
            file_path=SOURCE_FILE,
            original_sha256=_sha_text(before),
            replacement_sha256=_sha_text(after),
            replacement_content=after,
            is_new_file=False,
        )
    ]
    diff = source_diff
    generated_path = None
    if include_generated:
        generated_content = "def test_generated_example():\n    assert True\n"
        files.append(
            PreparedFileChange(
                file_path=GENERATED_FILE,
                original_sha256=EMPTY_SHA256,
                replacement_sha256=_sha_text(generated_content),
                replacement_content=generated_content,
                is_new_file=True,
            )
        )
        diff += _unified_diff(GENERATED_FILE, "", generated_content, new_file=True)
        generated_path = GENERATED_FILE

    inserted = sum(
        1
        for line in diff.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    )
    deleted = sum(
        1
        for line in diff.splitlines()
        if line.startswith("-") and not line.startswith("---")
    )
    return PreparedPatch(
        run_id=run_id,
        target_id=TARGET_ID,
        attempt_number=attempt_number,
        files=tuple(files),
        unified_diff=diff,
        diff_sha256=_sha_text(diff),
        files_changed=len(files),
        inserted_lines=inserted,
        deleted_lines=deleted,
        total_diff_bytes=len(diff.encode("utf-8")),
        generated_test_path=generated_path,
    )


def _generation_result(patch: PreparedPatch) -> PatchGenerationResult:
    first = patch.files[0]
    proposal = PatchProposal(
        run_id=patch.run_id,
        target_id=patch.target_id,
        attempt_number=patch.attempt_number,
        changes=(
            ProposedFileChange(
                file_path=first.file_path,
                original_content="return value",
                replacement_content="return value.strip()",
                rationale="Synthetic temporary-repository Git fixture.",
            ),
        ),
        security_rationale="Synthetic Git isolation fixture.",
        expected_effect="Materialize only the already-prepared patch.",
    )
    return PatchGenerationResult(
        run_id=patch.run_id,
        target_id=patch.target_id,
        attempt_number=patch.attempt_number,
        proposal=proposal,
        prepared_patch=patch,
        final_state=WorkflowState.PATCH_VALIDATING,
    )


def _flow(service: GitService, audit_root: Path) -> PatchBranchFlow:
    return PatchBranchFlow(
        git_service=service,
        policy_engine=service.policy_engine,
        audit_service=AuditService(project_root=audit_root),
    )


def test_clean_baseline_flow_materializes_prepared_patch_on_isolated_branch(tmp_path: Path) -> None:
    repo, repo_root, base_commit, before = _init_repo(tmp_path)
    audit_root = tmp_path / "audit"
    service = _service(repo_root, audit_root)
    patch = _prepared_patch(before=before)

    result = _flow(service, audit_root).run(
        generation_result=_generation_result(patch),
        expected_base_commit=base_commit,
    )

    assert result.final_state == WorkflowState.PATCH_APPLYING
    assert result.branch_name == "agent-patch/git-run/attempt-1"
    assert repo.active_branch.name == result.branch_name
    assert repo.head.commit.hexsha == base_commit
    assert repo.heads.main.commit.hexsha == base_commit
    assert result.changed_paths == (SOURCE_FILE,)
    assert result.prepared_diff_sha256 == patch.diff_sha256
    assert result.git_diff_sha256 == _sha_text(result.git_diff)
    assert (repo_root / SOURCE_FILE).read_text(encoding="utf-8").endswith("return value.strip()\n")
    assert repo.index.diff(None) == []

    operations = {
        event.operation
        for event in AuditService(project_root=audit_root).read_run(run_id="git-run")
    }
    for required in (
        "git_baseline_validation",
        "git_branch_creation",
        "git_patch_materialization",
        "git_diff_inspection",
        "workflow_transition",
    ):
        assert required in operations


def test_dirty_baseline_is_blocked_before_branch_creation(tmp_path: Path) -> None:
    repo, repo_root, base_commit, before = _init_repo(tmp_path)
    (repo_root / SOURCE_FILE).write_text(before + "# dirty\n", encoding="utf-8")
    service = _service(repo_root, tmp_path / "audit")

    with pytest.raises(GitServiceBlocked) as exc_info:
        service.verify_clean_baseline(run_id="dirty-run", expected_base_commit=base_commit)
    assert exc_info.value.error_code == "git-dirty-baseline"
    assert repo.active_branch.name == "main"


def test_wrong_current_branch_is_blocked_as_baseline(tmp_path: Path) -> None:
    repo, repo_root, base_commit, _ = _init_repo(tmp_path)
    repo.create_head("developer", base_commit).checkout()
    service = _service(repo_root, tmp_path / "audit")

    with pytest.raises(GitServiceBlocked) as exc_info:
        service.verify_clean_baseline(run_id="wrong-branch")
    assert exc_info.value.error_code == "git-wrong-baseline-branch"


def test_wrong_expected_base_commit_is_blocked(tmp_path: Path) -> None:
    _, repo_root, _, _ = _init_repo(tmp_path)
    service = _service(repo_root, tmp_path / "audit")

    with pytest.raises(GitServiceBlocked) as exc_info:
        service.verify_clean_baseline(run_id="wrong-sha", expected_base_commit="0" * 40)
    assert exc_info.value.error_code == "git-base-commit-mismatch"


def test_deterministic_branch_collision_is_blocked(tmp_path: Path) -> None:
    repo, repo_root, base_commit, before = _init_repo(tmp_path)
    service = _service(repo_root, tmp_path / "audit")
    patch = _prepared_patch(before=before)
    branch = service.git_policy.branch_name(
        run_id=patch.run_id,
        attempt_number=patch.attempt_number,
    )
    repo.create_head(branch, base_commit)

    with pytest.raises(GitServiceBlocked) as exc_info:
        service.create_patch_branch(prepared_patch=patch, base_commit=base_commit)
    assert exc_info.value.error_code == "git-branch-collision"


def test_source_hash_drift_fails_closed_and_flow_returns_to_main(tmp_path: Path) -> None:
    repo, repo_root, base_commit, before = _init_repo(tmp_path)
    service = _service(repo_root, tmp_path / "audit")
    patch = _prepared_patch(before=before)
    tampered = patch.model_copy(
        update={
            "files": (
                patch.files[0].model_copy(update={"original_sha256": "1" * 64}),
            )
        }
    )

    with pytest.raises(GitServiceBlocked) as exc_info:
        _flow(service, tmp_path / "audit").run(
            generation_result=_generation_result(tampered),
            expected_base_commit=base_commit,
        )
    assert exc_info.value.error_code == "git-source-hash-mismatch"
    assert repo.active_branch.name == "main"
    assert repo.head.commit.hexsha == base_commit
    assert not repo.is_dirty(untracked_files=True)


def test_materialization_on_main_is_explicitly_blocked(tmp_path: Path) -> None:
    _, repo_root, base_commit, before = _init_repo(tmp_path)
    service = _service(repo_root, tmp_path / "audit")
    patch = _prepared_patch(before=before)

    with pytest.raises(GitServiceBlocked) as exc_info:
        service.materialize_prepared_patch(
            prepared_patch=patch,
            branch_name="main",
            base_commit=base_commit,
        )
    assert exc_info.value.error_code == "git-baseline-write-blocked"
    assert (repo_root / SOURCE_FILE).read_text(encoding="utf-8") == before


def test_generated_security_test_is_materialized_only_on_patch_branch(tmp_path: Path) -> None:
    repo, repo_root, base_commit, before = _init_repo(tmp_path)
    service = _service(repo_root, tmp_path / "audit")
    patch = _prepared_patch(before=before, include_generated=True)

    result = _flow(service, tmp_path / "audit").run(
        generation_result=_generation_result(patch),
        expected_base_commit=base_commit,
    )

    assert result.changed_paths == tuple(sorted((SOURCE_FILE, GENERATED_FILE)))
    assert (repo_root / GENERATED_FILE).is_file()
    assert repo.heads.main.commit.hexsha == base_commit
    assert repo.active_branch.name == result.branch_name


def test_restore_baseline_restores_exact_paths_and_leaves_attempt_branch(tmp_path: Path) -> None:
    repo, repo_root, base_commit, before = _init_repo(tmp_path)
    service = _service(repo_root, tmp_path / "audit")
    patch = _prepared_patch(before=before, include_generated=True)
    result = _flow(service, tmp_path / "audit").run(
        generation_result=_generation_result(patch),
        expected_base_commit=base_commit,
    )

    service.restore_baseline(
        prepared_patch=patch,
        branch_name=result.branch_name,
        base_commit=base_commit,
    )

    assert repo.active_branch.name == "main"
    assert repo.head.commit.hexsha == base_commit
    assert not repo.is_dirty(untracked_files=True)
    assert (repo_root / SOURCE_FILE).read_text(encoding="utf-8") == before
    assert not (repo_root / GENERATED_FILE).exists()
    assert any(head.name == result.branch_name for head in repo.heads)


def test_restore_refuses_to_delete_unrelated_dirty_file(tmp_path: Path) -> None:
    repo, repo_root, base_commit, before = _init_repo(tmp_path)
    service = _service(repo_root, tmp_path / "audit")
    patch = _prepared_patch(before=before)
    result = _flow(service, tmp_path / "audit").run(
        generation_result=_generation_result(patch),
        expected_base_commit=base_commit,
    )
    unrelated = repo_root / "unrelated.txt"
    unrelated.write_text("do not erase", encoding="utf-8")

    with pytest.raises(GitServiceBlocked) as exc_info:
        service.restore_baseline(
            prepared_patch=patch,
            branch_name=result.branch_name,
            base_commit=base_commit,
        )
    assert exc_info.value.error_code == "git-restore-unrelated-dirty"
    assert unrelated.read_text(encoding="utf-8") == "do not erase"
    assert repo.active_branch.name == result.branch_name


def test_rejected_patch_decision_cannot_commit(tmp_path: Path) -> None:
    repo, repo_root, base_commit, before = _init_repo(tmp_path)
    service = _service(repo_root, tmp_path / "audit")
    patch = _prepared_patch(before=before)
    result = _flow(service, tmp_path / "audit").run(
        generation_result=_generation_result(patch),
        expected_base_commit=base_commit,
    )

    with pytest.raises(GitServiceBlocked) as exc_info:
        service.commit_accepted_patch(
            branch_result=result,
            decision=PatchDecision.REJECTED,
        )
    assert exc_info.value.error_code == "git-commit-not-accepted"
    assert repo.head.commit.hexsha == base_commit
    assert repo.heads.main.commit.hexsha == base_commit


def test_explicit_accepted_decision_creates_local_patch_branch_commit_only(tmp_path: Path) -> None:
    repo, repo_root, base_commit, before = _init_repo(tmp_path)
    service = _service(repo_root, tmp_path / "audit")
    patch = _prepared_patch(before=before)
    result = _flow(service, tmp_path / "audit").run(
        generation_result=_generation_result(patch),
        expected_base_commit=base_commit,
    )

    commit_sha = service.commit_accepted_patch(
        branch_result=result,
        decision=PatchDecision.ACCEPTED,
    )

    assert commit_sha != base_commit
    assert repo.active_branch.name == result.branch_name
    assert repo.head.commit.hexsha == commit_sha
    assert repo.head.commit.message.strip() == "Patch attempt git-run attempt 1"
    assert repo.heads.main.commit.hexsha == base_commit
    assert not repo.is_dirty(untracked_files=True)
    assert not repo.remotes


def test_commit_refuses_diff_drift_after_materialization(tmp_path: Path) -> None:
    repo, repo_root, base_commit, before = _init_repo(tmp_path)
    service = _service(repo_root, tmp_path / "audit")
    patch = _prepared_patch(before=before)
    result = _flow(service, tmp_path / "audit").run(
        generation_result=_generation_result(patch),
        expected_base_commit=base_commit,
    )
    path = repo_root / SOURCE_FILE
    path.write_text(path.read_text(encoding="utf-8") + "# drift\n", encoding="utf-8")

    with pytest.raises(GitServiceBlocked) as exc_info:
        service.commit_accepted_patch(
            branch_result=result,
            decision=PatchDecision.ACCEPTED,
        )
    assert exc_info.value.error_code == "git-commit-unstaged-changes"
    assert repo.heads.main.commit.hexsha == base_commit


def test_tampered_prepared_diff_hash_is_blocked_before_any_write(tmp_path: Path) -> None:
    repo, repo_root, base_commit, before = _init_repo(tmp_path)
    service = _service(repo_root, tmp_path / "audit")
    patch = _prepared_patch(before=before).model_copy(update={"diff_sha256": "0" * 64})
    branch = service.create_patch_branch(prepared_patch=patch, base_commit=base_commit)

    with pytest.raises(GitServiceBlocked) as exc_info:
        service.materialize_prepared_patch(
            prepared_patch=patch,
            branch_name=branch,
            base_commit=base_commit,
        )
    assert exc_info.value.error_code == "git-prepared-diff-hash-mismatch"
    assert (repo_root / SOURCE_FILE).read_text(encoding="utf-8") == before
    assert not repo.is_dirty(untracked_files=True)


def test_duplicate_prepared_paths_are_blocked(tmp_path: Path) -> None:
    repo, repo_root, base_commit, before = _init_repo(tmp_path)
    service = _service(repo_root, tmp_path / "audit")
    patch = _prepared_patch(before=before)
    duplicate = patch.model_copy(
        update={"files": (patch.files[0], patch.files[0]), "files_changed": 2}
    )
    branch = service.create_patch_branch(prepared_patch=duplicate, base_commit=base_commit)

    with pytest.raises(GitServiceBlocked) as exc_info:
        service.materialize_prepared_patch(
            prepared_patch=duplicate,
            branch_name=branch,
            base_commit=base_commit,
        )
    assert exc_info.value.error_code == "git-duplicate-patch-path"
    assert not repo.is_dirty(untracked_files=True)


def test_atomic_write_failure_rolls_back_already_written_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo, repo_root, base_commit, before = _init_repo(tmp_path)
    service = _service(repo_root, tmp_path / "audit")
    patch = _prepared_patch(before=before, include_generated=True)
    branch = service.create_patch_branch(prepared_patch=patch, base_commit=base_commit)
    original_write_text = Path.write_text

    def failing_write_text(path: Path, data: str, *args, **kwargs):
        if str(path).endswith("test_generated_example.py"):
            raise OSError("synthetic second-write failure")
        return original_write_text(path, data, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", failing_write_text)

    with pytest.raises(GitServiceError):
        service.materialize_prepared_patch(
            prepared_patch=patch,
            branch_name=branch,
            base_commit=base_commit,
        )

    assert (repo_root / SOURCE_FILE).read_text(encoding="utf-8") == before
    assert not (repo_root / GENERATED_FILE).exists()
    assert not repo.is_dirty(untracked_files=True)


def test_flow_rejects_non_patch_validating_input_before_git_mutation(tmp_path: Path) -> None:
    repo, repo_root, _, before = _init_repo(tmp_path)
    service = _service(repo_root, tmp_path / "audit")
    patch = _prepared_patch(before=before)
    result = _generation_result(patch).model_copy(
        update={"final_state": WorkflowState.PATCH_APPLYING}
    )

    with pytest.raises(PatchBranchFlowError):
        _flow(service, tmp_path / "audit").run(generation_result=result)
    assert repo.active_branch.name == "main"
    assert len(repo.heads) == 1


def test_attempt_numbers_generate_distinct_deterministic_branches() -> None:
    policy = GitPolicyConfig(baseline_branch="main", patch_branch_prefix="agent-patch")
    assert policy.branch_name(run_id="run-123", attempt_number=1) == "agent-patch/run-123/attempt-1"
    assert policy.branch_name(run_id="run-123", attempt_number=2) == "agent-patch/run-123/attempt-2"


def test_git_service_has_no_remote_merge_or_arbitrary_command_interface() -> None:
    prohibited = {
        "push",
        "force_push",
        "merge",
        "pull",
        "fetch",
        "run_git",
        "execute",
        "execute_command",
    }
    assert prohibited.isdisjoint(set(dir(GitService)))


def test_verify_materialized_patch_accepts_exact_recorded_staged_state(tmp_path: Path) -> None:
    repo, repo_root, base_commit, before = _init_repo(tmp_path)
    service = _service(repo_root, tmp_path / "audit")
    patch = _prepared_patch(before=before)
    result = _flow(service, tmp_path / "audit").run(
        generation_result=_generation_result(patch),
        expected_base_commit=base_commit,
    )

    assert service.verify_materialized_patch(
        prepared_patch=patch,
        branch_result=result,
    ) == result.git_diff_sha256
    assert repo.active_branch.name == result.branch_name
    assert repo.heads.main.commit.hexsha == base_commit


def test_verify_materialized_patch_blocks_unstaged_or_hash_drift(tmp_path: Path) -> None:
    repo, repo_root, base_commit, before = _init_repo(tmp_path)
    service = _service(repo_root, tmp_path / "audit")
    patch = _prepared_patch(before=before)
    result = _flow(service, tmp_path / "audit").run(
        generation_result=_generation_result(patch),
        expected_base_commit=base_commit,
    )
    path = repo_root / SOURCE_FILE
    path.write_text(path.read_text(encoding="utf-8") + "# unexpected\n", encoding="utf-8")

    with pytest.raises(GitServiceBlocked) as exc_info:
        service.verify_materialized_patch(
            prepared_patch=patch,
            branch_result=result,
        )
    assert exc_info.value.error_code in {
        "git-commit-unstaged-changes",
        "git-verification-file-hash-drift",
    }
    assert repo.heads.main.commit.hexsha == base_commit
