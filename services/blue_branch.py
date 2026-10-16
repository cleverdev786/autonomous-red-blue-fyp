"""Stage a source-checked Blue SQLi fix on a separate, local Git patch branch.

Consumes only independently pinned archived Red and model evidence. An
external Git repository is used so the FYP development branch and protected
baseline are never checked out or modified. Does not run Docker or replay.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sqlite3
from hashlib import sha256
from pathlib import Path
from urllib.parse import quote
from uuid import UUID

from git import Repo

from orchestrator.limits import RunLimitTracker
from orchestrator.patch_branch_flow import PatchBranchFlow
from orchestrator.policy_engine import PolicyEngine
from schemas.blue_team import TriageResult
from schemas.common import ClassificationLabel
from schemas.experiments import ExperimentLimits
from schemas.git import GitPolicyConfig
from services.audit_service import AuditService
from services.blue_input import build_blue_input
from services.blue_localize import _archived_file, _trusted_classification
from services.compact_source_selection import (
    CompactSourceSelection, build_verified_analysis, load_trusted_source_window,
)
from services.git_service import GitService
from services.q8_c12_development_bridge import localization_receipt
from services.target_registry import TargetRegistry
from services.trusted_remediation_compiler import SOURCE, TrustedRemediationCompiler

_ROOT = Path(__file__).resolve().parents[1]


class BlueBranchBlocked(RuntimeError):
    """Existing pinned model evidence cannot authorize an isolated staged patch."""


def _external(parent: Path, source: Path) -> Path:
    if not parent.is_absolute():
        raise BlueBranchBlocked("An absolute external output directory is required")
    if parent.is_symlink() or not parent.is_dir() or any(
        ancestor.is_symlink() for ancestor in parent.parents
    ):
        raise BlueBranchBlocked("Output directory must exist and contain no symlinks")
    actual = parent.resolve(strict=True)
    for protected in (source.resolve(strict=True), _ROOT.resolve(strict=True)):
        if actual == protected or protected in actual.parents:
            raise BlueBranchBlocked("Cannot write patch artifacts inside protected source")
    return actual


def _require_copy_safe(source_root: Path) -> None:
    # shutil.copytree follows symlinks by default. Never traverse an unexpected
    # checkout symlink into a host file while constructing the external branch.
    for relative in ("config", "dummy_apps/vulnerable_store"):
        tree = source_root / relative
        if tree.is_symlink() or not tree.is_dir():
            raise BlueBranchBlocked("Patch baseline folder is missing or symlinked")
        if any(item.is_symlink() for item in tree.rglob("*")):
            raise BlueBranchBlocked("Patch baseline contains an untrusted symlink")


def _evidenced_analysis(*, database: Path, job_id: str, source_root: Path,
                        evidence_dir: Path, admission_path: Path,
                        admission_sha256: str, receipt_sha256: str):
    """Recreate the exact typed analysis from write-once model raw evidence."""
    prepared = build_blue_input(
        database=database, job_id=job_id, source_root=source_root,
        evidence_dir=evidence_dir, admission_path=admission_path,
        admission_sha256=admission_sha256, receipt_sha256=receipt_sha256,
    )
    uri = "file:" + quote(str(database.absolute())) + "?mode=ro"
    with sqlite3.connect(uri, uri=True, timeout=5) as conn:
        classification = conn.execute(
            "SELECT status,result_json FROM blue_decisions WHERE job_id=?", (job_id,),
        ).fetchone()
        localization = conn.execute(
            "SELECT status,result_json FROM blue_localizations WHERE job_id=?", (job_id,),
        ).fetchone()
    if (classification is None or classification[0] != "recorded"
            or localization is None or localization[0] != "recorded"):
        raise BlueBranchBlocked("Recorded model classification and source localization required")
    saved_class = json.loads(classification[1])
    saved_loc = json.loads(localization[1])
    decision = _trusted_classification(saved_class, prepared, source_root)
    if (saved_loc["status"] != "recorded" or
            saved_loc["job_id"] != job_id or
            saved_loc["classification"] != "sql_injection" or
            saved_loc["model_origin"] != "q8_0_cpu_model" or
            saved_loc["red_receipt_sha256"] != receipt_sha256 or
            saved_loc["patch_preparation_authorized"] is not False or
            saved_loc["patch_applied"] is not False or
            saved_loc["final_research_qualified"] is not False):
        raise BlueBranchBlocked("Saved source analysis identity or policy is invalid")
    parent = Path(os.environ.get(
        "FYP_CONSOLE_EVIDENCE_DIR",
        str(Path.home() / ".local/state/sentinel-fyp/capability-evidence"),
    )).expanduser()
    archive_name = saved_loc["localization_evidence_id"]
    if (type(archive_name) is not str or
            re.fullmatch(r"[a-z][a-z0-9-]{0,63}", archive_name) is None):
        raise BlueBranchBlocked("Localization archive identity invalid")
    archive = parent / archive_name
    if (parent.is_symlink() or archive.is_symlink() or
            not archive.is_dir() or source_root.resolve() in archive.resolve().parents):
        raise BlueBranchBlocked("Localization archive missing or untrusted")
    loc_input = _archived_file(
        archive, "q8-localization-input.json",
        saved_loc["localization_input_sha256"], 16384,
    )
    raw = _archived_file(
        archive, "q8-localization-raw.json",
        saved_loc["localization_raw_sha256"], 262144,
    )
    if (loc_input != prepared["localization_request"] or
            raw.get("truncated") is not False or type(raw.get("content")) is not str):
        raise BlueBranchBlocked("Localization request or raw response changed")
    chosen = json.loads(raw["content"])
    gateway = _archived_file(archive, "q8-localization-gateway.json", None, 16384)
    if gateway != {
        "role": "source_localization", "result": chosen,
        "origin": "q8_0_cpu_model", "executed_tests": False,
    }:
        raise BlueBranchBlocked("Localization gateway is inconsistent with raw model output")
    typed = localization_receipt(
        request=loc_input, gateway_reply=gateway, project_root=source_root,
    )
    selection = CompactSourceSelection.model_validate(typed["selection"])
    if (selection.function_or_route != saved_loc["function_or_route"] or
            selection.sink_line != saved_loc["sink_line"] or
            selection.root_cause != saved_loc["root_cause"] or
            selection.confidence != saved_loc["confidence"] or
            saved_loc["source_file"] != typed["source_relative_path"] or
            saved_loc["source_sha256"] != typed["source_sha256"]):
        raise BlueBranchBlocked("Stored source selection differs from model evidence")
    analysis = build_verified_analysis(
        project_root=source_root, trusted_run_id=prepared["red_run_id"],
        triage=TriageResult(
            run_id=prepared["red_run_id"], is_suspicious=True,
            classification=ClassificationLabel.SQL_INJECTION,
            confidence=decision.confidence, reason=decision.reason,
        ),
        selection=selection,
        window=load_trusted_source_window(
            project_root=source_root, start_line=38, end_line=56,
        ),
    )
    digest = sha256(json.dumps(
        analysis.model_dump(mode="json"),
        sort_keys=True, separators=(",", ":"),
    ).encode()).hexdigest()
    if digest != saved_loc["blue_analysis_sha256"]:
        raise BlueBranchBlocked("Bound Blue analysis hash does not match saved model finding")
    return analysis, saved_loc


def prepare_blue_branch(
    *, database: Path, job_id: str, source_root: Path, evidence_dir: Path,
    admission_path: Path, admission_sha256: str, receipt_sha256: str,
    output_parent: Path,
) -> dict:
    """Stage an approved deterministic patch only in a new external Git repo."""
    canonical, source_root = str(UUID(job_id)), Path(source_root)
    database, evidence_dir = Path(database), Path(evidence_dir)
    admission_path = Path(admission_path)
    parent = _external(Path(output_parent), source_root)
    stage = parent / ("blue-patch-" + UUID(canonical).hex)
    if stage.exists() or stage.is_symlink():
        raise BlueBranchBlocked("An isolated patch attempt already exists for this job")
    try:
        analysis, saved = _evidenced_analysis(
            database=database, job_id=canonical, source_root=source_root,
            evidence_dir=evidence_dir, admission_path=admission_path,
            admission_sha256=admission_sha256, receipt_sha256=receipt_sha256,
        )
        _require_copy_safe(source_root)
        stage.mkdir(mode=0o700)
        try:
            project = stage / "repository"
            project.mkdir()
            shutil.copytree(source_root / "config", project / "config")
            shutil.copytree(
                source_root / "dummy_apps/vulnerable_store",
                project / "dummy_apps/vulnerable_store",
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
            )
            registry = TargetRegistry.from_directories(
                targets_dir=project / "config/targets",
                security_tests_dir=project / "config/security_tests",
            )
            audit = AuditService(project_root=stage / "audit")
            policy = PolicyEngine(registry=registry, project_root=project)
            compiler = TrustedRemediationCompiler(
                project_root=project, registry=registry, policy_engine=policy,
                audit_service=audit,
            )
            outcome = compiler.prepare(
                analysis=analysis, attempt_number=1,
                limits=RunLimitTracker(ExperimentLimits()),
            )
            if outcome.generation is None or outcome.provenance.status != "prepared":
                raise BlueBranchBlocked("Trusted compiler rejected the recorded model source")
            if outcome.provenance.blue_analysis_sha256 != saved["blue_analysis_sha256"]:
                raise BlueBranchBlocked("Compiler and model analysis disagree")
            repo = Repo.init(project)
            with repo.config_writer() as config:
                config.set_value("user", "name", "Isolated FYP Patch")
                config.set_value("user", "email", "patch@example.invalid")
            repo.git.symbolic_ref("HEAD", "refs/heads/main")
            repo.git.add("-A")
            repo.index.commit("Frozen source snapshot for isolated SQLi repair")
            git = GitService(
                repository_root=project,
                git_policy=GitPolicyConfig(
                    baseline_branch="main", patch_branch_prefix="agent-patch",
                ),
                policy_engine=policy, audit_service=audit,
            )
            branch = PatchBranchFlow(
                git_service=git, policy_engine=policy, audit_service=audit,
            ).run(generation_result=outcome.generation,
                  expected_base_commit=repo.head.commit.hexsha)
            if branch.changed_paths != (SOURCE,):
                raise BlueBranchBlocked("Prepared patch touched unexpected source files")
            # Recheck pinned model and Red evidence before returning staged output.
            current, current_saved = _evidenced_analysis(
                database=database, job_id=canonical, source_root=source_root,
                evidence_dir=evidence_dir, admission_path=admission_path,
                admission_sha256=admission_sha256, receipt_sha256=receipt_sha256,
            )
            if current != analysis or current_saved != saved:
                raise BlueBranchBlocked("Evidence changed during external patch staging")
            return {
                "job_id": canonical, "status": "staged",
                "branch_repo": str(project), "branch_name": branch.branch_name,
                "baseline_commit": branch.base_commit,
                "git_diff_sha256": branch.git_diff_sha256,
                "prepared_diff_sha256": branch.prepared_diff_sha256,
                "changed_paths": list(branch.changed_paths),
                "model_selected_function": saved["function_or_route"],
                "model_selected_line": saved["sink_line"],
                "blue_analysis_sha256": saved["blue_analysis_sha256"],
                "origin": "trusted_deterministic_builder",
                "model_localization_used": True,
                "patch_applied_to_live_repo": False,
                "security_replayed": False,
                "functionality_verified": False,
                "final_research_qualified": False,
            }
        except Exception:
            shutil.rmtree(stage)
            raise
    except BlueBranchBlocked:
        raise
    except Exception as exc:
        raise BlueBranchBlocked("Pinned Blue evidence or external patch preparation was rejected") from exc


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Stage a model-selected SQLi repair in an external Git repository",
    )
    for name in ("database", "source-root", "evidence-dir", "admission-path", "output-parent"):
        parser.add_argument("--" + name, required=True, type=Path)
    for name in ("job-id", "admission-sha256", "receipt-sha256"):
        parser.add_argument("--" + name, required=True)
    result = prepare_blue_branch(**vars(parser.parse_args()))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
