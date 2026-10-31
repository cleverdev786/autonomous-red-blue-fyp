"""Model-free registered Red -> trusted Blue repair -> isolated HTTP retest.

Real HTTP responses are observed with FastAPI TestClient. Only the pinned
synthetic source is compiled, never a model-supplied patch. No live repo,
Docker or research evidence is modified by this operation.
"""
from __future__ import annotations

import ast
import hashlib
import shutil
import tempfile
from contextlib import nullcontext
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

from fastapi.testclient import TestClient

from dashboard.api.operator_service import SCENARIOS
from dummy_apps.vulnerable_store.app import main as lab_main
from dummy_apps.vulnerable_store.app.config import StoreSettings
from orchestrator.limits import RunLimitTracker
from orchestrator.policy_engine import PolicyEngine
from schemas.blue_team import BlueTeamAnalysisResult, CodeFinding, SourceLineRange, TriageResult
from schemas.common import WorkflowState
from schemas.experiments import ClassificationMode, ExperimentLimits
from schemas.red_team import HttpExchangeEvidence
from security_tests.registry import SecurityTestRegistry
from services.audit_service import AuditService
from services.target_registry import TargetRegistry
from services.trusted_remediation_compiler import (
    EXPECTED_SOURCE_SHA256,
    SOURCE,
    TARGET,
    TrustedRemediationCompiler,
)

ROOT = Path(__file__).resolve().parents[1]
_REGISTERED_PATHS = {
    "sql": "/scenarios/sql-injection/login",
    "xss": "/scenarios/xss/search",
    "traversal": "/scenarios/path-traversal/read",
}


class OfflineWorkflowBlocked(RuntimeError):
    """Offline operation did not satisfy the exact registered tool contract."""


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _app_checks(*, runtime: Path, test, route: str, patched_router=None) -> dict:
    """Execute actual registered requests against a throwaway SQLite/file sandbox."""
    settings = StoreSettings(
        database_url=f"sqlite:///{runtime / 'store.db'}",
        seed_files_dir=runtime / "seed",
        scenario_files_dir=runtime / "scenarios",
    )
    context = (patch.object(lab_main, "build_scenario_router", patched_router)
               if patched_router is not None else nullcontext())
    with context, TestClient(lab_main.create_app(settings, reset_on_start=True)) as client:
        steps = test.build_steps()
        if len(steps) != 2 or any(
            s.endpoint_id not in (
                "scenario-sqli-login", "scenario-xss-search",
                "scenario-path-traversal-read"
            ) for s in steps
        ):
            raise OfflineWorkflowBlocked("registered_test_contract_changed")
        exchanges = []
        for index, step in enumerate(steps):
            reply = client.request(
                step.method.value,
                route,
                params=dict(step.query_params),
                json=dict(step.json_body) if step.json_body is not None else None,
                follow_redirects=False,
            )
            exchanges.append(HttpExchangeEvidence(
                exchange_id=f"offline-{index}",
                request_id=f"offline-{index}",
                step_id=step.step_id,
                endpoint_id=step.endpoint_id,
                method=step.method.value,
                status_code=reply.status_code,
                body_excerpt=reply.text[:2000],
                duration_ms=0,
            ))
        checks = {
            "health": client.get("/health").status_code == 200,
            "normal_login": client.post(
                "/login", json={"username": "student1", "password": "demo-pass-1"}
            ).status_code == 200,
            "normal_reject_bad_password": client.post(
                "/login", json={"username": "student1", "password": "bad-password"}
            ).status_code == 401,
            "normal_search": client.get("/search", params={"q": "notebook"}).status_code == 200,
            "control_request": exchanges[0].status_code in (200, 401),
        }
        evidence = test.evaluate(tuple(exchanges))
    return {
        "evidence_ids": [item.evidence_id for item in evidence],
        "control_status": exchanges[0].status_code,
        "attack_status": exchanges[1].status_code,
        "checks": checks,
        "normal_pass": all(checks.values()),
    }


def run_offline_cycle(scenario: str, *, project_root: Path = ROOT) -> dict:
    """Execute one source-pinned sandbox remediation with no LLM or network scanner."""
    if scenario not in _REGISTERED_PATHS or scenario not in SCENARIOS:
        raise OfflineWorkflowBlocked("scenario_not_registered")
    project_root = Path(project_root)
    desc = SCENARIOS[scenario]
    path = project_root / SOURCE
    if (project_root.is_symlink() or path.is_symlink() or not path.is_file()
            or _sha(path.read_bytes()) != EXPECTED_SOURCE_SHA256):
        raise OfflineWorkflowBlocked("source_snapshot_not_trusted")
    root_registry = TargetRegistry.from_directories(
        targets_dir=project_root / "config/targets",
        security_tests_dir=project_root / "config/security_tests",
    )
    SecurityTestRegistry.default().validate_against_target_registry(root_registry)
    target = root_registry.get_target(TARGET)
    selected = root_registry.get_security_test(desc["test_id"])
    if (desc["test_id"] not in target.allowed_test_ids
            or selected.test_id != desc["test_id"]):
        raise OfflineWorkflowBlocked("test_not_authorized")
    test = SecurityTestRegistry.default().get(desc["test_id"])
    route = _REGISTERED_PATHS[scenario]
    run_id = "offline-" + scenario
    with tempfile.TemporaryDirectory(prefix="mars-offline-rule-") as tmp:
        tmp_root = Path(tmp)
        baseline_dir, patched_dir = tmp_root / "baseline", tmp_root / "patched"
        baseline_dir.mkdir()
        patched_dir.mkdir()
        baseline = _app_checks(runtime=baseline_dir, test=test, route=route)
        if not baseline["evidence_ids"] or not baseline["normal_pass"]:
            raise OfflineWorkflowBlocked("registered_red_baseline_not_confirmed")
        source_root = tmp_root / "snapshot"
        shutil.copytree(project_root / "config", source_root / "config")
        cloned = source_root / SOURCE
        cloned.parent.mkdir(parents=True)
        shutil.copy2(path, cloned)
        registry = TargetRegistry.from_directories(
            targets_dir=source_root / "config/targets",
            security_tests_dir=source_root / "config/security_tests",
        )
        audit = AuditService(project_root=source_root)
        compiler = TrustedRemediationCompiler(
            project_root=source_root,
            registry=registry,
            policy_engine=PolicyEngine(registry=registry, project_root=source_root),
            audit_service=audit,
        )
        analysis = BlueTeamAnalysisResult(
            run_id=run_id,
            target_id=TARGET,
            classification_mode=ClassificationMode.RULE_ONLY,
            triage=TriageResult(
                run_id=run_id, is_suspicious=True, classification=desc["label"],
                confidence=1.0,
                reason="Registered baseline attack confirmed by the built-in test evaluator.",
            ),
            code_finding=CodeFinding(
                run_id=run_id, file_path=SOURCE,
                function_or_route=desc["function"], root_cause=desc["vector"],
                supporting_lines=(SourceLineRange(
                    start_line=desc["line"], end_line=desc["line"]),),
                confidence=1.0,
            ),
            final_state=WorkflowState.CODE_ANALYSIS,
        )
        result = compiler.prepare(
            analysis=analysis, attempt_number=1,
            limits=RunLimitTracker(ExperimentLimits()),
        )
        if result.generation is None or result.provenance.status != "prepared":
            raise OfflineWorkflowBlocked("trusted_patch_compiler_rejected")
        patch_file = result.generation.prepared_patch.files[0]
        if (patch_file.file_path != SOURCE
                or patch_file.original_sha256 != EXPECTED_SOURCE_SHA256
                or _sha(cloned.read_bytes()) != EXPECTED_SOURCE_SHA256):
            raise OfflineWorkflowBlocked("patch_source_identity_mismatch")
        replacement = patch_file.replacement_content.encode("utf-8")
        ast.parse(replacement.decode("utf-8"))
        # The compiler produced these exact bytes from hash-bound fixed templates.
        # They are not arbitrary model-written source.
        if replacement == path.read_bytes():
            raise OfflineWorkflowBlocked("patch_is_identical_to_baseline")
        module = ModuleType("dummy_apps.vulnerable_store.app._offline_verified")
        module.__package__ = "dummy_apps.vulnerable_store.app"
        exec(  # noqa: S102 - Only exact source compiled by pinned template engine.
            compile(replacement, "<pinned trusted offline source>", "exec"),
            module.__dict__,
        )
        patched = _app_checks(
            runtime=patched_dir, test=test, route=route,
            patched_router=module.build_scenario_router,
        )
        if not patched["normal_pass"] or patched["evidence_ids"]:
            raise OfflineWorkflowBlocked("patch_replay_failed")
        if patched["control_status"] != baseline["control_status"]:
            raise OfflineWorkflowBlocked("normal_control_regressed")
        if path.read_bytes() != cloned.read_bytes():
            raise OfflineWorkflowBlocked("live_source_changed")
        return {
            "result": "sandbox_verified",
            "scenario": scenario,
            "registered_test_id": desc["test_id"],
            "registered_red_confirmed": True,
            "baseline_red_evidence_ids": baseline["evidence_ids"],
            "baseline_control_passed": baseline["normal_pass"],
            "patched_security_test_passed": not patched["evidence_ids"],
            "patched_control_passed": patched["control_status"] == baseline["control_status"],
            "normal_application_passed": patched["normal_pass"],
            "normal_checks": patched["checks"],
            "baseline_attack_status": baseline["attack_status"],
            "patched_attack_status": patched["attack_status"],
            "patch_prepared": True,
            "patch_diff_sha256": result.generation.prepared_patch.diff_sha256,
            "source_location_verified": result.provenance.function_ast_sha256 is not None,
            "trusted_rule": result.provenance.rule_id,
            "model_used": False,
            "live_source_modified": False,
            "docker_replayed": False,
            "source_sha256": EXPECTED_SOURCE_SHA256,
            "patched_source_sha256": _sha(replacement),
            "scope": "isolated_in_process_http_test",
        }

if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) != 2:
        raise SystemExit(2)
    try:
        # Existing structured app logging writes to stdout during TestClient replay.
        # Keep exactly one machine-readable receipt on worker stdout.
        from contextlib import redirect_stdout
        with redirect_stdout(sys.stderr):
            outcome = run_offline_cycle(sys.argv[1])
        print(json.dumps(outcome, sort_keys=True))
    except OfflineWorkflowBlocked as exc:
        print(f"offline_rule_workflow_blocked: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
