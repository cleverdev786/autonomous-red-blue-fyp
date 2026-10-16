"""Operator-only, no-Docker registered SQLi replay against an isolated staged fix.

Only the exact trusted-template source may execute; neither Git nor Docker is
invoked to mutate the live checkout. This is development evidence, not final
registered-container security verification.
"""
from __future__ import annotations

import argparse
import json
import os
import tempfile
from hashlib import sha256
from pathlib import Path
from types import ModuleType
from unittest.mock import patch
from uuid import UUID

from fastapi.testclient import TestClient
from git import Repo

from dummy_apps.vulnerable_store.app import main as lab_main
from dummy_apps.vulnerable_store.app.config import StoreSettings
from schemas.red_team import HttpExchangeEvidence
from security_tests.registry import SecurityTestRegistry
from services.blue_branch import _external
from services.git_service import _staged_git_diff
from services.trusted_remediation_compiler import (
    EXPECTED_SOURCE_SHA256, SOURCE, _SQL_EXEC_NEW, _SQL_EXEC_OLD,
    _SQL_NEW, _SQL_OLD,
)


class BlueReplayBlocked(RuntimeError):
    """Isolated patch replay cannot trust the staged source or invocation."""


def _checked_stage(staged: dict, output_parent: Path, source_root: Path) -> tuple[Path, bytes]:
    job = str(UUID(staged["job_id"]))
    parent = _external(output_parent, source_root)
    expected = parent / ("blue-patch-" + UUID(job).hex) / "repository"
    if (Path(staged["branch_repo"]) != expected or
            any(path.is_symlink() for path in (expected, expected.parent, expected / SOURCE)) or
            not expected.is_dir() or staged.get("status") != "staged" or
            staged.get("changed_paths") != [SOURCE] or
            staged.get("origin") != "trusted_deterministic_builder" or
            staged.get("model_localization_used") is not True or
            staged.get("model_selected_function") != "vulnerable_login" or
            staged.get("model_selected_line") not in (48, 53) or
            staged.get("patch_applied_to_live_repo") is not False or
            staged.get("security_replayed") is not False or
            staged.get("final_research_qualified") is not False):
        raise BlueReplayBlocked("Patch staging identity or external location invalid")

    repo = Repo(expected)
    if (repo.active_branch.name != staged["branch_name"] or
            not staged["branch_name"].startswith("agent-patch/") or
            repo.head.commit.hexsha != staged["baseline_commit"] or
            repo.untracked_files or repo.index.diff(None)):
        raise BlueReplayBlocked("Git branch, baseline or working tree drifted")
    changed = {
        diff.b_path or diff.a_path for diff in repo.index.diff(repo.head.commit)
    }
    if changed != {SOURCE}:
        raise BlueReplayBlocked("Staged Git changes are not the registered source only")
    current_diff = _staged_git_diff(repo, (SOURCE,))
    if sha256(current_diff.encode()).hexdigest() != staged["git_diff_sha256"]:
        raise BlueReplayBlocked("Staged Git diff fingerprint changed")

    original = (repo.head.commit.tree / SOURCE).data_stream.read()
    if sha256(original).hexdigest() != EXPECTED_SOURCE_SHA256:
        raise BlueReplayBlocked("Isolated baseline source differs from pinned original")
    before = original.decode("utf-8")
    if before.count(_SQL_OLD) != 1 or before.count(_SQL_EXEC_OLD) != 1:
        raise BlueReplayBlocked("Trusted SQLi replacement anchors changed")
    expected_fix = before.replace(_SQL_OLD, _SQL_NEW).replace(
        _SQL_EXEC_OLD, _SQL_EXEC_NEW
    ).encode("utf-8")
    source = expected / SOURCE
    if (source.is_symlink() or not source.is_file() or
            source.read_bytes() != expected_fix):
        raise BlueReplayBlocked("Staged patch does not match exact trusted template")
    if repo.index.entries[(SOURCE, 0)].hexsha != repo.git.hash_object(str(source)):
        raise BlueReplayBlocked("Staged source differs from Git index")
    return expected, expected_fix


def _run_local_replay(source: bytes, output_parent: Path) -> dict:
    # The only compiled code is the exact pinned+trusted-template Python file.
    module = ModuleType("dummy_apps.vulnerable_store.app._verified_routes")
    module.__package__ = "dummy_apps.vulnerable_store.app"
    exec(compile(source, "<approved staged SQLi source>", "exec"), module.__dict__)
    test = SecurityTestRegistry.default().get("sqli-login-bypass-001")
    steps = test.build_steps()
    if (len(steps) != 2 or
            tuple(s.step_id for s in steps) !=
            ("control-wrong-password", "injection-bypass") or
            any(s.endpoint_id != "scenario-sqli-login" or
                s.method.value != "POST" or s.json_body is None for s in steps)):
        raise BlueReplayBlocked("Registered SQLi test definition changed")
    from security_tests.sql_injection.login_bypass import SqlInjectionLoginBypassTest
    if type(test) is not SqlInjectionLoginBypassTest:
        raise BlueReplayBlocked("Registered SQLi implementation changed")

    with tempfile.TemporaryDirectory(
        prefix="fyp-blue-replay-", dir=output_parent
    ) as working:
        runtime = Path(working)
        settings = StoreSettings(
            database_url=f"sqlite:///{runtime / 'store.db'}",
            seed_files_dir=runtime / "seeds",
            scenario_files_dir=runtime / "scenarios",
        )
        with patch.object(lab_main, "build_scenario_router", module.build_scenario_router):
            app = lab_main.create_app(settings, reset_on_start=True)
        exchanges = []
        with TestClient(app) as client:
            for index, step in enumerate(steps):
                response = client.request(
                    step.method.value, "/scenarios/sql-injection/login",
                    json=dict(step.json_body),
                )
                exchanges.append(HttpExchangeEvidence(
                    exchange_id=f"replay-{index}", request_id=f"replay-{index}",
                    step_id=step.step_id, endpoint_id=step.endpoint_id,
                    method=step.method.value, status_code=response.status_code,
                    body_excerpt=response.text[:2000], duration_ms=0,
                ))
            legitimate = client.post(
                "/scenarios/sql-injection/login",
                json={"username": "student1", "password": "demo-pass-1"},
            )
            normal = client.post(
                "/login", json={"username": "student1", "password": "demo-pass-1"}
            )
            invalid = client.post(
                "/login", json={"username": "student1", "password": "definitely-wrong"}
            )
            health = client.get("/health")
        evidence = test.evaluate(tuple(exchanges))
        checks = {
            "legitimate_scenario_login": legitimate.status_code == 200 and
                legitimate.json().get("username") == "student1",
            "incorrect_password_rejected": exchanges[0].status_code == 401,
            "normal_application_login": normal.status_code == 200 and
                normal.json().get("authenticated") is True,
            "normal_application_rejects_invalid_password": invalid.status_code == 401,
            "health_endpoint": health.status_code == 200,
        }
        passed = (all(checks.values()) and
                  exchanges[1].status_code == 401 and
                  not evidence and
                  "authenticated" not in exchanges[1].body_excerpt)
        return {
            "status": "passed" if passed else "failed",
            "test_id": test.test_id,
            "registered_steps_executed": len(exchanges),
            "control_status": exchanges[0].status_code,
            "injection_status": exchanges[1].status_code,
            "registered_exploit_evidence": [
                item.evidence_id for item in evidence
            ],
            "checks": checks,
        }


def verify_blue_replay(
    *, staged: dict, output_parent: Path, source_root: Path
) -> dict:
    """One write-once application-level registered replay of the staged fix."""
    try:
        parent = Path(output_parent)
        repo, patched_source = _checked_stage(staged, parent, Path(source_root))
        stage = repo.parent
        intent = stage / "replay.intent"
        # Intent comes BEFORE execution; a crash is never silently repeated.
        fd = os.open(intent, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(staged["git_diff_sha256"] + "\n")
        result = _run_local_replay(patched_source, parent)
        report = {
            **result,
            "job_id": str(UUID(staged["job_id"])),
            "replay_mode": "in_process_registered_test",
            "model_localization_used": True,
            "patch_origin": "trusted_deterministic_builder",
            "staged_source_sha256": sha256(patched_source).hexdigest(),
            "staged_git_diff_sha256": staged["git_diff_sha256"],
            "docker_replayed": False,
            "final_research_qualified": False,
            "final_repair_accepted": False,
        }
        data = (json.dumps(report, sort_keys=True, indent=2) + "\n").encode()
        fd = os.open(stage / "replay.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        return {**report, "report_sha256": sha256(data).hexdigest()}
    except FileExistsError as exc:
        raise BlueReplayBlocked("A registered replay was already attempted") from exc
    except BlueReplayBlocked:
        raise
    except Exception as exc:
        raise BlueReplayBlocked("Isolated replay or branch provenance failed") from exc


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify staged SQLi patch using registered in-process HTTP replay",
    )
    parser.add_argument("--branch-receipt", type=Path, required=True)
    parser.add_argument("--output-parent", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    args = parser.parse_args()
    receipt = json.loads(args.branch_receipt.read_text())
    print(json.dumps(verify_blue_replay(
        staged=receipt, output_parent=args.output_parent,
        source_root=args.source_root,
    ), indent=2))


if __name__ == "__main__":
    main()
