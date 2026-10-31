"""Registered SQLi replay against separately staged, source-checked Git patch."""
from pathlib import Path
from hashlib import sha256

import pytest

from test_branch import localized
from test_classify import environment
from test_localize import classified
from test_preview import reviewed_archive


@pytest.fixture
def staged(localized, tmp_path):
    from services.blue_branch import prepare_blue_branch
    db, job, pins, selected = localized
    output = tmp_path / "external-patches"
    output.mkdir()
    info = prepare_blue_branch(
        database=db, job_id=job["id"], output_parent=output, **pins,
    )
    return info, output, pins, selected


def test_registered_replay_on_staged_patch_retains_legitimate_behavior(staged):
    from services.blue_replay import verify_blue_replay
    from services.trusted_remediation_compiler import SOURCE
    info, parent, pins, selection = staged
    original = (pins["source_root"] / SOURCE).read_bytes()
    report = verify_blue_replay(
        staged=info, output_parent=parent, source_root=pins["source_root"],
    )
    assert report["status"] == "passed"
    assert report["test_id"] == "sqli-login-bypass-001"
    assert report["replay_mode"] == "in_process_registered_test"
    assert report["registered_steps_executed"] == 2
    assert report["control_status"] == 401
    assert report["injection_status"] == 401
    assert report["registered_exploit_evidence"] == []
    assert report["checks"] == {
        "legitimate_scenario_login": True,
        "incorrect_password_rejected": True,
        "normal_application_login": True,
        "normal_application_rejects_invalid_password": True,
        "health_endpoint": True,
    }
    assert report["model_localization_used"] is True
    assert report["patch_origin"] == "trusted_deterministic_builder"
    assert report["docker_replayed"] is False
    assert report["final_research_qualified"] is False
    assert report["final_repair_accepted"] is False
    assert len(report["staged_source_sha256"]) == 64
    assert (pins["source_root"] / SOURCE).read_bytes() == original
    evidence = parent / ("blue-patch-" + info["job_id"].replace("-", "")) / "replay.json"
    assert evidence.exists()
    assert sha256(evidence.read_bytes()).hexdigest() == report["report_sha256"]
    assert evidence.read_text().find("definitely-wrong") == -1


def test_registered_evaluator_detects_unpatched_baseline(tmp_path):
    from fastapi.testclient import TestClient
    from dummy_apps.vulnerable_store.app.main import create_app
    from dummy_apps.vulnerable_store.app.config import StoreSettings
    from schemas.red_team import HttpExchangeEvidence
    from security_tests.registry import SecurityTestRegistry

    test = SecurityTestRegistry.default().get("sqli-login-bypass-001")
    settings = StoreSettings(
        database_url=f"sqlite:///{tmp_path / 'baseline.db'}",
        seed_files_dir=tmp_path / "seed", scenario_files_dir=tmp_path / "scenario",
    )
    exchanges = []
    with TestClient(create_app(settings, reset_on_start=True)) as client:
        for n, step in enumerate(test.build_steps()):
            response = client.post("/scenarios/sql-injection/login", json=dict(step.json_body))
            exchanges.append(HttpExchangeEvidence(
                exchange_id=f"baseline-{n}", request_id=f"baseline-{n}",
                step_id=step.step_id, endpoint_id=step.endpoint_id,
                method="POST", status_code=response.status_code,
                body_excerpt=response.text[:2000], duration_ms=0,
            ))
    assert [x.status_code for x in exchanges] == [401, 200]
    assert [x.evidence_type for x in test.evaluate(tuple(exchanges))] == ["authentication_bypass"]


@pytest.mark.parametrize("mutate", [
    "source_worktree", "source_index", "base", "diff", "branch", "test_id", "external",
])
def test_replay_refuses_altered_branch_or_provenance(staged, mutate):
    from services.blue_replay import BlueReplayBlocked, verify_blue_replay
    from services.trusted_remediation_compiler import SOURCE
    from git import Repo

    info, parent, pins, selection = staged
    info = dict(info)
    repo_root = Path(info["branch_repo"])
    if mutate == "source_worktree":
        with (repo_root / SOURCE).open("ab") as out:
            out.write(b"\n# changed after staging")
    elif mutate == "source_index":
        repo = Repo(repo_root)
        (repo_root / SOURCE).write_text("print('different')\n")
        repo.index.add([SOURCE])
    elif mutate == "base":
        info["baseline_commit"] = "0" * 40
    elif mutate == "diff":
        info["git_diff_sha256"] = "0" * 64
    elif mutate == "branch":
        info["branch_name"] = "main"
    elif mutate == "test_id":
        info["changed_paths"] = ["not-registered.py"]
    elif mutate == "external":
        parent = pins["source_root"]
    with pytest.raises(BlueReplayBlocked):
        verify_blue_replay(staged=info, output_parent=parent, source_root=pins["source_root"])


def test_replay_is_one_attempt_with_saved_evidence(staged):
    from services.blue_replay import BlueReplayBlocked, verify_blue_replay
    info, parent, pins, _ = staged
    first = verify_blue_replay(
        staged=info, output_parent=parent, source_root=pins["source_root"],
    )
    with pytest.raises(BlueReplayBlocked, match="already"):
        verify_blue_replay(
            staged=info, output_parent=parent, source_root=pins["source_root"],
        )
    assert first["status"] == "passed"


def test_registered_test_evidence_of_exploit_produces_failure_not_acceptance(staged, monkeypatch):
    from services.blue_replay import verify_blue_replay
    from security_tests.sql_injection.login_bypass import SqlInjectionLoginBypassTest
    from schemas.red_team import EvidenceItem

    info, parent, pins, _ = staged
    def exploit_evidence(self, exchanges):
        return (EvidenceItem(evidence_id="registered-exploit",
                             evidence_type="authentication_bypass",
                             summary="Deliberately simulated positive evaluator result."),)
    monkeypatch.setattr(SqlInjectionLoginBypassTest, "evaluate", exploit_evidence)
    report = verify_blue_replay(
        staged=info, output_parent=parent, source_root=pins["source_root"],
    )
    assert report["status"] == "failed"
    assert report["registered_exploit_evidence"] == ["registered-exploit"]
    assert report["final_repair_accepted"] is False


def test_untrusted_extra_staged_python_cannot_execute(staged, tmp_path):
    from services.blue_replay import verify_blue_replay, BlueReplayBlocked
    from services.trusted_remediation_compiler import SOURCE

    info, parent, pins, _ = staged
    flag = tmp_path / "should-never-be-created"
    malicious = ("\nfrom pathlib import Path\n"
                 f"Path({str(flag)!r}).write_text('untrusted code executed')\n")
    with (Path(info["branch_repo"]) / SOURCE).open("a") as stream:
        stream.write(malicious)
    with pytest.raises(BlueReplayBlocked):
        verify_blue_replay(
            staged=info, output_parent=parent, source_root=pins["source_root"],
        )
    assert not flag.exists()
    assert not (Path(info["branch_repo"]).parent / "replay.intent").exists()
