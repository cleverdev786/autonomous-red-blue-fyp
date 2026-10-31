"""Externally isolated Git branch from independently pinned model-selected Blue analysis.

Registered Red remains simulated by the existing injected test runner;
no Docker or live source mutation is permitted in these tests.
"""
import json
from hashlib import sha256
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from test_classify import environment, reviewed_archive
from test_localize import classified, localization_reply


@pytest.fixture
def localized(reviewed_archive, monkeypatch, tmp_path):
    from services.blue_localize import localize_bound_job
    import dashboard.api.q8_development_service as q8
    db, job, pins, model, _calls, evidence = classified(
        reviewed_archive, monkeypatch, tmp_path,
    )
    monkeypatch.setattr(q8, "_raw_completion", localization_reply)
    found = localize_bound_job(database=db, job_id=job["id"], **pins)
    return db, job, pins, found


def test_model_selected_source_creates_only_external_staged_git_branch(localized, tmp_path):
    from git import Repo
    from services.blue_branch import prepare_blue_branch
    from services.trusted_remediation_compiler import SOURCE, EXPECTED_SOURCE_SHA256

    db, job, pins, found = localized
    live_source = pins["source_root"] / SOURCE
    before = live_source.read_bytes()
    assert sha256(before).hexdigest() == EXPECTED_SOURCE_SHA256
    parent = tmp_path / "patch-artifacts"
    parent.mkdir()
    result = prepare_blue_branch(
        database=db, job_id=job["id"], output_parent=parent, **pins,
    )
    assert result["status"] == "staged"
    assert result["model_selected_function"] == "vulnerable_login"
    assert result["model_selected_line"] == 53
    assert result["verified_sink_line"] == 53
    assert result["blue_analysis_sha256"] == found["blue_analysis_sha256"]
    assert result["origin"] == "trusted_deterministic_builder"
    assert result["model_localization_used"] is True
    assert result["patch_applied_to_live_repo"] is False
    assert result["security_replayed"] is False
    assert result["functionality_verified"] is False
    assert result["final_research_qualified"] is False
    external = Path(result["branch_repo"])
    assert parent.resolve() in external.resolve().parents
    assert pins["source_root"].resolve() not in external.resolve().parents
    repo = Repo(external)
    assert repo.active_branch.name.startswith("agent-patch/")
    assert repo.head.commit.hexsha == result["baseline_commit"]
    assert set(repo.git.diff("--cached", "--name-only").splitlines()) == {SOURCE}
    assert not repo.index.diff(None)
    changed = (external / SOURCE).read_text()
    assert "WHERE username = :username" in changed
    assert "'{payload.username}'" not in changed
    assert live_source.read_bytes() == before


def test_isolated_branch_passes_login_security_and_legitimate_behavior(
    localized, tmp_path, monkeypatch
):
    from services.blue_branch import prepare_blue_branch
    from services.trusted_remediation_compiler import SOURCE
    from dummy_apps.vulnerable_store.app import main as lab_main
    from dummy_apps.vulnerable_store.app.config import StoreSettings

    db, job, pins, found = localized
    parent = tmp_path / "staged"
    parent.mkdir()
    result = prepare_blue_branch(database=db, job_id=job["id"],
                                 output_parent=parent, **pins)
    source = Path(result["branch_repo"]) / SOURCE
    spec = spec_from_file_location(
        "dummy_apps.vulnerable_store.app._branch_routes", source,
    )
    assert spec is not None and spec.loader is not None
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(lab_main, "build_scenario_router", module.build_scenario_router)
    root = tmp_path / "isolated-runtime"
    settings = StoreSettings(
        database_url=f"sqlite:///{root / 'store.db'}",
        seed_files_dir=root / "seeds",
        scenario_files_dir=root / "scenarios",
    )
    with TestClient(lab_main.create_app(settings, reset_on_start=True)) as client:
        route = "/scenarios/sql-injection/login"
        legit = client.post(route, json={
            "username": "student1", "password": "demo-pass-1",
        })
        control = client.post(route, json={
            "username": "student1", "password": "definitely-wrong",
        })
        attack = client.post(route, json={
            "username": "' OR 1=1 --", "password": "definitely-wrong",
        })
        normal = client.post("/login", json={
            "username": "student1", "password": "demo-pass-1",
        })
        health = client.get("/health")
    assert (legit.status_code, control.status_code, attack.status_code,
            normal.status_code, health.status_code) == (200, 401, 401, 200, 200)
    assert legit.json()["username"] == "student1"


@pytest.mark.parametrize("mutate", [
    "raw_localization", "saved_decision", "admission", "source", "missing_prediction",
    "prompt_archive", "prompt_profile",
])
def test_invalid_model_or_registered_evidence_cannot_materialize(
    localized, tmp_path, mutate
):
    from services.blue_branch import BlueBranchBlocked, prepare_blue_branch
    from services.trusted_remediation_compiler import SOURCE
    import sqlite3
    db, job, pins, found = localized
    parent = tmp_path / "patch-output"
    parent.mkdir()
    if mutate == "raw_localization":
        archive = tmp_path / found["localization_evidence_id"]
        (archive / "q8-localization-raw.json").write_text("{}")
    elif mutate == "prompt_archive":
        archive = tmp_path / found["localization_evidence_id"]
        (archive / "q8-localization-prompt.json").write_text("{}")
    elif mutate == "prompt_profile":
        with sqlite3.connect(db) as conn:
            row = conn.execute("SELECT result_json FROM blue_localizations WHERE job_id=?",
                               (job["id"],)).fetchone()
            saved = json.loads(row[0])
            saved["localization_prompt_profile"] = "q8-localization-v1"
            conn.execute("UPDATE blue_localizations SET result_json=? WHERE job_id=?",
                         (json.dumps(saved), job["id"]))
    elif mutate == "saved_decision":
        with sqlite3.connect(db) as conn:
            conn.execute("UPDATE blue_localizations SET result_json=? WHERE job_id=?",
                         ('{"status":"recorded","sink_line":45}', job["id"]))
    elif mutate == "admission":
        pins["admission_sha256"] = "a" * 64
    elif mutate == "source":
        original = pins["source_root"] / SOURCE
        original.write_bytes(original.read_bytes() + b"\n# modified")
    else:
        with sqlite3.connect(db) as conn:
            conn.execute("DELETE FROM blue_decisions WHERE job_id=?", (job["id"],))
    with pytest.raises(BlueBranchBlocked):
        prepare_blue_branch(database=db, job_id=job["id"],
                            output_parent=parent, **pins)
    assert not list(parent.iterdir())


def test_never_write_an_artifact_inside_live_repository(localized):
    from services.blue_branch import BlueBranchBlocked, prepare_blue_branch
    db, job, pins, found = localized
    with pytest.raises(BlueBranchBlocked):
        prepare_blue_branch(
            database=db, job_id=job["id"],
            output_parent=pins["source_root"] / "artifacts", **pins,
        )
    assert not (pins["source_root"] / "artifacts").exists()


def test_same_job_cannot_create_second_branch(localized, tmp_path):
    from services.blue_branch import BlueBranchBlocked, prepare_blue_branch
    db, job, pins, found = localized
    parent = tmp_path / "new-branches"
    parent.mkdir()
    first = prepare_blue_branch(database=db, job_id=job["id"],
                                output_parent=parent, **pins)
    with pytest.raises(BlueBranchBlocked, match="already"):
        prepare_blue_branch(database=db, job_id=job["id"],
                            output_parent=parent, **pins)
    assert Path(first["branch_repo"]).exists()
    assert len(list(parent.iterdir())) == 1


def test_symlinked_artifact_parent_is_rejected(localized, tmp_path):
    from services.blue_branch import BlueBranchBlocked, prepare_blue_branch
    db, job, pins, found = localized
    legitimate = tmp_path / "parent"
    legitimate.mkdir()
    link = tmp_path / "link"
    link.symlink_to(legitimate, target_is_directory=True)
    with pytest.raises(BlueBranchBlocked):
        prepare_blue_branch(database=db, job_id=job["id"],
                            output_parent=link, **pins)
    assert not list(legitimate.iterdir())


def test_source_symlink_is_never_copied_to_external_branch(localized, tmp_path):
    from services.blue_branch import BlueBranchBlocked, prepare_blue_branch
    db, job, pins, found = localized
    target = tmp_path / "private.txt"
    target.write_text("PRIVATE SENTINEL")
    link = pins["source_root"] / "dummy_apps/vulnerable_store/seed_files/private-link.txt"
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(target)
    parent = tmp_path / "new-branches"
    parent.mkdir()
    with pytest.raises(BlueBranchBlocked):
        prepare_blue_branch(database=db, job_id=job["id"],
                            output_parent=parent, **pins)
    assert not list(parent.iterdir())



def test_v3_statement_selection_stages_only_verified_source_line(
    reviewed_archive, monkeypatch, tmp_path,
):
    import dashboard.api.q8_development_service as q8

    from services.blue_branch import prepare_blue_branch
    from services.blue_localize import localize_bound_job
    db, job, pins, _, _, _ = classified(reviewed_archive, monkeypatch, tmp_path)
    monkeypatch.setattr(q8, "_raw_completion", lambda *_: {
        "content": json.dumps({
            "function_or_route": "vulnerable_login", "sink_line": 46,
            "root_cause": "Username enters an interpolated SQL query.",
            "confidence": 0.87,
        }), "truncated": False,
    })
    result = localize_bound_job(database=db, job_id=job["id"], **pins)
    assert result["model_selected_line"] == 46
    assert result["sink_line"] == 48
    parent = tmp_path / "v3-output"
    parent.mkdir()
    staged = prepare_blue_branch(
        database=db, job_id=job["id"], output_parent=parent, **pins,
    )
    assert staged["model_selected_line"] == 46
    assert staged["verified_sink_line"] == 48
    assert staged["model_localization_used"] is True
    assert staged["patch_applied_to_live_repo"] is False
