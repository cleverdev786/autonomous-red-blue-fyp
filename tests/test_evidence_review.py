"""Sentinel evidence review: offline real-contract fixtures, no model/Docker dispatch."""
from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from test_bound_registered_red_evidence import archive
from test_isolated_compose_executor import environment as upstream_environment

import services.evidence_review as review
from dashboard.api import console
from dashboard.api.q8_development_service import SYNTHETIC_EXAMPLES
from services.q8_c12_development_bridge import classification_receipt, classification_request
from services.registered_assessment_plan import plan_from_model_receipt


def _save(path: Path, payload: object) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(payload, sort_keys=True, indent=2).encode()
    path.write_bytes(raw)
    return sha256(raw).hexdigest()


@pytest.fixture
def prepared(tmp_path):
    env = upstream_environment.__wrapped__(tmp_path)
    context, receipt, calls, dispatches, _ = archive(env)
    root, external, _, _, _ = env
    model_dir = external / "probe-0000000000000001"
    model_dir.mkdir()
    approval = external / "review-approval.json"

    def configure(label="sql_injection", origin="q8_0_cpu_model"):
        pair = SYNTHETIC_EXAMPLES["login_rejected"]
        decision = {"classification": label, "confidence": 0.9,
                    "reason": "Model-only observation, not a verified exploit."}
        response = {"content": json.dumps(decision), "truncated": False}
        gateway = {"role": "classification", "result": decision, "origin": origin,
                   "executed_tests": False}
        recorded = classification_receipt(pair=pair, gateway_reply=gateway)
        plan = plan_from_model_receipt(root=root, pair=pair, receipt=recorded)
        files = {
            "q8-input.json": classification_request(pair),
            "q8-raw-completion.json": response,
            "q8-gateway.json": gateway,
            "q8-assessment-plan.json": plan,
        }
        pins = {name: _save(model_dir / name, data) for name, data in files.items()}
        approved = {
            "schema_version": "sentinel-evidence-link-v1",
            "model_evidence_dir": str(model_dir),
            "model_files": pins,
            "red_evidence_dir": str(context["evidence_dir"]),
            "red_admission_path": str(context["admission_path"]),
            "red_admission_sha256": context["admission_sha256"],
            "red_receipt_sha256": context["receipt_sha256"],
            "red_run_id": receipt.run_id,
        }
        digest = _save(approval, approved)
        return approved, digest

    approved, digest = configure()
    return {
        "root": root, "approval": approval, "approved": approved,
        "digest": digest, "configure": configure,
        "context": context, "calls": calls, "dispatches": dispatches,
        "model_dir": model_dir,
    }


def _review(state):
    return review.review_archived_assessment(
        root=state["root"], approval_path=str(state["approval"]),
        approval_sha256=state["digest"]
    )


def test_no_config_no_paths_or_automatic_dispatch(monkeypatch):
    monkeypatch.delenv("FYP_ASSESSMENT_APPROVAL_PATH", raising=False)
    monkeypatch.delenv("FYP_ASSESSMENT_APPROVAL_SHA256", raising=False)
    with TestClient(console.create_console_app(database_path="/nonexistent/a.sqlite")) as client:
        response = client.get("/api/console/assessment/review")
        assert response.status_code == 200
        item = response.json()
        assert item["status"] == "not_configured"
        assert item["source_analysis_authorized"] is False
        assert item["patch_preparation_authorized"] is False
        assert item["final_research_qualified"] is False
        assert client.post("/api/console/assessment/review",
                           json={"path": "/tmp/arbitrary", "dispatch": True}).status_code == 405


def test_one_archived_registered_red_enables_analysis_only(prepared):
    before = len(prepared["calls"])
    result = _review(prepared)
    assert result["status"] == "evidence_bound"
    assert result["model_decision"]["classification"] == "sql_injection"
    assert result["model_input_scope"] == "hand_authored_synthetic_http_pair"
    assert result["red_evidence_verified"] is True
    assert result["red_evidence_scope"] == "archived_development_provenance"
    assert result["source_analysis_authorized"] is True
    assert result["patch_preparation_authorized"] is False
    assert result["patch_applied"] is False
    assert result["model_independently_qualified"] is False
    assert result["final_research_qualified"] is False
    assert len(prepared["calls"]) == before
    assert len(prepared["dispatches"]) == 1  # one offline fixture only


@pytest.mark.parametrize(("label", "status"), (
    ("benign", "benign_unverified"),
    ("unknown", "manual_review"),
    ("xss", "withheld"),
))
def test_non_actionable_or_mismatched_model_does_not_load_red(
    prepared, monkeypatch, label, status
):
    _, prepared["digest"] = prepared["configure"](label=label)
    monkeypatch.setattr(review, "verify_archived_registered_red",
                        lambda **_: pytest.fail("must not review Red for this decision"))
    result = _review(prepared)
    assert result["status"] == status
    assert result["model_decision"]["classification"] == label
    assert not result["source_analysis_authorized"]
    assert not result["trusted_safe_outcome"]
    assert not result["red_evidence_verified"]


@pytest.mark.parametrize("name", (
    "q8-input.json", "q8-raw-completion.json",
    "q8-gateway.json", "q8-assessment-plan.json",
))
def test_single_byte_model_archive_tampering_fails_closed(prepared, name):
    with (prepared["model_dir"] / name).open("ab") as output:
        output.write(b"x")
    response = _review(prepared)
    assert response["status"] == "blocked"
    assert response["source_analysis_authorized"] is False


def test_approval_digest_is_independent_and_required(prepared):
    assert review.review_archived_assessment(
        root=prepared["root"], approval_path=str(prepared["approval"]),
        approval_sha256="0" * 64
    )["status"] == "blocked"
    assert review.review_archived_assessment(
        root=prepared["root"], approval_path=str(prepared["approval"]),
        approval_sha256=""
    )["status"] == "blocked"
    prepared["approval"].write_bytes(prepared["approval"].read_bytes() + b" ")
    assert _review(prepared)["status"] == "blocked"


def test_red_receipt_mismatch_denies_source_analysis(prepared):
    prepared["approved"]["red_receipt_sha256"] = "0" * 64
    prepared["digest"] = _save(prepared["approval"], prepared["approved"])
    result = _review(prepared)
    assert result["status"] == "evidence_rejected"
    assert result["model_decision"]["classification"] == "sql_injection"
    assert result["source_analysis_authorized"] is False
    assert result["red_evidence_verified"] is False


def test_red_run_id_mismatch_denies_source_analysis(prepared):
    prepared["approved"]["red_run_id"] = "wrong-run-01"
    prepared["digest"] = _save(prepared["approval"], prepared["approved"])
    assert _review(prepared)["status"] == "evidence_rejected"


def test_incomplete_red_receipt_cannot_grant_source_authority(prepared):
    from services.isolated_compose_executor import RealExecutionReceipt

    receipt_path = Path(prepared["context"]["evidence_dir"]) / "receipt.json"
    receipt = RealExecutionReceipt.model_validate_json(receipt_path.read_bytes())
    incomplete = receipt.model_copy(
        update={"outcome": "inconclusive", "observation_sha256": None}
    )
    raw = (incomplete.model_dump_json(indent=2) + "\n").encode()
    receipt_path.write_bytes(raw)
    prepared["approved"]["red_receipt_sha256"] = sha256(raw).hexdigest()
    prepared["digest"] = _save(prepared["approval"], prepared["approved"])
    response = _review(prepared)
    assert response["status"] == "evidence_rejected"
    assert response["source_analysis_authorized"] is False


def test_missing_red_archive_denies_source_authority(prepared):
    (Path(prepared["context"]["evidence_dir"]) / "stdout.raw").unlink()
    response = _review(prepared)
    assert response["status"] == "evidence_rejected"
    assert response["red_evidence_verified"] is False


def test_pinned_model_cannot_claim_altered_raw_result(prepared):
    raw_path = prepared["model_dir"] / "q8-raw-completion.json"
    raw = json.loads(raw_path.read_text())
    raw["content"] = json.dumps({"classification": "benign", "confidence": 0.99,
                                 "reason": "Changed after inference."})
    prepared["approved"]["model_files"]["q8-raw-completion.json"] = _save(raw_path, raw)
    prepared["digest"] = _save(prepared["approval"], prepared["approved"])
    assert _review(prepared)["status"] == "blocked"


def test_api_reuses_same_read_only_gate(prepared, monkeypatch):
    monkeypatch.setenv("FYP_ASSESSMENT_APPROVAL_PATH", str(prepared["approval"]))
    monkeypatch.setenv("FYP_ASSESSMENT_APPROVAL_SHA256", prepared["digest"])
    monkeypatch.setattr(console, "review_archived_assessment",
                        lambda root: review.review_archived_assessment(
                            root=prepared["root"]))
    with TestClient(console.create_console_app(database_path="/nonexistent/a.sqlite")) as client:
        response = client.get("/api/console/assessment/review")
        assert response.status_code == 200
        assert response.json()["source_analysis_authorized"] is True
        assert response.json()["patch_preparation_authorized"] is False
        assert response.headers["Cache-Control"] == "no-store"


def _registered_red_display_config(prepared):
    context = prepared["context"]
    manifest = {
        "schema_version": "sentinel-registered-red-display-v1",
        "source_root": str(prepared["root"]),
        "red_evidence_dir": str(context["evidence_dir"]),
        "red_admission_path": str(context["admission_path"]),
        "red_admission_sha256": context["admission_sha256"],
        "red_receipt_sha256": context["receipt_sha256"],
        "red_run_id": "",
    }
    # Fixture run identity comes from its own admission, never from the new live case.
    from services.isolated_compose_executor import load_real_admission
    pin = load_real_admission(
        prepared["root"], Path(context["admission_path"]), context["admission_sha256"]
    )
    manifest["red_run_id"] = pin.run_id
    path = Path(context["admission_path"]).parent / "registered-red-display.json"
    return manifest, path, _save(path, manifest)


def test_registered_red_display_requires_operator_pin(monkeypatch):
    monkeypatch.delenv("FYP_REGISTERED_RED_DISPLAY_PATH", raising=False)
    monkeypatch.delenv("FYP_REGISTERED_RED_DISPLAY_SHA256", raising=False)
    result = review.review_pinned_registered_red(root=Path(__file__).resolve().parents[1])
    assert result["status"] == "not_configured"
    assert result["red_evidence_verified"] is False
    assert result["model_decision"] is None
    assert result["source_analysis_authorized"] is False
    assert result["patch_preparation_authorized"] is False


def test_registered_red_display_verifies_without_model_claim(prepared):
    manifest, path, digest = _registered_red_display_config(prepared)
    result = review.review_pinned_registered_red(
        root=prepared["root"], approval_path=str(path), approval_sha256=digest
    )
    assert result["status"] == "verified_archived_red"
    assert result["registered_test_id"] == "sqli-login-bypass-001"
    assert result["red_run_id"] == manifest["red_run_id"]
    assert result["exploit_confirmed"] is True
    assert result["red_evidence_scope"] == "archived_development_provenance"
    assert result["model_decision"] is None
    assert result["model_alignment_status"] == "not_established"
    assert result["source_analysis_authorized"] is False
    assert result["patch_preparation_authorized"] is False
    assert result["final_research_qualified"] is False


def test_registered_red_display_bad_pins_and_raw_tampering_fail_closed(prepared):
    manifest, path, digest = _registered_red_display_config(prepared)
    assert review.review_pinned_registered_red(
        root=prepared["root"], approval_path=str(path), approval_sha256="0" * 64
    )["status"] == "blocked"
    correct_run = manifest["red_run_id"]
    manifest["red_run_id"] = "different-run"
    bad_digest = _save(path, manifest)
    assert review.review_pinned_registered_red(
        root=prepared["root"], approval_path=str(path), approval_sha256=bad_digest
    )["red_evidence_verified"] is False
    manifest["red_run_id"] = correct_run
    digest = _save(path, manifest)
    raw = Path(prepared["context"]["evidence_dir"]) / "stdout.raw"
    raw.write_bytes(raw.read_bytes() + b"x")
    assert review.review_pinned_registered_red(
        root=prepared["root"], approval_path=str(path), approval_sha256=digest
    )["status"] == "blocked"


def test_registered_red_display_read_only_route(prepared, monkeypatch):
    _, path, digest = _registered_red_display_config(prepared)
    monkeypatch.setattr(
        console, "review_pinned_registered_red",
        lambda root: review.review_pinned_registered_red(
            root=prepared["root"], approval_path=str(path), approval_sha256=digest
        ),
    )
    with TestClient(console.create_console_app(database_path="/nonexistent/a.sqlite")) as client:
        response = client.get("/api/console/assessment/registered-red")
        assert response.status_code == 200
        assert response.headers["Cache-Control"] == "no-store"
        assert response.json()["red_evidence_verified"] is True
        assert response.json()["source_analysis_authorized"] is False
        assert client.post(
            "/api/console/assessment/registered-red",
            json={"test_id": "unregistered", "dispatch": True},
        ).status_code == 405


def _paired_red_fixture(prepared, *, changed_response=False):
    from services.bound_registered_red_evidence import verify_archived_registered_red

    bound = verify_archived_registered_red(**prepared["context"])
    steps = prepared["context"]["implementations"].get(bound.test_id).build_steps()
    exchanges = bound.observation.execution.exchanges
    assert len(steps) == len(exchanges) == 2
    rows = []
    for step, exchange in zip(steps, exchanges, strict=True):
        assert step.step_id == exchange.step_id
        rows.append({
            "method": getattr(step.method, "value", step.method),
            "parameters": step.json_body,
            "status_code": exchange.status_code,
            "response_excerpt": exchange.body_excerpt,
        })
    if changed_response:
        rows[1]["status_code"] = 201
    pair = {"route": "/sql-injection/login", "observations": rows}
    decision = {"classification": "sql_injection", "confidence": 0.9,
                "reason": "A model-only development prediction."}
    gateway = {"role": "classification", "result": decision,
               "origin": "q8_0_cpu_model", "executed_tests": False}
    parsed = classification_receipt(pair=pair, gateway_reply=gateway)
    files = {
        "q8-input.json": classification_request(pair),
        "q8-raw-completion.json": {"content": json.dumps(decision), "truncated": False},
        "q8-gateway.json": gateway,
        "q8-assessment-plan.json": plan_from_model_receipt(
            root=prepared["root"], pair=pair, receipt=parsed
        ),
    }
    prepared["approved"]["model_files"] = {
        name: _save(prepared["model_dir"] / name, value)
        for name, value in files.items()
    }
    provenance = {
        "schema_version": "q8-registered-sqli-reconstructed-pair-v1",
        "input_origin": "registered_step_definitions_plus_captured_exchange_responses",
        "original_http_request_body_capture": False,
        "registered_test_id": bound.test_id,
        "registered_run_id": bound.run_id,
        "registered_case_id": bound.case_id,
        "registered_receipt_sha256": bound.receipt_sha256,
        "registered_admission_sha256": bound.admission_sha256,
        "test_implementation_sha256": bound.observation.test_implementation_sha256,
        "registered_stdout_sha256": bound.observation.raw_result_sha256,
        "source_head": bound.source_head,
        "request_parameter_source": (
            "frozen registered test build_steps(), not captured HTTP request body"
        ),
        "response_excerpt_source": "captured registered executor HTTP exchanges",
        "exchange_step_ids": [step.step_id for step in steps],
        "no_evaluator_truth_in_model_input": True,
        "research_qualified": False,
        "model_source_analysis_authorized": False,
    }
    prepared["approved"]["red_source_root"] = str(prepared["root"])
    prepared["approved"]["reconstructed_pair_sha256"] = _save(
        prepared["model_dir"] / "pair-provenance.json", provenance
    )
    prepared["digest"] = _save(prepared["approval"], prepared["approved"])


def test_reconstructed_registered_pair_grants_archived_analysis_only(prepared):
    _paired_red_fixture(prepared)
    result = _review(prepared)
    assert result["status"] == "evidence_bound"
    assert result["model_decision"]["classification"] == "sql_injection"
    assert result["model_input_scope"] == "registered_steps_plus_captured_responses"
    assert result["red_evidence_verified"] is True
    assert result["source_analysis_authorized"] is True
    assert result["patch_preparation_authorized"] is False
    assert result["patch_applied"] is False
    assert result["final_research_qualified"] is False


def test_reconstructed_response_mismatch_with_valid_model_pins_is_rejected(prepared):
    _paired_red_fixture(prepared, changed_response=True)
    result = _review(prepared)
    assert result["status"] == "evidence_rejected"
    assert result["model_input_scope"] == "reconstructed_pair_pending_red_binding"
    assert result["red_evidence_verified"] is False
    assert result["source_analysis_authorized"] is False


def test_reconstructed_pair_provenance_tamper_and_missing_pin_fail_closed(prepared):
    _paired_red_fixture(prepared)
    path = prepared["model_dir"] / "pair-provenance.json"
    path.write_bytes(path.read_bytes() + b"x")
    assert _review(prepared)["status"] == "evidence_rejected"
    prepared["approved"].pop("reconstructed_pair_sha256")
    prepared["digest"] = _save(prepared["approval"], prepared["approved"])
    assert _review(prepared)["status"] == "blocked"


def _patched_replay_fixture(prepared, tmp_path):
    """Offline replica of bounded patched replay; never calls Docker."""
    folder = tmp_path / "patched-replay-case"
    folder.mkdir()
    old = json.loads((Path(prepared["context"]["evidence_dir"]) / "stdout.raw").read_text())
    old["run_id"] = "sql-20261015-r2"
    old["status_code"] = 401
    old["evidence"] = []
    old["error_code"] = "evidence-not-observed"
    old["exchanges"][1]["status_code"] = 401
    old["exchanges"][1]["body_excerpt"] = '{"detail":"Invalid username or password"}'
    raw = (json.dumps(old) + "\n").encode()
    (folder / "stdout.raw").write_bytes(raw)
    (folder / "stderr.raw").write_bytes(b"")
    (folder / "exit-code.txt").write_text("0\n")
    routes_sha = "c98aaccb4577804a7606b3e7059b5669e15ced05004c3ae9ba3a2ff14931fe98"
    sources = {"dummy_apps/vulnerable_store/app/scenario_routes.py": routes_sha}
    att = {
        "schema_version": "sentinel-patched-sqli-operator-runtime-attestation-v1",
        "registered_test_id": "sqli-login-bypass-001",
        "checks_passed": True, "error": None, "replay_executed_by_this_script": False,
        "run_id_reserved_not_executed": "sql-20261015-r2",
        "source_sha256": sources,
        "results": {
            "docker_context": "default",
            "baseline_image_id": (
                "sha256:2f3d8290709fb13e193075fd2c7f555fc08f959d7d58c899dda74cbb2a6029ea"
            ),
            "network_internal": True, "network_attachable": False,
            "patched_image_id": (
                "sha256:6d05b3656df9474b1b2d78876049b0adf196a69ea569f111276f49fee1035e53"
            ),
            "containers": {
                name: {"deployed_source_sha256": sources, "health": "healthy",
                       "published_host_ports": [], "read_only": True,
                       "user": "10001:10001", "image_id": (
                           "sha256:6d05b3656df9474b1b2d78876049b0adf196a69ea569f111276f49fee1035e53"
                       )}
                for name in ("vulnerable-store", "controlled-executor")
            },
        },
    }
    att_path = tmp_path / "runtime-attestation.json"
    att_digest = _save(att_path, att)
    _save(folder / "verified-replay.json", {
        "raw_result_sha256": sha256(raw).hexdigest(),
        "attestation_sha256": att_digest,
        "run_id": "sql-20261015-r2", "test_id": "sqli-login-bypass-001",
        "source_sha256": routes_sha,
        "approved_trusted_patch_diff_sha256": (
            "9313f632a7b893090206d8a614401614e8854909671174dbaafd4fa9b0adead1"
        ),
        "baseline_registered_receipt_sha256": (
            "3fda5b18680363736b1be1451407e35f4e5a3080ca3933ae5840ae387bacdd47"
        ),
        "patch_applied_to_original_repo": False,
        "registered_evaluator_recomputed": True, "test_completed": True,
        "exploit_confirmed": False, "research_qualified": False,
    })
    _save(folder / "legitimate-login.json", {
        "http_status": 200, "authenticated": True,
    })
    _save(folder / "search-file-regression.json", {
        "search_http": 200, "document_list_http": 200,
        "file_http": 200, "file_has_expected_public_text": True,
        "official_research": False,
    })
    files = {name: sha256((folder / name).read_bytes()).hexdigest()
             for name in review.PATCHED_REPLAY_FILES}
    approval_path = tmp_path / "patched-display-approval.json"
    approval_sha = _save(approval_path, {
        "schema_version": "sentinel-patched-sqli-display-v1",
        "evidence_dir": str(folder), "files": files,
        "attestation_path": str(att_path), "attestation_sha256": att_digest,
    })
    return folder, approval_path, approval_sha


def test_patched_replay_read_only_and_tamper_fail_closed(prepared, tmp_path):
    folder, approval, digest = _patched_replay_fixture(prepared, tmp_path)
    result = review.review_pinned_patched_replay(
        root=prepared["root"], approval_path=str(approval), approval_sha256=digest
    )
    assert result["status"] == "verified_archived_patched_replay"
    assert result["http_statuses"] == [401, 401]
    assert result["registered_replay_verified"] and result["exploit_confirmed"] is False
    assert not result["final_research_qualified"]
    assert review.review_pinned_patched_replay(
        root=prepared["root"], approval_path=str(approval), approval_sha256="0" * 64
    )["status"] == "blocked"
    (folder / "stdout.raw").write_bytes((folder / "stdout.raw").read_bytes() + b"x")
    assert review.review_pinned_patched_replay(
        root=prepared["root"], approval_path=str(approval), approval_sha256=digest
    )["status"] == "blocked"


def test_patched_replay_read_only_route_and_no_config(prepared, tmp_path, monkeypatch):
    _, approval, digest = _patched_replay_fixture(prepared, tmp_path)
    monkeypatch.setattr(
        console, "review_pinned_patched_replay",
        lambda root: review.review_pinned_patched_replay(
            root=prepared["root"], approval_path=str(approval), approval_sha256=digest
        ),
    )
    with TestClient(console.create_console_app(database_path="/nonexistent/a.sqlite")) as client:
        response = client.get("/api/console/assessment/patched-replay")
        assert response.status_code == 200
        assert response.headers["Cache-Control"] == "no-store"
        assert response.json()["registered_replay_verified"] is True
        assert client.post("/api/console/assessment/patched-replay").status_code == 405
    monkeypatch.delenv("FYP_PATCHED_REPLAY_APPROVAL_PATH", raising=False)
    monkeypatch.delenv("FYP_PATCHED_REPLAY_APPROVAL_SHA256", raising=False)
    assert review.review_pinned_patched_replay(root=prepared["root"])["status"] == "not_configured"


def test_phase5_archived_replays_are_pinned_read_only_and_fail_closed(
    prepared, tmp_path, monkeypatch,
):
    import difflib
    from types import SimpleNamespace

    import services.trusted_remediation_compiler as compiler
    from security_tests.registry import SecurityTestRegistry

    source_text = (Path(compiler.__file__).resolve().parents[1] / compiler.SOURCE).read_text()

    other = tmp_path / "external-phase5"
    other.mkdir()
    source = other / "source"
    source.mkdir()
    records = {}
    for name, (test_id, run_id, category, statuses, source_sha, image_id, diff_sha) in (
        review.PHASE5_REGISTERED.items()
    ):
        base = other / name
        base.mkdir()
        folder = base / "replay"
        folder.mkdir()
        steps = SecurityTestRegistry.default().get(test_id).build_steps()
        excerpts = (
            ("Search term: notebook", "Search term: &lt;script&gt;fyp_xss_marker()&lt;/script&gt;")
            if name == "xss" else ("Public scenario guide", "Scenario sandbox escape blocked")
        )
        data = {
            "run_id": run_id, "target_id": "vulnerable-store", "test_id": test_id,
            "attempt_number": 1, "request_count": 2, "completed": True,
            "timed_out": False, "status_code": statuses[-1], "evidence": [],
            "duration_ms": 1, "error_code": "evidence-not-observed",
            "exchanges": [
                {"exchange_id": f"exchange-0{i}", "request_id": f"req-{i}",
                 "step_id": step.step_id, "endpoint_id": step.endpoint_id,
                 "method": step.method.value, "status_code": statuses[i - 1],
                 "body_excerpt": excerpts[i - 1], "redirect_location": None,
                 "duration_ms": 1}
                for i, step in enumerate(steps, 1)
            ],
        }
        raw = json.dumps(data).encode()
        (folder / "stdout.raw").write_bytes(raw)
        (folder / "stderr.raw").write_bytes(b"")
        (folder / "exit-code.txt").write_text("0")
        report = {
            "raw_stdout_sha256": sha256(raw).hexdigest(),
            "approved_trusted_patch_diff_sha256": diff_sha,
            "patched_source_sha256": source_sha, "registered_evaluator_recomputed": True,
            "exploit_confirmed": False, "research_qualified": False,
            "source_repo_modified": False,
        }
        att = {
            "schema_version": f"sentinel-patched-{name}-operator-runtime-attestation-v1",
            "checks_passed": True, "error": None, "registered_test_id": test_id,
            "run_id_reserved_not_executed": run_id, "replay_executed_by_this_script": False,
            "source_sha256": {"dummy_apps/vulnerable_store/app/scenario_routes.py": source_sha},
            "results": {
                "network_internal": True, "network_attachable": False,
                "docker_context": "default", "patched_image_id": image_id,
                "baseline_image_id": (
                    "sha256:2f3d8290709fb13e193075fd2c7f555fc08f959d7d58c899dda74cbb2a6029ea"
                ),
                "containers": {
                    name2: {"health": "healthy", "read_only": True,
                            "user": "10001:10001", "published_host_ports": [],
                            "image_id": image_id, "deployed_source_sha256": {
                                "dummy_apps/vulnerable_store/app/scenario_routes.py": source_sha,
                            }}
                    for name2 in ("vulnerable-store", "controlled-executor")
                },
            },
        }
        att_path = base / "attestation.json"
        att_sha = _save(att_path, att)
        report["operator_attestation_sha256"] = att_sha
        baseline_sha = "a" * 64 if name == "xss" else "b" * 64
        report["original_baseline_receipt_sha256"] = baseline_sha
        _save(folder / "verified-replay.json", report)
        diff = base / "trusted.diff"
        new_text = (
            source_text.replace(compiler._XSS_IMPORT_OLD, compiler._XSS_IMPORT_NEW)
                       .replace(compiler._XSS_SINK_OLD, compiler._XSS_SINK_NEW)
            if name == "xss" else
            source_text.replace(compiler._PATH_OLD, compiler._PATH_NEW)
        )
        patched_diff = "".join(difflib.unified_diff(
            source_text.splitlines(keepends=True), new_text.splitlines(keepends=True),
            fromfile="a/" + compiler.SOURCE, tofile="b/" + compiler.SOURCE,
        ))
        assert sha256(patched_diff.encode()).hexdigest() == diff_sha
        diff.write_text(patched_diff)
        offline_path = base / "offline.json"
        offline = (
            {"marker_html_escaped": True, "valid_login_status": 200}
            if name == "xss" else
            {"private_synthetic_marker_blocked": True, "valid_login_http": 200}
        )
        offline_sha = _save(offline_path, offline)
        admission = base / "admission.json"
        admission.write_text("{}")
        records[name] = {
            "replay_dir": str(folder),
            "replay_files": {f: sha256((folder / f).read_bytes()).hexdigest()
                             for f in review._PHASE5_REPLAY_FILES},
            "attestation_path": str(att_path), "attestation_sha256": att_sha,
            "baseline_dir": str(base), "baseline_admission_path": str(admission),
            "baseline_admission_sha256": sha256(admission.read_bytes()).hexdigest(),
            "baseline_receipt_sha256": baseline_sha,
            "trusted_diff_path": str(diff), "trusted_diff_sha256": diff_sha,
            "offline_path": str(offline_path), "offline_sha256": offline_sha,
        }
    monkeypatch.setattr(review, "_registry", lambda source: object())
    monkeypatch.setattr(
        review, "verify_archived_registered_red",
        lambda **kw: SimpleNamespace(
            test_id=("xss-reflection-001" if kw["evidence_dir"].name == "xss"
                     else "path-traversal-private-file-001"),
            vulnerability_class=("xss" if kw["evidence_dir"].name == "xss"
                                 else "path_traversal"),
            observation=SimpleNamespace(test_completed=True, exploit_confirmed=True),
        ),
    )
    approval = other / "approval.json"
    digest = _save(approval, {
        "schema_version": "sentinel-phase5-patched-replay-display-v1",
        "source_root": str(source), "cases": records,
    })
    def checked():
        return review.review_pinned_phase5_replays(
            root=prepared["root"], approval_path=str(approval), approval_sha256=digest
        )
    result = checked()
    assert result["status"] == "verified_archived_phase5_replays", result
    assert result["replay_count"] == 2
    assert not result["patched_docker_functional_verified"]
    assert not result["model_driven_red_selection_verified"]
    monkeypatch.setattr(console, "review_pinned_phase5_replays", lambda root: checked())
    with TestClient(console.create_console_app(database_path="/nonexistent/a.sqlite")) as client:
        response = client.get("/api/console/assessment/phase5-replays")
        assert response.status_code == 200 and response.headers["cache-control"] == "no-store"
        assert response.json()["replay_count"] == 2
        assert client.post("/api/console/assessment/phase5-replays").status_code == 405
    (other / "xss/replay/stdout.raw").write_bytes(b"tampered")
    assert checked()["status"] == "blocked"
    assert review.review_pinned_phase5_replays(
        root=prepared["root"], approval_path=str(approval),
        approval_sha256="0" * 64,
    )["status"] == "blocked"
