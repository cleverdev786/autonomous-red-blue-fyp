"""Q8/C12 typed development bridge boundaries, without model or Docker calls."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from schemas.rq2_dataset import RQ2ClassifierEvent
from services.q8_c12_development_bridge import (
    Q8DevelopmentBlocked,
    archive_gateway_reply,
    classification_receipt,
    classification_request,
    localization_receipt,
    localization_request,
    refuse_single_rq2_event,
    trusted_source,
    validate_pair,
)
from services.trusted_remediation_compiler import EXPECTED_SOURCE_SHA256, SOURCE

ROOT = Path(__file__).resolve().parents[1]
PAIR = {
    "route": "/path-traversal/read",
    "observations": [
        {"method": "GET", "parameters": {"path": "manual.txt"},
         "response_excerpt": "PUBLIC_MANUAL", "status_code": 200},
        {"method": "GET", "parameters": {"path": "../private/hidden.txt"},
         "response_excerpt": "PRIVATE_EXAMPLE", "status_code": 200},
    ],
}


def response(*, role="classification", result=None, origin="q8_0_cpu_model"):
    if result is None:
        result = {
            "classification": "path_traversal",
            "confidence": 0.9,
            "reason": "Private content appeared only after requesting a parent path."
        }
    return {"role": role, "result": result, "origin": origin, "executed_tests": False}


def source_response(*, function="vulnerable_file_read", line=99):
    return response(
        role="source_localization",
        result={
            "function_or_route": function, "sink_line": line,
            "root_cause": "Untrusted path is used without containment to public root.",
            "confidence": 0.9,
        }
    )


def test_model_classification_maps_to_existing_typed_gate_without_dispatch():
    r = classification_receipt(pair=PAIR, gateway_reply=response())
    assert r["decision"]["classification"] == "path_traversal"
    assert r["preliminary_blue_action"] == "select_registered_test"
    assert r["origin"] == "q8_0_cpu_model"
    assert r["registered_test_dispatched"] is False
    assert r["ready_for_source_analysis"] is False
    assert r["ready_for_patch_preparation"] is False
    assert r["final_research_qualified"] is False


def test_benign_routing_no_action():
    r = classification_receipt(
        pair=PAIR,
        gateway_reply=response(result={"classification": "benign", "confidence": 0.8,
                                       "reason": "No changed evidence."}),
    )
    assert r["preliminary_blue_action"] == "no_action"


def test_sql_false_positive_not_patch_authority():
    value = json.loads(json.dumps(PAIR))
    value["route"] = "/sql-injection/login"
    for row in value["observations"]:
        row["method"] = "POST"
        row["status_code"] = 401
        row["response_excerpt"] = "Invalid username or password"
    r = classification_receipt(
        pair=value,
        gateway_reply=response(result={"classification": "sql_injection", "confidence": 0.9,
                                       "reason": "Potential injection."}),
    )
    assert r["decision"]["classification"] == "sql_injection"
    assert r["ready_for_patch_preparation"] is False


def test_deterministic_unknown_is_marked_non_neural():
    r = classification_receipt(
        pair=PAIR,
        gateway_reply=response(
            origin="insufficient_evidence_policy",
            result={"classification": "unknown", "confidence": 0.0,
                    "reason": "Missing modified response excerpt."},
        ),
    )
    assert r["origin"] == "insufficient_evidence_policy"
    assert r["preliminary_blue_action"] == "manual_review"
    assert r["final_research_qualified"] is False


@pytest.mark.parametrize("label", ["not_a_label", "sql", ""])
def test_invalid_model_label_is_not_silently_corrected(label):
    bad = response(result={"classification": label, "confidence": 0.9, "reason": "no"})
    with pytest.raises(Q8DevelopmentBlocked, match="classification_schema"):
        classification_receipt(pair=PAIR, gateway_reply=bad)


@pytest.mark.parametrize("mutator", [
    lambda p: p.update({"expected": "path_traversal"}),
    lambda p: p.update({"route": "/outside/scope"}),
    lambda p: p.update({"observations": [p["observations"][0]]}),
    lambda p: p["observations"][0].update({"ground_truth": "path_traversal"}),
    lambda p: p["observations"][1].update({"method": "POST"}),
    lambda p: p["observations"][1].update({"status_code": True}),
    lambda p: p["observations"][1].update({"response_excerpt": "x" * 4001}),
    lambda p: p["observations"][1]["parameters"].update({"a": 5}),
    lambda p: p["observations"][0].update({"status_code": 0}),
])
def test_malformed_input_is_rejected(mutator):
    bad = json.loads(json.dumps(PAIR))
    mutator(bad)
    with pytest.raises(Q8DevelopmentBlocked):
        validate_pair(bad)


def test_request_has_only_model_visible_http_evidence():
    assert classification_request(PAIR) == {"role": "classification", "input": PAIR}


def test_single_rq2_event_does_not_become_fabricated_pair():
    with pytest.raises(Q8DevelopmentBlocked, match="rq2_single_event"):
        refuse_single_rq2_event(RQ2ClassifierEvent.model_construct())


def test_source_snapshot_pinned_and_exposes_neutral_three_candidates():
    snapshot = trusted_source(ROOT)
    assert snapshot.sha256 == EXPECTED_SOURCE_SHA256
    assert tuple(sorted(snapshot.names)) == snapshot.names
    assert len(snapshot.names) == 3
    assert "vulnerable_file_read" in snapshot.names
    assert "099 " in snapshot.numbered_candidate_functions
    assert "033 " not in snapshot.numbered_candidate_functions
    assert 99 in snapshot.statement_lines_by_name["vulnerable_file_read"]


def test_source_request_contains_only_pinned_code_and_no_truth():
    request = localization_request(pair=PAIR, project_root=ROOT)
    source = trusted_source(ROOT)
    assert request["input"]["source_sha256"] == source.sha256
    assert request["input"]["candidate_function_names"] == list(source.names)
    assert request["input"]["numbered_candidate_functions"] == source.numbered_candidate_functions
    assert "ground_truth" not in json.dumps(request)


def test_matching_source_selection_is_typed_but_not_patch_authorized():
    request = localization_request(pair=PAIR, project_root=ROOT)
    r = localization_receipt(request=request, gateway_reply=source_response(), project_root=ROOT)
    assert r["selection"]["function_or_route"] == "vulnerable_file_read"
    assert r["selection"]["sink_line"] == 99
    assert r["supporting_line"] == {"start_line": 99, "end_line": 99}
    assert r["source_relative_path"] == SOURCE
    assert r["registered_test_dispatched"] is False
    assert r["ready_for_patch_preparation"] is False


@pytest.mark.parametrize("bad", [
    source_response(function="vulnerable_search", line=84),
    source_response(line=1000),
    source_response(line=101),
    source_response(function="missing_route", line=99),
    source_response(line="99"),
    source_response(line=True),
])
def test_bad_source_function_or_line_fails_closed(bad):
    request = localization_request(pair=PAIR, project_root=ROOT)
    with pytest.raises(Q8DevelopmentBlocked):
        localization_receipt(request=request, gateway_reply=bad, project_root=ROOT)


def test_statement_inside_compiler_range_but_not_actual_sink_is_rejected():
    req = localization_request(pair=PAIR, project_root=ROOT)
    # V2 historically selected line 105, an executable except guard rather
    # than the unsafe source operation. It must not gain patch authority.
    with pytest.raises(Q8DevelopmentBlocked, match="preapproved_compiler_source_anchors"):
        localization_receipt(
            request=req, gateway_reply=source_response(line=105),
            project_root=ROOT
        )


def test_executable_only_v2_preserves_three_functions_and_unchanged_numbering():
    from services.q8_c12_development_bridge import SOURCE_PROFILE_V2

    old = localization_request(pair=PAIR, project_root=ROOT)
    newer = localization_request(pair=PAIR, project_root=ROOT, source_profile=SOURCE_PROFILE_V2)
    assert newer["input"]["candidate_function_names"] == old["input"]["candidate_function_names"]
    assert newer["input"]["source_sha256"] == old["input"]["source_sha256"]
    assert "101 " in old["input"]["numbered_candidate_functions"]
    assert "101 " not in newer["input"]["numbered_candidate_functions"]
    assert "099 " in newer["input"]["numbered_candidate_functions"]
    with pytest.raises(Q8DevelopmentBlocked, match="source_context_not_trusted"):
        localization_receipt(
            request=newer, gateway_reply=source_response(line=99),
            project_root=ROOT
        )
    ok = localization_receipt(
        request=newer, gateway_reply=source_response(line=99),
        project_root=ROOT, source_profile=SOURCE_PROFILE_V2
    )
    assert ok["ready_for_patch_preparation"] is False


@pytest.mark.parametrize(("route","function","line"), [
    ("/sql-injection/login", "vulnerable_login", 48),
    ("/sql-injection/login", "vulnerable_login", 53),
    ("/xss/search", "vulnerable_search", 84),
    ("/path-traversal/read", "vulnerable_file_read", 99),
    ("/path-traversal/read", "vulnerable_file_read", 104),
])
def test_existing_trusted_compiler_source_operations_can_be_selected(route, function, line):
    data = json.loads(json.dumps(PAIR))
    data["route"] = route
    request = localization_request(pair=data, project_root=ROOT)
    reply = source_response(function=function, line=line)
    receipt = localization_receipt(request=request, gateway_reply=reply, project_root=ROOT)
    assert receipt["selection"]["sink_line"] == line
    assert receipt["ready_for_patch_preparation"] is False


@pytest.mark.parametrize(("route","function","line"), [
    ("/sql-injection/login", "vulnerable_login", 45),
    ("/xss/search", "vulnerable_search", 80),
    ("/path-traversal/read", "vulnerable_file_read", 105),
])
def test_preexisting_compiler_anchors_reject_comment_or_other_guard(route, function, line):
    data = json.loads(json.dumps(PAIR))
    data["route"] = route
    request = localization_request(pair=data, project_root=ROOT)
    reply = source_response(function=function, line=line)
    with pytest.raises(Q8DevelopmentBlocked):
        localization_receipt(request=request, gateway_reply=reply, project_root=ROOT)


def test_forged_source_file_is_not_accepted():
    request = localization_request(pair=PAIR, project_root=ROOT)
    request["input"]["source_sha256"] = "0" * 64
    with pytest.raises(Q8DevelopmentBlocked, match="source_context_not_trusted"):
        localization_receipt(request=request, gateway_reply=source_response(), project_root=ROOT)


def test_forged_numbered_source_is_not_accepted():
    request = localization_request(pair=PAIR, project_root=ROOT)
    request["input"]["numbered_candidate_functions"] += "\n999 malicious()"
    with pytest.raises(Q8DevelopmentBlocked):
        localization_receipt(request=request, gateway_reply=source_response(), project_root=ROOT)


def test_model_claims_executed_tests_fails_closed():
    reply = response()
    reply["executed_tests"] = True
    with pytest.raises(Q8DevelopmentBlocked):
        classification_receipt(pair=PAIR, gateway_reply=reply)


def test_invalid_origin_and_role_fail_closed():
    with pytest.raises(Q8DevelopmentBlocked):
        classification_receipt(pair=PAIR, gateway_reply=response(origin="unknown_authority"))
    with pytest.raises(Q8DevelopmentBlocked):
        classification_receipt(pair=PAIR, gateway_reply=response(role="source_localization"))


def test_source_drift_rejected(tmp_path):
    fake = tmp_path / SOURCE
    fake.parent.mkdir(parents=True)
    fake.write_bytes((ROOT / SOURCE).read_bytes() + b"\n# source modified")
    with pytest.raises(Q8DevelopmentBlocked, match="source_sha256_mismatch"):
        trusted_source(tmp_path)


def test_raw_gateway_reply_is_captured_before_rejection(tmp_path):
    raw = source_response(line=101)  # A comment, not executable AST statement.
    path = archive_gateway_reply(
        evidence_dir=tmp_path, filename="q8-raw-source.json",
        reply=raw, project_root=ROOT,
    )
    assert json.loads(path.read_text()) == raw
    assert path.stat().st_mode & 0o777 == 0o600
    request = localization_request(pair=PAIR, project_root=ROOT)
    with pytest.raises(Q8DevelopmentBlocked):
        localization_receipt(request=request, gateway_reply=raw, project_root=ROOT)
    assert json.loads(path.read_text()) == raw
    with pytest.raises(FileExistsError):
        archive_gateway_reply(
            evidence_dir=tmp_path, filename="q8-raw-source.json",
            reply=raw, project_root=ROOT,
        )


def test_evidence_inside_live_repo_is_rejected():
    with pytest.raises(Q8DevelopmentBlocked, match="outside_live_repository"):
        archive_gateway_reply(
            evidence_dir=ROOT, filename="q8-cannot-write.json",
            reply=response(), project_root=ROOT,
        )
