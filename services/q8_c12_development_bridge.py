"""Q8/C12 DEVELOPMENT integration into existing typed Blue decisions.

This is a data boundary, not an executor, classifier provider, or patch engine.
The caller must supply observed HTTP pairs and a separately recorded C12 gateway
reply. Nothing here qualifies Q8 for RQ2's original single-event dataset, M21,
or any model-authorized Red test/Blue patch.
"""
from __future__ import annotations

import ast
import json
import os
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from schemas.blue_team import SourceLineRange
from schemas.rq2_dataset import RQ2ClassificationDecision, RQ2ClassifierEvent
from services.compact_source_selection import CompactSourceSelection
from services.model_driven_decision_gate import route_model_triage
from services.trusted_remediation_compiler import EXPECTED_SOURCE_SHA256, SOURCE

BRIDGE_VERSION = "q8-c12-development-bridge-v1"
MODEL_SHA256 = "51b63a132c73a592d954e96b15c1d28176f0cc3e5f05533304e92a6fb40ad304"
ROUTE_FUNCTIONS = {
    "/sql-injection/login": "vulnerable_login",
    "/xss/search": "vulnerable_search",
    "/path-traversal/read": "vulnerable_file_read",
}
# Trusted source excerpts. Only the immutable approved lab file may supply bytes.
# These are DEVELOPMENT prompt windows, not an independently qualified prompt.
SOURCE_CONTEXT_WINDOWS = ((37, 56), (72, 88), (89, 113))
SOURCE_PROFILE_V1 = "c12-numbered-source-v1"
SOURCE_PROFILE_V2 = "q8-executable-lines-v2"
# V2 is a prospectively declared development-only prompt transformation.
# No manual sink-line hints, target labels, or evaluator ground truth are injected.
INPUT_FIELDS = frozenset(("route", "observations"))
OBS_FIELDS = frozenset(("method", "parameters", "response_excerpt", "status_code"))
PROHIBITED = frozenset(("ground_truth", "expected", "truth", "evaluator_only", "label"))


class Q8DevelopmentBlocked(ValueError):
    """Fail-closed when an unqualified bridge cannot prove its input identity."""


def _block(message: str) -> None:
    raise Q8DevelopmentBlocked(message)


def validate_pair(value: object) -> dict[str, Any]:
    """Validate two actual caller-supplied observations; never synthesize one."""
    if type(value) is not dict or set(value) != INPUT_FIELDS:
        _block("two_observation_input_required")
    route = value["route"]
    if route not in ROUTE_FUNCTIONS:
        _block("route_not_registered_in_synthetic_lab")
    rows = value["observations"]
    if type(rows) is not list or len(rows) != 2:
        _block("exactly_two_observations_required")
    for row in rows:
        if type(row) is not dict or set(row) != OBS_FIELDS:
            _block("observation_schema_mismatch_or_extra_fields")
        if type(row["method"]) is not str or row["method"] not in ("GET", "POST"):
            _block("unsupported_observation_method")
        if type(row["status_code"]) is not int or not 100 <= row["status_code"] <= 599:
            _block("status_code_invalid")
        if type(row["parameters"]) is not dict or len(row["parameters"]) > 12:
            _block("parameters_invalid")
        if any(
            type(key) is not str or len(key) > 100 or type(val) is not str or len(val) > 1000
            for key, val in row["parameters"].items()
        ):
            _block("parameter_value_invalid")
        excerpt = row["response_excerpt"]
        if excerpt is not None and (type(excerpt) is not str or len(excerpt) > 4000):
            _block("response_excerpt_invalid")
        if PROHIBITED.intersection(row):
            _block("evaluator_metadata_forbidden")
    if rows[0]["method"] != rows[1]["method"]:
        _block("two_observation_method_mismatch")
    # Deep JSON roundtrip ensures the owned result is not a mutable user mapping.
    return json.loads(json.dumps(value, ensure_ascii=False))


def refuse_single_rq2_event(event: RQ2ClassifierEvent) -> None:
    """No lossless mapping: original RQ2 events lack C12's paired HTTP bodies."""
    if not isinstance(event, RQ2ClassifierEvent):
        _block("not_an_rq2_classifier_event")
    _block("rq2_single_event_not_equivalent_to_c12_http_pair")


@dataclass(frozen=True)
class SourceSnapshot:
    sha256: str
    numbered_candidate_functions: str
    names: tuple[str, ...]
    span_by_name: dict[str, tuple[int, int]]
    statement_lines_by_name: dict[str, frozenset[int]]


def trusted_source(
    project_root: Path, *, source_profile: str = SOURCE_PROFILE_V1
) -> SourceSnapshot:
    """Build a *read-only*, hash-bound source view from existing trusted lab code."""
    file = project_root / SOURCE
    if file.is_symlink() or not file.is_file():
        _block("source_file_not_regular")
    raw = file.read_bytes()
    digest = sha256(raw).hexdigest()
    if digest != EXPECTED_SOURCE_SHA256:
        _block("source_sha256_mismatch")
    code = raw.decode("utf-8")
    lines = code.splitlines()
    tree = ast.parse(code)
    router = [n for n in tree.body if isinstance(n, ast.FunctionDef)
              and n.name == "build_scenario_router"]
    if len(router) != 1:
        _block("trusted_router_not_unique")
    funcs: dict[str, ast.FunctionDef] = {}
    for node in router[0].body:
        if isinstance(node, ast.FunctionDef) and node.name in ROUTE_FUNCTIONS.values():
            if node.name in funcs:
                _block("trusted_function_not_unique")
            funcs[node.name] = node
    if set(funcs) != set(ROUTE_FUNCTIONS.values()):
        _block("trusted_function_missing")
    spans = {name: (node.lineno, node.end_lineno) for name, node in funcs.items()}
    stmt_lines: dict[str, frozenset[int]] = {}
    for name, node in funcs.items():
        stmt_lines[name] = frozenset(
            i for x in ast.walk(node) if isinstance(x, ast.stmt) and x is not node
            for i in range(x.lineno, x.end_lineno + 1)
        )
    if source_profile not in (SOURCE_PROFILE_V1, SOURCE_PROFILE_V2):
        _block("source_profile_not_approved")
    def visible(idx: int) -> bool:
        if source_profile == SOURCE_PROFILE_V1:
            return True
        line = lines[idx - 1].strip()
        return bool(line) and not line.startswith("#")
    view = "\n\n".join(
        "\n".join(
            f"{idx:03d} {lines[idx - 1]}"
            for idx in range(first, last + 1) if visible(idx)
        )
        for first, last in SOURCE_CONTEXT_WINDOWS
    )
    return SourceSnapshot(
        sha256=digest,
        numbered_candidate_functions=view,
        names=tuple(sorted(funcs)),
        span_by_name=spans,
        statement_lines_by_name=stmt_lines,
    )


def classification_request(pair: dict[str, Any]) -> dict[str, Any]:
    return {"role": "classification", "input": validate_pair(pair)}


def localization_request(
    *, pair: dict[str, Any], project_root: Path,
    source_profile: str = SOURCE_PROFILE_V1
) -> dict[str, Any]:
    data = validate_pair(pair)
    source = trusted_source(project_root, source_profile=source_profile)
    return {"role": "source_localization", "input": {
        **data,
        "source_sha256": source.sha256,
        "numbered_candidate_functions": source.numbered_candidate_functions,
        "candidate_function_names": list(source.names),
    }}


def _gateway_result(reply: object, expected_role: str, origins: frozenset[str]) -> dict:
    if type(reply) is not dict or set(reply) != {"role", "result", "origin", "executed_tests"}:
        _block("c12_gateway_envelope_invalid")
    if reply["role"] != expected_role or reply["origin"] not in origins:
        _block("c12_role_or_origin_invalid")
    if reply["executed_tests"] is not False or type(reply["result"]) is not dict:
        _block("c12_test_execution_or_result_invalid")
    return reply["result"]


def classification_receipt(*, pair: dict[str, Any], gateway_reply: dict) -> dict:
    validate_pair(pair)
    result = _gateway_result(
        gateway_reply, "classification",
        frozenset(("q8_0_cpu_model", "insufficient_evidence_policy"))
    )
    try:
        decision = RQ2ClassificationDecision.model_validate(result)
    except ValidationError as exc:
        raise Q8DevelopmentBlocked("existing_classification_schema_rejected") from exc
    preliminary = route_model_triage(decision=decision)
    return {
        "bridge_version": BRIDGE_VERSION,
        "decision": decision.model_dump(mode="json"),
        "origin": gateway_reply["origin"],
        "preliminary_blue_action": preliminary.action.value,
        "preliminary_reason_code": preliminary.reason_code,
        "registered_test_dispatched": False,
        "ready_for_source_analysis": False,
        "ready_for_patch_preparation": False,
        "final_research_qualified": False,
    }


def localization_receipt(
    *, request: dict, gateway_reply: dict, project_root: Path,
    source_profile: str = SOURCE_PROFILE_V1
) -> dict:
    if type(request) is not dict or set(request) != {"role", "input"}:
        _block("source_request_invalid")
    if request["role"] != "source_localization" or type(request["input"]) is not dict:
        _block("source_request_role_invalid")
    data = request["input"]
    if not INPUT_FIELDS.issubset(data):
        _block("source_observations_missing")
    # Rebuild entire request from trusted source; never accept model-controlled paths.
    approved = localization_request(
        pair={"route": data["route"], "observations": data["observations"]},
        project_root=project_root,
        source_profile=source_profile,
    )
    if request != approved:
        _block("source_context_not_trusted")
    result = _gateway_result(
        gateway_reply, "source_localization", frozenset(("q8_0_cpu_model",))
    )
    try:
        selected = CompactSourceSelection.model_validate(result)
    except ValidationError as exc:
        raise Q8DevelopmentBlocked("existing_compact_source_schema_rejected") from exc
    source = trusted_source(project_root)
    function = selected.function_or_route
    if function != ROUTE_FUNCTIONS[data["route"]]:
        _block("selected_function_not_bound_to_trusted_route")
    start, end = source.span_by_name[function]
    if not start <= selected.sink_line <= end:
        _block("selected_sink_outside_trusted_function")
    if selected.sink_line not in source.statement_lines_by_name[function]:
        _block("selected_sink_not_executable_source_statement")
    # Operational safety: use the PRE-EXISTING trusted compiler's exact source
    # replacement strings to require a semantically relevant executable line.
    # This is NOT evaluator ground truth and MUST NOT alter raw model scores.
    from services.trusted_remediation_compiler import (
        _PATH_OLD,
        _SQL_EXEC_OLD,
        _XSS_SINK_OLD,
    )
    anchors = {
        "vulnerable_login": (_SQL_EXEC_OLD, "WHERE username ="),
        "vulnerable_search": (_XSS_SINK_OLD, "Search term: {q}"),
        "vulnerable_file_read": (_PATH_OLD, "(intended_public_root / path)"),
    }
    original_line = (project_root / SOURCE).read_text(encoding="utf-8").splitlines()[
        selected.sink_line - 1
    ]
    if not any(text in original_line for text in anchors[function]):
        _block("selected_sink_does_not_match_preapproved_compiler_source_anchors")
    region = SourceLineRange(start_line=selected.sink_line, end_line=selected.sink_line)
    return {
        "bridge_version": BRIDGE_VERSION,
        "selection": selected.model_dump(mode="json"),
        "source_relative_path": SOURCE,
        "source_sha256": source.sha256,
        "supporting_line": region.model_dump(mode="json"),
        "origin": gateway_reply["origin"],
        "registered_test_dispatched": False,
        "ready_for_patch_preparation": False,
        "final_research_qualified": False,
    }


def archive_gateway_reply(*, evidence_dir: Path, filename: str, reply: object,
                          project_root: Path) -> Path:
    """Save gateway reply once *before* source validation; no repo evidence writes."""
    if not filename.startswith("q8-") or not filename.endswith(".json"):
        _block("receipt_filename_invalid")
    if any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-." for c in filename):
        _block("receipt_filename_invalid")
    if evidence_dir.is_symlink() or not evidence_dir.is_dir():
        _block("evidence_directory_not_regular")
    if project_root.resolve() == evidence_dir.resolve() or (
        project_root.resolve() in evidence_dir.resolve().parents
    ):
        _block("evidence_must_be_outside_live_repository")
    payload = (json.dumps(reply, sort_keys=True, ensure_ascii=False, indent=2) + "\n").encode()
    if len(payload) > 120000:
        _block("receipt_too_large")
    path = evidence_dir / filename
    fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    return path
