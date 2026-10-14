"""Compact source-to-compiler development boundary checks."""

import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from orchestrator.limits import RunLimitTracker
from orchestrator.policy_engine import PolicyEngine
from schemas.blue_team import TriageResult
from schemas.common import ClassificationLabel
from schemas.experiments import ExperimentLimits
from services.audit_service import AuditService
from services.compact_source_selection import (
    SCHEMA_VERSION,
    CompactSourceSelection,
    build_verified_analysis,
    load_trusted_source_window,
)
from services.target_registry import TargetRegistry
from services.trusted_remediation_compiler import (
    EXPECTED_SOURCE_SHA256,
    SOURCE,
    TrustedRemediationCompiler,
)

ROOT = Path(__file__).resolve().parents[1]
CASES = (
    (ClassificationLabel.SQL_INJECTION, "vulnerable_login", 48, (38, 56)),
    (ClassificationLabel.XSS, "vulnerable_search", 84, (77, 89)),
    (ClassificationLabel.PATH_TRAVERSAL, "vulnerable_file_read", 104, (92, 109)),
)


@pytest.fixture
def lab(tmp_path):
    path = tmp_path / SOURCE
    path.parent.mkdir(parents=True)
    original = (ROOT / SOURCE).read_bytes()
    assert hashlib.sha256(original).hexdigest() == EXPECTED_SOURCE_SHA256
    path.write_bytes(original)
    return tmp_path, path


def make_triage(category, run_id="compact-test"):
    return TriageResult(
        run_id=run_id, is_suspicious=True,
        classification=category, confidence=0.92,
        reason="Synthetic development observation."
    )


def selection(name, line):
    return CompactSourceSelection.model_validate_json(json.dumps({
        "function_or_route": name, "sink_line": line,
        "root_cause": "Untrusted input reaches the unsafe application sink.",
        "confidence": 0.92,
    }))


@pytest.mark.parametrize("category,name,line,bounds", CASES)
def test_three_approved_paths_prepare_without_application(lab, category, name, line, bounds):
    root, path = lab
    before = path.read_bytes()
    window = load_trusted_source_window(
        project_root=root, start_line=bounds[0], end_line=bounds[1]
    )
    result = build_verified_analysis(
        project_root=root, trusted_run_id="compact-test",
        triage=make_triage(category), selection=selection(name, line), window=window,
    )
    assert result.code_finding.file_path == SOURCE
    registry = TargetRegistry.from_directories(
        targets_dir=ROOT / "config/targets",
        security_tests_dir=ROOT / "config/security_tests",
    )
    compiler = TrustedRemediationCompiler(
        project_root=root, registry=registry,
        policy_engine=PolicyEngine(registry=registry, project_root=root),
        audit_service=AuditService(project_root=root),
    )
    outcome = compiler.prepare(
        analysis=result, attempt_number=1, limits=RunLimitTracker(ExperimentLimits())
    )
    assert outcome.provenance.status == "prepared", outcome.provenance.reason_code
    assert outcome.generation is not None
    assert outcome.provenance.model_decision_used is False
    assert path.read_bytes() == before


@pytest.mark.parametrize("payload", [
    {"function_or_route":"wrong_function","sink_line":48,"root_cause":"Untrusted SQL","confidence":0.9},
    {"function_or_route":"vulnerable_login","sink_line":"48","root_cause":"Untrusted SQL","confidence":0.9},
    {"function_or_route":"vulnerable_login","sink_line":48,"root_cause":" ","confidence":0.9},
    {"function_or_route":"vulnerable_login","sink_line":48,"root_cause":"Untrusted SQL","confidence":0.9,"run_id":"forged"},
])
def test_bad_compact_response_is_rejected(payload):
    with pytest.raises(ValidationError):
        CompactSourceSelection.model_validate(payload)


def test_contract_contains_no_model_controlled_identity():
    assert SCHEMA_VERSION == "q6-compact-source-development-v1"
    schema = CompactSourceSelection.model_json_schema()
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == {"function_or_route", "sink_line", "root_cause", "confidence"}
    assert "run_id" not in schema["properties"]
    assert "file_path" not in schema["properties"]


def test_wrong_line_function_run_or_window_is_blocked(lab):
    root, _ = lab
    window = load_trusted_source_window(project_root=root, start_line=38, end_line=56)
    kw = {
        "project_root": root,
        "trusted_run_id": "compact-test",
        "triage": make_triage(ClassificationLabel.SQL_INJECTION),
        "window": window,
    }
    with pytest.raises(ValueError):
        build_verified_analysis(selection=selection("vulnerable_search", 48), **kw)
    with pytest.raises(ValueError):
        build_verified_analysis(selection=selection("vulnerable_login", 84), **kw)
    with pytest.raises(ValueError):
        build_verified_analysis(
            selection=selection("vulnerable_login", 48),
            **{**kw, "triage":make_triage(ClassificationLabel.SQL_INJECTION,run_id="other")}
        )
    with pytest.raises(ValueError):
        load_trusted_source_window(project_root=root, start_line=1, end_line=200)


def test_source_drift_and_no_action_are_blocked(lab):
    root, path = lab
    window = load_trusted_source_window(project_root=root, start_line=38, end_line=56)
    with pytest.raises(ValueError):
        build_verified_analysis(
            project_root=root, trusted_run_id="compact-test",
            triage=make_triage(ClassificationLabel.BENIGN),
            selection=selection("vulnerable_login",48), window=window
        )
    path.write_bytes(path.read_bytes() + b"\n# drift\n")
    with pytest.raises(ValueError, match="hash"):
        build_verified_analysis(
            project_root=root, trusted_run_id="compact-test",
            triage=make_triage(ClassificationLabel.SQL_INJECTION),
            selection=selection("vulnerable_login",48), window=window
        )
