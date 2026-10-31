"""Read-only, independently pinned Q8-to-registered-Red development evidence review.

Browser requests select no paths, hashes, targets, or commands. Operator-controlled,
externally SHA-pinned approval binds the recorded (synthetic) Q8 pair and a separately
executed registered Red archive. This does not dispatch Red, patch source, attest
the model weights, or admit any final research result.
"""
from __future__ import annotations

import json
import os
import re
from hashlib import sha256
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, model_validator

from schemas.red_team import TestExecutionResult
from schemas.rq2_dataset import RQ2ClassificationDecision
from security_tests.registry import SecurityTestRegistry
from services.bound_registered_red_evidence import verify_archived_registered_red
from services.model_driven_decision_gate import authorize_bound_source_analysis
from services.q8_c12_development_bridge import classification_receipt, classification_request
from services.registered_assessment_plan import _registry, plan_from_model_receipt

MODEL_FILES = {
    "q8-input.json": 16384,
    "q8-raw-completion.json": 262144,
    "q8-gateway.json": 16384,
    "q8-assessment-plan.json": 32768,
}
HEX64 = re.compile(r"[a-f0-9]{64}\Z")
CASE = re.compile(r"probe-[a-f0-9]{16}\Z")
NOTICE = "Development archive review only; no new execution, patch, or final research admission."


class ReviewBlocked(ValueError):
    """An external approval or saved model record was not independently pinned."""


class EvidenceApproval(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: str = Field(pattern=r"^sentinel-evidence-link-v1$")
    model_evidence_dir: str
    model_files: dict[str, str]
    red_evidence_dir: str
    red_admission_path: str
    red_admission_sha256: str
    red_receipt_sha256: str
    red_run_id: str
    red_source_root: str | None = None
    reconstructed_pair_sha256: str | None = None

    @model_validator(mode="after")
    def validate_pins(self):
        if set(self.model_files) != set(MODEL_FILES):
            raise ValueError("complete model evidence file pins required")
        hashes = (*self.model_files.values(), self.red_admission_sha256, self.red_receipt_sha256)
        if any(HEX64.fullmatch(x) is None for x in hashes):
            raise ValueError("all evidence SHA-256 pins are required")
        if not CASE.fullmatch(Path(self.model_evidence_dir).name):
            raise ValueError("not an approved Q8 development evidence case")
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,47}", self.red_run_id):
            raise ValueError("invalid registered run identifier")
        if (self.red_source_root is None) != (self.reconstructed_pair_sha256 is None):
            raise ValueError("reconstructed input needs source checkout and provenance pin")
        if self.reconstructed_pair_sha256 is not None and HEX64.fullmatch(
            self.reconstructed_pair_sha256
        ) is None:
            raise ValueError("reconstruction provenance digest invalid")
        return self


def _external(path_value: str, root: Path, *, directory: bool) -> Path:
    path = Path(path_value)
    if not path.is_absolute() or path.is_symlink() or any(x.is_symlink() for x in path.parents):
        raise ReviewBlocked("external_path_invalid")
    if not (path.is_dir() if directory else path.is_file()):
        raise ReviewBlocked("external_path_unavailable")
    resolved = path.resolve(strict=True)
    source = root.resolve(strict=True)
    if resolved == source or source in resolved.parents:
        raise ReviewBlocked("evidence_must_remain_outside_repository")
    return path


def _pinned(path: Path, digest: str, maximum: int) -> bytes:
    if path.is_symlink() or any(x.is_symlink() for x in path.parents) or not path.is_file():
        raise ReviewBlocked("pinned_file_missing_or_symlinked")
    if path.stat().st_size > maximum:
        raise ReviewBlocked("pinned_file_size_exceeded")
    raw = path.read_bytes()
    if len(raw) > maximum or sha256(raw).hexdigest() != digest:
        raise ReviewBlocked("pinned_file_digest_mismatch")
    return raw


def _approval(root: Path, path_value: str, digest: str) -> EvidenceApproval:
    if HEX64.fullmatch(digest) is None:
        raise ReviewBlocked("independent_approval_sha256_required")
    path = _external(path_value, root, directory=False)
    try:
        return EvidenceApproval.model_validate_json(_pinned(path, digest, 8192))
    except (ValueError, TypeError) as exc:
        raise ReviewBlocked("evidence_approval_invalid") from exc


def _model_record(root: Path, approval: EvidenceApproval) -> tuple[dict, dict, dict]:
    directory = _external(approval.model_evidence_dir, root, directory=True)
    try:
        files = {name: json.loads(_pinned(directory / name, approval.model_files[name], limit))
                 for name, limit in MODEL_FILES.items()}
        request = files["q8-input.json"]
        pair = request["input"]
        if request != classification_request(pair):
            raise ReviewBlocked("model_request_mismatch")
        raw = files["q8-raw-completion.json"]
        gateway = files["q8-gateway.json"]
        if (type(raw) is not dict or raw.get("truncated") is not False
                or type(raw.get("content")) is not str
                or type(gateway) is not dict
                or gateway.get("origin") != "q8_0_cpu_model"
                or gateway.get("executed_tests") is not False
                or gateway.get("role") != "classification"
                or json.loads(raw["content"]) != gateway.get("result")):
            raise ReviewBlocked("raw_model_answer_mismatch")
        receipt = classification_receipt(pair=pair, gateway_reply=gateway)
        plan = plan_from_model_receipt(root=root, pair=pair, receipt=receipt)
        if files["q8-assessment-plan.json"] != plan:
            raise ReviewBlocked("saved_assessment_plan_mismatch")
        return receipt, plan, pair
    except (KeyError, TypeError, ValueError) as exc:
        raise ReviewBlocked("q8_model_archive_invalid") from exc


def _verified_reconstructed_pair(
    *, approval: EvidenceApproval, source: Path, pair: dict, bound: object,
) -> None:
    """Bind registered step request definitions to captured Red responses."""
    if bound.test_id != "sqli-login-bypass-001":
        raise ReviewBlocked("unregistered_reconstruction")
    directory = _external(approval.model_evidence_dir, source, directory=True)
    record = json.loads(_pinned(
        directory / "pair-provenance.json", approval.reconstructed_pair_sha256, 8192
    ))
    expected = {
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
        "no_evaluator_truth_in_model_input": True,
        "research_qualified": False,
        "model_source_analysis_authorized": False,
    }
    if not isinstance(record, dict) or any(record.get(k) != v for k, v in expected.items()):
        raise ReviewBlocked("reconstructed_pair_provenance_mismatch")
    steps = SecurityTestRegistry.default().get(bound.test_id).build_steps()
    exchanges = bound.observation.execution.exchanges
    if len(steps) != len(exchanges) or len(steps) != 2:
        raise ReviewBlocked("registered_pair_cardinality_mismatch")
    rows = []
    for step, exchange in zip(steps, exchanges, strict=True):
        method = getattr(step.method, "value", step.method)
        observed_method = getattr(exchange.method, "value", exchange.method)
        if (step.step_id != exchange.step_id
                or step.endpoint_id != exchange.endpoint_id
                or step.endpoint_id != bound.endpoint_id
                or method != observed_method
                or not isinstance(step.json_body, dict)):
            raise ReviewBlocked("registered_pair_step_mismatch")
        rows.append({
            "method": method, "parameters": step.json_body,
            "response_excerpt": exchange.body_excerpt,
            "status_code": exchange.status_code,
        })
    if (record.get("exchange_step_ids") != [step.step_id for step in steps]
            or pair != {"route": "/sql-injection/login", "observations": rows}):
        raise ReviewBlocked("model_input_not_bound_to_registered_exchange")


def _result(*, status: str, reason: str, receipt: dict | None = None,
            plan: dict | None = None, red_run_id: str | None = None,
            verified: bool = False, authorized: bool = False,
            model_input_scope: str = "hand_authored_synthetic_http_pair") -> dict:
    return {
        "kind": "pinned_development_evidence_review_v1",
        "status": status,
        "reason_code": reason,
        "model_decision": receipt["decision"] if receipt else None,
        "model_origin": receipt["origin"] if receipt else None,
        "model_input_scope": model_input_scope if receipt else None,
        "registered_test_id": plan["registered_test_id"] if plan else None,
        "red_run_id": red_run_id,
        "red_evidence_verified": verified,
        "red_evidence_scope": "archived_development_provenance" if verified else None,
        "source_analysis_authorized": authorized,
        "trusted_safe_outcome": False,
        "patch_preparation_authorized": False,
        "patch_applied": False,
        "post_remediation_verified": False,
        "model_independently_qualified": False,
        "final_research_qualified": False,
        "notice": NOTICE,
    }


def review_archived_assessment(
    *, root: Path, approval_path: str | None = None, approval_sha256: str | None = None
) -> dict:
    """Review approved archived evidence without model, Docker, Git or write calls."""
    path = approval_path if approval_path is not None else os.environ.get("FYP_ASSESSMENT_APPROVAL_PATH")
    digest = (approval_sha256 if approval_sha256 is not None
              else os.environ.get("FYP_ASSESSMENT_APPROVAL_SHA256"))
    if not path and not digest:
        return _result(status="not_configured", reason="operator_pinned_evidence_not_supplied")
    if not path or not digest:
        return _result(status="blocked", reason="incomplete_operator_approval")
    try:
        approved = _approval(root, path, digest)
        source = root
        if approved.red_source_root is not None:
            candidate = Path(approved.red_source_root)
            source = (root if candidate == root.resolve(strict=True)
                      else _external(approved.red_source_root, root, directory=True))
        receipt, plan, pair = _model_record(source, approved)
    except (ReviewBlocked, OSError, ValueError):
        return _result(status="blocked", reason="operator_approval_or_model_archive_rejected")
    input_scope = ("reconstructed_pair_pending_red_binding"
                   if approved.reconstructed_pair_sha256 else "hand_authored_synthetic_http_pair")

    # Benign is not trusted safe. Unknown is manual review; neither loads Red.
    if plan["triage_action"] != "select_registered_test":
        status = ("benign_unverified" if plan["triage_action"] == "no_action"
                  else "manual_review")
        return _result(status=status, reason=plan["reason_code"], receipt=receipt,
                       plan=plan, model_input_scope=input_scope)
    if plan["registered_selection_reason"] != "registered_selection_allowed":
        return _result(status="withheld", reason=plan["registered_selection_reason"],
                       receipt=receipt, plan=plan, model_input_scope=input_scope)

    try:
        archive = _external(approved.red_evidence_dir, root, directory=True)
        admission = _external(approved.red_admission_path, root, directory=False)
        bound = verify_archived_registered_red(
            source_root=source, dispatch_root=source, evidence_dir=archive,
            admission_path=admission,
            admission_sha256=approved.red_admission_sha256,
            receipt_sha256=approved.red_receipt_sha256,
            registry=_registry(source), implementations=SecurityTestRegistry.default(),
        )
        if bound.run_id != approved.red_run_id:
            raise ReviewBlocked("approved_red_run_mismatch")
        if approved.reconstructed_pair_sha256 is not None:
            _verified_reconstructed_pair(
                approval=approved, source=source, pair=pair, bound=bound,
            )
            input_scope = "registered_steps_plus_captured_responses"
        gate = authorize_bound_source_analysis(
            decision=RQ2ClassificationDecision.model_validate(receipt["decision"]),
            selected_test_id=plan["registered_test_id"], target_id=plan["target_id"],
            trusted_endpoint_id=plan["endpoint_id"],
            trusted_run_id=approved.red_run_id, evidence=bound, registry=_registry(source),
        )
    except (OSError, ValueError, ReviewBlocked):
        return _result(status="evidence_rejected", reason="red_archive_not_independently_bound",
                       receipt=receipt, plan=plan, model_input_scope=input_scope)
    allowed = gate.action.value == "source_analysis"
    return _result(status="evidence_bound" if allowed else "withheld",
                   reason=gate.reason_code, receipt=receipt, plan=plan,
                   red_run_id=bound.run_id, verified=True, authorized=allowed,
                   model_input_scope=input_scope)


class RegisteredRedDisplayApproval(BaseModel):
    """Externally pinned Red-only archive. No inference or execution authority."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: str = Field(pattern=r"^sentinel-registered-red-display-v1$")
    source_root: str
    red_evidence_dir: str
    red_admission_path: str
    red_admission_sha256: str
    red_receipt_sha256: str
    red_run_id: str


def review_pinned_registered_red(
    *, root: Path, approval_path: str | None = None,
    approval_sha256: str | None = None,
) -> dict:
    """Inspect one operator-pinned real lab receipt; model linkage stays withheld."""
    path = approval_path if approval_path is not None else os.environ.get(
        "FYP_REGISTERED_RED_DISPLAY_PATH"
    )
    digest = approval_sha256 if approval_sha256 is not None else os.environ.get(
        "FYP_REGISTERED_RED_DISPLAY_SHA256"
    )
    result = {
        "kind": "registered_red_archive_display_v1",
        "status": "not_configured" if not path and not digest else "blocked",
        "reason_code": "no_external_red_approval" if not path and not digest
                       else "operator_red_approval_rejected",
        "registered_test_id": None,
        "red_run_id": None,
        "red_case_id": None,
        "vulnerability_class": None,
        "request_count": None,
        "red_evidence_verified": False,
        "exploit_confirmed": False,
        "red_evidence_scope": None,
        "model_decision": None,
        "model_alignment_status": "not_established",
        "source_analysis_authorized": False,
        "patch_preparation_authorized": False,
        "patch_applied": False,
        "final_research_qualified": False,
    }
    if not path or not digest:
        return result
    try:
        if HEX64.fullmatch(digest) is None:
            raise ReviewBlocked("external_approval_digest_required")
        manifest = RegisteredRedDisplayApproval.model_validate_json(
            _pinned(_external(path, root, directory=False), digest, 8192)
        )
        if (
            any(HEX64.fullmatch(value) is None for value in (
                manifest.red_admission_sha256, manifest.red_receipt_sha256
            ))
            or not re.fullmatch(r"[a-z][a-z0-9_-]{0,47}", manifest.red_run_id)
        ):
            raise ReviewBlocked("invalid_red_identity")
        source = Path(manifest.source_root)
        if (
            not source.is_absolute() or source.is_symlink()
            or any(part.is_symlink() for part in source.parents)
            or not source.is_dir()
        ):
            raise ReviewBlocked("source_root_unavailable")
        bound = verify_archived_registered_red(
            source_root=source, dispatch_root=source,
            evidence_dir=_external(manifest.red_evidence_dir, root, directory=True),
            admission_path=_external(manifest.red_admission_path, root, directory=False),
            admission_sha256=manifest.red_admission_sha256,
            receipt_sha256=manifest.red_receipt_sha256,
            registry=_registry(source), implementations=SecurityTestRegistry.default(),
        )
        if (
            bound.run_id != manifest.red_run_id
            or bound.test_id != "sqli-login-bypass-001"
            or bound.observation.execution.request_count > 2
        ):
            raise ReviewBlocked("wrong_registered_case")
    except (OSError, ValueError, RuntimeError, TypeError, KeyError):
        return result
    result.update(
        status="verified_archived_red", reason_code="registered_receipt_bound",
        registered_test_id=bound.test_id, red_run_id=bound.run_id,
        red_case_id=bound.case_id, vulnerability_class=bound.vulnerability_class,
        request_count=bound.observation.execution.request_count,
        red_evidence_verified=True, exploit_confirmed=True,
        red_evidence_scope=bound.evidence_scope,
    )
    return result


PATCHED_REPLAY_FILES = {
    "stdout.raw": 4096,
    "stderr.raw": 4096,
    "exit-code.txt": 64,
    "verified-replay.json": 8192,
    "legitimate-login.json": 2048,
    "search-file-regression.json": 2048,
}


class PatchedReplayApproval(BaseModel):
    """Server-side SHA pins, never accepted from the browser."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: str = Field(pattern=r"^sentinel-patched-sqli-display-v1$")
    evidence_dir: str
    files: dict[str, str]
    attestation_path: str
    attestation_sha256: str

    @model_validator(mode="after")
    def validate_pins(self):
        if set(self.files) != set(PATCHED_REPLAY_FILES):
            raise ValueError("complete replay file set required")
        if any(HEX64.fullmatch(v) is None for v in (
            *self.files.values(), self.attestation_sha256,
        )):
            raise ValueError("invalid replay SHA-256")
        return self


def review_pinned_patched_replay(
    *, root: Path, approval_path: str | None = None,
    approval_sha256: str | None = None,
) -> dict:
    """Revalidate one archived patched Docker result without issuing requests."""
    path = (approval_path if approval_path is not None
            else os.environ.get("FYP_PATCHED_REPLAY_APPROVAL_PATH"))
    digest = (approval_sha256 if approval_sha256 is not None
              else os.environ.get("FYP_PATCHED_REPLAY_APPROVAL_SHA256"))
    result = {
        "status": "not_configured" if not path and not digest else "blocked",
        "reason_code": "no_replay_approval" if not path and not digest
                       else "replay_evidence_rejected",
        "test_id": None, "run_id": None, "request_count": None,
        "http_statuses": None, "registered_replay_verified": False,
        "exploit_confirmed": None, "legitimate_login_verified": False,
        "search_file_verified": False,
        "evidence_scope": "archived_development_self_review",
        "model_initiated_original_red": False,
        "patch_applied_to_original_repo": False,
        "final_research_qualified": False,
    }
    if not path or not digest:
        return result
    try:
        if HEX64.fullmatch(digest) is None:
            raise ReviewBlocked("invalid replay approval SHA")
        approval = PatchedReplayApproval.model_validate_json(
            _pinned(_external(path, root, directory=False), digest, 8192)
        )
        folder = _external(approval.evidence_dir, root, directory=True)
        data = {
            name: _pinned(folder / name, approval.files[name], maximum)
            for name, maximum in PATCHED_REPLAY_FILES.items()
        }
        a = json.loads(_pinned(
            _external(approval.attestation_path, root, directory=False),
            approval.attestation_sha256, 16384,
        ))
        evidence = json.loads(data["verified-replay.json"])
        legitimate = json.loads(data["legitimate-login.json"])
        functional = json.loads(data["search-file-regression.json"])
        record = TestExecutionResult.model_validate_json(data["stdout.raw"])
        impl = SecurityTestRegistry.default().get("sqli-login-bypass-001")
        steps = impl.build_steps()
        if (
            data["stderr.raw"] or data["exit-code.txt"].strip() != b"0"
            or a.get("schema_version") != "sentinel-patched-sqli-operator-runtime-attestation-v1"
            or a.get("registered_test_id") != "sqli-login-bypass-001"
            or a.get("checks_passed") is not True or a.get("error") is not None
            or a.get("replay_executed_by_this_script") is not False
            or a.get("run_id_reserved_not_executed") != "sql-20261015-r2"
            or a["results"].get("docker_context") != "default"
            or a["results"].get("baseline_image_id") !=
               "sha256:2f3d8290709fb13e193075fd2c7f555fc08f959d7d58c899dda74cbb2a6029ea"
            or a["results"].get("network_internal") is not True
            or a["results"].get("network_attachable") is not False
            or a["results"].get("patched_image_id") !=
               "sha256:6d05b3656df9474b1b2d78876049b0adf196a69ea569f111276f49fee1035e53"
            or a["source_sha256"].get("dummy_apps/vulnerable_store/app/scenario_routes.py")
               != "c98aaccb4577804a7606b3e7059b5669e15ced05004c3ae9ba3a2ff14931fe98"
            or any(v.get("deployed_source_sha256") != a["source_sha256"]
                   or v.get("health") != "healthy" or v.get("published_host_ports")
                   or v.get("read_only") is not True
                   or v.get("user") != "10001:10001"
                   or v.get("image_id") != a["results"]["patched_image_id"]
                   for v in a["results"]["containers"].values())
            or set(a["results"]["containers"]) != {"vulnerable-store", "controlled-executor"}
            or record.run_id != "sql-20261015-r2"
            or record.test_id != "sqli-login-bypass-001" or record.target_id != "vulnerable-store"
            or record.attempt_number != 1 or record.request_count != 2
            or not record.completed or record.timed_out or record.evidence
            or record.error_code != "evidence-not-observed"
            or len(record.exchanges) != len(steps) or len(steps) != 2
            or [v.status_code for v in record.exchanges] != [401, 401]
            or any(s.step_id != v.step_id or s.endpoint_id != v.endpoint_id
                   or s.method.value.lower() != v.method.lower()
                   for s, v in zip(steps, record.exchanges, strict=True))
            or impl.evaluate(record.exchanges) != ()
            or evidence.get("run_id") != record.run_id
            or evidence.get("test_id") != record.test_id
            or evidence.get("source_sha256") != a["source_sha256"][
                "dummy_apps/vulnerable_store/app/scenario_routes.py"
            ]
            or evidence.get("approved_trusted_patch_diff_sha256") !=
               "9313f632a7b893090206d8a614401614e8854909671174dbaafd4fa9b0adead1"
            or evidence.get("baseline_registered_receipt_sha256") !=
               "3fda5b18680363736b1be1451407e35f4e5a3080ca3933ae5840ae387bacdd47"
            or evidence.get("patch_applied_to_original_repo") is not False
            or evidence.get("raw_result_sha256") != sha256(data["stdout.raw"]).hexdigest()
            or evidence.get("attestation_sha256") != approval.attestation_sha256
            or evidence.get("registered_evaluator_recomputed") is not True
            or evidence.get("test_completed") is not True
            or evidence.get("exploit_confirmed") is not False
            or evidence.get("research_qualified") is not False
        ):
            raise ReviewBlocked("patched replay evidence mismatch")
        if (
            legitimate.get("http_status") != 200
            or legitimate.get("authenticated") is not True
            or functional.get("search_http") != 200
            or functional.get("document_list_http") != 200
            or functional.get("file_http") != 200
            or functional.get("file_has_expected_public_text") is not True
            or functional.get("official_research") is not False
        ):
            raise ReviewBlocked("patched functional verification missing")
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RuntimeError):
        return result
    result.update(
        status="verified_archived_patched_replay",
        reason_code="registered_exploit_not_observed_after_patch",
        test_id=record.test_id, run_id=record.run_id,
        request_count=record.request_count,
        http_statuses=[v.status_code for v in record.exchanges],
        registered_replay_verified=True, exploit_confirmed=False,
        legitimate_login_verified=True, search_file_verified=True,
    )
    return result


# Frozen development receipts; adding another scenario requires a separate review.
PHASE5_REGISTERED = {
    "xss": (
        "xss-reflection-001", "xss-20261015-r2", "xss",
        (200, 200),
        "546382c5b95df179daa1fdd74ec55b247e510a290056a3a722530c97ae9eacee",
        "sha256:bd79c22d65af5025b36480e91c8cab46c967720ed93b33fa3e37559fd003f189",
        "8d3e4d6d25f810dfe253ff78146a2d92daed4127445d9157a256f965507baee5",
    ),
    "traversal": (
        "path-traversal-private-file-001", "trav-20261015-r2", "path_traversal",
        (200, 403),
        "3e68b72de0aa09110f8f806238b2050b1f3099899ae24cd1b5927b335315ecea",
        "sha256:629cfa75c03a426a5ee64eecf61fc00139e56fe51fe7e8a792aa00ea81939fac",
        "d33aab09fc036abe99a511966e106103a1bf630b18dd577d9a1c5ce540bc6cc1",
    ),
}
_PHASE5_CASE_FIELDS = {
    "replay_dir", "replay_files", "attestation_path", "attestation_sha256",
    "baseline_dir", "baseline_admission_path", "baseline_admission_sha256",
    "baseline_receipt_sha256", "trusted_diff_path", "trusted_diff_sha256",
    "offline_path", "offline_sha256",
}
_PHASE5_REPLAY_FILES = {
    "stdout.raw": 4096, "stderr.raw": 4096, "exit-code.txt": 64,
    "verified-replay.json": 8192,
}


def review_pinned_phase5_replays(
    *, root: Path, approval_path: str | None = None,
    approval_sha256: str | None = None,
) -> dict:
    """Read-only, fail-closed baseline-to-replay verification for XSS and traversal."""
    path = (approval_path if approval_path is not None
            else os.environ.get("FYP_PHASE5_REPLAY_APPROVAL_PATH"))
    digest = (approval_sha256 if approval_sha256 is not None
              else os.environ.get("FYP_PHASE5_REPLAY_APPROVAL_SHA256"))
    answer = {
        "status": "not_configured" if not path and not digest else "blocked",
        "results": {}, "replay_count": 0,
        "scope": "archived_author_development_self_review",
        "model_driven_red_selection_verified": False,
        "patched_docker_functional_verified": False,
        "final_research_qualified": False,
    }
    if not path or not digest:
        return answer
    try:
        if HEX64.fullmatch(digest) is None:
            raise ReviewBlocked("phase5 approval SHA missing")
        manifest = json.loads(_pinned(_external(path, root, directory=False), digest, 16384))
        if (type(manifest) is not dict
                or manifest.get("schema_version") != "sentinel-phase5-patched-replay-display-v1"
                or type(manifest.get("cases")) is not dict
                or set(manifest["cases"]) != set(PHASE5_REGISTERED)):
            raise ReviewBlocked("phase5 approval scope mismatch")
        source = _external(manifest["source_root"], root, directory=True)
        registry = _registry(source)
        implementations = SecurityTestRegistry.default()
        results = {}
        for name, (test_id, run_id, category, statuses, source_sha, image_id, diff_sha) in (
            PHASE5_REGISTERED.items()
        ):
            case = manifest["cases"][name]
            if (type(case) is not dict or set(case) != _PHASE5_CASE_FIELDS
                    or type(case["replay_files"]) is not dict
                    or set(case["replay_files"]) != set(_PHASE5_REPLAY_FILES)):
                raise ReviewBlocked("phase5 replay evidence file set mismatch")
            folder = _external(case["replay_dir"], root, directory=True)
            raw = {
                key: _pinned(folder / key, case["replay_files"][key], limit)
                for key, limit in _PHASE5_REPLAY_FILES.items()
            }
            attestation = json.loads(_pinned(
                _external(case["attestation_path"], root, directory=False),
                case["attestation_sha256"], 16384,
            ))
            diff = _pinned(
                _external(case["trusted_diff_path"], root, directory=False),
                case["trusted_diff_sha256"], 8192,
            )
            offline = json.loads(_pinned(
                _external(case["offline_path"], root, directory=False),
                case["offline_sha256"], 8192,
            ))
            baseline = verify_archived_registered_red(
                source_root=source, dispatch_root=source,
                evidence_dir=_external(case["baseline_dir"], root, directory=True),
                admission_path=_external(case["baseline_admission_path"], root, directory=False),
                admission_sha256=case["baseline_admission_sha256"],
                receipt_sha256=case["baseline_receipt_sha256"],
                registry=registry, implementations=implementations,
            )
            record = TestExecutionResult.model_validate_json(raw["stdout.raw"])
            saved = json.loads(raw["verified-replay.json"])
            a = attestation["results"]
            step_defs = implementations.get(test_id).build_steps()
            if (
                baseline.test_id != test_id or baseline.vulnerability_class != category
                or not baseline.observation.test_completed
                or not baseline.observation.exploit_confirmed
                or sha256(diff).hexdigest() != diff_sha
                or attestation.get("schema_version") !=
                   f"sentinel-patched-{name}-operator-runtime-attestation-v1"
                or attestation.get("checks_passed") is not True
                or attestation.get("error") is not None
                or attestation.get("registered_test_id") != test_id
                or attestation.get("run_id_reserved_not_executed") != run_id
                or attestation.get("replay_executed_by_this_script") is not False
                or a.get("network_internal") is not True
                or a.get("network_attachable") is not False
                or a.get("docker_context") != "default"
                or a.get("patched_image_id") != image_id
                or a.get("baseline_image_id") !=
                   "sha256:2f3d8290709fb13e193075fd2c7f555fc08f959d7d58c899dda74cbb2a6029ea"
                or attestation["source_sha256"].get(
                   "dummy_apps/vulnerable_store/app/scenario_routes.py") != source_sha
                or set(a["containers"]) != {"vulnerable-store", "controlled-executor"}
                or any(c.get("health") != "healthy" or c.get("read_only") is not True
                       or c.get("user") != "10001:10001" or c.get("published_host_ports")
                       or c.get("image_id") != image_id
                       or c.get("deployed_source_sha256") != attestation["source_sha256"]
                       for c in a["containers"].values())
                or raw["stderr.raw"] or raw["exit-code.txt"].strip() != b"0"
                or record.test_id != test_id or record.run_id != run_id
                or record.target_id != "vulnerable-store" or record.attempt_number != 1
                or record.request_count != 2 or not record.completed or record.timed_out
                or record.error_code != "evidence-not-observed" or record.evidence
                or len(step_defs) != len(record.exchanges) or len(step_defs) != 2
                or tuple(x.status_code for x in record.exchanges) != statuses
                or any(step.step_id != x.step_id or step.endpoint_id != x.endpoint_id
                       or step.method.value.lower() != x.method.lower()
                       for step, x in zip(step_defs, record.exchanges, strict=True))
                or implementations.get(test_id).evaluate(record.exchanges) != ()
                or saved.get("raw_stdout_sha256") != sha256(raw["stdout.raw"]).hexdigest()
                or saved.get("operator_attestation_sha256") != case["attestation_sha256"]
                or saved.get("original_baseline_receipt_sha256") !=
                   case["baseline_receipt_sha256"]
                or saved.get("approved_trusted_patch_diff_sha256") != diff_sha
                or saved.get("patched_source_sha256") != source_sha
                or saved.get("registered_evaluator_recomputed") is not True
                or saved.get("exploit_confirmed") is not False
                or saved.get("research_qualified") is not False
                or saved.get("source_repo_modified") is not False
            ):
                raise ReviewBlocked("phase5 replay provenance mismatched")
            if name == "xss":
                if ("<script>fyp_xss_marker()</script>" in record.exchanges[1].body_excerpt
                        or "&lt;script&gt;fyp_xss_marker()&lt;/script&gt;"
                        not in record.exchanges[1].body_excerpt
                        or offline.get("marker_html_escaped") is not True
                        or offline.get("valid_login_status") != 200):
                    raise ReviewBlocked("XSS mitigation or offline functional evidence missing")
            elif ("FYP_SCENARIO_SECRET=" in record.exchanges[1].body_excerpt
                  or "Public scenario guide" not in record.exchanges[0].body_excerpt
                  or offline.get("private_synthetic_marker_blocked") is not True
                  or offline.get("valid_login_http") != 200):
                raise ReviewBlocked("traversal mitigation or offline evidence missing")
            results[name] = {
                "registered_test_id": test_id, "run_id": run_id, "request_count": 2,
                "baseline_exploit_confirmed": True, "patched_exploit_confirmed": False,
                "http_statuses": list(statuses), "registered_replay_verified": True,
                "offline_functional_verified": True,
                "patched_docker_functional_verified": False,
            }
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RuntimeError):
        return answer
    answer.update(status="verified_archived_phase5_replays", results=results, replay_count=2)
    return answer
