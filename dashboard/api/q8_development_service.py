"""Local-only, opt-in Q8/C12 *synthetic development classification* for Sentinel.

No scans, no Red dispatch, no source selection, no remediation or final evaluation.
C12's pinned prompt is loaded from a separately verified external package.
Every prompt/model response is recorded outside the repository before validation.
"""
from __future__ import annotations

import http.client
import json
from hashlib import sha256
from pathlib import Path
from time import monotonic
from typing import Literal

from dashboard.api.operator_service import (
    ROOT,
    OperatorError,
    StrictPayload,
    _call_evidence_directory,
    manager,
)
from services.q8_c12_development_bridge import (
    MODEL_SHA256,
    Q8DevelopmentBlocked,
    archive_gateway_reply,
    classification_receipt,
    classification_request,
)
from services.registered_assessment_plan import AssessmentPlanBlocked, plan_from_model_receipt

C12_EXTERNAL = (
    ROOT.parent / "Q8_C12_Integration_Audit_2026-10-14" / "staging"
    / "C12_Q8_CPU_Hybrid_Integration_2026-10-14"
)
# This is a verified external engineering package, NOT an install into the app.
C12_MANIFEST = "C12_STAGING_MANIFEST.json"
MAX_RESPONSE = 256 * 1024
LOCALIZATION_PROMPT_PROFILE = "q8-localization-v3-ast"



class Q8Demonstration(StrictPayload):
    example: Literal["traversal_private", "xss_escaped", "login_rejected", "ordinary_search"]


def _row(method: str, parameter: str, value: str, response: str, code: int):
    return {"method": method, "parameters": {parameter: value},
            "response_excerpt": response, "status_code": code}


# Observations are hand-authored, not executed HTTP traces, and MUST be displayed
# as synthetic examples. No hidden evaluator labels exist in this registry.
SYNTHETIC_EXAMPLES: dict[str, dict] = {
    "traversal_private": {
        "route": "/path-traversal/read",
        "observations": [
            _row("GET", "path", "manual.txt", "PUBLIC_MANUAL", 200),
            _row("GET", "path", "../private/local.txt", "PRIVATE_LEARNING_FIXTURE", 200),
        ],
    },
    "xss_escaped": {
        "route": "/xss/search",
        "observations": [
            _row("GET", "q", "note", "<p>note</p>", 200),
            _row("GET", "q", "<script>alert(1)</script>",
                 "<p>&lt;script&gt;alert(1)&lt;/script&gt;</p>", 200),
        ],
    },
    "login_rejected": {
        "route": "/sql-injection/login",
        "observations": [
            _row("POST", "username", "student", "Invalid username or password", 401),
            _row("POST", "username", "student' OR '1'='1",
                 "Invalid username or password", 401),
        ],
    },
    "ordinary_search": {
        "route": "/xss/search",
        "observations": [
            _row("GET", "q", "lecture notes", "<p>lecture notes</p>", 200),
            _row("GET", "q", "chapter two", "<p>chapter two</p>", 200),
        ],
    },
}


def _frozen_system(role: Literal["classification", "source_localization"] = "classification") -> str:
    stage = C12_EXTERNAL
    if stage.is_symlink() or not stage.is_dir() or any(part.is_symlink() for part in stage.parents):
        raise OperatorError("Verified external C12 package directory not available")
    manifest_path = stage / C12_MANIFEST
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise OperatorError("C12 package manifest missing")
    manifest = json.loads(manifest_path.read_bytes())
    expected = manifest.get("files")
    if type(expected) is not dict or len(expected) != 14:
        raise OperatorError("C12 manifest count mismatch")
    for relative, entry in expected.items():
        if Path(relative).is_absolute() or ".." in Path(relative).parts:
            raise OperatorError("C12 manifest path invalid")
        file = stage / relative
        if file.is_symlink() or not file.is_file() or (
            file.stat().st_size != entry["bytes"]
            or sha256(file.read_bytes()).hexdigest() != entry["sha256"]
        ):
            raise OperatorError("C12 package integrity mismatch")
    prompt = json.loads((stage / "prompt_contract.json").read_text())
    system = prompt.get(role)
    required = ("two HTTP observations" if role == "classification"
                else "THREE competing route functions")
    if not isinstance(system, str) or required not in system:
        raise OperatorError("C12 frozen prompt contract invalid")
    return system


def development_localization_prompt(source_input: dict) -> str:
    """Versioned development-only refinement; frozen C12 source remains intact."""
    system = _frozen_system("source_localization") + (
        "\nDevelopment-only source-selection v2: choose the exact numbered line "
        "that itself contains the unsafe interpolation or sensitive execution "
        "operation. The start of a multiline statement is also allowed only "
        "when that same executable statement contains the unsafe operation. "
        "Do not select an unrelated line, declaration, or comment. "
        "Keep root_cause at most 160 characters, describing the direct "
        "source issue. Return only the four requested JSON fields. "
        "Never invent source lines."
    )
    payload = json.dumps(source_input, separators=(",", ":"), ensure_ascii=False)
    return (
        "<|im_start|>system\n" + system + "<|im_end|>\n"
        "<|im_start|>user\n" + payload + "<|im_end|>\n"
        "<|im_start|>assistant\n"
    )


def _raw_completion(port: int, prompt: str) -> dict:
    payload = json.dumps(
        {"prompt": prompt, "temperature": 0, "seed": 42, "n_predict": 192,
         "repeat_penalty": 1.0, "stream": False, "cache_prompt": False},
        separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=240)
    try:
        conn.request("POST", "/completion", body=payload,
                     headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        if resp.status != 200:
            raise OperatorError("Pinned local server returned a non-200 response")
        raw = resp.read(MAX_RESPONSE + 1)
        if len(raw) > MAX_RESPONSE:
            raise OperatorError("Local server exceeded the response byte limit")
        parsed = json.loads(raw)
        if type(parsed) is not dict:
            raise OperatorError("Local model server returned invalid JSON")
        return parsed
    finally:
        conn.close()


def q8_development_status() -> dict:
    state = manager.status()
    return {
        "status": "ready" if state.get("state") == "running"
                  and state.get("sha256") == MODEL_SHA256
                  and state.get("filename") == "c08b-nf4-effective-Q8_0.gguf" else "not_ready",
        "scope": "synthetic_development_classification_only",
        "final_research_qualified": False,
        "registered_tests_enabled": False,
        "patch_preparation_enabled": False,
        "source_localization_enabled": False,
        "examples": tuple(SYNTHETIC_EXAMPLES),
    }


def run_q8_development_classification(example: Q8Demonstration) -> dict:
    """One synchronous, bounded inference on the console-managed Q8 server."""
    if manager.probe_busy():
        raise OperatorError("Another model inference is in progress")
    try:
        state = manager.status()
        if (
            state.get("state") != "running"
            or state.get("sha256") != MODEL_SHA256
            or state.get("filename") != "c08b-nf4-effective-Q8_0.gguf"
        ):
            raise OperatorError("Load the verified C08B Q8_0 model before Q8 development checks")
        system = _frozen_system()
        pair = SYNTHETIC_EXAMPLES[example.example]
        req = classification_request(pair)
        user = json.dumps(req["input"], separators=(",", ":"), ensure_ascii=False)
        prompt = (
            "<|im_start|>system\n" + system + "<|im_end|>\n"
            "<|im_start|>user\n" + user + "<|im_end|>\n<|im_start|>assistant\n"
        )
        evidence = _call_evidence_directory()
        archive_gateway_reply(evidence_dir=evidence, filename="q8-input.json",
                              reply=req, project_root=ROOT)
        started = monotonic()
        raw = _raw_completion(state["port"], prompt)
        archive_gateway_reply(evidence_dir=evidence, filename="q8-raw-completion.json",
                              reply=raw, project_root=ROOT)
        if raw.get("truncated") is not False or type(raw.get("content")) is not str:
            raise OperatorError("Q8 output incomplete; see the append-only evidence")
        try:
            result = json.loads(raw["content"])
        except ValueError as exc:
            raise OperatorError("Q8 returned non-JSON output; raw answer preserved") from exc
        reply = {"role": "classification", "result": result, "origin": "q8_0_cpu_model",
                 "executed_tests": False}
        archive_gateway_reply(evidence_dir=evidence, filename="q8-gateway.json",
                              reply=reply, project_root=ROOT)
        try:
            decision = classification_receipt(pair=pair, gateway_reply=reply)
        except Q8DevelopmentBlocked as exc:
            raise OperatorError("Q8 classification failed typed validation; raw answer preserved") from exc
        if manager.status().get("sha256") != MODEL_SHA256:
            raise OperatorError("Model session changed before inference completed")
        try:
            assessment = plan_from_model_receipt(root=ROOT, pair=pair, receipt=decision)
        except AssessmentPlanBlocked as exc:
            raise OperatorError("Trusted target registry rejected the model assessment plan") from exc
        archive_gateway_reply(
            evidence_dir=evidence, filename="q8-assessment-plan.json",
            reply=assessment, project_root=ROOT,
        )
        return {
            "example": example.example,
            "result": decision,
            "assessment_plan": assessment,
            "latency_seconds": round(monotonic() - started, 2),
            "synthetic_observations_only": True,
            "model_not_independently_qualified": True,
            "registered_test_executed": False,
            "source_analysis_authorized": False,
            "patch_prepared": False,
            "evidence_id": evidence.name,
        }
    finally:
        manager.finish_probe()
