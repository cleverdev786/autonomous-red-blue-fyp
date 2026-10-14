"""Localhost-only operator console for the existing registered synthetic FYP lab.

No broad target selection, no arbitrary commands, no arbitrary API URLs. A preview
is not an executed Red attack or an accepted Blue patch. Credentials are never saved.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from threading import Lock
from time import monotonic

import httpx
from pydantic import BaseModel, ConfigDict, Field

from orchestrator.limits import RunLimitTracker
from orchestrator.policy_engine import PolicyEngine
from schemas.blue_team import BlueTeamAnalysisResult, CodeFinding, SourceLineRange, TriageResult
from schemas.common import ClassificationLabel, WorkflowState
from schemas.experiments import ClassificationMode, ExperimentLimits
from services.audit_service import AuditService
from services.target_registry import TargetRegistry
from services.trusted_remediation_compiler import SOURCE, TARGET, TrustedRemediationCompiler

ROOT = Path(__file__).resolve().parents[2]
API_PROVIDERS: dict[str, str] = {
    "openai": "https://api.openai.com/v1/chat/completions",
    "groq": "https://api.groq.com/openai/v1/chat/completions",
    "together": "https://api.together.xyz/v1/chat/completions",
}
MAX_RESPONSE = 256 * 1024
MODEL_ID = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._:/+\-]{0,127}$")


class OperatorError(ValueError):
    pass


class StrictPayload(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class LocalStart(StrictPayload):
    filename: str = Field(min_length=5, max_length=180)
    model_name: str = Field(min_length=1, max_length=128)


class ProbeRequest(StrictPayload):
    source: str = Field(pattern=r"^(local|api)$")
    model_name: str = Field(min_length=1, max_length=128)
    provider: str = "openai"
    api_key: str | None = Field(default=None, max_length=2048, repr=False)


class DemoRequest(StrictPayload):
    scenario: str = Field(pattern=r"^(sql|xss|traversal)$")


class ConsoleCapabilityDecision(StrictPayload):
    """Synthetic structural screening, never a final-research output schema."""

    classification: ClassificationLabel
    confidence: float = Field(ge=0, le=1)
    file_path: str | None = None
    function_or_route: str | None = None
    registered_test_id: str | None = None
    no_action: bool
    reason: str = Field(min_length=1, max_length=1000)


SCENARIOS = {
    "sql": {
        "title": "SQL injection",
        "test_id": "sqli-login-bypass-001",
        "scenario_id": "sqli-login-001",
        "label": ClassificationLabel.SQL_INJECTION,
        "function": "vulnerable_login",
        "line": 48,
        "vector": "Unsafe interpolation in a login query",
        "remediation": "Named SQL parameters",
    },
    "xss": {
        "title": "Cross-site scripting",
        "test_id": "xss-reflection-001",
        "scenario_id": "xss-search-001",
        "label": ClassificationLabel.XSS,
        "function": "vulnerable_search",
        "line": 84,
        "vector": "Unescaped search-term reflection",
        "remediation": "HTML text-context escaping",
    },
    "traversal": {
        "title": "Path traversal",
        "test_id": "path-traversal-private-file-001",
        "scenario_id": "path-traversal-read-001",
        "label": ClassificationLabel.PATH_TRAVERSAL,
        "function": "vulnerable_file_read",
        "line": 102,
        "vector": "Unsafe public-root containment",
        "remediation": "Canonical public-root containment",
    },
}


def _hash(path: Path) -> str:
    hasher = sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _mem_available() -> int | None:
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError):
        pass
    return None


def _checked_local_path(directory: Path, filename: str) -> Path:
    if filename != Path(filename).name or not filename.lower().endswith(".gguf"):
        raise OperatorError("Select a listed GGUF filename; paths are not accepted")
    if directory.is_symlink() or any(part.is_symlink() for part in directory.parents):
        raise OperatorError("Model directory cannot contain symlinks")
    path = directory / filename
    if path.is_symlink() or not path.is_file() or path.resolve().parent != directory.resolve():
        raise OperatorError("Model file must be a regular file within the configured directory")
    return path


def _reject_bad_name(name: str) -> None:
    if not MODEL_ID.fullmatch(name):
        raise OperatorError(
            "Model name must be 1–128 characters using letters, digits, . _ : / + or -"
        )


def _no_external_redirects() -> httpx.AsyncClient:
    return httpx.AsyncClient(
        follow_redirects=False, trust_env=False, timeout=httpx.Timeout(28.0, connect=5.0)
    )


def _call_evidence_directory() -> Path:
    """Create a private, unique run directory outside the project source."""
    default = Path.home() / ".local/state/sentinel-fyp/capability-evidence"
    parent = Path(os.environ.get("FYP_CONSOLE_EVIDENCE_DIR", str(default))).expanduser()
    root = ROOT.resolve()
    resolved = parent.resolve(strict=False)
    if parent.is_symlink() or resolved == root or root in resolved.parents:
        raise OperatorError("Capability evidence must be outside the protected repository")
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    output = parent / ("probe-" + secrets.token_hex(8))
    output.mkdir(mode=0o700)
    return output


def _save_once(path: Path, content: bytes) -> None:
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())


@dataclass
class Session:
    process: subprocess.Popen[bytes]
    logfile: object
    filename: str
    model_name: str
    sha256: str
    scope: str
    port: int


class ModelManager:
    """One resource-constrained local model instance; no shell string interpolation."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._session: Session | None = None
        self._probe_lock = Lock()

    @staticmethod
    def directory() -> Path | None:
        val = os.environ.get("FYP_MODEL_DIRECTORY")
        return Path(val).expanduser() if val else None

    def list_local(self) -> list[dict]:
        directory = self.directory()
        if directory is None or not directory.is_dir() or directory.is_symlink():
            return []
        results = []
        for path in sorted(directory.glob("*.gguf"))[:30]:
            if path.is_file() and not path.is_symlink():
                results.append({"filename": path.name, "bytes": path.stat().st_size})
        return results

    def status(self) -> dict:
        with self._lock:
            session = self._session
            if session is None:
                return {"state": "unloaded", "final_research_ready": False}
            live = session.process.poll() is None
            ready = False
            if live:
                try:
                    with socket.create_connection(("127.0.0.1", session.port), timeout=0.35):
                        ready = True
                except OSError:
                    pass
            return {
                "state": ("running" if ready else "starting") if live else "stopped",
                "model_name": session.model_name,
                "filename": session.filename,
                "sha256": session.sha256,
                "port": session.port,
                "concurrency": 1,
                "context_tokens": 1536,
                "final_research_ready": False,
            }

    def start(self, data: LocalStart) -> dict:
        _reject_bad_name(data.model_name)
        directory = self.directory()
        if directory is None:
            raise OperatorError("Set FYP_MODEL_DIRECTORY to a folder of approved local GGUF files")
        model = _checked_local_path(directory, data.filename)
        binary_env = os.environ.get("FYP_LLAMA_SERVER_BIN")
        if not binary_env:
            raise OperatorError("Set FYP_LLAMA_SERVER_BIN to the pinned llama.cpp server")
        binary = Path(binary_env).expanduser()
        if binary.is_symlink() or not binary.is_file() or not os.access(binary, os.X_OK):
            raise OperatorError("Pinned llama.cpp binary is not an executable regular file")
        available = _mem_available()
        # A fixed 3.4 GiB memory scope cannot safely host GGUF weights larger than
        # its own bound. Never let the kernel discover this via an OOM kill.
        if model.stat().st_size + 750 * 1024 * 1024 > 3400 * 1024 * 1024:
            raise OperatorError("Model exceeds the conservative local 3.4 GiB memory budget")
        if available is None or available < model.stat().st_size + 900 * 1024 * 1024:
            raise OperatorError(
                "Insufficient verified free RAM: keep at least 900 MiB beyond model size"
            )
        if shutil.which("systemd-run") is None or shutil.which("systemctl") is None:
            raise OperatorError("Memory-limited systemd user scopes are required for local loading")
        port = int(os.environ.get("FYP_LOCAL_MODEL_PORT", "18083"))
        if not 1024 <= port <= 65535:
            raise OperatorError("Invalid configured local model port")
        with self._lock:
            if self._session is not None:
                raise OperatorError("Stop the previous model session before loading another")
            # No DNS or port hopping: only a dedicated loopback port.
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                if s.connect_ex(("127.0.0.1", port)) == 0:
                    raise OperatorError("The configured local model port is occupied")
            model_sha = _hash(model)
            scope = "fyp-console-model-" + secrets.token_hex(6)
            # This session-scoped log is explicitly closed in ModelManager.stop().
            log = tempfile.TemporaryFile(mode="w+b")  # noqa: SIM115
            args = [
                "systemd-run",
                "--user",
                "--scope",
                "--quiet",
                "--unit",
                scope,
                "-p",
                "MemoryMax=3400M",
                "-p",
                "MemorySwapMax=512M",
                "-p",
                "TasksMax=80",
                str(binary),
                "--model",
                str(model),
                "--host",
                "127.0.0.1",
                "--port",
                str(port),
                "--alias",
                data.model_name,
                "--ctx-size",
                "1536",
                "--parallel",
                "1",
                "--batch-size",
                "64",
                "--ubatch-size",
                "16",
                "--threads",
                "2",
                "--threads-batch",
                "2",
                "--n-gpu-layers",
                "0",
                "--no-warmup",
            ]
            try:
                process = subprocess.Popen(
                    args,
                    stdin=subprocess.DEVNULL,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
            except OSError as exc:
                log.close()
                raise OperatorError("Could not start the controlled local model server") from exc
            self._session = Session(
                process, log, model.name, data.model_name, model_sha, scope, port
            )
        return self.status()

    def stop(self) -> dict:
        with self._lock:
            session = self._session
            self._session = None
        if session is not None:
            subprocess.run(
                ["systemctl", "--user", "stop", session.scope + ".scope"],
                capture_output=True,
                timeout=15,
                check=False,
            )
            if session.process.poll() is None:
                session.process.terminate()
                try:
                    session.process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    session.process.kill()
                    session.process.wait(timeout=5)
            session.logfile.close()
        return {"state": "unloaded", "final_research_ready": False}

    def probe_busy(self) -> bool:
        return not self._probe_lock.acquire(blocking=False)

    def finish_probe(self) -> None:
        self._probe_lock.release()


manager = ModelManager()


async def probe_capability(data: ProbeRequest) -> dict:
    """Four sequential synthetic capability cases; strictly not a final qualification."""
    _reject_bad_name(data.model_name)
    if manager.probe_busy():
        raise OperatorError("Another capability check is already in progress")
    try:
        if data.source == "local":
            state = manager.status()
            if state["state"] != "running" or state.get("model_name") != data.model_name:
                raise OperatorError("Load and wait for the selected local model first")
            uri = f"http://127.0.0.1:{state['port']}/v1/chat/completions"
            key = None
        else:
            if data.provider not in API_PROVIDERS:
                raise OperatorError("Select an approved API provider")
            key = data.api_key
            if not key or not key.strip():
                raise OperatorError("An API key is required and is used only for this request")
            uri = API_PROVIDERS[data.provider]
        evidence = _call_evidence_directory()
        schema = ConsoleCapabilityDecision.model_json_schema()
        trials = (
            (
                "SQL injection",
                "A synthetic local login endpoint formed a SQL query by interpolating untrusted username input, resulting in unauthorized authentication.",
                "sql_injection",
                "vulnerable_login",
                "sqli-login-bypass-001",
                False,
            ),
            (
                "Cross-site scripting",
                "A synthetic search route rendered user-provided text directly into its HTML response without escaping.",
                "xss",
                "vulnerable_search",
                "xss-reflection-001",
                False,
            ),
            (
                "Path traversal",
                "A synthetic public document endpoint allowed a resolved file path to escape its intended public directory.",
                "path_traversal",
                "vulnerable_file_read",
                "path-traversal-private-file-001",
                False,
            ),
            (
                "Benign restraint",
                "A synthetic health endpoint returned 200 OK with a normal heartbeat and no attack signals.",
                "benign",
                None,
                None,
                True,
            ),
        )
        system = (
            "Classify synthetic observations only. Output exact JSON matching the supplied schema. "
            "For security findings use source file dummy_apps/vulnerable_store/app/scenario_routes.py, "
            "choose the likely vulnerable function name and only one registered test ID from: "
            "sqli-login-bypass-001, xss-reflection-001, path-traversal-private-file-001. "
            "For benign events, return no_action true and null for file_path, function_or_route and registered_test_id. "
            "Never request a tool, run an attack, edit files, or claim verification."
        )
        results = []
        async with _no_external_redirects() as client:
            for call_index, (name, event, expected, function, test_id, no_action) in enumerate(
                trials, 1
            ):
                payload = {
                    "model": data.model_name,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": event},
                    ],
                    "temperature": 0,
                    "max_tokens": 280,
                    "stream": False,
                    "response_format": {
                        "type": "json_schema",
                        "json_schema": {
                            "name": "synthetic_capability",
                            "schema": schema,
                            "strict": True,
                        },
                    },
                }
                if data.source == "local":
                    payload["top_k"] = 20
                request_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
                prefix = f"call-{call_index:02d}"
                _save_once(evidence / f"{prefix}-request.json", request_bytes)
                received = b""
                http_status = None
                usage = None
                started = monotonic()
                failure = None
                try:
                    async with client.stream(
                        "POST",
                        uri,
                        content=request_bytes,
                        headers={
                            "Content-Type": "application/json",
                            **({"Authorization": f"Bearer {key}"} if key else {}),
                        },
                    ) as response:
                        http_status = response.status_code
                        chunks = bytearray()
                        async for chunk in response.aiter_bytes():
                            space = MAX_RESPONSE + 1 - len(chunks)
                            chunks.extend(chunk[:space])
                            if len(chunks) > MAX_RESPONSE:
                                raise OperatorError(
                                    "Model provider response exceeds the fixed 256 KiB limit"
                                )
                        received = bytes(chunks)
                    if http_status != 200:
                        raise OperatorError(f"Model provider returned HTTP {http_status}")
                    envelope = json.loads(received)
                    if isinstance(envelope.get("usage"), dict):
                        raw_usage = envelope["usage"]
                        if (
                            type(raw_usage.get("prompt_tokens")) is int
                            and type(raw_usage.get("completion_tokens")) is int
                            and raw_usage["prompt_tokens"] >= 0
                            and raw_usage["completion_tokens"] >= 0
                        ):
                            usage = {
                                "input_tokens": raw_usage["prompt_tokens"],
                                "output_tokens": raw_usage["completion_tokens"],
                            }
                    choice = envelope["choices"][0]
                    if choice.get("finish_reason") != "stop" or choice["message"].get("tool_calls"):
                        raise OperatorError(
                            "Model completion was incomplete or included a tool call"
                        )
                    decision = ConsoleCapabilityDecision.model_validate_json(
                        choice["message"]["content"]
                    )
                    right = (
                        decision.classification.value == expected
                        and decision.no_action is no_action
                        and decision.function_or_route == function
                        and decision.registered_test_id == test_id
                        and (
                            decision.file_path == SOURCE if function else decision.file_path is None
                        )
                    )
                    results.append(
                        {
                            "case": name,
                            "status": "pass" if right else "fail",
                            "classification": decision.classification.value,
                            "confidence": decision.confidence,
                            "expected": expected,
                            "function_or_route": decision.function_or_route,
                            "registered_test_id": decision.registered_test_id,
                            "no_action": decision.no_action,
                        }
                    )
                except (httpx.HTTPError, ValueError, KeyError, IndexError, TypeError) as exc:
                    failure = type(exc).__name__ if not isinstance(exc, OperatorError) else str(exc)
                    results.append(
                        {
                            "case": name,
                            "status": "fail",
                            "classification": None,
                            "expected": expected,
                            "reason": failure,
                        }
                    )
                finally:
                    _save_once(evidence / f"{prefix}-response.raw", received)
                    receipt = {
                        "case": name,
                        "model_name": data.model_name,
                        "source": data.source,
                        "api_provider": data.provider if data.source == "api" else None,
                        "request_sha256": sha256(request_bytes).hexdigest(),
                        "response_sha256": sha256(received).hexdigest(),
                        "response_bytes": len(received),
                        "http_status": http_status,
                        "latency_ms": round((monotonic() - started) * 1000),
                        "usage": usage,
                        "usage_status": "REPORTED" if usage else "NOT_REPORTED",
                        "schema_and_expected_behavior": results[-1]["status"],
                        "failure": failure,
                        "timestamp_utc": datetime.now(UTC).isoformat(),
                        "final_research": False,
                        "automatic_retries": 0,
                    }
                    _save_once(
                        evidence / f"{prefix}-receipt.json",
                        (json.dumps(receipt, sort_keys=True) + "\n").encode(),
                    )
        return {
            "model_name": data.model_name,
            "source": data.source,
            "results": results,
            "capable_for_demo": len(results) == 4 and all(x["status"] == "pass" for x in results),
            "final_research_eligible": False,
            "evidence_directory": str(evidence),
            "note": "Four development capability screens, not an independent M20 or final RQ1/RQ2 qualification.",
        }
    finally:
        manager.finish_probe()


def scenario_catalog() -> list[dict]:
    return [
        {
            "id": key,
            "title": value["title"],
            "scenario_id": value["scenario_id"],
            "registered_test": value["test_id"],
            "vector": value["vector"],
            "remediation": value["remediation"],
        }
        for key, value in SCENARIOS.items()
    ]


def prepare_preview(scenario: str) -> dict:
    """Actually invoke existing trusted compiler in an ephemeral copy, never apply."""
    desc = SCENARIOS.get(scenario)
    if desc is None:
        raise OperatorError("Only three registered synthetic scenarios are supported")
    run_id = "console-preview-" + secrets.token_hex(6)
    with tempfile.TemporaryDirectory(prefix="fyp-console-preview-") as temporary:
        temp = Path(temporary)
        # The existing registry/policy/source-reader are used unchanged.
        shutil.copytree(ROOT / "config", temp / "config")
        dst = temp / SOURCE
        dst.parent.mkdir(parents=True)
        shutil.copy2(ROOT / SOURCE, dst)
        registry = TargetRegistry.from_directories(
            targets_dir=temp / "config" / "targets",
            security_tests_dir=temp / "config" / "security_tests",
        )
        audit = AuditService(project_root=temp)
        compiler = TrustedRemediationCompiler(
            project_root=temp,
            registry=registry,
            policy_engine=PolicyEngine(registry=registry, project_root=temp),
            audit_service=audit,
        )
        analysis = BlueTeamAnalysisResult(
            run_id=run_id,
            target_id=TARGET,
            classification_mode=ClassificationMode.HYBRID,
            triage=TriageResult(
                run_id=run_id,
                is_suspicious=True,
                classification=desc["label"],
                confidence=1.0,
                reason="Trusted scenario mapping, not a model-generated claim",
            ),
            code_finding=CodeFinding(
                run_id=run_id,
                file_path=SOURCE,
                function_or_route=desc["function"],
                root_cause=desc["vector"],
                supporting_lines=(SourceLineRange(start_line=desc["line"], end_line=desc["line"]),),
                confidence=1.0,
            ),
            final_state=WorkflowState.CODE_ANALYSIS,
        )
        result = compiler.prepare(
            analysis=analysis, attempt_number=1, limits=RunLimitTracker(ExperimentLimits())
        )
        patch = result.generation.prepared_patch if result.generation else None
        return {
            "run_id": run_id,
            "scenario": scenario,
            "title": desc["title"],
            "registered_test_id": desc["test_id"],
            "steps": [
                {"name": "Target policy", "status": "checked", "detail": TARGET},
                {"name": "Registered Red scenario", "status": "mapped", "detail": desc["test_id"]},
                {"name": "Blue triage", "status": "trusted fixture", "detail": desc["label"].value},
                {"name": "Code localization", "status": "matched", "detail": desc["function"]},
                {
                    "name": "Trusted patch compiler",
                    "status": result.provenance.status,
                    "detail": result.provenance.reason_code,
                },
                {
                    "name": "Registered replay",
                    "status": "not executed",
                    "detail": "Requires isolated, authorized Docker verification",
                },
            ],
            "prepared": patch is not None,
            "prepared_diff_sha256": patch.diff_sha256 if patch else None,
            "diff_preview": patch.unified_diff[:5000] if patch else None,
            "source_sha256": result.provenance.source_sha256,
            "applied": False,
            "verified": False,
            "final_research": False,
            "notice": "Real trusted compiler output. This is a non-mutating preview, NOT a security replay or an accepted patch.",
        }
