"""Explicit-admission, bounded real isolated Docker registered-test seam.

This module does NOT run at import, does not start/build/stop containers and
cannot authorize itself. An external independently reviewed, hash-pinned
admission is required before a caller can trigger its sole registered replay.
No final research status is conferred by this developmental collector.
"""
from __future__ import annotations

import json
import os
import re
import selectors
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from schemas.registered_red_observation import REGISTERED, observe_registered_result
from security_tests.registry import SecurityTestRegistry
from services.isolated_compose_mock_adapter import (
    APP_CONTAINER,
    EXECUTOR_CONTAINER,
    IMAGE,
    ISOLATED_COMPOSE,
    NETWORK,
    ORIGINAL_ROUTES_SHA256,
    PROJECT,
    VOLUME,
    verify_isolation_yaml,
)
from services.target_registry import TargetRegistry

HEX40 = r"^[0-9a-f]{40}$"
HEX64 = r"^[0-9a-f]{64}$"
CASE_ID = r"^[a-z][a-z0-9_-]{0,47}$"
MAX_OUTPUT = 65536
MAX_INSPECT = 131072
TIMEOUT = 180

# All are within the trusted Docker build COPY directories.
CONTAINER_FILES = (
    "dummy_apps/vulnerable_store/app/scenario_routes.py",
    "infrastructure/executor/run_verification_test.py",
    "services/controlled_executor.py",
    "config/targets/vulnerable-store.json",
    "config/security_tests/sqli-login-bypass-001.json",
    "config/security_tests/xss-reflection-001.json",
    "config/security_tests/path-traversal-private-file-001.json",
    "security_tests/sql_injection/login_bypass.py",
    "security_tests/xss/reflection.py",
    "security_tests/path_traversal/private_file.py",
)
HOST_FILES = CONTAINER_FILES + (
    "compose.yaml", ISOLATED_COMPOSE, "dummy_apps/vulnerable_store/Dockerfile",
    "config/verification-policy.json", "pyproject.toml",
)


class IsolatedExecutionBlocked(RuntimeError):
    """An admission, identity, provenance, or bounded execution gate failed."""


class RealExecutionAdmission(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["isolated-registered-live-admission-v1"] = "isolated-registered-live-admission-v1"
    purpose: Literal["development_registered_observation"] = "development_registered_observation"
    final_evaluation: Literal[False] = False
    allow_single_registered_execution: Literal[True] = True
    context: Literal["default"] = "default"
    source_branch: Literal["development"] = "development"
    source_head: str = Field(pattern=HEX40)
    source_tree: str = Field(pattern=HEX40)
    source_hashes: dict[str, str]
    daemon_id: str = Field(min_length=1, max_length=128)
    image_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    app_container_id: str = Field(pattern=HEX64)
    executor_container_id: str = Field(pattern=HEX64)
    run_id: str = Field(pattern=CASE_ID)
    case_id: str = Field(pattern=CASE_ID)
    scenario_id: Literal["sqli-login-001", "xss-search-001", "path-traversal-read-001"]
    attempt_number: Literal[1] = 1

    @model_validator(mode="after")
    def check_identifiers(self):
        if set(self.source_hashes) != set(HOST_FILES):
            raise ValueError("complete exact source manifest required")
        if any(re.fullmatch(HEX64, value) is None for value in self.source_hashes.values()):
            raise ValueError("source manifest contains invalid SHA256")
        if self.source_hashes[CONTAINER_FILES[0]] != ORIGINAL_ROUTES_SHA256:
            raise ValueError("frozen vulnerable source digest changed")
        if self.app_container_id == self.executor_container_id:
            raise ValueError("app and executor cannot be the same container")
        return self

    def canonical_bytes(self) -> bytes:
        return (json.dumps(self.model_dump(mode="json"), sort_keys=True, separators=(",", ":")) + "\n").encode()


def load_real_admission(root: Path, path: Path, external_sha256: str) -> RealExecutionAdmission:
    """Hash must come from outside this repository and NOT be self-discovered."""
    root = root.resolve(strict=True)
    if (not re.fullmatch(HEX64, external_sha256) or not path.is_absolute()
            or not path.is_file() or path.is_symlink()):
        raise IsolatedExecutionBlocked("independent external admission required")
    resolved_manifest = path.resolve(strict=True)
    if resolved_manifest == root or root in resolved_manifest.parents:
        raise IsolatedExecutionBlocked("external admission resolves inside source")
    raw = path.read_bytes()
    if len(raw) > 8192 or sha256(raw).hexdigest() != external_sha256:
        raise IsolatedExecutionBlocked("external admission digest mismatch")
    try:
        admission = RealExecutionAdmission.model_validate_json(raw)
    except Exception as exc:
        raise IsolatedExecutionBlocked("invalid admission schema") from exc
    if admission.canonical_bytes() != raw:
        raise IsolatedExecutionBlocked("admission not canonical")
    return admission


@dataclass(frozen=True, slots=True)
class BinaryResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool = False


Runner = Callable[[tuple[str, ...], Path], BinaryResult]


def run_local_binary(argv: tuple[str, ...], cwd: Path) -> BinaryResult:
    """Execute one fixed-argv command with bounded live output and a hard timeout.

    Linux/POSIX binary-pipe reader. No shell, retries, Docker startup, or
    inferred permission. A future caller must separately authorize dispatch.
    """
    timeout = TIMEOUT if "infrastructure.executor.run_verification_test" in argv else 30
    stdout = bytearray()
    stderr = bytearray()
    with subprocess.Popen(
        argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False,
    ) as proc:
        try:
            if proc.stdout is None or proc.stderr is None:
                raise IsolatedExecutionBlocked("subprocess stream unavailable")
            with selectors.DefaultSelector() as selector:
                for stream, target in ((proc.stdout, stdout), (proc.stderr, stderr)):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, target)
                deadline = time.monotonic() + timeout
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(argv, timeout)
                    for key, _ in selector.select(remaining):
                        target = key.data
                        limit = MAX_INSPECT if target is stdout else MAX_OUTPUT
                        chunk = os.read(key.fileobj.fileno(), 8192)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        target.extend(chunk[: max(0, limit + 1 - len(target))])
                        if len(target) > limit:
                            raise IsolatedExecutionBlocked("live process output exceeded hard limit")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(argv, timeout)
                returncode = proc.wait(timeout=remaining)
                return BinaryResult(returncode, bytes(stdout), bytes(stderr))
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            return BinaryResult(-1, bytes(stdout), bytes(stderr), True)
        except BaseException:
            proc.kill()
            proc.wait()
            raise


class RealExecutionReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["isolated-registered-execution-v1"] = "isolated-registered-execution-v1"
    scope: Literal["development_only_not_final_research"] = "development_only_not_final_research"
    model_calls: Literal[0] = 0
    agent_red_plan_authored: Literal[False] = False
    case_id: str
    run_id: str
    scenario_id: str
    source_head: str
    source_tree: str
    daemon_id: str
    image_id: str
    app_container_id: str
    executor_container_id: str
    admission_sha256: str
    dispatch_argv: tuple[str, ...]
    stdout_sha256: str
    stderr_sha256: str
    returncode: int
    timed_out: bool
    outcome: Literal[
        "baseline_exploit_confirmed", "baseline_exploit_not_observed",
        "inconclusive", "executor_failed", "provenance_failed",
    ]
    reason: str
    observation_sha256: str | None = None


class IsolatedDockerExecutor:
    """Real command seam gated by external identity pins and frozen operations."""

    def __init__(self, *, source_root: Path, evidence_root: Path,
                 admission_path: Path, admission_sha256: str,
                 registry: TargetRegistry, implementations: SecurityTestRegistry,
                 runner: Runner = run_local_binary):
        if not source_root.is_dir() or source_root.is_symlink():
            raise IsolatedExecutionBlocked("invalid source checkout")
        self.root = source_root.resolve(strict=True)
        if (not evidence_root.is_dir() or evidence_root.is_symlink()
                or evidence_root.resolve(strict=True) == self.root
                or self.root in evidence_root.resolve(strict=True).parents):
            raise IsolatedExecutionBlocked("evidence parent must be external")
        self.evidence = evidence_root.resolve(strict=True)
        self.path = admission_path
        self.digest = admission_sha256
        self.pin = load_real_admission(self.root, admission_path, admission_sha256)
        self.registry = registry
        self.implementations = implementations
        self.runner = runner

    def _run(self, argv: tuple[str, ...], *, inspect: bool = False) -> BinaryResult:
        response = self.runner(argv, self.root)
        max_bytes = MAX_INSPECT if inspect else MAX_OUTPUT
        if (not isinstance(response, BinaryResult) or type(response.returncode) is not int
                or type(response.stdout) is not bytes or type(response.stderr) is not bytes
                or type(response.timed_out) is not bool):
            raise IsolatedExecutionBlocked("runner returned malformed binary response")
        if len(response.stdout) > max_bytes or len(response.stderr) > MAX_OUTPUT:
            raise IsolatedExecutionBlocked("process stream exceeded hard bound")
        if response.timed_out or response.returncode != 0:
            raise IsolatedExecutionBlocked("trusted command failed or timed out")
        return response

    def _docker(self, *args: str) -> tuple[str, ...]:
        return ("docker", "--context", self.pin.context, *args)

    def _compose(self, *args: str) -> tuple[str, ...]:
        return self._docker("compose", "-f", str(self.root / ISOLATED_COMPOSE),
                            "--project-directory", str(self.root), *args)

    def _source_snapshot(self) -> dict:
        # The full Git clean identity is mandatory. Uncommitted implementation
        # from Gate 2 must be separately reviewed/committed before any live gate.
        commands = {
            "head": ("git", "-C", str(self.root), "rev-parse", "HEAD"),
            "tree": ("git", "-C", str(self.root), "rev-parse", "HEAD^{tree}"),
            "branch": ("git", "-C", str(self.root), "symbolic-ref", "--short", "HEAD"),
            "status": ("git", "-C", str(self.root), "--no-optional-locks",
                       "status", "--porcelain=v1", "--untracked-files=all"),
        }
        got = {key: self._run(cmd).stdout.decode("utf-8").strip()
               for key, cmd in commands.items()}
        if (got["head"] != self.pin.source_head or got["tree"] != self.pin.source_tree
                or got["branch"] != self.pin.source_branch or got["status"]):
            raise IsolatedExecutionBlocked("Git HEAD/tree/branch or cleanliness drift")
        for relative, digest in self.pin.source_hashes.items():
            path = self.root / relative
            if (path.is_symlink() or not path.is_file()
                    or sha256(path.read_bytes()).hexdigest() != digest):
                raise IsolatedExecutionBlocked("source hash drift: " + relative)
        verify_isolation_yaml(self.root)
        return got

    @staticmethod
    def _parse_object(raw: bytes) -> dict:
        value = json.loads(raw)
        if type(value) is not dict:
            raise IsolatedExecutionBlocked("Docker JSON object expected")
        return value

    def _container(self, name: str, service: str, network_id: str) -> dict:
        c = self._parse_object(self._run(self._docker(
            "container", "inspect", "--format", "{{json .}}", name), inspect=True).stdout)
        expected_id = (self.pin.app_container_id if service == "vulnerable-store"
                       else self.pin.executor_container_id)
        labels = c.get("Config", {}).get("Labels") or {}
        state = c.get("State") or {}
        host = c.get("HostConfig") or {}
        networks = c.get("NetworkSettings", {}).get("Networks") or {}
        if (c.get("Id") != expected_id or c.get("Image") != self.pin.image_id
                or c.get("Config", {}).get("Image") != IMAGE
                or labels.get("com.docker.compose.project") != PROJECT
                or labels.get("com.docker.compose.service") != service
                or not state.get("Running") or state.get("Health", {}).get("Status") != "healthy"
                or not host.get("ReadonlyRootfs") or host.get("Privileged") is not False
                or "ALL" not in (host.get("CapDrop") or [])
                or "no-new-privileges:true" not in (host.get("SecurityOpt") or [])
                or set(networks) != {NETWORK}
                or networks[NETWORK].get("NetworkID") != network_id
                or c.get("Config", {}).get("User") != "10001:10001"
                or host.get("NanoCpus") != (500000000 if service == "vulnerable-store" else 250000000)
                or host.get("Memory") != (268435456 if service == "vulnerable-store" else 134217728)
                or host.get("PidsLimit") != (128 if service == "vulnerable-store" else 64)):
            raise IsolatedExecutionBlocked("container identity, state, or isolation mismatch")
        mounts = c.get("Mounts") or []
        if service == "vulnerable-store":
            if len(mounts) != 1 or any(
                item.get("Type") != "volume" or item.get("Name") != VOLUME
                or item.get("Destination") != "/runtime" for item in mounts
            ):
                raise IsolatedExecutionBlocked("application runtime volume ownership mismatch")
        elif mounts:
            raise IsolatedExecutionBlocked("executor has an unexpected mounted volume")
        ports = host.get("PortBindings") or {}
        if service == "vulnerable-store":
            if ports != {"8000/tcp": [{"HostIp": "127.0.0.1", "HostPort": "18080"}]}:
                raise IsolatedExecutionBlocked("application host port binding mismatch")
        elif ports:
            raise IsolatedExecutionBlocked("executor exposes a host port")
        return {"id": c["Id"], "image": c["Image"], "network": NETWORK,
                "service": service, "healthy": True}

    def _container_source(self, service: str) -> None:
        argv = self._compose("exec", "-T", service, "sha256sum",
                             *(f"/workspace/{rel}" for rel in CONTAINER_FILES))
        output = self._run(argv).stdout.decode("ascii").splitlines()
        expected = {f"/workspace/{rel}": self.pin.source_hashes[rel]
                    for rel in CONTAINER_FILES}
        observed: dict[str, str] = {}
        for line in output:
            parts = line.split("  ", 1)
            if len(parts) != 2 or parts[1] in observed:
                raise IsolatedExecutionBlocked("malformed in-container source hash")
            observed[parts[1]] = parts[0]
        if observed != expected:
            raise IsolatedExecutionBlocked("deployed source bytes do not match approved checkout")

    def _runtime_snapshot(self) -> dict:
        context = self._run(("docker", "context", "show")).stdout.decode().strip()
        info = self._parse_object(self._run(self._docker(
            "info", "--format", "{{json .}}"), inspect=True).stdout)
        normalized = self._parse_object(self._run(self._compose(
            "config", "--format", "json"), inspect=True).stdout)
        network = self._parse_object(self._run(self._docker(
            "network", "inspect", "--format", "{{json .}}", NETWORK), inspect=True).stdout)
        image = self._parse_object(self._run(self._docker(
            "image", "inspect", "--format", "{{json .}}", IMAGE), inspect=True).stdout)
        volume = self._parse_object(self._run(self._docker(
            "volume", "inspect", "--format", "{{json .}}", VOLUME), inspect=True).stdout)
        services = normalized.get("services", {})
        app, executor = services.get("vulnerable-store", {}), services.get("controlled-executor", {})
        if (context != self.pin.context or info.get("ID") != self.pin.daemon_id
                or image.get("Id") != self.pin.image_id
                or image.get("Config", {}).get("Labels", {}).get("com.docker.compose.project") != PROJECT
                or volume.get("Name") != VOLUME or volume.get("Driver") != "local"
                or volume.get("Labels", {}).get("com.docker.compose.project") != PROJECT
                or not volume.get("Mountpoint")
                or normalized.get("name") != PROJECT or set(services) != {"vulnerable-store", "controlled-executor"}
                or normalized.get("networks", {}).get("security-lab", {}).get("name") != NETWORK
                or normalized.get("volumes", {}).get("store-runtime", {}).get("name") != VOLUME
                or network.get("Name") != NETWORK or network.get("Driver") != "bridge"
                or network.get("Internal") is not True
                or network.get("Attachable") is not False
                or network.get("Options", {}).get(
                    "com.docker.network.bridge.host_binding_ipv4") != "127.0.0.1"
                or network.get("Labels", {}).get("com.docker.compose.project") != PROJECT
                or set((network.get("Containers") or {}).keys())
                    != {self.pin.app_container_id, self.pin.executor_container_id}
                or app.get("image") != IMAGE or executor.get("image") != IMAGE
                or app.get("container_name") != APP_CONTAINER
                or executor.get("container_name") != EXECUTOR_CONTAINER
                or app.get("ports") != [{"host_ip": "127.0.0.1", "mode": "ingress",
                                         "protocol": "tcp", "published": "18080", "target": 8000}]
                or executor.get("ports")):
            raise IsolatedExecutionBlocked("Docker context, image, network or normalized Compose drift")
        network_id = network.get("Id")
        if not isinstance(network_id, str) or not network_id:
            raise IsolatedExecutionBlocked("network identifier is unavailable")
        a = self._container(APP_CONTAINER, "vulnerable-store", network_id)
        e = self._container(EXECUTOR_CONTAINER, "controlled-executor", network_id)
        self._container_source("vulnerable-store")
        self._container_source("controlled-executor")
        return {"context": context, "daemon_id": info["ID"], "image_id": image["Id"],
                "app_container": a, "executor_container": e,
                "volume": {"name": volume["Name"], "mountpoint": volume["Mountpoint"],
                           "created_at": volume.get("CreatedAt")},
                "source_hashes": {rel: self.pin.source_hashes[rel] for rel in CONTAINER_FILES}}


    @staticmethod
    def _save_new(path: Path, data: bytes) -> None:
        # Explicit O_EXCL + O_NOFOLLOW on Linux; never follow a raced symlink.
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())

    @staticmethod
    def _json_bytes(value: dict) -> bytes:
        return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()

    def run_registered(self) -> RealExecutionReceipt:
        """One admitted attempt. Never builds/starts/stops/cleans or retries."""
        pin = load_real_admission(self.root, self.path, self.digest)
        if pin != self.pin:
            raise IsolatedExecutionBlocked("admission changed since construction")
        self._source_snapshot()
        before = self._runtime_snapshot()
        test_id = REGISTERED[pin.scenario_id][0]
        argv = self._compose(
            "exec", "-T", "controlled-executor", "python", "-m",
            "infrastructure.executor.run_verification_test",
            "--test-id", test_id, "--attempt-number", "1", "--run-id", pin.run_id,
        )
        case = self.evidence / pin.case_id
        if (self.evidence.is_symlink() or not self.evidence.is_dir()
                or self.evidence.resolve(strict=True) != self.evidence):
            raise IsolatedExecutionBlocked("external evidence parent changed")
        try:
            case.mkdir(mode=0o700, exist_ok=False)
        except FileExistsError as exc:
            raise IsolatedExecutionBlocked("case already exists; no redispatch") from exc
        intent = {
            "scope": "development_only_not_final_research",
            "admission_sha256": self.digest, "case_id": pin.case_id,
            "run_id": pin.run_id, "scenario_id": pin.scenario_id,
            "test_id": test_id, "argv": argv, "cwd": str(self.root),
            "source_head": pin.source_head, "source_tree": pin.source_tree,
            "before": before, "attempt_number": 1,
        }
        self._save_new(case / "dispatch-intent.json", self._json_bytes(intent))
        stdout, stderr, returncode, timed_out = b"", b"", -1, False
        observation_sha = None
        outcome = "executor_failed"
        reason = "registered process did not return a valid result"
        try:
            try:
                response = self.runner(argv, self.root)
                if (not isinstance(response, BinaryResult)
                        or type(response.stdout) is not bytes
                        or type(response.stderr) is not bytes
                        or type(response.returncode) is not int
                        or type(response.timed_out) is not bool):
                    raise IsolatedExecutionBlocked("malformed binary process result")
                if len(response.stdout) > MAX_OUTPUT or len(response.stderr) > MAX_OUTPUT:
                    raise IsolatedExecutionBlocked("registered stream exceeded bound")
                stdout, stderr = response.stdout, response.stderr
                returncode, timed_out = response.returncode, response.timed_out
            except Exception as exc:  # noqa: BLE001 - fail closed on injected runner exceptions
                reason = "registered command raised " + type(exc).__name__
            self._save_new(case / "stdout.raw", stdout)
            self._save_new(case / "stderr.raw", stderr)
            try:
                self._source_snapshot()
                after = self._runtime_snapshot()
                if after != before:
                    raise IsolatedExecutionBlocked("Docker identity changed across dispatch")
                if load_real_admission(self.root, self.path, self.digest) != pin:
                    raise IsolatedExecutionBlocked("admission changed after dispatch")
            except Exception:  # noqa: BLE001 - all provenance errors forbid acceptance
                outcome, reason = "provenance_failed", "source, Docker or admission drift after dispatch"
            else:
                if timed_out:
                    outcome, reason = "inconclusive", "trusted command timed out; partial bytes not evaluated"
                elif returncode != 0:
                    outcome, reason = "executor_failed", "trusted registered command returned nonzero"
                else:
                    try:
                        # Bind the registered output to *observed* Docker identities
                        # and the immutable local source/execution intent.
                        session_sha = sha256(self._json_bytes(intent)).hexdigest()
                        policy_path = f"config/security_tests/{test_id}.json"
                        implementation_path = {
                            "sqli-login-bypass-001": "security_tests/sql_injection/login_bypass.py",
                            "xss-reflection-001": "security_tests/xss/reflection.py",
                            "path-traversal-private-file-001": "security_tests/path_traversal/private_file.py",
                        }[test_id]
                        observation = observe_registered_result(
                            raw_result=stdout, scenario_id=pin.scenario_id,
                            phase="vulnerable_baseline",
                            source_sha256=pin.source_hashes[CONTAINER_FILES[0]],
                            policy_config_sha256=pin.source_hashes[policy_path],
                            test_implementation_sha256=pin.source_hashes[implementation_path],
                            evidence_scope="reported_controlled_executor",
                            docker_session_evidence_sha256=session_sha,
                            registry=self.registry, implementations=self.implementations,
                        )
                        result = observation.execution
                        if (result.run_id != pin.run_id or result.test_id != test_id
                                or result.attempt_number != 1):
                            raise IsolatedExecutionBlocked("registered result run/test identity mismatch")
                        payload = (observation.model_dump_json(indent=2) + "\n").encode()
                        self._save_new(case / "observation.json", payload)
                        observation_sha = sha256(payload).hexdigest()
                        if observation.test_completed:
                            outcome = ("baseline_exploit_confirmed" if observation.exploit_confirmed
                                       else "baseline_exploit_not_observed")
                        else:
                            outcome = "inconclusive"
                        reason = "trusted registered evidence recomputed from captured bytes"
                    except Exception:  # noqa: BLE001 - untrusted stdout must fail closed
                        outcome = "provenance_failed"
                        reason = "registered stdout could not be independently validated"
        except Exception:  # noqa: BLE001 - preserve no-retry state after evidence failure
            outcome = "provenance_failed"
            reason = "evidence persistence failed; do not redispatch"
        receipt = RealExecutionReceipt(
            case_id=pin.case_id, run_id=pin.run_id, scenario_id=pin.scenario_id,
            source_head=pin.source_head, source_tree=pin.source_tree,
            daemon_id=pin.daemon_id, image_id=pin.image_id,
            app_container_id=pin.app_container_id,
            executor_container_id=pin.executor_container_id,
            admission_sha256=self.digest, dispatch_argv=argv,
            stdout_sha256=sha256(stdout).hexdigest(),
            stderr_sha256=sha256(stderr).hexdigest(),
            returncode=returncode, timed_out=timed_out,
            outcome=outcome, reason=reason, observation_sha256=observation_sha,
        )
        self._save_new(case / "receipt.json",
                       (receipt.model_dump_json(indent=2) + "\n").encode())
        return receipt
