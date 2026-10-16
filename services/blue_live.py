"""Operator-admitted single SQLi replay in already-running patched Docker containers.

No build, start, stop, cleanup, or self-created approval. The independent
admission and candidate SHA-256 must be supplied from outside the worktree.
"""
from __future__ import annotations

import argparse
import json
import os
import re
from hashlib import sha256
from pathlib import Path
from typing import Literal
from uuid import UUID

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from schemas.red_team import TestExecutionResult
from security_tests.registry import SecurityTestRegistry
from services.blue_docker import ROOT
from services.isolated_compose_executor import (
    CONTAINER_FILES,
    BinaryResult,
    run_local_binary,
)
from services.isolated_compose_mock_adapter import verify_isolation_yaml


class BlueLiveBlocked(RuntimeError):
    """An independently admitted patched replay is not safe to execute."""


class BlueLiveAdmission(BaseModel):
    """Independently approved pinned identities, not a generated request."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["patched-docker-admission-v1"] = "patched-docker-admission-v1"
    purpose: Literal["development_registered_patch_replay"] = "development_registered_patch_replay"
    independently_approved: Literal[True] = True
    final_research_authorized: Literal[False] = False
    context: Literal["default"] = "default"
    job_id: str
    candidate_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    build_attestation_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    build_attestation_path: str
    daemon_id: str = Field(min_length=1, max_length=128)
    image_id: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    app_container_id: str = Field(pattern=r"^[a-f0-9]{64}$")
    executor_container_id: str = Field(pattern=r"^[a-f0-9]{64}$")
    network_id: str = Field(min_length=1, max_length=128)
    run_id: str = Field(pattern=r"^[a-z][a-z0-9-]{1,47}$")
    test_id: Literal["sqli-login-bypass-001"] = "sqli-login-bypass-001"
    attempt_number: Literal[1] = 1

    @model_validator(mode="after")
    def bound_identity(self):
        UUID(self.job_id)
        if self.app_container_id == self.executor_container_id:
            raise ValueError("Both services must have separate container identities")
        return self

    def canonical_bytes(self) -> bytes:
        return (json.dumps(self.model_dump(mode="json"), sort_keys=True,
                           separators=(",", ":")) + "\n").encode()


def _read_json(path: Path, digest: str, max_size: int = 131072) -> dict:
    if (path.is_symlink() or not path.is_file() or
            not re.fullmatch(r"[a-f0-9]{64}", digest) or
            path.stat().st_size > max_size):
        raise BlueLiveBlocked("Pinned external evidence file missing or oversized")
    data = path.read_bytes()
    if sha256(data).hexdigest() != digest:
        raise BlueLiveBlocked("External evidence SHA-256 does not match")
    value = json.loads(data)
    if type(value) is not dict:
        raise BlueLiveBlocked("External evidence is not a JSON object")
    return value


def _candidate(context: Path, candidate_sha: str) -> dict:
    if (not context.is_absolute() or context.name != "docker-context" or
            context.is_symlink() or context.parent.is_symlink() or
            ROOT.resolve() in context.resolve().parents):
        raise BlueLiveBlocked("Docker candidate must be in an external, regular directory")
    parent = context.parent
    receipt = _read_json(parent / "candidate.json", candidate_sha)
    if (receipt.get("schema_version") != "isolated-docker-candidate-v1" or
            parent.name != "blue-patch-" + UUID(receipt["job_id"]).hex or
            receipt.get("compose_path") != "compose.blue.yaml" or
            receipt.get("image_built") is not False or
            receipt.get("docker_executed") is not False or
            receipt.get("independent_admission_granted") is not False or
            receipt.get("final_repair_accepted") is not False):
        raise BlueLiveBlocked("Not an independently reviewable Docker candidate")
    files = receipt["file_sha256"]
    if (type(files) is not dict or len(files) > 1500 or
            not all(isinstance(name, str) and isinstance(digest, str) for
                    name, digest in files.items())):
        raise BlueLiveBlocked("Invalid candidate file inventory")
    actual = {}
    for path in context.rglob("*"):
        if path.is_symlink():
            raise BlueLiveBlocked("Docker candidate contains a symlink")
        if path.is_file():
            actual[str(path.relative_to(context))] = sha256(path.read_bytes()).hexdigest()
    if actual != files:
        raise BlueLiveBlocked("Build context differs from reviewed candidate")
    verify_isolation_yaml(context)
    compose = yaml.safe_load((context / "compose.blue.yaml").read_text())
    name = "fyp-blue-" + UUID(receipt["job_id"]).hex[:12]
    image = name + ":local"
    if (compose.get("name") != name or receipt.get("image") != image or
            compose.get("x-lab-image", {}).get("image") != image or
            set(compose.get("services", {})) != {"vulnerable-store", "controlled-executor"} or
            compose.get("networks", {}).get("security-lab", {}).get("name") != name + "-network" or
            compose.get("volumes", {}).get("store-runtime", {}).get("name") != name + "-volume"):
        raise BlueLiveBlocked("Patched Compose project identity is invalid")
    for service in ("vulnerable-store", "controlled-executor"):
        if (compose["services"][service].get("image") != image or
                compose["services"][service].get("container_name") != name + "-" + service):
            raise BlueLiveBlocked("Patched Compose service identity is invalid")
    return receipt


def run_patched_replay(
    *, candidate_dir: Path, admission_path: Path,
    admission_sha256: str, candidate_sha256: str,
    runner=run_local_binary,
) -> dict:
    """Single bounded registered test with independent admission and runtime pins."""
    try:
        context = Path(candidate_dir).resolve(strict=True)
        if Path(candidate_dir).is_symlink() or not context.is_dir():
            raise BlueLiveBlocked("Candidate context is untrusted")
        receipt = _candidate(context, candidate_sha256)
        path = Path(admission_path)
        if (not path.is_absolute() or path.is_symlink() or
                not path.is_file() or ROOT.resolve() in path.resolve().parents or
                context.parent in path.resolve().parents):
            raise BlueLiveBlocked("Admission must be independently stored outside the candidate")
        raw = path.read_bytes()
        admitted = BlueLiveAdmission.model_validate_json(raw)
        if (sha256(raw).hexdigest() != admission_sha256 or
                raw != admitted.canonical_bytes() or
                admitted.job_id != receipt["job_id"] or
                admitted.candidate_sha256 != candidate_sha256):
            raise BlueLiveBlocked("Independent patched-runtime admission does not match candidate")
        attestation = Path(admitted.build_attestation_path)
        if (not attestation.is_absolute() or attestation.is_symlink() or
                ROOT.resolve() in attestation.resolve().parents or
                context.parent in attestation.resolve().parents):
            raise BlueLiveBlocked("Build attestation must be independently stored")
        build = _read_json(attestation, admitted.build_attestation_sha256, 4096)
        if (set(build) != {
                "schema_version", "candidate_sha256", "daemon_id", "image_id",
                "patched_source_sha256", "build_log_sha256",
                "independent_review_complete",
            } or build["schema_version"] != "reviewed-image-build-v1" or
                build["candidate_sha256"] != candidate_sha256 or
                build["daemon_id"] != admitted.daemon_id or
                build["image_id"] != admitted.image_id or
                build["patched_source_sha256"] != receipt["patched_source_sha256"] or
                type(build["independent_review_complete"]) is not bool or
                build["independent_review_complete"] is not True or
                type(build["build_log_sha256"]) is not str or
                not re.fullmatch(r"[a-f0-9]{64}", build["build_log_sha256"])):
            raise BlueLiveBlocked("Image build evidence differs from independently pinned source")
        name = receipt["image"].split(":")[0]
        network = name + "-network"
        app = name + "-vulnerable-store"
        executor = name + "-controlled-executor"

        def docker(*args: str, inspect: bool = True) -> bytes:
            argv = ("docker", "--context", admitted.context, *args)
            response = runner(argv, context)
            if (not isinstance(response, BinaryResult) or
                    type(response.stdout) is not bytes or
                    type(response.stderr) is not bytes or
                    type(response.returncode) is not int or
                    response.returncode != 0 or response.timed_out or
                    len(response.stdout) > (131072 if inspect else 65536) or
                    len(response.stderr) > 65536):
                raise BlueLiveBlocked("Pinned Docker inspection or execution failed")
            return response.stdout

        def inspect_runtime() -> None:
            if runner(("docker", "context", "show"), context) != BinaryResult(0,b"default\n",b""):
                raise BlueLiveBlocked("The selected host Docker context differs from approved default")
            daemon = json.loads(docker("info", "--format", "{{json .}}"))
            image = json.loads(docker("image", "inspect", "--format", "{{json .}}", receipt["image"]))
            net = json.loads(docker("network", "inspect", "--format", "{{json .}}", network))
            if (daemon.get("ID") != admitted.daemon_id or
                    image.get("Id") != admitted.image_id or
                    net.get("Id") != admitted.network_id or
                    net.get("Name") != network or net.get("Internal") is not True or
                    net.get("Attachable") is not False or
                    set(net.get("Containers", {})) != {
                        admitted.app_container_id, admitted.executor_container_id
                    }):
                raise BlueLiveBlocked("Docker daemon, image, or isolated network mismatch")
            for service, cname, cid in (
                ("vulnerable-store",app,admitted.app_container_id),
                ("controlled-executor",executor,admitted.executor_container_id),
            ):
                container = json.loads(docker(
                    "container", "inspect", "--format", "{{json .}}", cname
                ))
                cfg = container.get("Config") or {}
                host = container.get("HostConfig") or {}
                state = container.get("State") or {}
                networks = (container.get("NetworkSettings") or {}).get("Networks") or {}
                mounted = container.get("Mounts") or []
                is_app = service == "vulnerable-store"
                mounts_valid = (
                    len(mounted) == 1 and all(
                        x.get("Type") == "volume" and
                        x.get("Name") == name+"-volume" and
                        x.get("Destination") == "/runtime" and
                        x.get("RW") is not False for x in mounted
                    )
                ) if is_app else not mounted
                if (container.get("Id") != cid or container.get("Image") != admitted.image_id or
                        cfg.get("Image") != receipt["image"] or cfg.get("User") != "10001:10001" or
                        (cfg.get("Labels") or {}).get("com.docker.compose.project") != name or
                        (cfg.get("Labels") or {}).get("com.docker.compose.service") != service or
                        state.get("Running") is not True or
                        (state.get("Health") or {}).get("Status") != "healthy" or
                        host.get("ReadonlyRootfs") is not True or
                        host.get("Privileged") is not False or
                        "ALL" not in (host.get("CapDrop") or []) or
                        "no-new-privileges:true" not in (host.get("SecurityOpt") or []) or
                        host.get("NanoCpus") != (500000000 if is_app else 250000000) or
                        host.get("Memory") != (268435456 if is_app else 134217728) or
                        host.get("PidsLimit") != (128 if is_app else 64) or
                        host.get("PortBindings") not in ({}, None) or
                        set(networks) != {network} or
                        networks[network].get("NetworkID") != admitted.network_id or
                        any(x is not None for x in (
                            (container.get("NetworkSettings") or {}).get("Ports") or {}
                        ).values()) or
                        not mounts_valid):
                    raise BlueLiveBlocked("Patched service identity or isolation mismatch")

            expected = {
                f"/workspace/{rel}":receipt["file_sha256"][rel]
                for rel in CONTAINER_FILES
            }
            for service in ("vulnerable-store","controlled-executor"):
                output = docker(
                    "compose", "-f", str(context/"compose.blue.yaml"),
                    "--project-directory", str(context),
                    "exec", "-T", service, "sha256sum",
                    *(f"/workspace/{rel}" for rel in CONTAINER_FILES),
                )
                observed = {}
                for line in output.decode("ascii").splitlines():
                    parts = line.split("  ",1)
                    if len(parts) != 2 or parts[1] in observed:
                        raise BlueLiveBlocked("In-container source hash output is malformed")
                    observed[parts[1]] = parts[0]
                if observed != expected:
                    raise BlueLiveBlocked("Patched container source differs from candidate")

        inspect_runtime()
        # This exclusive reservation is intentionally before execution. Do not retry.
        stage = context.parent
        intent = stage / "docker-replay.intent"
        fd = os.open(intent, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd,"w") as out:
            out.write(admission_sha256 + "\n")
        output = docker(
            "compose", "-f", str(context / "compose.blue.yaml"),
            "--project-directory", str(context),
            "exec", "-T", "controlled-executor", "python", "-m",
            "infrastructure.executor.run_verification_test",
            "--test-id", admitted.test_id, "--attempt-number", "1",
            "--run-id", admitted.run_id, inspect=False,
        )
        # Keep the byte-exact registered response even if subsequent
        # provenance inspection or schema validation fails.
        fd = os.open(stage / "docker-stdout.raw",
                     os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as out:
            out.write(output)
        inspect_runtime()
        result = TestExecutionResult.model_validate_json(output)
        test = SecurityTestRegistry.default().get(admitted.test_id)
        steps = test.build_steps()
        observed = result.exchanges
        if (result.run_id != admitted.run_id or
                result.target_id != "vulnerable-store" or
                result.test_id != admitted.test_id or result.attempt_number != 1 or
                not result.completed or result.timed_out or
                result.request_count != 2 or len(observed) != 2 or len(steps) != 2 or
                any(x.step_id != s.step_id or x.endpoint_id != s.endpoint_id or
                    x.method != s.method.value for x,s in zip(observed,steps,strict=True))):
            raise BlueLiveBlocked("Docker registered-test execution was not complete or bound")
        expected_evidence = test.evaluate(observed)
        if tuple(result.evidence) != expected_evidence:
            raise BlueLiveBlocked("Executor claim differs from recomputed registered evidence")
        # The registered executor marks a completed test with no exploit
        # evidence as "evidence-not-observed". That is the expected outcome
        # for a repaired target, not a transport or execution error.
        expected_code = None if expected_evidence else "evidence-not-observed"
        if result.error_code != expected_code:
            raise BlueLiveBlocked("Registered test error code conflicts with evidence")
        success = observed[0].status_code == 401 and observed[1].status_code == 401 and not expected_evidence
        real = runner is run_local_binary
        report = {
            "status": "passed" if success else "failed",
            "job_id":admitted.job_id,"run_id":admitted.run_id,
            "test_id":admitted.test_id,
            "control_status":observed[0].status_code,
            "injection_status":observed[1].status_code,
            "registered_exploit_evidence":[x.evidence_id for x in expected_evidence],
            "docker_replayed":real,
            "evidence_scope":"live_pinned_docker" if real else "injected_offline_runner",
            "candidate_sha256":candidate_sha256,
            "admission_sha256":admission_sha256,
            "stdout_sha256":sha256(output).hexdigest(),
            "functionality_verified":False,
            "final_repair_accepted":False,
            "final_research_qualified":False,
        }
        data=(json.dumps(report,sort_keys=True,indent=2)+"\n").encode()
        fd=os.open(stage/"docker-replay.json",
                   os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,"wb") as out:
            out.write(data)
        return {**report,"report_sha256":sha256(data).hexdigest()}
    except FileExistsError as exc:
        raise BlueLiveBlocked("Patched registered replay already attempted") from exc
    except BlueLiveBlocked:
        raise
    except Exception as exc:
        raise BlueLiveBlocked("Patched Docker replay refused or inconclusive") from exc


def main() -> None:
    parser=argparse.ArgumentParser(description="One externally admitted patched Docker SQLi replay")
    for item in ("candidate-dir","admission-path"):
        parser.add_argument("--"+item,required=True,type=Path)
    for item in ("candidate-sha256","admission-sha256"):
        parser.add_argument("--"+item,required=True)
    args=vars(parser.parse_args())
    print(json.dumps(run_patched_replay(**{
        k.replace("-","_"):v for k,v in args.items()
    }),indent=2))


if __name__ == "__main__":
    main()
