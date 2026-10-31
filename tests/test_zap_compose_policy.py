"""T09: profile-gated official ZAP container cannot alter the default lab.

Static-only tests: no image pull, startup, or vulnerability scan.
"""

import re
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "compose.yaml"
OVERLAY = ROOT / "compose.zap.yaml"
IMAGE = (
    "ghcr.io/zaproxy/zaproxy:2.17.0@sha256:"
    "0075662e5c287cf0a68caebabbfea872e5dc461912ad6d7345fa02a290d0ccb6"
)


def read_yaml(path: Path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def rendered(*, zap=False):
    args = ["docker", "compose", "-f", str(BASE)]
    if zap:
        args += ["-f", str(OVERLAY), "--profile", "zap"]
    result = subprocess.run(args + ["config", "--format", "json"], capture_output=True,
                            text=True, timeout=20, check=True)
    import json
    return json.loads(result.stdout)


def test_default_compose_unchanged_and_no_zap_without_profile():
    baseline = read_yaml(BASE)
    assert set(baseline["services"]) == {"vulnerable-store", "controlled-executor"}
    assert set(baseline["networks"]) == {"security-lab"}
    assert set(rendered()["services"]) == {"vulnerable-store", "controlled-executor"}


def test_vetted_image_pinned_to_exact_amd64_digest():
    overlay = read_yaml(OVERLAY)
    zap = overlay["services"]["zap"]
    assert zap["image"] == IMAGE
    assert zap["platform"] == "linux/amd64"
    assert zap["profiles"] == ["zap"]
    assert re.fullmatch(r"ghcr\.io/zaproxy/zaproxy:2\.17\.0@sha256:[a-f0-9]{64}", zap["image"])


def test_zap_only_shares_private_target_network_and_no_host_egress():
    config = rendered(zap=True)
    networks = config["networks"]
    assert networks["zap-target"]["internal"] is True
    # Compose omits false default booleans from normalized configuration.
    assert networks["zap-target"].get("attachable", False) is False
    assert read_yaml(OVERLAY)["networks"]["zap-target"]["attachable"] is False
    assert networks["zap-target"]["driver"] == "bridge"
    zap = config["services"]["zap"]
    assert set(zap["networks"]) == {"zap-target"}
    assert set(config["services"]["vulnerable-store"]["networks"]) == {"security-lab"}
    assert set(config["services"]["controlled-executor"]["networks"]) == {"security-lab"}
    assert [
        name for name, service in config["services"].items()
        if "zap-target" in service["networks"]
    ] == ["zap", "zap-request-gate"]
    gate = config["services"]["zap-request-gate"]
    assert set(gate["networks"]) == {"security-lab", "zap-target"}
    assert gate["networks"]["zap-target"]["aliases"] == ["vulnerable-store"]
    assert "ports" not in zap
    assert "network_mode" not in zap
    assert "extra_hosts" not in zap


def test_zap_api_is_loopback_only_and_target_is_hard_limited_gate():
    zap = read_yaml(OVERLAY)["services"]["zap"]
    assert zap["entrypoint"] == ["/bin/sh", "-c"]
    assert "command -v zap.sh" in zap["command"][0]
    assert "zap.sh -daemon" in zap["command"][0]
    assert "-host 127.0.0.1" in zap["command"][0]
    assert "api.disablekey=true" in zap["command"][0]
    assert "zap-baseline.py" not in str(zap)
    assert "zap-full-scan.py" not in str(zap)
    assert "ZAP_API_KEY" not in str(zap)
    assert zap.get("restart", "no") == "no"
    assert zap["stop_grace_period"] == "5s"


def test_zap_security_and_resource_limits():
    zap = read_yaml(OVERLAY)["services"]["zap"]
    assert zap["user"] == "1000:1000"
    assert zap["read_only"] is True
    assert zap["privileged"] is False
    assert zap["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in zap["security_opt"]
    assert zap["pids_limit"] <= 64
    assert zap["mem_limit"] == "512m"
    assert zap["cpus"] <= 0.5
    assert zap["init"] is True
    assert zap["tmpfs"]
    assert "volumes" not in zap
    assert "devices" not in zap
    assert "pid" not in zap
    assert "ipc" not in zap
    assert "healthcheck" in zap


def test_compose_overlay_preserves_base_lab_security_properties():
    base = rendered()
    composed = rendered(zap=True)
    for name in ("vulnerable-store", "controlled-executor"):
        original = base["services"][name].copy()
        newer = composed["services"][name].copy()
        if name == "vulnerable-store":
            original.pop("networks", None)
            newer.pop("networks", None)
        assert original == newer
    assert composed["networks"]["security-lab"] == base["networks"]["security-lab"]


def test_no_docker_socket_or_host_bind_mounts_even_in_overlay():
    text = OVERLAY.read_text(encoding="utf-8")
    assert "docker.sock" not in text
    assert "privileged: true" not in text
    zap = rendered(zap=True)["services"]["zap"]
    assert not zap.get("volumes")
    assert not zap.get("ports")


def test_request_gate_has_fixed_mode_no_public_port_and_tight_limits():
    gate = read_yaml(OVERLAY)["services"]["zap-request-gate"]
    assert gate["command"] == ["python", "-m", "infrastructure.zap_request_gate"]
    assert gate["environment"] == {"MARS_ZAP_GATE_MODE": "xss-reflection-001"}
    assert gate["read_only"] is True and gate["privileged"] is False
    assert gate["cap_drop"] == ["ALL"]
    assert gate["mem_limit"] == "64m" and gate["cpus"] <= 0.25
    assert gate["pids_limit"] <= 32
    assert "ports" not in gate and "volumes" not in gate
