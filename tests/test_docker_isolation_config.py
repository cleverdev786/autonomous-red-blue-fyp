"""Static safety tests for the Milestone 5 Docker/Compose design.

Docker runtime checks are performed by scripts/verify_docker_isolation.* on a
machine with Docker available. These tests validate the configuration itself.
"""

from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
COMPOSE_PATH = ROOT / "compose.yaml"
DOCKERFILE_PATH = ROOT / "dummy_apps" / "vulnerable_store" / "Dockerfile"


def load_compose() -> dict:
    return yaml.safe_load(COMPOSE_PATH.read_text(encoding="utf-8"))


def test_security_lab_network_is_externally_isolated() -> None:
    compose = load_compose()
    network = compose["networks"]["security-lab"]

    assert network["driver"] == "bridge"
    assert network["internal"] is True
    assert network["attachable"] is False


def test_only_expected_services_exist() -> None:
    compose = load_compose()
    assert set(compose["services"]) == {
        "vulnerable-store",
        "controlled-executor",
    }


def test_both_services_use_only_security_lab_network() -> None:
    compose = load_compose()

    for service_name in ("vulnerable-store", "controlled-executor"):
        networks = compose["services"][service_name]["networks"]
        assert set(networks) == {"security-lab"}
        assert "network_mode" not in compose["services"][service_name]


def test_controlled_executor_has_no_ports_or_host_mounts() -> None:
    compose = load_compose()
    executor = compose["services"]["controlled-executor"]

    assert "ports" not in executor
    assert "volumes" not in executor
    assert executor["read_only"] is True
    assert executor["privileged"] is False
    assert executor["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in executor["security_opt"]


def test_dummy_app_port_is_bound_only_to_loopback() -> None:
    compose = load_compose()
    ports = compose["services"]["vulnerable-store"]["ports"]

    assert ports == ["127.0.0.1:8000:8000"]


def test_runtime_hardening_and_resource_limits_exist() -> None:
    compose = load_compose()

    for service_name in ("vulnerable-store", "controlled-executor"):
        service = compose["services"][service_name]
        assert service["read_only"] is True
        assert service["privileged"] is False
        assert service["cap_drop"] == ["ALL"]
        assert "no-new-privileges:true" in service["security_opt"]
        assert service["pids_limit"] > 0
        assert service["mem_limit"]
        assert service["cpus"] > 0
        assert service["tmpfs"]


def test_no_docker_socket_mount_exists() -> None:
    compose_text = COMPOSE_PATH.read_text(encoding="utf-8")
    assert "/var/run/docker.sock" not in compose_text
    assert "docker.sock" not in compose_text


def test_app_uses_only_named_runtime_volume() -> None:
    compose = load_compose()
    volumes = compose["services"]["vulnerable-store"]["volumes"]

    assert len(volumes) == 1
    volume = volumes[0]
    assert volume["type"] == "volume"
    assert volume["source"] == "store-runtime"
    assert volume["target"] == "/runtime"


def test_dockerfile_runs_as_non_root_user() -> None:
    dockerfile = DOCKERFILE_PATH.read_text(encoding="utf-8")

    assert "USER 10001:10001" in dockerfile
    assert "USER root" not in dockerfile


def test_executor_probe_is_hard_coded_not_generic_cli() -> None:
    probe = (
        ROOT / "infrastructure" / "executor" / "isolation_probe.py"
    ).read_text(encoding="utf-8")

    assert "http://vulnerable-store:8000/health" in probe
    assert "http://example.com/" in probe
    assert "argparse" not in probe
    assert "sys.argv" not in probe
