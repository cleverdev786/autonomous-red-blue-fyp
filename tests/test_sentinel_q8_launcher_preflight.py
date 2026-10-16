"""Actual bash launcher selection without starting model, browser, or HTTP server."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "launch-sentinel.sh"
PIN = "b29c606e28a01b1bc8c1351026a0fa6e616bf6c4"
Q8 = ROOT / "models/c08b-nf4-effective-Q8_0.gguf"
Q8_RUNTIME = (
    ROOT.parent
    / "Q8_C12_Integration_Audit_2026-10-14/staging/C12_Q8_CPU_Hybrid_Integration_2026-10-14"
    / "vendor/llama.cpp"
)


def preflight(*, override=None):
    env = os.environ.copy()
    env.pop("FYP_MODEL_DIRECTORY", None)
    env.pop("FYP_LLAMA_SERVER_BIN", None)
    env["SENTINEL_PRINT_MODEL_CONFIG_ONLY"] = "1"
    if override is not None:
        env["FYP_LLAMA_SERVER_BIN"] = override
    proc = subprocess.run(
        ["bash", str(LAUNCHER)], env=env, cwd=ROOT, capture_output=True,
        text=True, timeout=20, check=True
    )
    return dict(line.split("=", 1) for line in proc.stdout.splitlines() if "=" in line)


def test_sentinel_launcher_is_valid_bash():
    result = subprocess.run(
        ["bash", "-n", str(LAUNCHER)], cwd=ROOT, check=False,
        capture_output=True, text=True
    )
    assert result.returncode == 0


def test_explicit_runtime_override_is_preserved_without_process_launch():
    override = "/tmp/example-user-approved-llama-server"
    result = preflight(override=override)
    assert result["FYP_LLAMA_SERVER_BIN"] == override
    assert result["FYP_MODEL_DIRECTORY"] == str(ROOT / "models")


def test_verified_q8_default_is_pinned_without_model_loading():
    if not Q8.is_file() or not (Q8_RUNTIME / "build/bin/llama-server").is_file():
        pytest.skip("Q8 local weights or pinned runtime not installed on this machine")
    commit = subprocess.run(
        ["git", "-C", str(Q8_RUNTIME), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True, timeout=5
    ).stdout.strip()
    if commit != PIN:
        pytest.skip("Local Q8 runtime does not match the expected commit")
    result = preflight()
    assert result["FYP_MODEL_DIRECTORY"] == str(ROOT / "models")
    assert Path(result["FYP_LLAMA_SERVER_BIN"]).resolve() == (
        Q8_RUNTIME / "build/bin/llama-server"
    ).resolve()


def test_launcher_restores_only_pinned_display_configuration(tmp_path):
    """Cold-start preflight never starts browsers, models or localhost services."""
    import hashlib

    state = tmp_path / "state" / "sentinel-fyp"
    state.mkdir(parents=True)
    approvals = tmp_path / "approvals"
    approvals.mkdir()
    expected = (
        ("REGISTERED_RED_DISPLAY", "red"),
        ("ASSESSMENT_APPROVAL", "blue"),
        ("PATCHED_REPLAY_APPROVAL", "sqli"),
        ("PHASE5_REPLAY_APPROVAL", "phase5"),
    )
    lines = []
    for label, content in expected:
        path = approvals / f"{content}.json"
        path.write_text(content)
        lines.extend((
            f"FYP_{label}_PATH={path}",
            f"FYP_{label}_SHA256={hashlib.sha256(path.read_bytes()).hexdigest()}",
        ))
    config = state / "archive-display.env"
    config.write_text("\n".join(lines) + "\n")
    config.chmod(0o600)

    def check(*, overrides=(), mode=None, link=False):
        if config.is_symlink():
            config.unlink()
        if link:
            config.unlink(missing_ok=True)
            config.symlink_to(state / "external", target_is_directory=False)
        else:
            config.write_text("\n".join(overrides or lines) + "\n")
            config.chmod(0o600 if mode is None else mode)
        env = os.environ.copy()
        for label, _ in expected:
            env.pop(f"FYP_{label}_PATH", None)
            env.pop(f"FYP_{label}_SHA256", None)
        env.pop("SENTINEL_PRINT_MODEL_CONFIG_ONLY", None)
        env["SENTINEL_PRINT_ARCHIVE_CONFIG_ONLY"] = "1"
        env["XDG_STATE_HOME"] = str(tmp_path / "state")
        proc = subprocess.run(
            ["bash", str(LAUNCHER)], cwd=ROOT, env=env,
            capture_output=True, text=True, check=True, timeout=20,
        )
        return proc.stdout.strip(), proc.stderr

    assert check()[0] == "ARCHIVE_DISPLAY_CONFIG=CONFIGURED"
    assert check(overrides=lines[:-1])[0] == "ARCHIVE_DISPLAY_CONFIG=NOT_CONFIGURED"
    assert check(overrides=lines + lines[:1])[0] == "ARCHIVE_DISPLAY_CONFIG=NOT_CONFIGURED"
    assert check(overrides=lines, mode=0o644)[0] == "ARCHIVE_DISPLAY_CONFIG=NOT_CONFIGURED"
    assert check(link=True)[0] == "ARCHIVE_DISPLAY_CONFIG=NOT_CONFIGURED"

    attack = tmp_path / "should-not-exist"
    bad = lines.copy()
    bad[0] = f"FYP_REGISTERED_RED_DISPLAY_PATH=$(touch {attack})"
    assert check(overrides=bad)[0] == "ARCHIVE_DISPLAY_CONFIG=NOT_CONFIGURED"
    assert not attack.exists()
    bad = lines.copy()
    bad[1] = "FYP_REGISTERED_RED_DISPLAY_SHA256=not-a-digest"
    assert check(overrides=bad)[0] == "ARCHIVE_DISPLAY_CONFIG=NOT_CONFIGURED"
    bad[1] = "FYP_REGISTERED_RED_DISPLAY_SHA256=" + "0" * 64
    assert check(overrides=bad)[0] == "ARCHIVE_DISPLAY_CONFIG=NOT_CONFIGURED"
    assert check()[0] == "ARCHIVE_DISPLAY_CONFIG=CONFIGURED"
