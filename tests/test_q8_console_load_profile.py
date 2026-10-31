"""Q8-only local loader profile; never spawn actual systemd/llama.cpp."""
from __future__ import annotations

import pytest

import dashboard.api.operator_service as service
from dashboard.api.operator_service import (
    Q8_APPROVED_BYTES,
    Q8_APPROVED_FILENAME,
    Q8_APPROVED_SHA256,
    Q8_MIN_AVAILABLE_MIB,
    LocalStart,
    ModelManager,
    OperatorError,
)


class FakeProcess:
    def poll(self):
        return None


@pytest.fixture
def harness(tmp_path, monkeypatch):
    model = tmp_path / Q8_APPROVED_FILENAME
    with model.open("wb") as stream:
        # Sparse allocation: filesystem contains no actual model and no memory-heavy bytes.
        stream.truncate(Q8_APPROVED_BYTES)
    bin_path = tmp_path / "llama-server"
    bin_path.write_bytes(b"synthetic executable")
    bin_path.chmod(0o755)
    monkeypatch.setenv("FYP_MODEL_DIRECTORY", str(tmp_path))
    monkeypatch.setenv("FYP_LLAMA_SERVER_BIN", str(bin_path))
    monkeypatch.setenv("FYP_LOCAL_MODEL_PORT", "19483")
    monkeypatch.setattr(service, "_mem_available", lambda: 5_200 * 1024 * 1024)
    monkeypatch.setattr(service, "_hash", lambda model: Q8_APPROVED_SHA256)
    monkeypatch.setattr(service.shutil, "which", lambda binary: "/usr/bin/" + binary)
    launched = []

    def fake_popen(args, **kwargs):
        launched.append((args, kwargs))
        return FakeProcess()

    monkeypatch.setattr(service.subprocess, "Popen", fake_popen)
    manager = ModelManager()
    yield manager, model, launched
    if manager._session is not None:
        manager._session.logfile.close()
        manager._session = None


def test_q8_allowlisted_model_starts_with_separate_4400m_profile(harness):
    manager, model, launched = harness
    status = manager.start(LocalStart(filename=model.name, model_name="q8-development"))
    assert len(launched) == 1
    args, opts = launched[0]
    assert args[args.index("--model") + 1] == str(model)
    assert "MemoryMax=4400M" in args
    assert "MemorySwapMax=512M" in args
    assert args[args.index("--ctx-size") + 1] == "2048"
    assert args[args.index("--host") + 1] == "127.0.0.1"
    assert args[args.index("--n-gpu-layers") + 1] == "0"
    assert opts["stdin"] is service.subprocess.DEVNULL
    assert status["context_tokens"] == 2048
    assert status["final_research_ready"] is False


@pytest.mark.parametrize("free_mib", [0, 100, 4399])
def test_q8_fails_closed_below_minimum_mem_available(harness, monkeypatch, free_mib):
    manager, model, launched = harness
    monkeypatch.setattr(service, "_mem_available", lambda: free_mib * 1024 * 1024)
    with pytest.raises(OperatorError, match="4400"):
        manager.start(LocalStart(filename=model.name, model_name="q8-development"))
    assert launched == []


def test_q8_can_pass_exact_ram_threshold_without_override(harness, monkeypatch):
    manager, model, launched = harness
    monkeypatch.setattr(service, "_mem_available", lambda: Q8_MIN_AVAILABLE_MIB * 1024 * 1024)
    manager.start(LocalStart(filename=model.name, model_name="q8-development"))
    assert len(launched) == 1


def test_q8_wrong_hash_cannot_spawn_model_server(harness, monkeypatch):
    manager, model, launched = harness
    monkeypatch.setattr(service, "_hash", lambda model: "0" * 64)
    with pytest.raises(OperatorError, match="SHA-256 mismatch"):
        manager.start(LocalStart(filename=model.name, model_name="q8-development"))
    assert launched == []


def test_q8_wrong_bytes_cannot_spawn_server(harness):
    manager, model, launched = harness
    with model.open("r+b") as stream:
        stream.truncate(Q8_APPROVED_BYTES - 1)
    with pytest.raises(OperatorError, match="model size"):
        manager.start(LocalStart(filename=model.name, model_name="q8-development"))
    assert launched == []


def test_unapproved_large_gguf_still_rejected_at_original_3400m(harness):
    manager, model, launched = harness
    other = model.parent / "unapproved-Q8.gguf"
    with other.open("wb") as stream:
        stream.truncate(Q8_APPROVED_BYTES)
    with pytest.raises(OperatorError, match="3.4 GiB"):
        manager.start(LocalStart(filename=other.name, model_name="q8-development"))
    assert launched == []


def test_legacy_small_model_keeps_original_memory_scope(harness):
    manager, model, launched = harness
    other = model.parent / "legacy-synthetic.gguf"
    other.write_bytes(b"synthetic")
    manager.start(LocalStart(filename=other.name, model_name="legacy-dev"))
    args, _ = launched[0]
    assert "MemoryMax=3400M" in args
    assert args[args.index("--ctx-size") + 1] == "1536"


def test_scope_stop_failure_keeps_single_model_slot(harness, monkeypatch):
    """A failed systemd stop cannot free the slot for another heavy model."""
    from types import SimpleNamespace

    manager, model, launched = harness
    manager.start(LocalStart(filename=model.name, model_name="q8-development"))
    session = manager._session
    assert session is not None

    def failed_stop(*args, **kwargs):
        assert manager._lock.locked()
        assert args[0][-1] == session.scope + ".scope"
        return SimpleNamespace(returncode=1)

    monkeypatch.setattr(service.subprocess, "run", failed_stop)
    with pytest.raises(OperatorError, match="Could not confirm"):
        manager.stop()
    assert manager._session is session
    assert not session.logfile.closed
    with pytest.raises(OperatorError, match="Stop the previous"):
        manager.start(LocalStart(filename=model.name, model_name="q8-development"))
    assert len(launched) == 1

    class TerminatingProcess:
        terminated = False

        def poll(self):
            return 0 if self.terminated else None

        def terminate(self):
            self.terminated = True

        def wait(self, timeout):
            assert timeout == 8
            return 0

    session.process = TerminatingProcess()
    monkeypatch.setattr(
        service.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=0)
    )
    assert manager.stop() == {"state": "unloaded", "final_research_ready": False}
    assert session.process.terminated is True and session.logfile.closed
    assert manager._session is None
    manager.start(LocalStart(filename=model.name, model_name="q8-development"))
    assert len(launched) == 2


def test_scope_stop_timeout_preserves_session(harness, monkeypatch):
    manager, model, _ = harness
    manager.start(LocalStart(filename=model.name, model_name="q8-development"))
    session = manager._session

    def timed_out(*args, **kwargs):
        raise service.subprocess.TimeoutExpired(cmd="systemctl", timeout=15)

    monkeypatch.setattr(service.subprocess, "run", timed_out)
    with pytest.raises(OperatorError, match="Could not confirm"):
        manager.stop()
    assert manager._session is session
    assert not session.logfile.closed
