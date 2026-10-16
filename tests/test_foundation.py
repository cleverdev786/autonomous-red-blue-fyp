"""Repository-foundation tests."""

from __future__ import annotations

import importlib

from orchestrator.config import PROJECT_ROOT, ProjectSettings


def test_core_packages_import() -> None:
    """The four foundation packages must remain importable."""
    for package_name in ("orchestrator", "schemas", "services", "llm"):
        imported = importlib.import_module(package_name)
        assert imported is not None


def test_default_settings_load(monkeypatch) -> None:
    """Configuration must have deterministic local defaults."""
    monkeypatch.delenv("FYP_ENV", raising=False)
    monkeypatch.delenv("FYP_DATA_DIR", raising=False)
    monkeypatch.delenv("FYP_DATABASE_URL", raising=False)

    settings = ProjectSettings.from_env()

    assert settings.environment == "development"
    assert settings.data_dir == (PROJECT_ROOT / "data").resolve()
    assert settings.database_url == "sqlite:///./data/fyp.db"


def test_environment_overrides(monkeypatch, tmp_path) -> None:
    """Supported environment variables must override their defaults."""
    data_dir = tmp_path / "runtime-data"

    monkeypatch.setenv("FYP_ENV", "test")
    monkeypatch.setenv("FYP_DATA_DIR", str(data_dir))
    monkeypatch.setenv("FYP_DATABASE_URL", "sqlite:///./custom.db")

    settings = ProjectSettings.from_env()

    assert settings.environment == "test"
    assert settings.data_dir == data_dir.resolve()
    assert settings.database_url == "sqlite:///./custom.db"


def test_distribution_keeps_registered_console_resources() -> None:
    """A standalone wheel must contain the registered policies and UI assets."""
    import tomllib

    config = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text())
    packages = config["tool"]["setuptools"]["packages"]["find"]["include"]
    data = config["tool"]["setuptools"]["package-data"]
    assert all(f"{name}*" in packages for name in (
        "security_tests", "infrastructure", "dummy_apps", "config",
    ))
    assert {"targets/*.json", "security_tests/*.json"} <= set(data["config"])
    assert {"frontend/dist/index.html", "frontend/dist/assets/*.js",
            "frontend/dist/assets/*.css"} <= set(data["dashboard"])
    for label in (
        "config/targets/vulnerable-store.json",
        "config/security_tests/sqli-login-bypass-001.json",
        "config/security_tests/xss-reflection-001.json",
        "config/security_tests/path-traversal-private-file-001.json",
    ):
        assert (PROJECT_ROOT / label).is_file()
