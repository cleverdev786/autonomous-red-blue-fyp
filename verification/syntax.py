"""One-shot patched-source syntax and fixed import verification.

This module is intended to run only inside the isolated controlled-executor image.
It compiles changed Python sources without executing generated tests, then imports
one fixed trusted application module.
"""

from __future__ import annotations

import argparse
import importlib
import json
import os
from pathlib import Path
import time


PROJECT_ROOT = Path("/workspace")
FIXED_IMPORT_MODULE = "dummy_apps.vulnerable_store.app.main"
ALLOWED_ROOTS = (
    Path("dummy_apps/vulnerable_store/app"),
    Path("dummy_apps/vulnerable_store/tests/generated"),
)


def _safe_path(value: str) -> Path:
    supplied = Path(value)
    if supplied.is_absolute() or ".." in supplied.parts:
        raise ValueError("verification syntax paths must be project-relative")
    if supplied.suffix != ".py":
        raise ValueError("verification syntax paths must be Python files")
    if not any(
        supplied == root or supplied.is_relative_to(root)
        for root in ALLOWED_ROOTS
    ):
        raise ValueError("verification syntax path is outside approved patch roots")
    return supplied


def check_sources(*, project_root: Path, paths: tuple[str, ...]) -> tuple[bool, str, int]:
    started = time.monotonic()
    try:
        for raw in paths:
            relative = _safe_path(raw)
            source_path = project_root / relative
            source = source_path.read_text(encoding="utf-8")
            compile(source, str(relative), "exec", dont_inherit=True)
        # The fixed application module creates its FastAPI app at import time.
        # Keep that deterministic import entirely inside this ephemeral container
        # and redirect its synthetic reset state to writable /tmp rather than the
        # read-only /workspace source tree.
        os.environ["VULNERABLE_STORE_DATABASE_URL"] = "sqlite:////tmp/m14-import.db"
        os.environ["VULNERABLE_STORE_SEED_FILES_DIR"] = "/tmp/m14-import-seed"
        os.environ["VULNERABLE_STORE_SCENARIO_FILES_DIR"] = "/tmp/m14-import-scenarios"
        importlib.invalidate_caches()
        importlib.import_module(FIXED_IMPORT_MODULE)
    except Exception as exc:  # bounded error text only; never execute generated tests
        return False, f"syntax/import check failed: {type(exc).__name__}: {str(exc)[:1000]}", max(
            0, int((time.monotonic() - started) * 1000)
        )
    return True, "all changed Python files compiled and the fixed application module imported", max(
        0, int((time.monotonic() - started) * 1000)
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Compile changed Python sources and fixed app import.")
    parser.add_argument("--path", action="append", required=True)
    args = parser.parse_args()
    passed, details, duration_ms = check_sources(
        project_root=PROJECT_ROOT,
        paths=tuple(args.path),
    )
    print(json.dumps({"passed": passed, "details": details, "duration_ms": duration_ms}))
    raise SystemExit(0 if passed else 2)


if __name__ == "__main__":
    main()
