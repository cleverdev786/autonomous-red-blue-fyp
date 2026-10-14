#!/usr/bin/env bash
# Start the local-only operator UI and open its browser page. No Docker lifecycle actions.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
if [[ -x "$ROOT/.venv/bin/python" ]]; then
    PYTHON="$ROOT/.venv/bin/python"
else
    PYTHON="$(command -v python3)"
fi
if ! "$PYTHON" -c 'import fastapi,uvicorn,sqlalchemy,pydantic' >/dev/null 2>&1; then
    if command -v zenity >/dev/null 2>&1; then
        zenity --error --text="Sentinel needs the project's Python dependencies. Follow docs/OPERATOR_CONSOLE.md." || true
    fi
    exit 1
fi
# Local weights are ignored by Git; preserve compatibility with the external Q6 cache.
mkdir -p -- "$ROOT/models"
DEFAULT_CACHE="$(dirname "$ROOT")/.cache/autonomous-red-blue-fyp/m20-feasibility-v1"
if [[ -z "${FYP_MODEL_DIRECTORY:-}" ]]; then
    if find "$ROOT/models" -maxdepth 1 -type f -name '*.gguf' -print -quit | grep -q .; then
        export FYP_MODEL_DIRECTORY="$ROOT/models"
    elif [[ -d "$DEFAULT_CACHE/models" ]]; then
        export FYP_MODEL_DIRECTORY="$DEFAULT_CACHE/models"
    else
        export FYP_MODEL_DIRECTORY="$ROOT/models"
    fi
fi
if [[ -z "${FYP_LLAMA_SERVER_BIN:-}" && -x "$DEFAULT_CACHE/runtime/llama-b10964/llama-b10964/llama-server" ]]; then
    export FYP_LLAMA_SERVER_BIN="$DEFAULT_CACHE/runtime/llama-b10964/llama-b10964/llama-server"
fi
export PYTHONDONTWRITEBYTECODE=1
mkdir -p "${XDG_STATE_HOME:-$HOME/.local/state}/sentinel-fyp"
LOG="${XDG_STATE_HOME:-$HOME/.local/state}/sentinel-fyp/operator.log"
"$PYTHON" -m uvicorn dashboard.api.console:app --host 127.0.0.1 --port 8090 --no-access-log >>"$LOG" 2>&1 &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true' EXIT INT TERM
for _ in {1..30}; do
    if "$PYTHON" -c 'import urllib.request; urllib.request.urlopen("http://127.0.0.1:8090/api/console/status",timeout=0.5)' >/dev/null 2>&1; then
        if command -v xdg-open >/dev/null 2>&1; then
            xdg-open http://127.0.0.1:8090/ >/dev/null 2>&1 || true
        fi
        wait "$SERVER_PID"
        exit $?
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "Sentinel could not start. Review $LOG" >&2
        exit 1
    fi
    sleep 1
done
echo "Sentinel did not become ready. Review $LOG" >&2
exit 1
