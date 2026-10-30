#!/usr/bin/env bash
# Start the local-only MARS dashboard and its registered Docker lab.
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
        zenity --error --text="MARS needs the project's Python dependencies. Follow docs/OPERATOR_CONSOLE.md." || true
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
# The Q8-only profile must use its independently verified pinned CPU runtime.
# Preserve explicitly configured binaries and the older model cache fallback.
Q8_SOURCE="$ROOT/../Q8_C12_Integration_Audit_2026-10-14/staging/C12_Q8_CPU_Hybrid_Integration_2026-10-14/vendor/llama.cpp"
Q8_SERVER="$Q8_SOURCE/build/bin/llama-server"
Q8_PIN="b29c606e28a01b1bc8c1351026a0fa6e616bf6c4"
if [[ -z "${FYP_LLAMA_SERVER_BIN:-}" ]]; then
    if [[ "$FYP_MODEL_DIRECTORY" == "$ROOT/models" && -f "$ROOT/models/c08b-nf4-effective-Q8_0.gguf" ]]; then
        if [[ -x "$Q8_SERVER" && "$(git -C "$Q8_SOURCE" rev-parse HEAD 2>/dev/null || true)" == "$Q8_PIN" ]]; then
            export FYP_LLAMA_SERVER_BIN="$Q8_SERVER"
        else
            echo "Q8 pinned llama-server unavailable; model launch requires the approved CPU runtime." >&2
        fi
    elif [[ -x "$DEFAULT_CACHE/runtime/llama-b10964/llama-b10964/llama-server" ]]; then
        export FYP_LLAMA_SERVER_BIN="$DEFAULT_CACHE/runtime/llama-b10964/llama-b10964/llama-server"
    fi
fi
export PYTHONDONTWRITEBYTECODE=1
# Side-effect-free startup check for laptop integration tests.
if [[ "${SENTINEL_PRINT_MODEL_CONFIG_ONLY:-0}" == "1" ]]; then
    printf 'FYP_MODEL_DIRECTORY=%s\n' "$FYP_MODEL_DIRECTORY"
    printf 'FYP_LLAMA_SERVER_BIN=%s\n' "${FYP_LLAMA_SERVER_BIN:-}"
    exit 0
fi
# Optional, pinned evidence display only. Never evaluate this file as shell code.
STATE="${XDG_STATE_HOME:-$HOME/.local/state}/sentinel-fyp"
PID_FILE="$STATE/operator.pid"
APPROVAL_CONFIG="$STATE/archive-display.env"
load_archive_display() {
    [[ -e "$APPROVAL_CONFIG" ]] || return 0
    if [[ ! -f "$APPROVAL_CONFIG" || -L "$APPROVAL_CONFIG" ||
          "$(stat -c %u "$APPROVAL_CONFIG")" != "$(id -u)" ||
          "$(stat -c %a "$APPROVAL_CONFIG")" != "600" ]]; then
        echo "Invalid archive display configuration permissions; evidence hidden." >&2
        return 0
    fi
    local key value
    local -A pins=()
    while IFS='=' read -r key value || [[ -n "$key" ]]; do
        [[ -z "$key" && -z "$value" ]] && continue
        case "$key" in
            FYP_REGISTERED_RED_DISPLAY_PATH|FYP_ASSESSMENT_APPROVAL_PATH|FYP_PATCHED_REPLAY_APPROVAL_PATH|FYP_PHASE5_REPLAY_APPROVAL_PATH)
                [[ "$value" == /* && -f "$value" ]] || { echo "Invalid archive path; evidence hidden." >&2; return 0; } ;;
            FYP_REGISTERED_RED_DISPLAY_SHA256|FYP_ASSESSMENT_APPROVAL_SHA256|FYP_PATCHED_REPLAY_APPROVAL_SHA256|FYP_PHASE5_REPLAY_APPROVAL_SHA256)
                [[ "$value" =~ ^[[:xdigit:]]{64}$ ]] || { echo "Invalid archive digest; evidence hidden." >&2; return 0; } ;;
            *) echo "Unexpected archive configuration key; evidence hidden." >&2; return 0 ;;
        esac
        [[ ! -v "pins[$key]" ]] || { echo "Duplicate archive configuration key; evidence hidden." >&2; return 0; }
        pins[$key]="$value"
    done < "$APPROVAL_CONFIG"
    [[ "${#pins[@]}" == "8" ]] || { echo "Incomplete archive configuration; evidence hidden." >&2; return 0; }
    local prefix path_key sha_key actual
    for prefix in REGISTERED_RED_DISPLAY ASSESSMENT_APPROVAL PATCHED_REPLAY_APPROVAL PHASE5_REPLAY_APPROVAL; do
        path_key="FYP_${prefix}_PATH"
        sha_key="FYP_${prefix}_SHA256"
        actual="$(sha256sum -- "${pins[$path_key]}")" || return 0
        [[ "${actual%% *}" == "${pins[$sha_key]}" ]] || {
            echo "Archive approval checksum mismatch; evidence hidden." >&2
            return 0
        }
    done
    for key in "${!pins[@]}"; do
        [[ -v "$key" ]] || export "$key=${pins[$key]}"
    done
}
load_archive_display
if [[ "${SENTINEL_PRINT_ARCHIVE_CONFIG_ONLY:-0}" == "1" ]]; then
    for key in FYP_REGISTERED_RED_DISPLAY_PATH FYP_REGISTERED_RED_DISPLAY_SHA256 FYP_ASSESSMENT_APPROVAL_PATH FYP_ASSESSMENT_APPROVAL_SHA256 FYP_PATCHED_REPLAY_APPROVAL_PATH FYP_PATCHED_REPLAY_APPROVAL_SHA256 FYP_PHASE5_REPLAY_APPROVAL_PATH FYP_PHASE5_REPLAY_APPROVAL_SHA256; do
        [[ -n "${!key:-}" ]] || { echo "ARCHIVE_DISPLAY_CONFIG=NOT_CONFIGURED"; exit 0; }
    done
    echo "ARCHIVE_DISPLAY_CONFIG=CONFIGURED"
    exit 0
fi
mars_ready() {
    "$PYTHON" -c 'import json,urllib.request; x=json.load(urllib.request.urlopen("http://127.0.0.1:8090/api/console/status",timeout=0.5)); assert x.get("project")=="Autonomous Red–Blue Framework" and x.get("execution_mode")=="development preview"' >/dev/null 2>&1
}
open_mars() {
    [[ "${MARS_NO_BROWSER:-0}" == "1" ]] && return 0
    if command -v xdg-open >/dev/null 2>&1; then
        xdg-open http://127.0.0.1:8090/dashboard/ >/dev/null 2>&1 || true
    fi
}
# Keep the complete registered Docker lab available on each normal MARS launch.
# ZAP remains an explicitly approved, short-lived profile and is never started here.
# Preflight modes above intentionally have no Docker side effects.
if ! command -v docker >/dev/null 2>&1; then
    echo "Docker is required to start the complete MARS development stack." >&2
    exit 1
fi
if ! docker compose -f "$ROOT/compose.yaml" up -d --build --wait; then
    echo "MARS Docker lab could not be started; review docker compose ps." >&2
    exit 1
fi
# Reusing an existing verified localhost service must not launch a second process.
if mars_ready; then
    open_mars
    exit 0
fi
mkdir -p "$STATE"
chmod 700 "$STATE"
LOG="$STATE/operator.log"
"$PYTHON" -m uvicorn backend.app:app --host 127.0.0.1 --port 8090 --no-access-log >>"$LOG" 2>&1 &
SERVER_PID=$!
umask 077
printf '%s\n' "$SERVER_PID" > "$PID_FILE.tmp"
mv -f -- "$PID_FILE.tmp" "$PID_FILE"
cleanup() {
    if [[ -f "$PID_FILE" && ! -L "$PID_FILE" && "$(<"$PID_FILE")" == "$SERVER_PID" ]]; then
        rm -f -- "$PID_FILE"
    fi
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM
for _ in {1..30}; do
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "MARS could not start. Review $LOG" >&2
        exit 1
    fi
    if mars_ready; then
        open_mars
        wait "$SERVER_PID"
        exit $?
    fi
    sleep 1
done
echo "MARS did not become ready. Review $LOG" >&2
exit 1
