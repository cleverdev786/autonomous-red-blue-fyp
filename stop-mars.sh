#!/usr/bin/env bash
# Stop the MARS-managed dashboard and registered Docker lab without deleting data.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE="${XDG_STATE_HOME:-$HOME/.local/state}/sentinel-fyp"
PID_FILE="$STATE/operator.pid"

stop_dashboard() {
    if [[ ! -e "$PID_FILE" ]]; then
        echo "MARS dashboard is not managed by the launcher."
        return 0
    fi
    if [[ ! -f "$PID_FILE" || -L "$PID_FILE" ||
          "$(stat -c %u "$PID_FILE")" != "$(id -u)" ]]; then
        echo "Refusing an unsafe MARS PID file: $PID_FILE" >&2
        return 1
    fi

    local pid process_root command_line
    pid="$(<"$PID_FILE")"
    if [[ ! "$pid" =~ ^[1-9][0-9]*$ ]]; then
        echo "Refusing an invalid MARS PID file: $PID_FILE" >&2
        return 1
    fi
    if [[ ! -d "/proc/$pid" ]]; then
        rm -f -- "$PID_FILE"
        echo "Removed stale MARS PID file."
        return 0
    fi

    process_root="$(readlink -f -- "/proc/$pid/cwd" 2>/dev/null || true)"
    command_line="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || true)"
    if [[ "$process_root" != "$ROOT" ||
          "$command_line" != *"uvicorn backend.app:app"* ||
          "$command_line" != *"--port 8090"* ]]; then
        echo "Refusing to stop PID $pid because it is not the MARS dashboard." >&2
        return 1
    fi

    kill -TERM "$pid"
    for _ in {1..40}; do
        [[ ! -d "/proc/$pid" ]] && break
        sleep 0.25
    done
    if [[ -d "/proc/$pid" ]]; then
        echo "MARS dashboard did not stop cleanly; PID $pid was left running." >&2
        return 1
    fi
    rm -f -- "$PID_FILE"
    echo "MARS dashboard stopped."
}

stop_dashboard
if command -v docker >/dev/null 2>&1; then
    docker compose -f "$ROOT/compose.yaml" down --remove-orphans
    echo "MARS Docker lab stopped; the named runtime volume was preserved."
else
    echo "Docker is unavailable; no containers were changed." >&2
fi
