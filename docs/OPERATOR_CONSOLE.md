# MARS Dashboard: one application

MARS is the default React interface of the Autonomous Red–Blue FYP. The
older Sentinel static dashboard has been removed. The FastAPI backend and
its existing operator APIs remain accessible to the React UI.

## Start the local development stack

Double-click **MARS Dashboard.desktop** or run **./launch-mars.sh** from the
project root. It starts the required Docker Compose lab,
starts the MARS application on 127.0.0.1:8090 if it is not already running,
and opens http://127.0.0.1:8090/dashboard/. The root page redirects there.
Starting the app never automatically loads an LLM or executes an attack.
Historical Q8 runtime pins and archive-display approvals remain supported.

The launcher now requires Docker, builds and waits for both registered lab
services, and fails closed rather than opening a partial stack. Stop everything
with the desktop entry's **Stop MARS services** action or `./stop-mars.sh`.
Normal stop preserves the named runtime volume. The Docker security-lab network
is internal; do not expose the intentionally vulnerable app to unapproved
networks. See `docs/RED_TEAM_RUNBOOK.md` for the complete lifecycle.

## Run model-free Red and Blue verification

1. Open **Remediation** in the MARS sidebar.
2. Select SQL injection, reflected XSS or path traversal.
3. Click **Run offline Red → Blue verification**.
4. Inspect the actual Red baseline response, trusted Blue patch fingerprint,
   retest result and functional regression checks.

This executes real HTTP requests against separate disposable FastAPI/SQLite/
filesystem sandboxes. It does not call LLMs, modify live source, deploy a
Docker patch, or claim formal research results. **Prepare trusted preview**
remains available separately.

More detail: TOOL_DRIVEN_MARS_OPERATION_2026-10-24.md.

## Red operator review API (T08)

The `/api/red/operator` routes are **disabled unless** the MARS server starts
with a separately configured `MARS_RED_OPERATOR_TOKEN` containing at least 32
characters. Do not store the token in Git, a browser bundle, or a query string.
Authorized local clients send `Authorization: Bearer <operator token>` and an
approved `Origin` header. After fetching `GET /api/red/operator/csrf`, supply
its `csrf_token` as `X-Red-CSRF` with a unique `request_id` on
`POST /api/red/operator/reviews`. Replay IDs are rejected durably.

The release's effectful Red endpoints reuse these protections and additionally
enforce immutable assessment authorization, legal state transitions and
idempotent command IDs. The browser cannot provide a URL, command, resource
budget or authorization fingerprint. A review request alone still does not
approve, queue or execute an operation.

## Optional confined ZAP image preflight (T09)

The default `./launch-mars.sh` does **not** start ZAP. The official
ZAP 2.17.0 Linux/amd64 image is pinned to a verified registry manifest digest
in `compose.zap.yaml`. This separate, opt-in Compose overlay connects ZAP only
to a dedicated internal network shared with `vulnerable-store`. It uses
non-root/read-only hardening, 0.5 CPU, 512 MiB RAM, a 64-PID limit and
an idle 180-second lifetime. **It does not run a scan or expose a ZAP API.**

Review the local image and health behavior before opting in:

```bash
docker compose -f compose.yaml -f compose.zap.yaml --profile zap config --quiet
docker compose -f compose.yaml -f compose.zap.yaml --profile zap up -d --no-deps --no-build zap
docker network connect --alias vulnerable-store fyp-red-blue-lab_zap-target fyp-vulnerable-store
docker compose -f compose.yaml -f compose.zap.yaml --profile zap ps zap
# Only probe http://vulnerable-store:8000/health; do not run ZAP scans.
docker compose -f compose.yaml -f compose.zap.yaml --profile zap stop zap
docker compose -f compose.yaml -f compose.zap.yaml --profile zap rm -f zap
docker network disconnect fyp-red-blue-lab_zap-target fyp-vulnerable-store
docker network rm fyp-red-blue-lab_zap-target
```

The image is large and not part of normal startup. The pinned image was
downloaded and the health-only smoke test passed on 2026-10-27: internal
lab-target health responded, public TCP egress was denied, and the temporary
ZAP container/network were removed. The commands above assume the normal
Compose project `fyp-red-blue-lab` and must be stopped before cleanup.
Do not enable an active scanner or expose any ZAP API; registered
reconnaissance and dispatch safeguards are separate tasks.

## Troubleshooting

Run docker compose ps and check the MARS status endpoint at
http://127.0.0.1:8090/api/console/status. The container health checks must
pass. Direct host access to Docker port 8000 can be unavailable because the
Compose security-lab network is internal; do not disable that isolation.
