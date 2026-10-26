# MARS Dashboard: one application

MARS is the default React interface of the Autonomous Red–Blue FYP. The
older Sentinel static dashboard has been removed. The FastAPI backend and
its existing operator APIs remain accessible to the React UI.

## Start the local development stack

Double-click **MARS Dashboard.desktop** or run **./launch-mars.sh** from the
project root. It starts the Docker Compose lab if Docker is available,
starts the MARS application on 127.0.0.1:8090 if it is not already running,
and opens http://127.0.0.1:8090/dashboard/. The root page redirects there.
Starting the app never automatically loads an LLM or executes an attack.
Historical Q8 runtime pins and archive-display approvals remain supported.

If Docker cannot start, MARS reports the issue and can still provide
its local sandbox assessments. The Docker security-lab network is internal;
do not expose the intentionally vulnerable app to unapproved networks.

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

## Troubleshooting

Run docker compose ps and check the MARS status endpoint at
http://127.0.0.1:8090/api/console/status. The container health checks must
pass. Direct host access to Docker port 8000 can be unavailable because the
Compose security-lab network is internal; do not disable that isolation.
