# Sentinel Red–Blue Operator Console

## What is included

The operator console adds a professional, browser-based workspace to the **existing** Python framework. It does not replace the FastAPI research read service, agent orchestration, target registry, trusted remediation compiler, experiment runners, storage tables or existing React dashboard. `dashboard.api.console` wraps the original read API when an actual SQLite experiment database exists and remains browsable with a clear empty state when it does not.

Start by double-clicking **Sentinel Console.desktop** (on the original laptop checkout) or `launch-sentinel.sh` in a file manager. The launcher resolves the existing project environment and opens `http://127.0.0.1:8090/` automatically. It does **not** run attacks, create Docker resources or trigger an experiment. The launcher uses the existing project virtual environment if available. Dependencies must have been installed once as described in the original README.

For a checkout elsewhere, adapt the `.desktop` file path or use `launch-sentinel.sh` directly. The server always binds to localhost, with a fixed local port, and permits only localhost/testserver hostnames. The original read-only experiment API continues to work if an existing SQLite database is configured using `FYP_DASHBOARD_DATABASE`.

## Model Studio

Git and Docker both exclude the entire repository-root models/ directory, regardless of file extension. The launcher creates this directory automatically, prefers its direct GGUF files if present, and otherwise retains the approved external cache fallback. Explicit FYP_MODEL_DIRECTORY overrides both. Verify with git check-ignore -v models/example.gguf models/example.txt; never force-track model weights or credentials.\n\nFor local GGUF model selection, set `FYP_MODEL_DIRECTORY` to an approved directory and `FYP_LLAMA_SERVER_BIN` to a pinned, executable llama.cpp server. On the original laptop, the launcher automatically discovers the existing cache sibling of the repo when present. Model selection is from regular `.gguf` filenames only, never arbitrary file paths. Server arguments are fixed and passed as a subprocess array, without shell commands supplied by the browser or model. The systemd user scope caps RAM at **3400 MiB for legacy models** or **4400 MiB for the separately hash-approved Q8 profile**, swap at **512 MiB**, one inference slot, a 1536-token legacy or 2048-token Q8 context and 16-token microbatches, with conservative preflight available-memory checks. If the machine cannot enforce these limits, local model loading is blocked rather than unsafely starting an uncapped process. Only one model session can be active. Stop the session when finished.

Alternatively choose an approved OpenAI-compatible API provider (OpenAI, Groq, Together AI), enter its exact model name and a temporary API key. API endpoints are pinned to known HTTPS hosts, **not** user-provided arbitrary URLs. The key is used only for the current request; the application does not persist it. Neither local nor API models get filesystem, Docker, Git, target-selection, policy or command execution authority.

The **Run capability check** control sends exactly **four synthetic development capability questions** (SQLi, XSS, path traversal and benign restraint), validates the response against the strict `RQ2ClassificationDecision` schema and checks labels. Failed, malformed or unavailable model responses are shown as failures with no hidden retries. Passing this screen is **not** evidence of M20 qualification, source localization, independent Red planning, direct patch acceptance, or final RQ1/RQ2 suitability. Those require separately preregistered evaluations.

## Guided Red–Blue workbench

Select SQLi login bypass, reflected XSS or path traversal, then click **Prepare trusted remediation**. The API invokes the real `TrustedRemediationCompiler.prepare` using the existing policy, source-reader, registered target and registered vulnerability rules against an isolated temporary source copy. It returns an in-memory candidate diff and provenance. This action **does not** dispatch security tests, apply a patch, change the original checkout or run Docker. The final security-replay step is clearly labelled **NOT EXECUTED**.

The workbench demonstrates the architecture visually and honestly. Real attacks, accepted remediation, live Red/Blue model attribution, qualification and primary research trials still require their own authorized, recorded and source-pinned execution path.

## Research and safety

The research view preserves `ExperienceMode.DISABLED`, unknown telemetry as `NOT_REPORTED`, the **closed M20 2/6** original direct-patching result, and independently verified minimum final counts: **18 RQ1 runs** and **180 RQ2 condition-event observations**. It never substitutes a demonstration preview for research results. Frozen `ground_truth.jsonl` is evaluator-only, and **must not** be copied into any model prompt or qualification input.

The original `dashboard.api.main.create_app` remains read-only, and is reused without database schema changes. The new console does not write to the research database. The model manager is scoped to local presentation, not an authorization system for arbitrary targets.

## Sandbox verification

`python -m pytest -q -p no:cacheprovider tests/test_operator_console.py` tests the interface, trusted compiler previews, safe model selection, strict schema failures, API provider validation and origin restriction. Use the existing full test suite to validate the unchanged core. All tests that lack real GGUF weights or Docker are explicitly labelled offline; no final results are fabricated.

## Deployment checklist

- Verify the two original Git commits, frozen registry files, source hash, and original Docker/volume recovery evidence on the destination machine.
- Reconfirm local loopback binding, selected model SHA-256, capped systemd scope and adequate free RAM before local inference.
- If actual RQ1/RQ2 evidence is needed, obtain a frozen preregistered admission and run the original guarded executor separately. Do not use this console's preview or four-question screening as research measurements.
- Record original model outputs, errors, nonreported telemetry, source and runtime identities in external provenance files; never overwrite historical failures.


## Incremental React/Vite development-evidence view (2026-10-15)

The original React research dashboard remains separate from the Sentinel operator
console and now includes **Development Evidence** in the sidebar. It displays
the existing operator-pinned SQLi/Q8/XSS/traversal records through four **GET**
requests. Missing, mismatched, or incomplete evidence is labelled unverified.
It neither runs a security test nor loads a model or applies a patch.

Start the already-configured localhost Sentinel console on
`http://127.0.0.1:8090`, then from `dashboard/frontend` run:

```bash
npm run test:evidence
npm ci
npm run test:evidence
npm run build
npm run preview -- --port 4173 --strictPort
```

Visit `http://127.0.0.1:4173`, then select **Development Evidence**.
Vite dev/preview proxy same-origin `/api` requests to port 8090. Research
requests use `VITE_API_BASE_URL` when explicitly configured, or `/api`
otherwise. Operator evidence requests always use the local
`/api/console` path, independently of the research API override.

For the regular laptop launcher, build React once with `npm run build` and
open **React research dashboard** from the operator console sidebar. The same
FastAPI service serves the build at `http://127.0.0.1:8090/research-dashboard/`
and both dashboards use its existing `/api` routes. No separate Node server
or proxy is needed after building. Without a build, the React route returns
an explicit HTTP 503 instruction and the original console remains usable.
Running the launcher twice reuses the verified existing local service rather
than starting a second process. React operator parity is **incremental**,
not complete. The development
evidence is author-reviewed only; no independently accepted research or
prospective model-driven Red operation is inferred. XSS/traversal separate
patched-Docker legitimate-function checks remain unverified due to the prior
remote tool safety block.


## Cold-start archive restoration (2026-10-15)

The laptop's operator-approved evidence display pins are persisted **outside
Git**, in `~/.local/state/sentinel-fyp/archive-display.env` (mode 0600,
owned by the current user). This file holds only four absolute approval
manifest paths and four SHA-256 digests. It contains no model credentials,
raw holdout records, API keys, or authority to dispatch tests. The launcher
parses a fixed eight-key allowlist, rejects malformed or unsafe files,
and verifies the approval-file digests without evaluating shell code.
Explicit operator-provided approval environment variables are retained.

A restart without this local configuration still opens the operator console,
but the archived evidence panels correctly show `not_configured`. Moving
the project to a different laptop requires separately transferring and
validating the external development evidence and refreshing its pinned paths,
not committing the state file to the repository. The backend independently
revalidates the pinned underlying receipts on every read-only request.

Use `SENTINEL_PRINT_ARCHIVE_CONFIG_ONLY=1 bash launch-sentinel.sh` to check
whether all four pinned archive manifests are configured without starting
the server or browser. The original
`SENTINEL_PRINT_MODEL_CONFIG_ONLY=1` preflight remains unchanged.

On 2026-10-15 the launcher was cold-started with all eight display variables
unset, and the four localhost evidence routes returned the previously
verified archived Red, Q8/Blue, SQLi replay, and XSS/traversal replay states.
This was a restart-persistence check, **not** a model evaluation, a security
replay, or an independent research qualification.


## Resource-scope shutdown and recovery (2026-10-15)

The local model manager holds the single-model lock for the **entire**
`systemctl --user stop` and subprocess shutdown. The session remains
reserved if systemd rejects or times out during scope stop; it returns a
controlled `400` failure message to **Unload model**, not a false
`unloaded` success or an uncaught `500`. This intentionally fails
closed to prevent a second heavy model from starting while the first
could still own resources. Once systemd shutdown succeeds, the
underlying process is terminated if necessary, the log is closed and
the session slot is released. Repeat the normal Unload action after
resolving a failed systemd user scope; do **not** launch another heavy
model until the previous scope is confirmed stopped.

The Q8 allowlisted local profile is pinned to its exact GGUF SHA-256,
4400 MiB memory scope, 512 MiB swap allowance, one inference slot,
2048-token context, CPU-only layers and minimum 4400 MiB available
memory. The earlier Q6/legacy path retains its 3400 MiB cap.
The shutdown failure tests are **mocked scope/process tests**. No
large GGUF or real model subprocess was loaded during this gate,
so the full physical resource budget is not independently qualified.


## Development evidence export and keyboard navigation (2026-10-15)

Open **Evidence & audit** in the localhost operator console and choose
**Download development evidence JSON**; the embedded React dashboard exposes
the same download. Both use the single read-only endpoint
`GET /api/console/assessment/export`. Its JSON contains only scoped
verification statuses, registered test/run identifiers, the preserved Q8
classification label, and explicit remaining limitations. The server
revalidates the four operator-pinned archives on each request. It does **not**
export raw HTTP exchanges, unrestricted model outputs, private paths,
credentials, registered holdouts, or the complete audit record.
If approval evidence is missing or mismatched, the export reports the
reviewer's blocked/not-configured status rather than inventing a pass.
The downloadable snapshot is development self-review, **not** independent
scientific qualification or a reproducible complete evidence package.
There is no POST handler, and the response prevents caching and MIME sniffing.

Keyboard access in the original console uses **Skip to main content**,
visible high-contrast focus outlines, focus restoration upon sidebar
navigation, and native anchor/download controls. Both interfaces respect
the reduced-motion preference. These checks are automated accessibility
smoke tests only, **not** a full assistive-technology WCAG audit.

For installation on the original laptop, `Sentinel Console.desktop`
launches the current checkout, and `npm run build` in
`dashboard/frontend` prepares the embedded React assets. A missing
build falls back to the original operator UI and returns a clear HTTP 503
instruction at the React route. The existing frontend dependency tree and
desktop entry were validated in this gate.

A genuinely empty CPython 3.12 virtual environment was also used to install
the **built Python wheel and its staged dependencies with networking disabled**.
The resulting console passed the read-only registered-policy catalogue,
three trusted SQLi/XSS/traversal previews, and the embedded React HTML/CSS/JS
checks. The wheel includes `security_tests`, `infrastructure`, `dummy_apps`,
the immutable registration JSON and built React assets. The checked Linux
x86_64 wheelhouse is stored outside Git as
`Downloads Red Blue/Sentinel_Python_Offline_Install_2026-10-15_v2.zip`;
see its `INSTALL.txt` and `SHA256SUMS.txt`.
**Limits:** it was installed on this same laptop, not an independent machine.
The archived evidence approvals, models, holdout material and vulnerable
Docker runtime are deliberately NOT included. No independent research,
cross-platform installation, or full assistive-technology audit is qualified.


## Incremental React trusted workbench (2026-10-15)

The embedded React page now has **Trusted Preview** alongside Development
Evidence. It obtains the current three synthetic registered scenarios from
`GET /api/console/scenarios`, matches their frozen registered-test IDs,
and uses only the existing strict `POST /api/console/preview` handler.
It shows a bounded inert diff and SHA-256 **only** when the returned
scenario/test identity matches and the response is `prepared=true`,
`applied=false`, `verified=false`, `final_research=false`.
Malformed or mismatched responses fail closed in the UI. Firefox's isolated
browser run completed the three registered previews and rejected a forged
mismatched result. It did **not** dispatch a registered test, run a model,
apply a repair, or produce a scientific observation.

The original operator console remains the fallback for model controls and
official registered replays. Full React feature parity and the proposed
frontend/backend restructuring are **not** complete.
