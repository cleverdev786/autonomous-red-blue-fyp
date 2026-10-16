# MARS Backend

**Canonical Python ASGI entrypoint:** `backend.app:app`

From the repository root, in the existing virtual environment:

```bash
.venv/bin/python -m uvicorn backend.app:app --host 127.0.0.1 --port 8090
```

The backend is already implemented. This package provides a discoverable and
stable entrypoint without copying backend logic or introducing a second server.

## Where the backend code currently lives

| Responsibility | Existing authoritative location |
|---|---|
| FastAPI app factory, route mounting and compatibility | `dashboard/api/console.py` |
| MARS assessment drafts, job states and preflight | `dashboard/api/mars_plans.py` |
| Operator/model management APIs | `dashboard/api/operator_service.py` |
| Read-only historical run API | `dashboard/api/main.py`, `read_service.py` |
| Deterministic registered executor | `services/controlled_executor.py` |
| Isolated Docker execution verification | `services/isolated_compose_executor.py` |
| Durable single-attempt safety store | `services/mars_dispatch_intent.py` |
| Externally admitted SQLi job handoff | `services/job_dispatch.py` |
| Receipt evidence reconciliation | `services/receipt_record.py` |
| Independently bound SQLi patch preview | `services/blue_preview.py` |
| Captured Red to model input | `services/blue_input.py` |
| Explicit local Q8 job classification | `services/blue_classify.py` |
| Model-selected source localization | `services/blue_localize.py` |
| Red/Blue workflow orchestration | `orchestrator/`, `agents/` |
| Persistent local MARS workspace | `~/.local/state/mars/workspace.sqlite3` |
| React web application | `dashboard/frontend/` |

## Boundaries

A backend package is not a new authorization mechanism. No new execution
permission is conferred by this entrypoint. The existing `/api/mars/jobs/{id}/start`
route intentionally refuses launch. The admitted development-only SQLi handoff is
instead explicitly invoked with `python -m services.job_dispatch`,
using `--help` to inspect its required arguments. It accepts an existing
scope-reviewed MARS job, an independently reviewed external admission file and
SHA-256, and an external evidence directory. Its case/run identifier must be
`mars-` followed by the job UUID without hyphens. It reuses the isolated
executor's Git, Docker and source checks, then commits exactly one durable
attempt intent before delegation. A failed or uncertain dispatch is **never
retried automatically**.

**This is not independent admission itself.** Do not invoke the real worker
without separately reviewed Docker/source pins and permitted synthetic runtime.
A returned executor receipt must match the saved external receipt bytes,
registered SQLi observation (when present), and durable admission reference
before one audited receipt summary is persisted. The React Assessments view can
read `GET /api/mars/jobs/{id}/execution`, which distinguishes
`not_dispatched`, `outcome_unknown`, and `receipt_recorded` with the actual
reported outcome. The durable intent stays unknown to forbid unsafe retries.
The SQLi development-only patch preview can be recorded with
`python -m services.blue_preview --help`, supplying the existing job database,
pinned source checkout, archived evidence directory, admission path and its
independently obtained SHA-256, plus the independently obtained receipt SHA-256.
It requires a confirmed, matching archived registered Red result and reruns
the repository's existing archived Red evidence verifier **without Docker**.
Only then does it invoke the existing deterministic trusted patch compiler
in an ephemeral source copy; no source file is changed or patched.

`GET /api/mars/jobs/{id}/proposal` and the React Assessments View proposal
show the resulting diff with explicit `model_decision_used=false`,
`patch_applied=false`, `security_replayed=false`, and
`final_research_qualified=false`. This is a source-grounded deterministic
development proposal, **not** a model-generated Blue classification or repair
acceptance.

### Local Q8 classification of independently bound Red observations

`services.blue_input` reconstructs the registered SQLi pair using the
**frozen registered request definitions** and **actual archived response
excerpts**. The original HTTP request bodies were not captured, so this is
a documented reconstruction, not a raw HTTP trace. Classification and source
localization prompt inputs contain no exploit evaluator truth.

The Assessments view includes **Classify with Q8** and **View Blue result**.
The former calls `POST /api/mars/jobs/{id}/classify` (local-origin only).
The server must have an actually loaded, SHA-verified C08B Q8 model and its
independently validated external C12 prompt package. It also needs five
operator-controlled environment variables, configured before server startup:

- `MARS_SOURCE_ROOT`: exact registered archived source checkout
- `MARS_EVIDENCE_DIR`: external registered Red case directory
- `MARS_ADMISSION_PATH`: independently reviewed admission file
- `MARS_ADMISSION_SHA256`: externally pinned admission digest
- `MARS_RECEIPT_SHA256`: externally pinned case receipt digest

The browser cannot supply paths or pins, and classification never launches
Docker. Model request/response bytes are saved in the existing external,
append-only Q8 evidence location. One classified job allows one attempt only;
an interrupted inference is shown as `outcome_unknown`, never silently
retried. The model's **actual label** is retained, even if benign, unknown,
or wrong. All Q8 decisions remain development-only and
**cannot authorize source analysis or patch application**.

### Model-selected SQLi source localization

A saved, actual Q8 `sql_injection` prediction can be followed with
`POST /api/mars/jobs/{id}/localize`. A non-SQLi or unknown/benign label
cannot enter this path. The same five server-side independently pinned Red
inputs are required as for classification. The worker **revalidates** the raw
archived Q8 classification and the independently bound Red observation before
using the **manifest-verified, existing C12 localization prompt**. It sends
only the captured HTTP pair and exact trusted numbered source snippets.

The model selects `function_or_route`, `sink_line`, `root_cause` and
`confidence`, validated by the existing compact-source schema, executable
source-line verifier, bound source registry and Blue analysis adapter. Raw
model responses remain in separate, external append-only evidence, with
SHA-256 fingerprints for the localization input and raw model response. A failed
or interrupted localization stays `outcome_unknown` and cannot auto-retry.
`GET /api/mars/jobs/{id}/localization` and Assessments **View source
finding** display the recorded selection. The UI only offers **Localize
with Q8** after a recorded SQLi prediction is displayed and Q8 is ready.
No browser-supplied paths, new Docker dispatch, Git mutation, patch authority
or research admission have been added.

### Isolated Git branch preparation

`python -m services.blue_branch --help` exposes the operator-only
`prepare_blue_branch` workflow. It requires the same independently pinned
workspace job, registered Red archive and admission/receipt hashes, plus
`--output-parent` pointing to an existing **external** directory outside
the live repository.

The worker rereads the saved Q8 raw classification and raw source selection,
validates both against registered Red evidence and the exact pinned source
snapshot, then invokes the existing deterministic remediation compiler.
An isolated Git repository is created beneath the external output directory,
with a snapshot `main` and an `agent-patch/` branch containing only the
staged SQLi source change. This isolated snapshot's baseline commit is **not**
the original repository commit. Neither the live development branch nor
the vulnerable baseline is checked out, edited, or committed by this action.

The branch result distinguishes model-selected localization from deterministic
patch generation. Tests include a sandboxed application-level SQLi/legitimate
login regression, but the worker does **not** itself claim functionality
verification or a registered Docker replay. Independent replay and acceptance
still need to be integrated before any final repair or research claim.

The protected baseline and disabled HTTP Red execution endpoint remain unchanged.

Legacy ASGI imports such as `dashboard.api.console:app` continue to work.
A future physical migration of the API modules should be done separately with
endpoint and package compatibility coverage, not through duplicated code.

### Isolated in-process registered SQLi replay

After **operator-only** staging via `python -m services.blue_branch`,
save its JSON result to a file outside the source checkout. Run:

```bash
python -m services.blue_replay \
  --branch-receipt /absolute/external/branch-receipt.json \
  --output-parent /absolute/external/patch-artifacts \
  --source-root /absolute/pinned/source-checkout
```

`services.blue_replay` checks the exact separate Git branch, pinned
unpatched baseline, staged diff SHA-256 and exact trusted SQLi source
replacement **before executing any patched code**. It then uses
`SqlInjectionLoginBypassTest.build_steps()` and
`SqlInjectionLoginBypassTest.evaluate()` against an in-process FastAPI
application with a private, temporary SQLite database. It requires the
registered control and injection requests to both return 401 with no
registered exploit evidence, plus successful legitimate scenario login,
normal login, invalid-password refusal and app health.

The write-once evidence is saved at
`<output-parent>/blue-patch-<job UUID hex>/replay.json`. The returned
`report_sha256` authenticates those bytes. An attempt reservation is
written first, preventing silently repeating a failed or interrupted
replay. The live repository's application source and Git branch are never
modified; failed checks are recorded with `status=failed`.

This is **in-process registered-test replay**, NOT the independently
admitted, isolated Docker registered-security replay required for actual
remediation acceptance. The report always states
`docker_replayed=false`, `final_repair_accepted=false`, and
`final_research_qualified=false`. Neither application-level success nor
a simulated Red fixture should be promoted to final research evidence.

### Patched Docker review candidate (offline, not deployment)

The previous `blue_replay` result must have `status=passed`. From the
operator-owned external directory, use:

```bash
python -m services.blue_docker \
  --branch-receipt /absolute/external/branch-receipt.json \
  --output-parent /absolute/external/patch-artifacts \
  --source-root /absolute/pinned/source-checkout \
  --replay-sha256 /the/64-character/sha256/from/blue_replay
```

The SHA-256 argument is a **digest string**, not a filename. The command
validates the staged Git patch and the recorded in-process SQLi checks, then
reads only committed Dockerfile inputs from the development Git tree. It
creates an external `docker-context/` with the exact trusted SQLi source
replacement and a `compose.blue.yaml` whose project/image/container/network/
volume names are unique to the job. The frozen Compose isolation verifier must
pass, including no published ports, internal-only bridge, read-only containers,
dropped capabilities, and CPU/memory/PID restrictions. The output
`candidate.json` inventories SHA-256 of every build-context file and records
both the development source Git commit and staged patch fingerprint.

Neither producing `candidate.json` nor hashing it grants runtime permission.
No Docker CLI is invoked, no image is built, and no containers are started or
stopped. The existing baseline-only `IsolatedDockerExecutor` explicitly
requires the **original vulnerable route SHA-256** and cannot be reused for a
patched image. An independent reviewer must approve a separate patched-image
build/deployment, pin image and daemon/container identities, verify isolation,
and explicitly admit a single registered replay. Until those actions occur,
`image_built=false`, `docker_executed=false`,
`independent_admission_granted=false`, and `final_repair_accepted=false`.

### Independently admitted patched Docker replay

The offline `blue_docker` candidate **does not authorize live execution**.
A separately reviewed image build and previously started, isolated Docker
services must exist before using the operator-only
`python -m services.blue_live` command. This command does not build, start,
stop, reset, or remove any Docker resources.

The operator supplies two externally reviewed, SHA-256-pinned artifacts:

1. A canonical `BlueLiveAdmission` JSON containing the candidate SHA-256,
   independent image-build attestation SHA-256 and its path, pinned Docker
   daemon, image, application/executor container IDs, network ID, and the one
   allowed registered SQLi run. The admission file's SHA-256 **must be pinned
   independently**; do not discover and then trust its hash in the same
   process. An approval flag alone is not proof of reviewer authorization.
2. A separately retained JSON image-build attestation binding the reviewed
   candidate SHA-256 to the image and Docker daemon identities, the patched
   source hash, and the independently preserved build-log SHA-256. Its
   contents and provenance require an independent human review.

After independent approval, the authorized operator can invoke:

```bash
python -m services.blue_live \
  --candidate-dir /absolute/external/docker-context \
  --candidate-sha256 <externally-pinned-candidate-sha256> \
  --admission-path /absolute/reviewer/admission.json \
  --admission-sha256 <independently-pinned-admission-sha256>
```

The worker verifies the complete candidate-file inventory and frozen
isolation policy; checks the approved build attestation, active Docker daemon,
image, network, and both container identities and isolation controls; and
hashes registered implementation/source bytes **inside each container**.
Only after those checks does it create a no-retry intent and use the frozen
`infrastructure.executor.run_verification_test` command for
`sqli-login-bypass-001`. It saves raw registered output externally and
rechecks runtime identities afterward. Forged or incomplete results never
count as a passed replay.

The output explicitly separates `evidence_scope=live_pinned_docker` from
`injected_offline_runner` (the latter is used by unit tests only). Even a
passing Docker replay does not grant repair acceptance or research
qualification without independently assessed functionality and replay evidence.
The baseline-only `IsolatedDockerExecutor` and its original approvals are
unchanged; they must not be reused as patched-target approval.

### Author-authorized patched SQLi Docker smoke (2026-10-16)

An actual, isolated, non-research Docker smoke test of the **trusted
deterministic SQLi repair** was completed. The cached vulnerable base image
(`sha256:2f3d8290709fb13e193075fd2c7f555fc08f959d7d58c899dda74cbb2a6029ea`)
was verified to contain the pinned unmodified source
(`f8675d5bed857138f49cdf717bd4c696aad7e4e42c5f14cd41b4623b140a6e5d`).
A separate local image used the exact trusted deterministic replacement
(`c98aaccb4577804a7606b3e7059b5669e15ced05004c3ae9ba3a2ff14931fe98`),
which was verified inside **both** containers.

The real registered `sqli-login-bypass-001` control and injection steps both
returned HTTP 401; legitimate scenario and application logins, invalid-password
refusals, and health all passed (five functional checks). The registered
executor correctly reported `error_code=evidence-not-observed`, not a
transport failure. `blue_live` now accepts this expected completed,
non-exploited result only when its recomputed registered evidence is empty,
and rejects contradictory error codes.

The author-authorized smoke report and raw outputs are retained outside Git
under `~/.local/state/sentinel-fyp/blue-docker-smoke-20261016/`.
The final `smoke-report.json` SHA-256 is
`5df68156ef407140bd6f074f3d097b9f1a4f9579b8857969d42aeb61d47d2687`.
Only smoke-specific containers were started and subsequently stopped; the
separate image remains cached. This result does **not** show actual Q8 model
inference, a model-driven job assessment, independent research evaluation,
or final FYP remediation qualification. Historical baseline evidence and
protected research holdouts were not modified.

#### Development-only Q8 source prompt v2

The 2026-10-17 real SQLi development job confirmed baseline exploitation and
recorded a correct Q8 classification, but its one-shot C12 source localization
selected the multiline query's opening line 46 and returned a 202-character
explanation. Both violated existing source-selection checks; the archived
model completion remains unchanged and the job remains `outcome_unknown`.

For **new development jobs only**, `q8-localization-v2` appends a short
source-agnostic instruction to the independently manifest-verified C12
localization prompt. It asks Q8 to select the exact line containing the unsafe
operation (rather than a multiline statement header or comment) and limit
`root_cause` to 160 characters. It does not supply SQLi sink line numbers or
functions, change model generation settings, relax the 200-character schema,
rewrite model output, or modify C12's frozen files. The complete composed
prompt is archived before inference as `q8-localization-prompt.json`; its
profile and SHA-256 accompany any recorded finding. The isolated Git patch
workflow independently reconstructs that prompt and refuses changed or
unversioned evidence. Previous failed attempts are not reprocessed or retried.


### Live local model identity in the dashboard

The **System** page at `/dashboard/system` displays the active GGUF filename,
session state (`unloaded`, `starting`, `running`, or `stopped`), model
identifier, loaded SHA-256 fingerprint and local inference endpoint from the
existing read-only `/api/console/models/local` response. It updates every 15
seconds, or immediately on **Refresh status**, and labels non-active GGUF files
as on disk rather than loaded. The page refuses missing or malformed active
model identity metadata instead of guessing which model is running. A running
model is **not** an independently research-qualified model.


### Prospective AST-aware source-localization v3

For **future** one-shot model attempts, `q8-localization-v3-ast` accepts
either a directly identified unsafe SQL operation or the *starting line of
the same executable multiline SQL assignment*, provided that the trusted
hash-pinned source AST independently proves a `payload.username`
interpolation at a unique preapproved unsafe source anchor and a connected
registered SQL execution call. It does **not** accept arbitrary lines inside
that statement, an unrelated assignment, comments, different source functions,
or modified baseline source. The original model-selected line and the
verified unsafe operation line are saved as **different fields**; the
original raw model completion remains unchanged. The isolated patch gate
rebuilds and verifies both lines independently from the registered source.
This is a prospective development contract, not retroactive acceptance of
v1/v2 archived model outputs or final research qualification.
