# Sentinel Red–Blue Operator Console

## What is included

The operator console adds a professional, browser-based workspace to the **existing** Python framework. It does not replace the FastAPI research read service, agent orchestration, target registry, trusted remediation compiler, experiment runners, storage tables or existing React dashboard. `dashboard.api.console` wraps the original read API when an actual SQLite experiment database exists and remains browsable with a clear empty state when it does not.

Start by double-clicking **Sentinel Console.desktop** (on the original laptop checkout) or `launch-sentinel.sh` in a file manager. The launcher resolves the existing project environment and opens `http://127.0.0.1:8090/` automatically. It does **not** run attacks, create Docker resources or trigger an experiment. The launcher uses the existing project virtual environment if available. Dependencies must have been installed once as described in the original README.

For a checkout elsewhere, adapt the `.desktop` file path or use `launch-sentinel.sh` directly. The server always binds to localhost, with a fixed local port, and permits only localhost/testserver hostnames. The original read-only experiment API continues to work if an existing SQLite database is configured using `FYP_DASHBOARD_DATABASE`.

## Model Studio

Git and Docker both exclude the entire repository-root models/ directory, regardless of file extension. The launcher creates this directory automatically, prefers its direct GGUF files if present, and otherwise retains the approved external cache fallback. Explicit FYP_MODEL_DIRECTORY overrides both. Verify with git check-ignore -v models/example.gguf models/example.txt; never force-track model weights or credentials.\n\nFor local GGUF model selection, set `FYP_MODEL_DIRECTORY` to an approved directory and `FYP_LLAMA_SERVER_BIN` to a pinned, executable llama.cpp server. On the original laptop, the launcher automatically discovers the existing cache sibling of the repo when present. Model selection is from regular `.gguf` filenames only, never arbitrary file paths. Server arguments are fixed and passed as a subprocess array, without shell commands supplied by the browser or model. The systemd user scope caps RAM at **3400 MiB**, swap at **512 MiB**, one inference slot, 1536-token context and 16-token microbatches, with conservative preflight free-memory checks. If the machine cannot enforce these limits, local model loading is blocked rather than unsafely starting an uncapped process. Only one model session can be active. Stop the session when finished.

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
