# Q8/C12 development-only application integration

**Status:** Prospective service-layer integration in the live `development` working tree. **Not final research approved**. The original Q6 provider, sealed holdout protocols, and M20 official 2/6 closure remain unchanged.

## Scope and artifacts

- New `services/q8_c12_development_bridge.py`: strict two-HTTP-observation input, existing `RQ2ClassificationDecision` validation and `route_model_triage`, read-only source snapshot, and `CompactSourceSelection` + AST line validation.
- Existing `dashboard/api/operator_service.py`: adds a *Q8-only* model-loading profile tied to **exact filename, size and SHA-256**. Older model filenames retain the original 3400 MiB memory limit and 1536 token context. No arbitrary QQ/CPU resources gain this exception.
- External C12 gateway and actual GGUF weights remain outside the repository at `/home/zain/Documents/RED FYP/ggff_engineering` and in the separately verified C12 staging folder. The bridge does not copy weights or vendor binaries into Git.
- Production-like persistent model sessions and raw C12 integration are **not** registered as final capabilities. The current service module is an opt-in engineering adapter and deliberately grants no execution or patch authority.

## Verified model candidate

- Model: `c08b-nf4-effective-Q8_0.gguf`
- Expected size: `3285473024` bytes
- Expected SHA-256: `51b63a132c73a592d954e96b15c1d28176f0cc3e5f05533304e92a6fb40ad304`
- C12 pinned CPU server commit: `b29c606e28a01b1bc8c1351026a0fa6e616bf6c4`.
- C12 frozen generation settings: temperature 0, seed 42, 192 max output tokens, repetition penalty 1.0, 2048 context, GPU layers 0. GUI model load still requires the caller to supply safe behavior and does not automatically configure a research-accepted C12 role prompt.

## Input schema mismatch: never invent evidence

The original RQ2 evaluator consumes `RQ2ClassifierEvent` with a single run-neutral application event. C12 was trained against **two HTTP exchanges** from the same route. It is **not** possible to losslessly construct C12's second request/response from the original RQ2 event alone. `refuse_single_rq2_event` raises a typed failure instead of mixing independent events, inventing missing response excerpts, or reading evaluator ground truth.

A later independently approved experiment design must decide whether to obtain prospectively captured paired HTTP evidence, train an appropriate single-event classifier, or use a different comparator. Changing frozen primary RQ2 inputs without approval would invalidate the original comparison.

## Safety and provenance

`classification_receipt` accepts C12 output only with a strictly shaped envelope, strict original Pydantic schema, and a declared `origin`: `q8_0_cpu_model` or `insufficient_evidence_policy`. Output includes **preliminary** action only, always `registered_test_dispatched=false`, `ready_for_source_analysis=false` and `ready_for_patch_preparation=false`. The claim of origin is reported metadata, **not external proof of which server process loaded the weights**.

`localization_request` reads only the original exact hash-bound synthetic `scenario_routes.py`, presents three function names and their source windows, and never exposes arbitrary file paths. `localization_receipt` requires an exactly rebuilt request, strictly typed four-field compact answer, trusted route-to-function match, function AST membership, and executable statement membership. Successful source selection still **does not** grant patch authority: the original trusted execution/provenance and compiler checks remain required.

`archive_gateway_reply` writes append-only `q8-*.json` files, creates no outputs within the Git working tree, and refuses overwrite. Callers must save each raw gateway/llama response **before** strict validation. Raw evidence may include synthetic request content; no secrets should be included.

## Console Q8 loading requirements

Set `FYP_MODEL_DIRECTORY` to the directory containing the verified GGUF, and `FYP_LLAMA_SERVER_BIN` to the pinned executable llama.cpp server. The console remains localhost-only.

The Q8-only profile requires **at least 4400 MiB `MemAvailable`** before model load, verifies **exact GGUF size and SHA-256** before spawn, and uses `MemoryMax=4400M`, `MemorySwapMax=512M`, `--ctx-size 2048`, single slot, two CPU threads, and zero GPU layers. Any other model retains the older 3400 MiB limit; the Q8 filename alone never bypasses hash verification.

The laptop audit observed approximately 3.3 GiB model-server resident RAM and 17–52 seconds for earlier example calls. These measurements do not guarantee latency and RAM behavior for the actual GUI workflow, and the new Q8 profile still requires controlled end-to-end launch evidence.

## Evidence and tests

- `tests/test_q8_c12_development_bridge.py`: strict typed mapping, malicious/benign/unknown and fail-closed source/security boundaries, append-only evidence.
- `tests/test_q8_console_load_profile.py`: Q8 SHA/size/RAM/launch flags and legacy loader preservation, with a **mocked** systemd command (never spawns model).
- Frozen developer C12 package and previous laptop synthetic smoke: `/home/zain/Documents/RED FYP/Q8_C12_Integration_Audit_2026-10-14/runs/20261014T043826Z-83864`.
- Earlier 3-case disposable rehearsal and failure: `/home/zain/Documents/RED FYP/Q8_C12_Integration_Audit_2026-10-14/disposable_integration/evidence/20261014T050827Z`. The original source rejection remains immutable.
- New standalone model-backed bridge diagnostic: `/home/zain/Documents/RED FYP/Q8_C12_Integration_Audit_2026-10-14/live_bridge_gate/run_live_bridge_q8.py`, saving separate SHA manifest and raw model responses, outside Git. Running it is not research qualification.

## Actual device evidence (2026-10-14)

The new service-layer Q8 diagnostic and a separate real console loader smoke both completed after the tests were authored. Evidence was saved outside the repository:

- `/home/zain/Documents/RED FYP/Q8_C12_Integration_Audit_2026-10-14/live_bridge_gate/runs/20261014T053640Z`. Actual Q8 classified synthetic traversal (`path_traversal`, 29.126s) and benign search (`benign`, 30.795s) and both mapped into the existing typed decision gate. Source localization selected the correct trusted function but **line 101**, a source comment, so the strict AST executable-line validator correctly refused the selection after 135.227s. The full raw completion was preserved, not overwritten or retried for a better score.
- `/home/zain/Documents/RED FYP/Q8_C12_Integration_Audit_2026-10-14/live_bridge_gate/console_smoke/20261014T054208Z`. The actual Sentinel Q8 profile launched the approved model in a user-scope localhost process, returned HTTP 200 from `/health`, and stopped cleanly. Actual model and Git identity were preserved. **No inference was performed in that loader-only smoke.**

The full repository suite with this code had **1042 passed, one deprecation warning**. New scoped Ruff checks passed. The known baseline repository-wide lint findings remain separate. These are engineering checks and do not qualify the model for final research or make the GUI capable of automatic source remediation.

## October 14 next gate: Model Studio Q8 classification and source diagnostic

An additional **development-only** endpoint now exists in the standalone Sentinel console:

- `GET /api/console/q8/status`: reports whether the exact locally loaded C08B Q8_0 candidate is available, with source localization, registered-test execution, patch preparation and final-research readiness all disabled.
- `POST /api/console/q8/classify`: accepts only one of four registered, hand-authored synthetic observation pairs (`traversal_private`, `xss_escaped`, `login_rejected`, `ordinary_search`). No user-supplied URLs, code, raw test payloads, network target addresses, or executor commands are accepted.
- The endpoint checks the manager's pinned filename/hash, validates the 14-file external C12 package manifest, builds its **original C12 classification prompt**, sends one bounded loopback-only `/completion` call, saves the input/raw reply and parsed gateway object **outside the Git repository**, and reuses the existing typed Blue gate. The resulting `select_registered_test` is always a *preliminary nonexecuting recommendation*, not registered-test authority.
- Model Studio presents a separate **Q8 classification · development only** section with explicit restrictions, stored evidence ID, origin, and preliminary Blue action. The older generic six-key capability check is disabled for the Q8 session because its output contract is different from the C12 three-field classifier.
- User-facing Q8 loading continues to require an explicit selected model and retains the Q8-only memory constraints. Its session is not automatically started by the new endpoint.

**Observed actual laptop endpoint run:**
`/home/zain/Documents/RED FYP/Q8_C12_Integration_Audit_2026-10-14/live_bridge_gate/console_classify_runs/20261014T055956Z`. The genuine Q8 model was loaded through Sentinel, returned HTTP **200**, and produced classification **`xss` at confidence 0.90** on the `ordinary_search` development pair which contains ordinary search terms and no demonstrated exploit. This is a **false positive under the synthetic example's assumptions**. The model-suggested registered-test consideration was **not executed**, and source authorization and patch preparation stayed false. Actual raw completion, typed response, clean model unload, source hash and Git preservation were recorded.

**Versioned source-view diagnostic:** A comment-elided V2 prompt was tested once, with all three source functions and original source line numbers preserved, under `/home/zain/Documents/RED FYP/Q8_C12_Integration_Audit_2026-10-14/live_bridge_gate/source_v2/20261014T055120Z`. Q8 selected `vulnerable_file_read` but line **105**, an executable `except` boundary handler rather than a vulnerability sink. The original AST-only V2 acceptance is retained unchanged as historical development evidence, but a separately recorded post-hoc *operational* review rejects it using the trusted compiler's pre-existing source replacement anchors. This is not an independent improvement in model localization accuracy. The earlier line-101 failure is also unchanged.

**Source safety hardening:** `localization_receipt` now refuses candidate lines that fail the trusted compiler's previously approved source-operation anchors, in addition to schema/source-SHA/function/AST checks. It does **not** replace wrong model selections with ground truth. It remains a safety admission boundary, not a neural accuracy metric, and still grants no automatic patch authority.

**Regression status:** 1,055 repository tests passed with one dependency deprecation warning, scoped Ruff passed, Node JavaScript syntax passed. These are engineering results and cannot substitute for independent G08–G10 or final M21 evaluations.

## Prospective C12 classifier diagnostic and frozen RQ2 compatibility (2026-10-14)

**Classification:** The prospective development suite `/home/zain/Documents/RED FYP/Q8_C12_Integration_Audit_2026-10-14/live_bridge_gate/prospective_benign_v1/20261014T061731Z` was pre-registered and SHA-256 sealed **before** the six inference calls. It used the **original frozen C12 classification prompt**, C08B Q8 exact model and frozen decoder. Every case was synthetic and no HTTP target was executed. Results: **4/6 correct; 3/3 modeled attack examples correct; 1/3 benign examples correct.** Q8 false-positively returned `xss` on an ordinary safe search and an HTML-escaped malicious-looking search term, in both cases with confidence 0.90. It correctly classified the rejected SQL-looking login as benign, although its explanation was imperfect. The observations support a **development diagnosis** of XSS benign-restraint weakness, not independent model qualification. Model and preregistered-case hashes verified unchanged. Never overwrite previous development baselines or post-hoc adjust these labels.

**Frozen RQ2 compatibility:** The original M18 `RQ2ClassifierEvent` is **one** normalized application log event with no paired HTTP excerpts. C12 requires **two** request/response observations. There is no information-preserving conversion. See `docs/Q8_RQ2_COMPATIBILITY_DECISION_2026-10-14.md` and `tests/test_q8_rq2_frozen_event_guard.py`. Six new typed tests establish the mismatch on valid synthetic M18 examples without changing `schemas/rq2_dataset.py`. The original 60-event/three-condition RQ2 protocol remains frozen. A future model adapter would require a separately versioned single-event prompt, development diagnosis and prospective research admission; paired HTTP demonstration outputs cannot be passed off as primary RQ2 results.

**Source selection:** Two development Q8 attempts selected the correct trusted function but invalid sink lines (101 comment, 105 exception handler). The added AST and approved compiler-source-operation checks prevent both from authorizing remediation. Tested relevant source anchors across all three vulnerabilities, while preserving model predictions verbatim. Deterministic source evidence grounded in the trusted compiler can be separately used as such, but must never be described as neural source localization or new research success.

**Operational decision:** Q8 remains available as a **non-authoritative classifier** for observed pairs, subject to independently attested registered Red evidence. This gate does not justify new retraining, autonomous patching, or unapproved model-use changes in final experiments.

## Research and operational blockers

1. Q8 still has a known synthetic benign SQL-login false positive (401 versus 401), and the prior full-source prompt failed an AST sink-line check. Keep software/red-evidence gates.
2. A successfully typed model output is not proof of correct source localization or patch safety. Investigate raw source selections, line semantics, and context budget before any staged remediation call.
3. The Q8-specific console profile is a controlled enhancement, not a validated full operator-workflow release.
4. Independent G08–G10 scientific admission, approved research freeze, 18 genuine RQ1 model-authored controlled runs, 180 RQ2 experiment observations, M22 analysis, report, and demo are not complete.
5. Do not commit or publish private sealed holdout-generation recipes. Preserve the nine local untracked qualification-related files from the previous GitHub WIP gate.

**Never claim:** the C12 50/50 post-hoc hybrid replay is 50/50 new neural accuracy; the current Q8 developer tests are blind qualification; the GUI preview is model-authored or applied remediation; or M20 historical fail was overturned.


## Separately versioned single-event RQ2 development prompt outcome

`services/q8_rq2_single_event_development.py` models exactly one original M18 `RQ2ClassifierEvent` without inventing C12 paired HTTP requests. On nine SHA-256 pre-registered, synthetic development events under its new **v1 single-event prompt** the Q8 model scored **6/9 total: attacks 3/3, ambiguous 3/3, benign 0/3**. All three benign cases were **`unknown`**; no false positive vulnerability claims occurred on those three, but benign discrimination failed. The original paired-HTTP C12 prompt/weights were untouched. This v1 is **NO-GO for primary RQ2 admission** despite passing output-schema checks. Complete evidence and caveats: `docs/Q8_RQ2_SINGLE_EVENT_V1_GATE_2026-10-14.md`.
