# Operational Red-Blue Workflow: First Application Integration Milestone

**Date:** 2026-10-14

**Branch:** development

**Scope:** The next non-executing application milestone, not independent scientific model admission or a final experiment.

## 1. Existing system components reviewed

| Framework area | Existing implementation | Current integration status |
|---|---|---|
| Human-registered target and test policy | `services/target_registry.py`, `config/targets/`, `config/security_tests/`, `orchestrator/policy_engine.py` | Implemented; tested |
| Policy-controlled Red agent flow | `orchestrator/red_team_flow.py`, `services/controlled_executor.py`, `services/isolated_compose_executor.py` | Implemented and unit-tested; no newly admitted end-to-end live execution this gate |
| Existing typed Blue triage, monitoring and source analysis | `orchestrator/blue_team_flow.py`, `services/model_driven_decision_gate.py` | Implemented; integration gates require independent Red confirmation |
| Q8/C12 CPU model classification | `dashboard/api/q8_development_service.py`, `services/q8_c12_development_bridge.py` | Actual laptop Q8 HTTP classification previously demonstrated; still development-only |
| Trusted source compiler and deterministic preview | `services/trusted_remediation_compiler.py`, `dashboard/api/operator_service.py` | Prepared preview works on ephemeral source; not applied or verified |
| Actual patch branch, retest and verification | `orchestrator/patch_branch_flow.py`, `orchestrator/remediation_outcome_flow.py`, `experiments/synthetic_verification.py` | Implemented service flows and tests; no new fully connected operator-run demonstration |
| Read-only outcome dashboard | `dashboard/api/main.py`, `dashboard/api/read_service.py` | Existing experiment database reporting; Sentinel's separate operator preview did not present a unified assessed lifecycle |

**Main gap identified:** Q8 classification, registry checks, Red provenance, Blue authorization, patch preview and verification statuses were not represented as one traceable operator assessment. Model Studio produced a classification while Workbench displayed a separate trusted template patch. That separation could imply that the model observation directly justified the unrelated patch.

## 2. This milestone's actual integration

**New:** `services/registered_assessment_plan.py` combines existing typed model receipt, the **real human-controlled target/test registry**, existing `route_model_triage`, `authorize_registered_test`, and `authorize_source_analysis` with **no verified Red result**. It validates exact approved synthetic routes, methods and parameter names against the static registry.

Operational outcomes are explicitly separated from model labels:

- **Raw model prediction:** preserved without relabeling, including false positives and `unknown`.
- **Evidence-policy status:** records whether trusted safe evidence or independent Red verification is missing.
- **Operational verdict:** `suspected_requires_registered_verification`, `withheld_registration_mismatch`, `manual_review_required` or `benign_unverified_requires_trusted_safe_evidence`.
- **Reason code:** the existing Blue gate's reason or missing-evidence policy reason.
- **Execution authority:** always **false**. No model output, case name or registered-test eligibility can dispatch attacks, authorize source analysis, prepare patches or change final scientific admission.

The returned 8-stage plan displays target registration, preliminary model triage, registry selection, Red verification, Blue source analysis, trusted remediation, post-remediation verification and development-only reporting. Missing evidence is visibly marked **not executed / withheld**, never silently substituted with fixture results.

**Integrated:** The existing `POST /api/console/q8/classify` now saves `q8-assessment-plan.json` alongside its existing append-only raw llama/C12 evidence and returns `assessment_plan`. Sentinel Model Studio renders the separate operational verdict, registered-test candidate, evidence-policy result and staged handoff. **GET `/api/console/assessment/registry`** exposes only registered local target and bounded security-test metadata for the operator. Its handler never discovers or probes external hosts.

**Launcher improvement:** `launch-sentinel.sh` selects the exact pinned Q8 CPU llama.cpp runtime when the approved Q8 GGUF is available under `models/`, while retaining an explicitly configured override and legacy-runtime fallback. It has a no-server `SENTINEL_PRINT_MODEL_CONFIG_ONLY=1` preflight used only to verify the configuration without creating model processes or opening a browser.

## 3. Limitations and next practical milestone

This is an honest **operator integration milestone, not a successful live Red-Blue assessment**. All current Q8 Model Studio examples are hand-authored synthetic observations, not newly executed HTTP baseline/modified requests. The Q8 model's XSS false positives and failed source-line selection remain known limitations; no known model errors are fixed or hidden by this plan.

The next milestone requires a separately approved **isolated local target admission** and actual registered-test execution using the existing executor, with verified immutable Red evidence. Only then may the existing Blue gate evaluate a source selection, and only a grounded source selection plus trusted compiler policy can lead to patch preparation. Subsequent stages must actually apply a patch in an isolated approved branch, run functional and registered security verification, persist status/evidence, and display the outcome. Do not present the existing synthetic compiler preview as an executed or verified patch.

The original M18 RQ2 input contract, M20 historical 2/6 ineligible verdict, independent holdouts, Q8 weights, protected research material and planned 18 RQ1 / 180 RQ2 scientific observations remain unchanged. Additional specialist models are **future** extensibility only; avoid concurrent heavyweight residency on the 8 GB laptop.

## 4. Memory design and tests

Current CPU inference manager already supports explicit lazy model start, unload, single model residency, context 2048 for Q8, 2 CPU threads, localhost `llama-server`, pinned Q8 exact hash/size and a 4400 MiB available-memory guard. The Q8 model is stored on the local SSD; llama.cpp's default memory mapping can be used without converting this dense model into an MoE model. No unmeasured parallel specialist loading has been introduced.

Tests added or strengthened: `tests/test_registered_assessment_plan.py`, `tests/test_q8_console_development_classification.py`, and `tests/test_sentinel_q8_launcher_preflight.py`. They cover the real static registry, all three vulnerability registrations, same-route/method/parameter constraints, unknown and benign preservation, conflicting evidence, forged authority flags, HTTP API visibility and startup runtime selection.

All evidence for this milestone is kept outside the live repository under:

`/home/zain/Documents/RED FYP/Q8_C12_Integration_Audit_2026-10-14/app_workflow_gate/`

**Do not claim** model qualification, independently verified vulnerability discoveries, executed exploits, completed autonomous remediation or final research scores on the strength of this planning milestone.
