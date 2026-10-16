# Q8/C12 and Frozen M18 RQ2: Contract Compatibility Decision

**Date:** 2026-10-14

**Gate:** RQ2 compatibility audit and prospective development planning, NOT admission of a new experiment.

**Decision:** **Do not automatically route the frozen single-event M18 RQ2 dataset into C12's two-HTTP-observation classifier.** Preserve the original contract, dataset hashes, evaluator-only truth and historical experiment record.

## 1. Exactly what the current interfaces support

| Item | Existing frozen RQ2 v1 | Current C12 Q8 engineering classifier |
|---|---|---|
| Model input | `RQ2ClassifierEvent` normalized application log event | `{"route": ..., "observations": [baseline, modified]}` |
| Required observations | **One** normalized event | **Two** HTTP request/response observations |
| Fields | `schema_version, event_type, component, route_name, method, status_code, attributes, error_type` | Each observation includes `method, parameters, status_code, response_excerpt` |
| Response text | **Not available** | **Required for reliable semantics**, though C12 may abstain on some missing data |
| Model-visible labels | No evaluator ground truth | No evaluator ground truth |
| Output response type | `RQ2ClassificationDecision` | Same three keys (`classification, confidence, reason`), which can be validated through the existing type |
| Scientific status | Frozen evaluation design; research trials still pending | Q8 **development** candidate, not independently admitted |
| Permitted assumption | Single event means single event | Both responses must actually exist and match the same authorized route/method |

The **output** compatibility does not resolve the **input** incompatibility.

The typed barrier `refuse_single_rq2_event` in `services/q8_c12_development_bridge.py` explicitly raises `rq2_single_event_not_equivalent_to_c12_http_pair`. The new `tests/test_q8_rq2_frozen_event_guard.py` uses a real, valid `RQ2ClassifierEvent` and confirms this refusal, absence of response excerpts, immutable original data, and evaluator-truth exclusion. The original `schemas/rq2_dataset.py` was not modified.

## 2. Why a synthetic mapping would be invalid

For a single application event, we cannot infer a genuine baseline request, modified request, response body, or pairing identity. None of these can be filled from a vulnerability class label, target route name or evaluator metadata. Borrowing a different event would contaminate the input and change the unit of analysis.

Other impermissible shortcuts include: duplicating the same event to create two observations, choosing synthetic example fixtures according to the known truth label, reading source-test metadata from the evaluator-only `RQ2GroundTruthItem`, or turning deterministic C12 registry selection into purported model-only output. All would make the frozen RQ2 three-condition comparison unreliable.

## 3. Primary scientific route (recommended)

**Keep the original 60 frozen v1 normalized events and all three original RQ2 conditions on exactly equal model-visible event content**. If Q8 is to be assessed on RQ2, design an explicitly versioned **single-event** Q8 prompt adapter without inventing HTTP response content, and test it first on new synthetic development events with pre-registered labels, parser contract and generation settings. The adapter must expose that it is a *new prompt*, not the original C12 training/inference protocol, and preserve raw responses and model origin.

Before any independent evaluation: freeze the new prompt/adapter/model hash, declare metric definitions and abstention policy, verify qualified model acceptance (new G08-G10 admission), and obtain approval for its use as the RQ2 model condition. A model failing development checks does not become eligible simply because it can emit valid JSON. Retaining the original M18 input and evaluator-only labels ensures the original study unit is respected.

**No model inference on the protected 60-event set, no scoring against its ground truth, and no primary RQ2 launch are authorized by this document.** It is also acceptable to retain the original approved specialist or generalist RQ2 model under its valid single-event prompt, if independent admission of this Q8 prompt fails. This choice must be reported transparently rather than renaming the comparator after looking at final results.

## 4. Separate operational Q8 capability

The paired-observation C12 classification panel can remain a useful **supplementary development demonstration** with explicitly recorded HTTP pairs and evidence provenance. It must not be reported as a trial from the original M18 dataset or mixed into the 180 RQ2 scores. The C12 model confidence is uncalibrated and must not authorize Red execution or Blue patching without independent registered Red confirmation.

A second option, only with explicit supervisor-approved amendment, is to create a *new* paired-observation dataset and repeat **all** RQ2 comparators on identical new pairs. Such an amended study is a new version with new freeze/hashes/holdouts, not a corrected score for the original 60 events.

## 5. Outstanding gates

1. Complete **prospective development** classification diagnosis on synthetic pairs (original frozen C12 prompt) and label all examples as authored assumptions, not actual target execution. Do not retune mid-run.
2. Diagnose a new single-event Q8 prompt contract on development-only application event examples **before** proposing this for new G08–G10 qualification. This is unimplemented pending the diagnostic verdict.
3. Source localization must pass semantic sink checks, not merely AST executability, and cannot gain remediation authority on failure.
4. Obtain independent model admissibility and the relevant research design sign-off; preserve primary `ExperienceMode.DISABLED`, original budgets, original rule/model/hybrid comparators and original M20 `2/6 INELIGIBLE`.
5. Only then collect genuine research evidence for **18 RQ1 runs and 180 RQ2 condition observations** under their frozen approved protocol.

## 6. Integrity statement

This decision and its tests do not read any frozen evaluator truth/holdout bytes, modify `schemas/rq2_dataset.py`, run Docker, dispatch registered tests, patch a target, retrain the model, or assert new scientific qualification.

The 2026-10-14 service-level development evidence is stored outside the repository at `/home/zain/Documents/RED FYP/Q8_C12_Integration_Audit_2026-10-14/live_bridge_gate`.


## 7. Subsequent prospective single-event prompt diagnostic

The separately versioned Q8 single-event development adapter was implemented and tested **after** this original design decision; see `docs/Q8_RQ2_SINGLE_EVENT_V1_GATE_2026-10-14.md`. It passed schema-isolation/unit tests, but the original model's new prompt classified **0/3 benign** events as benign (all abstained as unknown) while classifying **3/3 explicitly evidenced synthetic attacks** and **3/3 ambiguous events** according to their pre-registered expected labels. Overall **6/9** on synthetic development cases. It is therefore **not admitted as the frozen primary RQ2 comparator**. No research-holdout bytes or original C12 prompt/weights were changed; do not overwrite original M18 results or treat these synthetic scores as blind qualification.
