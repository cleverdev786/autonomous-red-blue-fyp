# Q8 RQ2 single-event prompt: development qualification gate

**Date:** 2026-10-14

**Verdict:** **NO-GO for primary RQ2 model admission.** The new single-event prompt is technically schema-compatible, but its classification behavior is not fit for the frozen benign/attack comparator. The model is unchanged and no training was performed.

## 1. Experiment authority and frozen configuration

This was a **prospectively registered, synthetic development diagnostic**. It did **not** read or score the original M18 frozen 60-event dataset, any evaluator ground-truth files, independent model holdouts, or final study cases.

- Prompt version: `q8-rq2-single-event-v1-development`. This is **new** and explicitly **not** the original C12 paired-HTTP classifier prompt.
- Prompt SHA-256: `6b4cc45cc5b3067653e8e6e3b65cc0f026e28ad66474a7e0f69157cc94031510`.
- Q8 model SHA-256: `51b63a132c73a592d954e96b15c1d28176f0cc3e5f05533304e92a6fb40ad304`.
- Pre-registration SHA-256: `95542652994e4d3fafa2651cb82bd6c77a77a8cab7ff726e105b9e7f14a55d2d`.
- Pinned llama.cpp CPU server; `ctx_size=2048`, `threads=2`, `n_gpu_layers=0`, `temperature=0`, `seed=42`, `n_predict=192`, `repeat_penalty=1.0`; no retries and no prompt edits during the nine cases.
- Input: exactly one `RQ2ClassifierEvent` model-visible JSON object with the original frozen fields, with `error_type` and event attributes as recorded. Output: the exact original `RQ2ClassificationDecision` three-field type.
- Case expectations: **hand-authored synthetic assumptions**, not proof that any actual HTTP security test succeeded.

All cases, assumptions, configuration, and expected labels were SHA-256 sealed **before the first model call**.

## 2. Recorded performance

| Development case group | Correct | Total | Observation |
|---|---:|---:|---|
| Benign, affirmative safety indicators | **0** | 3 | All three predicted `unknown`, not `benign` |
| Explicit attack indicators | **3** | 3 | One each of SQLi, XSS, traversal |
| Ambiguous single events | **3** | 3 | All correctly predicted `unknown` |
| **All nine** | **6** | **9** | Three benign misses due to abstention |

All nine responses parsed into the existing typed output schema, and all nine source raw response files passed their manifest hashes.

The *positive-vulnerability false-positive count* on these three benign examples was **zero**. But that is **not benign classification success**, since every benign label was missed. Conversely, these authored examples with explicit outcome indicators may be easier than genuine runtime log classification; 3/3 synthetic attack accuracy alone cannot establish real-world effectiveness.

Some model reasons were overconfident or asserted unsupported interpretations of the attributes. These statements are model output, **not proof** of causal exploitation.

Model inference was relatively slow at **approximately 49–55 seconds per case** under the tested laptop conditions, excluding final application workflow overhead.

## 3. Source of truth and software status

- Source adapter: `services/q8_rq2_single_event_development.py`. Strictly validates the original M18 fields and forbids introducing a second HTTP observation, evaluator labels, source test IDs, or other hidden metadata. Preserves model-generated class and reason without post-hoc rewriting.
- Typed adapter output remains **non-authoritative**: `registered_test_dispatched=false`, `source_analysis_authorized=false`, `patch_preparation_authorized=false`, `research_admitted=false`.
- Test suite: `tests/test_q8_rq2_single_event_development.py`, including exact schema, prompt/injection data isolation, label validity, unknown, and output authority checks. The focused suite recorded **31 passed**.
- M18 `schemas/rq2_dataset.py`, historical M20 conclusion, original C12 prompt/weight files, and trusted patch compiler were unchanged.

## 4. Research decision

**Do not use this v1 prompt as the model-only condition in the frozen RQ2 primary study.** Its `unknown` predictions on clearly benign examples make it an unsuitable replacement for a comparator that must classify benign and attack events. Treat it as a valid engineering experiment showing cautious abstention, not as a model improvement or qualification.

Preserve the original frozen RQ2 research design: 60 independently collected normalized events, equal model-visible inputs and three comparator conditions, plus evaluator-only truth. The new paired-HTTP C12 demonstration must not be mixed into those scores.

Possible **separately authorized prospective** routes are:

1. Evaluate the already-planned original RQ2 model/prompt for single-event classification under its legitimate **development** protocol. Retain it if independently admitted, rather than rebranding C12 as the RQ2 model.
2. Design a new versioned single-event Q8 prompt with explicit benign-evidence calibration and independently specified acceptance thresholds **before** generating fresh development cases. No tuning or rescoring against these nine already-used cases as if blind.
3. Consider conditional corrective data/training or an amended paired-observation study **only if a cause-localization study and research supervisor accept the protocol change**.

The current Q8 paired-HTTP model remains usable only as a **non-authoritative operational development adviser**. No autonomous registered Red dispatch or Blue remediation becomes permissible because a Q8 model emits a confident label.

## 5. Reproducibility

Complete pre-registration, all nine raw completions, results, model/prompt checks, and immutable file SHA manifest:

`/home/zain/Documents/RED FYP/Q8_C12_Integration_Audit_2026-10-14/live_bridge_gate/single_event_v1/20261014T063419Z`

This gate does **not** satisfy independent G08–G10 admission, the genuine 18 RQ1 experiments, the original 180 RQ2 observations, M22 interpretation, or final academic submission.
