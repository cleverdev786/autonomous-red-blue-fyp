# MARS: Development implementation and validation results

**Draft research-report section, 17 October 2026.** This is a documented account of completed *development* observations, **not** a report of the final frozen research experiment. It is intended to be incorporated into the eventual FYP thesis only after review against original evidence. Quantitative claims are deliberately limited to the observed small development samples.

## Project and evaluation context

The project, *An Autonomous Multi-Agent Red–Blue Framework for Web Application Vulnerability Detection and Remediation*, operates against a deliberately vulnerable local FastAPI application in an isolated, registered Docker test environment. Its approved scope comprises SQL injection (SQLi), reflected cross-site scripting (XSS), and path/directory traversal. A deterministic executor performs allowlisted security-test steps, while a model-assisted Blue path is being developed to classify observations, localize relevant source code and, only when independently justified, prepare a candidate remediation. The central safety controls enforce scope, source and container identity, one-attempt admission, raw evidence preservation and isolation. The project proposal calls for testing the original Red attack again after patching and checking ordinary functionality.

Development demonstrations, model qualification and final hypothesis testing are **different evidence categories**. An exploit-confirmed Red receipt validates a vulnerability in the synthetic application; it does not show that a model discovered or correctly diagnosed the vulnerability. A deterministic patch that passes replay does not establish a model-authored repair. Nor may paired-HTTP demonstrations substitute for the original RQ2 event contract.

## Completed development implementation

The codebase includes registered SQLi/XSS/traversal endpoints and security tests, a scoped Red execution path, a model-managed Q8 development endpoint, a SQLite MARS workspace, deterministic read-only Blue previews, isolated patched application verification and a React dashboard. In the observed XSS/traversal runs, a reviewed registered job was bound to a source-hash-pinned Docker admission. The real executor completed the registered steps, and write-once receipts were independently checked against captured HTTP observations. The Blue model-input builder reconstructed registered requests and observed responses from this evidence and refused historical preview reuse.

A later implementation change on local `development` commit `0a8922c` added structured `rejected_localization` accounting for a valid model selection that fails trusted source-grounding checks. It leaves interrupted, malformed and untrustworthy model attempts as `outcome_unknown`; neither state confers repair authority. The previous attempts and their original database status were not rewritten. Latest observed local commit at the end of the preceding continuation was `aac26f48220612dc2735537ce7e16027aad63ca0`, with a clean checkout; the GitHub `development` reference remained `3755e11d8ec1c047c6068ffe288d448a490abae0`. Those are **historical observations** until a new live verification is possible.

## Real XSS and traversal development results

On 17 October 2026, two new registered baseline Docker jobs were reviewed and admitted. Both finished with `baseline_exploit_confirmed`: XSS job `ae1c2518-3787-4ca1-918e-cbe7e2d2a61e` used registered test `xss-reflection-001`; traversal job `6fdd62e5-5c9b-4144-aae8-9bab8cb51f58` used `path-traversal-private-file-001`. The Q8 candidate (`c08b-nf4-effective-Q8_0.gguf`, SHA-256 `51b63a132c73a592d954e96b15c1d28176f0cc3e5f05533304e92a6fb40ad304`) was queried against the captured paired observations. The model classified both positive examples correctly, assigning 0.90 confidence to each, but **neither source-localization answer passed trusted validation**.

| Scenario | Real Red baseline | Model classification | Model-selected line | Registered deterministic repair anchor | Localization verdict | Patched Docker security/functional replay |
|---|---|---|---:|---:|---|---|
| Reflected XSS | Confirmed | `xss` (0.90 confidence) | 86 | 84 | Rejected | Passed |
| Path traversal | Confirmed | `path_traversal` (0.90 confidence) | 101 | 104 | Rejected | Passed |

The XSS response identified a nearby closing line of the HTML construction instead of the actual unescaped interpolation. The traversal response identified a comment instead of the relevant containment call. The independent validator rejected the suggested lines. The original one-shot probe intents therefore remained `outcome_unknown` under the then-current database contract, while raw model answers and rejected evidence were archived. **Two correct labels among two selected attack-positive examples are not a meaningful estimate of benign specificity, generalization, or end-to-end Blue success.**

Separate *trusted deterministic* patched images were byte-checked against their approved source replacements. Fresh isolated Docker stacks then executed each previously registered security test again. Neither registered exploit was observed. XSS continued to support an ordinary search and escaped the script marker. Traversal preserved public-file access, denied the private-file attempt with HTTP 403, and passed health checks. These are genuine patched Docker replays, but **not model-directed patches** because both model localizations were rejected. No automatic patch was accepted or applied based on these answers.

Evidence index: `~/.local/state/sentinel-fyp/mars-nonsql-live-20261017-v1/outcome.json`; SHA-256 `7bd9b048dff60d1c7a50e43d706de167e1acccbd6296f4bc86120cf12a95f545`. XSS patched-Docker receipt SHA-256 `77cd5fa9406066c8294b8b5feb9e011e05c3b68b452e48ce4f8c37acb65485ed`; traversal receipt SHA-256 `d04cbe08a79a9d4d7513e9f65012392e2b3248b0fc607bb82e8d6d729a56c8a4`.

## Retrospective source-context diagnostic

A separate, explicitly non-qualifying experiment reused copies of the same archived HTTP observations with the existing `q8-executable-lines-v2` development source profile. This view removed blank and comment-only source lines while preserving original numbering and source identity. It did not change model weights, old receipts, source code or acceptance checks.

The model selected XSS line 85 instead of source anchor 84 and traversal line 108 instead of anchor 104. Both suggestions again failed the trusted validator. **The retrospective diagnostic yielded 0/2 accepted localizations.** This finding supports rejecting simple comment-filtering as a sufficient solution on these two seen examples; it is not a new independent test of model generalization.

Diagnostic evidence index: `~/.local/state/sentinel-fyp/mars-source-profile-v2-retrospective-20261017/audit.json`; SHA-256 `1066fb310b94e241911e6c675fe25fd6eb550647057f66db43e696918bcd0e8f`.

## Earlier model-quality evidence and its limits

Earlier development measurements on a distinct, eight-case matched XSS comparison found that Q6 and Q8 both identified four attack-positive examples but neither correctly labeled any of four benign examples. Q8 generated three benign abstentions and one benign false alarm; Q6 produced four benign false alarms. In a separately authored 12-case Q8 single-event prompt-v2 development check, nine outputs met the then-used development criterion, but path traversal was detected in 0/2 attack cases. That candidate **failed its predeclared development acceptance**. The incomplete Qwen3-4B exploratory observations do not constitute a comparative accuracy result. These small, selected and non-independent developer-authored cases cannot qualify any candidate for final evaluation.

## Interpretation

Taken together, the registered executor, evidence-binding infrastructure and deterministic patch replays support the claim that the controlled *engineering demonstration* works for these scenarios. They do not establish the stated model-driven detection/repair goal. The observed source-localization failures and historical benign-classification weakness are material limits. The source validator's refusal is successful **safety enforcement**, not a successful vulnerability fix by the model. Confidence scores of 0.90 are model outputs and have not been independently calibrated.

The correct research posture is to retain negative results, avoid retrospective rescoring, and withhold automatic repair authority. Selecting exact source anchors using the deterministic compiler after a wrong model answer would transform a model failure into a trusted-template demonstration and must never be reported as model localization success.

## Remaining scientific evaluation and report completion

The original RQ2 contract calls for **60 single normalized application events** (10 SQLi, 10 XSS, 10 traversal, 30 benign), evaluated in `rule_only`, `llm_only` and `hybrid` conditions for **180 condition-event observations**. These single-event inputs are not the paired HTTP requests used by the C12 development checks. The RQ1 plan calls for **18 genuine runs** across three scenarios, two Blue architecture conditions and three repetitions. At last verified status neither the blinded model qualification, final freeze, 18 RQ1 runs nor 180 RQ2 observations had been completed. No final detection metrics, patch-acceptance rates, time/cost comparison, statistical significance or hypothesis conclusion may be inferred from these development results.

To complete the thesis, independently qualify the candidate model(s) on prospective unseen source families and benign/unknown cases, freeze exact model/prompt/provider/settings and sealed scoring protocol, execute the original runs under immutable evidence collection, then calculate per-class confusion matrices, benign false-positive rate, macro-F1, accepted model-authored repair rates, functional regressions, timings, model usage and limitations. The final chapter must clearly distinguish successful engineering safeguards from qualified autonomous remediation.

## Traceability and citation checklist for thesis integration

Primary local sources to recheck before publication: `docs/MODEL_QUALITY.md`, `docs/NON_SQL_REAL_DEVELOPMENT_2026-10-17.md`, `docs/NON_SQL_SOURCE_PROFILE_V2_RETROSPECTIVE_2026-10-17.md`, `docs/RQ2_FROZEN_DATASET.md`, registered test implementation files, recorded Docker receipts, raw Q8 outputs and the write-once external SHA-256 indexes above. Proposal baseline: the original Google Drive FYP proposal entitled *An Autonomous Multi-Agent Red–Blue Framework for Web Application Vulnerability Detection and Remediation*. No external academic literature citations have been fabricated in this development-results draft.
