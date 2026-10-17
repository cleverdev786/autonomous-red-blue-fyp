# Model quality and remaining final research

**2026-10-17, development-only technical review.** MARS application
development and scientific research have different acceptance requirements.
A passed deterministic or AST-verified patch demonstration is not evidence
that a model can safely classify benign XSS events or author a robust patch.

## Prospective, paired Q6 versus Q8 study

- **Study source:** `~/.local/state/sentinel-fyp/q6-q8-xss-comparison-20261017/`,
  outside the repository and protected research artifacts.
- **Pre-registration SHA-256:**
  `874cc5b554fd8f86276aa5c6b5e124079243c00c4f043fe9f232d41609572701`.
  The eight new synthetic normalized events, their expected labels, common
  versioned single-event prompt, common decoding settings, model hashes,
  scoring rules and no-retry requirement were sealed *before* inference.
- **Input:** one `RQ2ClassifierEvent` v1 per case, with no evaluator labels,
  execution provenance, paired HTTP observations or ground-truth material
  copied into a prompt. **Output:** strict `RQ2ClassificationDecision`
  (one class, confidence, reason). Both used the same existing
  `q8-rq2-single-event-v1-development` prompt and llama.cpp runtime binary,
  seed 42, temperature 0, top-p 0.8, top-k 20 and 192-token output budget.
  The context/memory profiles necessarily differed (2048/Q8, 1536/Q6).
  Runs were sequential, one inference slot per model.
- **Q8 file:** `c08b-nf4-effective-Q8_0.gguf`,
  SHA-256 `51b63a132c73a592d954e96b15c1d28176f0cc3e5f05533304e92a6fb40ad304`.
- **Q6 file:** `qwen25coder3b-specialist-Q6_K-b10964.gguf`,
  SHA-256 `07bcec4047a457766a92c9737fd0ac8045e328ccf703baf43768c2ea962bf7a9`.

| Development metric (8 paired cases) | Q8 | Q6 |
|---|---:|---:|
| Correct XSS-positive predictions / attack recall | 4/4 | 4/4 |
| Correct benign predictions / benign specificity | 0/4 | 0/4 |
| Vulnerability false-positive claims on benign events | 1/4 | 4/4 |
| Benign events classified `unknown` (abstention) | 3/4 | 0/4 |
| Completed valid schema responses | 8/8 | 8/8 |

Q8 predicted three of the four benign events as `unknown` and one as `xss`.
Q6 predicted one as `sql_injection` and three as `xss`.
Both returned `xss` on all four explicit attack events.

**Decision:** Q8 exhibited fewer positive false alarms than Q6 in these
particular paired examples. Neither distinguished benign cases reliably.
There is **no qualified XSS winner** and no evidence to finalize Q6 as the
XSS model or automatically promote Q8. The registered catalog therefore
withholds XSS specialist assignment; the successful SQLi development workflow
retains its independently pinned Q8 provenance. This does not alter old runs.

**Evidence audit SHA-256:**
`a442b2bc881cc757c9a1558fa99a9b5399b60a7e293cb0f0a1a693b95e17ce72`.
Q8 raw-result SHA-256:
`97efd33119b6e30c044e9523deeb5a87c992ce3e75665e8fde583d39d399c7ce`.
Q6 raw-result SHA-256:
`00ae7442cc3f8266b27f95aa16ac1667786c36f74d48a865169e7c5b4fc6879b`.
The external audit independently checked every raw request, raw completion,
typed decision, receipt and predicted label against the preregistration.
The two small case groups were **authored by the developer, not an independent
blinded holdout**. Do not report percentages as generalization estimates or
use the current test answers for tuning and then claim these cases are unseen.

## Scientific status verified from project sources

The original M20 feasibility contract remains **closed**, with the Q6
direct-patch candidate **ineligible (2/6)** and no admitted final candidate;
see [M20 feasibility](M20_DEVELOPMENT_FEASIBILITY.md). Separately, Q8's
single-event development v1 did not pass benign classification (0/3);
see [the Q8 event gate](Q8_RQ2_SINGLE_EVENT_V1_GATE_2026-10-14.md).
The successful registered SQLi patch and patched-Docker replay are valid
**development execution evidence**, not an amendment to either decision.

The original M18 RQ2 dataset remains frozen:
`experiments/datasets/rq2-classification-v1/`, exactly **60 observed
events** (10 SQLi, 10 XSS, 10 traversal, 30 benign), with only **six unique
semantic-input patterns** despite 60 event IDs. The three files' actual
SHA-256 hashes were freshly verified on the laptop against
[RQ2 dataset documentation](RQ2_FROZEN_DATASET.md). No frozen
`ground_truth.jsonl` contents were read by the comparison or sent to a
model. This dataset can support the approved comparison of 60 events under
three conditions but cannot be a new model-selection holdout.

### Minimum legitimate path to finish the original research

1. **Independent, prospective model qualification.** Agree on the
   classification, benign-restraint, localization and model-authored
   remediation criteria *before* a new blinded qualification test. Separate
   performance by class, count `unknown` as abstention rather than correct
   benign, and retain all timeouts/invalid outputs. A fresh, reviewer-controlled
   evaluation is required; these developer-authored eight cases cannot qualify
   either model. Any change in the model/prompt or assignment is a new version,
   never a correction to an old result.
2. **Approve the actual H-stage final experiment freeze**, including single
   M18 event input for RQ2, exact model/prompt/runtime hashes, provider
   binding, deterministic control, model-call budget, RQ1 architecture pair,
   run schedule, source/baseline hashes, immutable result storage and
   `ExperienceMode.DISABLED`. The repository already implements
   `experiments.freeze` preflight checks; do not bypass them to start
   `FINAL_EVALUATION` runs.
3. **Collect M21 observations under the frozen plan:** at least
   **18 genuine RQ1 runs** (3 scenarios × 2 Blue architecture conditions
   × 3 repetitions) and **180 real RQ2 classification observations**
   (60 events × `rule_only`, `llm_only`, `hybrid`). Preserve failures,
   times, costs, raw model provenance and no-repair decisions.
   Model-authored remediation outcomes must not be substituted with
   trusted-template demonstrations.
4. **Analyze real M21 data for M22** (per-class confusion, benign FPR,
   macro F1, patch acceptance, regression, source localization, runtime,
   token/cost and confidence), then finish academic report and demonstration.

**Status as of this review:** step 1 has useful negative development evidence
but lacks an independently qualified model; step 2 is not frozen; steps 3–4
cannot be honestly marked completed. This is a model-quality blocker, not a
missing dashboard feature. The path forward is independent evaluation and
a defensible final protocol, not more unfrozen demonstrations.

## Follow-up: Q8 single-event v2 benign calibration (2026-10-17)

This **prospective, newly versioned DEVELOPMENT-only** test attempted to correct
the false-alarm/abstention issue, without rewriting the rejected v1 single-event
prompt, the 60-event M18 dataset or old research decisions.

- Implementation: `services/q8_rq2_v2.py`, prompt version
  `q8-rq2-single-event-v2-development`. Its v1-compatible response validator
  does not change model labels or authorize research, tests or remediation.
- Sealed registration and write-once raw requests/completions:
  `~/.local/state/sentinel-fyp/q8-benign-calibration-20261017/`.
- Pre-inference registration SHA-256:
  `55778b12b25e1f6d710334c00770e1a844b8fa27a00d94cd95b35f17bf1210aa`.
- Observations: **12 newly authored synthetic single events**, covering benign
  (4), SQL injection (2), XSS (2), traversal (2) and ambiguous (2).
  Model: original pinned C08B Q8 GGUF; local CPU; temperature 0,
  seed 42, top-p 0.8, top-k 20, 160 generated tokens; one attempted
  completion per item, zero retries. Expected labels stayed outside prompts.
- **Predeclared development criteria:** 3/4 or better benign, 5/6 or better
  attack classes combined, 1/2 or better ambiguous, zero invalid responses.
  **Verdict: FAIL** (not a qualification). No test was rescored or retried.

| Class | Correct | Total |
|---|---:|---:|
| Benign | 3 | 4 |
| SQL injection | 2 | 2 |
| XSS | 2 | 2 |
| Path traversal | **0** | **2** |
| Unknown / ambiguous | 2 | 2 |
| Overall | **9** | **12** |

All 12 were valid typed responses. One benign case elicited a false-positive
`xss` label, and **both** real traversal-disclosure descriptions were
incorrectly labeled `benign`. Examination of saved model reasons found
unsupported assertions of safe outcomes contradictory to event attributes.
This is a grounding failure, not a schema failure. These hand-authored examples
do not establish a causal gain over older prompts tested on different cases
and cannot substitute for independent blind model qualification.

The audited outcome SHA-256 is
`08387f51dfafe08a86584b3e36a4790bae6457ddc3fdb4b14f52350ca97de551`.
The external requests and raw completions were independently revalidated
against the sealed manifest and typed output contract.

### Additional Qwen3-4B probe

A separately sealed **adaptive, non-blind** Qwen3-4B Q4 development follow-up
used the same v2 prompt/cases but was not among the preregistered Q8 candidates.
The model fingerprint was
`7485fe6f11af29433bc51cab58009521f205840f5b4ae3a32fa7f92e8534fdf5`.
Its first two calls generated reasoning text (beginning `<think>`) rather
than strict JSON and failed parsing under the fixed 160-token limit. A third
call was interrupted when the heavy CPU/memory probe was stopped, and nine
were not attempted. **No accuracy denominator is reported** and no model
quality conclusion can be drawn. In particular it was not a valid like-for-like
accuracy comparison without a versioned Qwen3 non-thinking configuration.

Evidence: `~/.local/state/sentinel-fyp/qwen3-4b-development-20261017/`;
preregistration SHA-256:
`ac06e13c67d44f2f478c8607a031508d5de26b33ea1989c912aae8167b3baef3`;
aborted-run report SHA-256:
`16ff7a6c4b197c407066778b03c34afc5dd2ed498f1f525c4a7594a6973f44f8`.

**Research consequence:** V2 remains a separately versioned rejected
development prompt; it is not automatically activated for M21, and no model
is admitted by this follow-up. Do not generate final RQ1/RQ2 scores or
replace independently tested source patch evidence with claimed model output.
A next model candidate must establish reliable **benign and traversal**
behavior, schema compatibility and real source/remediation acceptance
through independent reviewer-controlled qualification. The already-working
registered SQLi application demonstration is preserved.

### End-to-end implementation dependency

The author-authorized, model-linked registered SQLi workflow has demonstrated
baseline Red execution, genuine Q8 classification/source localization,
trusted-template staging and patched Docker replay. Its saved development
evidence is separate from final research. **Other scenarios are not at the
same maturity:** `services/job_dispatch.py`,
`services/blue_classify.py` and `services/blue_replay.py` currently admit
only SQLi-specific jobs/source anchors. XSS and path traversal have registered
security tests and trusted compiler templates, but these do not themselves
constitute independently admitted full Red-to-Blue workflows.

The next implementation slice is to extend these existing guarded seams
per registered scenario, with newly versioned model input/response evidence
and independent functional/security replay, without changing the deliberately
vulnerable live baseline or claiming that the classifier has passed
qualification. Model-quality remediation and final RQ1/RQ2 freeze remain
separate research dependencies; do not use a deterministic compiler preview
as a substitute for genuine model-authored behavior.

## Registered Red dispatch for XSS and traversal (2026-10-17)

The development-only MARS **Red** job dispatcher and write-once receipt
reconciler now accept all three already registered local scenarios:
`sqli-login-001`, `xss-search-001`, and
`path-traversal-read-001`. This reuses the existing independently
hash-pinned `RealExecutionAdmission` and `IsolatedDockerExecutor`;
it does not add an HTTP attack endpoint, create admissions, start containers,
retry an unknown attempt, or grant final research authority.

- The reviewed job, saved plan, trusted endpoint/test registry, external
  admission scenario, Git tree, binary source manifests and running Docker
  identities must agree *before* the one-time attempt reservation.
- Receipt reconciliation requires matching stored raw bytes, admission intent,
  scenario, registered test and endpoint, and (for assessed outcomes) the
  actual typed deterministic observation and its SHA-256.
- An XSS or traversal Red result **does not** unlock SQLi's Q8 Blue
  classification, source localization or patch/replay flow. Those existing
  Blue services still require the original `_reviewed_sql_scope` gate.
- Test coverage includes positive synthetic XSS/traversal observations through
  the existing injected isolated-executor runner, mismatched/cross-scenario
  admission and receipt refusals, duplicate receipt refusal and no retry.
  These are offline integration tests, not newly claimed live Docker runs.
- An operator must provision an explicitly authorized external admission,
  start independently attested isolated Docker services and invoke
  `python -m services.job_dispatch` with all existing required external
  pins to collect new **real** evidence. The dashboard start endpoint remains
  intentionally disabled and final research remains unadmitted.

**Next:** independently admitted live XSS/traversal baseline collection,
then model provenance, source localization, isolated patch and registered
patched replay for each. No model has yet met the separate model-quality
qualification requirements for those scenarios.

## Bound read-only Blue previews across all three scenarios (2026-10-17)

The existing deterministic `services.blue_preview.prepare_blue_preview`
now accepts SQLi, XSS and traversal **only after** a matching saved plan,
reviewed job, exact registered scope, independently pinned admission,
write-once receipt, and archived live Red observation all verify. The
scenario ID, registered test, endpoint, and exploit-confirmation claim must
match the same reviewed job. Only then is the existing trusted compiler
asked to prepare its already-supported template inside an ephemeral copy.

This stage is **not AI classification**: `model_decision_used=False`,
`origin=trusted_deterministic_builder`. It never runs a new security test,
modifies the protected vulnerable baseline, applies a patch, approves
source localization from an unqualified LLM or qualifies final research.
An existing SQLi-only Blue model path remains separately gated.

The two real Docker baseline runs registered in
`~/.local/state/sentinel-fyp/mars-all-red-20261017/outcome.json`
were revalidated and their separate one-time Blue proposals stored in the
live MARS job database:

- XSS, `xss-reflection-001`: proposed diff SHA-256
  `8d3e4d6d25f810dfe253ff78146a2d92daed4127445d9157a256f965507baee5`
  (HTML text escaping).
- Traversal, `path-traversal-private-file-001`: proposed diff SHA-256
  `d33aab09fc036abe99a511966e106103a1bf630b18dd577d9a1c5ce540bc6cc1`
  (restrict reads to the intended public root).

Both returned `prepared` with
`model_decision_used=False`, `patch_applied=False`,
`security_replayed=False`, and `final_research_qualified=False`.
The protected baseline remained
`f8675d5bed857138f49cdf717bd4c696aad7e4e42c5f14cd41b4623b140a6e5d`.
Operator evidence is at `xss-preview.json` and
`traversal-preview.json` beside the external Red report.
Focus tests exercise each independently bound path, cross-scenario
substitution refusal, duplicate preparation and SQLi regression.

**Next actual Blue milestone:** source-localized model evidence for each
non-SQL class, then isolated patch application and independently admitted
patched security and functional replay. These deterministic previews are
useful operational evidence but are not substitutes for those tasks.

## Centralized local GGUF storage (2026-10-17)

All three regular GGUF files formerly under
`../.cache/autonomous-red-blue-fyp/m20-feasibility-v1/models/`
have been moved with post-copy SHA-256 verification into the repository's
Git-ignored `models/` directory. The source directory now contains only
legacy symlinks pointing to the new model files, so existing historical
research invocations retain their paths. Eight regular GGUFs are now in
`models/`. No binaries were added to Git, and the Q8 runtime continues to
load its pinned GGUF from `models/`. The outside-repo, file-by-file
verified manifest is
`~/.local/state/sentinel-fyp/gguf-relocation-20261017/manifest.json`,
SHA-256
`5e48103974bd270c5d8a0f319f144ca4116242a22d644a102a88e33f5ede3bf3`.


## Additional guarded non-SQL model evidence path (2026-10-17)

New development-only implementation, **not a newly completed live experiment**:

- `services.blue_input.build_registered_blue_input` reconstructs the exact two
  registered GET steps and captured responses for XSS and traversal after
  validating the reviewed job, scope, externally pinned admission, write-once
  execution receipt, full archived Docker evidence and untouched source hash.
  The historical SQLi-only `build_blue_input` contract is unchanged.
- `services.blue_non_sql_probe.probe_bound_non_sql_job` performs at most one
  Q8 classification plus one *conditional* model-selected source localization
  on a separately admitted new XSS/traversal job. It reserves a durable
  outcome-unknown intent **before** inference, saves raw/model/prompt files
  outside Git with fingerprints, validates route/function/executable sink
  against the original hash-pinned source, and will not retry an unknown
  attempt. A mismatched benign/unknown/wrong-class answer does not trigger
  localization; an invalid/misgrounded localization is rejected with raw
  evidence preserved. No previous one-shot Red/preview record is reused.
- Every accepted record explicitly has `model_independently_qualified=false`,
  `source_analysis_authorized=false`,
  `patch_preparation_authorized=false`, `patch_applied=false`,
  `security_replayed=false`, and `final_research_qualified=false`.
  Localization verification means only that *this* answer identified a
  source-grounded line; it does **not** authorize autonomous remediation.

The operator-only entrypoint is `python -m services.blue_non_sql_probe`,
which requires a **newly reviewed and independently pinned Red job**, exact
admission/receipt hashes and archived evidence. No model probes or patched
Docker replays are claimed just because the new code and offline integration
tests pass. Independently blinded qualification, separate operator-admitted
isolated patched security/functional replays and the original RQ1/RQ2 freeze
remain required. Never treat historical developer-authored matched examples
as a prospective qualification.


### Registered in-process patched application replay

`services.non_sql_local_replay.verify_non_sql_local_replay` now checks both
existing exact trusted compiler source transformations against an ephemeral
FastAPI application instance. It executes each existing registered XSS or
traversal test step unchanged, reuses the existing registered evidence
evaluator, and checks normal search, public-file readability, synthetic private
file denial, and health. It refuses changed baseline source hashes and does
not alter the live intentionally vulnerable file. These are automated local
functional/security integration checks, **not independently admitted patched
Docker replays**, not model-authored patches, and not final scientific outcomes.
The corresponding genuine Docker replay and independent model qualification
remain unfinished.

The MARS workspace exposes a **GET-only** provenance reader at
`/api/mars/jobs/{job_id}/non-sql-model-probe`. An unattempted job returns
`not_requested`; an attempted but interrupted/invalid inference returns
`outcome_unknown`, not an inferred benign outcome. The route has no POST
execution or automatic repair operation. The original SQLi job routes and
trusted-source protections are unchanged.

To enforce the handoff's no-retroactive-reuse rule, the guarded non-SQL
model-input builder now explicitly rejects a registered job that already
has a deterministic Blue preview. The earlier real XSS and traversal jobs
have completed previews, so they cannot be silently converted into
prospective model-driven results. A genuinely **new**, separately admitted
one-shot job is required for each model-evidence run.
