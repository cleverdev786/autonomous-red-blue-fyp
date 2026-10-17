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
