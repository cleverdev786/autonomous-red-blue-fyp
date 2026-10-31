# Milestone 20 DEVELOPMENT Feasibility Evidence and Decision

## Status

Milestone 20 DEVELOPMENT feasibility execution is terminally closed with **no eligible candidate**.

```text
M20 DEVELOPMENT feasibility cycle     CLOSED
eligible candidate selected           NO
Q6_K official decision                INELIGIBLE
official Q6_K 75-call rerun           FORBIDDEN
final experiment freeze established   NO
M21 final experiments authorized      NO
```

This document records the as-run DEVELOPMENT evidence. It does not authorize final RQ1/RQ2/RQ3 experiments.

## Frozen DEVELOPMENT authority

The frozen `feasibility-v1` contract remained unchanged: 8 synthetic fixtures, `F2 = 30`, `F3 = 45`, 75 logical calls per official exposure, context 8192, max output 4096, temperature 0.7, top-p 0.8, top-k 20, seed null, non-streaming, zero automatic retries, tools disabled, grounding disabled, and a 600-second request timeout.

```text
fixture input bundle
fa8d1209710d7782f58395f8ffe678aa6abbd2590275fc63e15f95e433012595

evaluator truth
c3927af2124361cc145dc766307059f904369ad3f86445e9124af88d92176e70

prompt bundle
577c03e6bf47f1ba58ddce6b6e67404f37cfcb9d411e794555d4bf8ff0f79980

generation settings
57953bfcfd8ea9e60276bfc1047a4b16e2011ee967745efe47ed2f30d42981f1

selector: experiments/feasibility.py
2fcc1b5cf83ea36ff74b7b27c1fdfee8420ee13cd579735b269500568992151a

direct verifier: experiments/synthetic_verification.py
a69bcc057b1d23bfa043c898b91668e632bb1ab74f58a43cdf5fa078610370aa
```

Evaluator truth remained evaluator-only during model calls.

## Candidate-set history

```text
v1: L1/L2 failed semantic feasibility; C1 quota-confounded; no candidate selected.
v2: L3/L4 readiness PASS; C2 NOT READY because observed RPD 20 < 75; no round-2 inference.
v3: V3-DISCOVERY-NONE; repository candidate set never instantiated.
v4: L3 INELIGIBLE; L4 INELIGIBLE; C4 INELIGIBLE.
    C4: 59 HTTP 200 / 16 HTTP 503 / 0 HTTP 429 / zero retries.
```

The old v4 repository-support `NOT RUN` statements are preserved as historical checkpoint facts, not current status.

## Fine-tuned specialist lineage

```text
base model
Qwen/Qwen2.5-Coder-3B-Instruct

pinned revision
488639f1ff808d1d3d0ba301aef8c11461451ec5

fixtures                   576
train fixtures             384
validation fixtures        192
train role records        1440
validation role records    720
classes                    SQL injection / XSS / Path Traversal / benign
```

The actual frozen feasibility-v1 candidate-input and evaluator-truth records were excluded from training; hard contamination checks found zero forbidden hits. Training design was nevertheless informed by the frozen DEVELOPMENT interface: the same four capability roles, bounded fixture structure, structured response conventions, registered-test catalogue behavior, verifier-compatible remediation idioms, benign restraint examples, and explicit `frozen_aligned`/`security_diverse` patch styles. The final gate is therefore DEVELOPMENT artifact qualification rather than a fully blind external benchmark.

```text
adapter_config.json
a714a51d466536087eec121622cafab60eb686884f0fde75cc2f5b11edf0c0d9

adapter_model.safetensors
cd662452f70ed76de669d3c3a2183694aca77bcc10d3fe85e84645595108fef3

F16 GGUF
298fa5f7ecb6fba3acf27c9c2b44ac902d2d77a471b562587748174eb69b12aa

Q4_K_M GGUF
c7642912e943e3a5507caedcf11ea06a5cbea20ce507af313f9c08b04c83dbaf

Q6_K GGUF
07bcec4047a457766a92c9737fd0ac8045e328ccf703baf43768c2ea962bf7a9
```

## Quantization diagnosis

```text
Q4_K_M CPU full selector       168/192
Q4_K_M CPU SQL selector         24/48
Q4_K_M T4 SQL screen             8/48
F16 T4 SQL screen               48/48
Q8 T4 SQL screen                48/48
Q6_K T4 SQL screen              48/48
```

Prompt/token parity and sampler diagnostics did not explain the failure. Quantization sensitivity was the leading diagnosis. Q6_K was the smallest tested representation restoring the affected capability.

Q6_K CPU selector evidence:

```text
/home/zain/Documents/RED FYP/.cache/autonomous-red-blue-fyp/m20-feasibility-v1/evidence/q6-test-selection-192-v1/20261007T061232Z/q6-test-selection-192

192/192 correct
48/48 per class
provider failures 0
parse failures 0
automatic retries 0
ExperienceMode.DISABLED

summary
92834d6f1e4a4b49101cc41ada4194cb4f5a85b947e2c9ca45aa5fe8a9e5c745

manifest
abf6ca345aeb817b93d279137aeda2ecd10604ec123c5ab294cb054328a19dd5
```

## Q6_K CPU artifact-specific pilot

Original completion evidence:

```text
/home/zain/Documents/RED FYP/.cache/autonomous-red-blue-fyp/m20-feasibility-v1/evidence/q6-pilot-completion-528-v1/20261007T172058Z/q6-pilot-completion-528

FIRST_FAILURE.json
4597a719849b0cbb49711be7cb582ca7a683c5c57e8721c34d3bf128732d7fb7

arm-manifest.json
26697fe9322f1efd35f98c97a4d4162a5eeb2e911487029577f8cf1513149966
```

The run completed 144/144 patch calls and 146/146 measured classification responses before global position 291 timed out at 600 seconds with no HTTP response and no assistant content. The event is preserved as an unmeasured provider/infrastructure failure, not a semantic miss.

Before any replacement output, a one-time infrastructure-recovery amendment was frozen:

```text
c43807050e4d9938b519f9b853ac821728f13cfdf05b0a877262c5380e2f96e4
```

The exact timed-out request was executed once after a fresh server start under unchanged settings and completed correctly in 47.958 seconds. Remaining calls completed.

```text
amended evidence
/home/zain/Documents/RED FYP/.cache/autonomous-red-blue-fyp/m20-feasibility-v1/evidence/q6-pilot-completion-528-infra-recovery-v1/20261008T013843Z/q6-pilot-completion-528-amended

manifest
a0fd4b97619bf6194c82853f790e86238ce37f400579d3e033630df94b82c0e7

schema validity                 720/720
benign no-action                144/144
classification                  192/192
source/function localization    192/192
registered-test selection       192/192
independent patch gate          144/144
corrected frozen-aligned gate    72/72

PILOT_GO_UNDER_INFRASTRUCTURE_RECOVERY_AMENDMENT = true
clean_original_frozen_run_pass = false
```

## Official Q6_K 75-call DEVELOPMENT gate

Official root:

```text
/home/zain/Documents/RED FYP/.cache/autonomous-red-blue-fyp/m20-feasibility-v1/evidence/q6-official-feasibility75-v1/20261008T065441Z
```

The official exposure had no recovery amendment, zero retries and `ExperienceMode.DISABLED`. It used the direct frozen repository verifier, not the pilot bridge.

```text
pre-call schedule
dc68008a3acf9690b96887c6cb294cda79e40f26c71c74990d05b82db11285ad

logical calls dispatched       75/75
HTTP 200                       75/75
provider failures                  0
automatic retries                  0
catastrophic failures               0

classification                   PASS
source/function localization     PASS
registered-test selection        PASS
benign handling                  PASS
stability                        PASS
local-resource feasibility       PASS

patch verification              2/6
required                        >=4/6 and >=1/class

semantic_pass                   false
eligible                        false
```

Official decision:

```text
Q6_K frozen DEVELOPMENT feasibility-v1: INELIGIBLE
```

Official result SHA-256:

```text
f9e1ddf22ed97e71be79aee7062cd4e467f097f6ed2782efc8d1ef868296f841
```

The 75-call exposure is final for this DEVELOPMENT gate and must not be rerun to improve the outcome.

## Patch root cause

| Fixture | Result | Root cause |
|---|---|---|
| SQL member lookup | REJECTED | Continued to concatenate tainted data into SQL; genuine remediation failure |
| SQL invoice load | REJECTED | Parameterized intent, but `%s` and f-string AST were incompatible with the frozen `?` / constant-string contract |
| XSS badge preview | ACCEPTED | Correct `html.escape` remediation |
| XSS note render | ACCEPTED | Correct `html.escape` remediation |
| Path export download | REJECTED | No canonical `resolve()` and defective containment logic |
| Path asset open | REJECTED | No canonical `resolve()` and defective containment logic |

Corrected bridge v1.1 SHA-256:

```text
0b17cba6aa3bfe87de9c31f1e20f94ffa3c0cff29ce040b92276f92dd62c52dc
```

The bridge embeds the same frozen `synthetic_verification.py` bytes as the direct verifier. The discrepancy is therefore not bridge-versus-direct semantics. The verifier is deliberately narrow, but the official failure cannot be dismissed as verifier incompatibility because one SQL patch remained unsafe and both Path Traversal patches were functionally defective.

## Preservation correction

```text
official tree files
35

official tree inventory
231f3677940a42cb6cfec62fab0bd7b8c67e06c83d66f7561a7edee7ccc3736d

original RUN_MANIFEST.json
00ab64dd6dddf751a25e0ce27308e346b06e6d4dfa285a480f77dbe68ee491ed
```

The original manifest has one known packaging-order mismatch limited to `seal.log`. It remains unchanged. A sibling preservation-only correction records the final quiescent tree:

```text
/home/zain/Documents/RED FYP/.cache/autonomous-red-blue-fyp/m20-feasibility-v1/evidence/q6-official-feasibility75-v1/20261008T065441Z-preservation-correction

detached-final-tree-manifest.json
4e4f9082fe613e1881c0ad06fb1e9c66bde0bc6e260a128314dcf2dc80b17cd0

correction-record.json
68adfe2a114c23c3f7b96ee561d6cbc78fd1ddba9333ecc941c01c0341b2ec19

PRESERVATION_PROTECTION.sha256
51e3797dce1719dc3c57ba7685c633f571439b4c56520169fbef13386a91238d
```

The original official tree digest was identical before and after the preservation correction.

## Git boundary

Large runtime evidence and model artifacts remain outside Git, including `.cache/.../models/*.gguf`, `.cache/.../evidence/**`, fine-tuning checkpoints/runtime outputs, Colab/Drive runtime artifacts, and raw provider/server/resource logs. Git documentation records identities, paths, outcomes and hashes only.

The runtime-generated Q6 official candidate descriptor remains part of the sealed evidence arm. It is not promoted to a repository Candidate Set v5 or final experiment configuration.

## Final decision

M20 produced a preserved negative DEVELOPMENT feasibility result. Candidate Sets v1-v4 produced no eligible candidate. Fine-tuning recovered a capability lost under aggressive Q4_K_M quantization, but Q6_K failed the frozen remediation threshold in the sealed official gate and is formally **INELIGIBLE**.

No final experiment configuration is admitted from this cycle.

**The final experiment freeze is not established. M21 remains blocked pending an explicit pre-final-evaluation design decision.**
