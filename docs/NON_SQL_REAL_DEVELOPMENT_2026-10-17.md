# Prospective XSS / traversal Red-to-Blue development observations, 2026-10-17

**Scope:** authorized localhost synthetic MARS security lab, development only. This is
**not** the final frozen RQ1/RQ2 experiment, an independent blinded qualification,
a claim of autonomous model remediation, or a replacement for old evidence.

## Immutable evidence location and original runtime

All newly collected records are outside Git at
`~/.local/state/sentinel-fyp/mars-nonsql-live-20261017-v1/`.

The operator-written, write-once `outcome.json` has SHA-256
`7bd9b048dff60d1c7a50e43d706de167e1acccbd6296f4bc86120cf12a95f545`
and inventories **41 external source/evidence files** plus separately
fingerprinted raw Q8 model archives. Review those bytes before reinterpreting
any observation.

- Starting code and registered admission source HEAD:
  `e730b7d384c16ffa190f365fe5274c893562fc7f` on `development`.
- Original intentionally vulnerable source fingerprint:
  `f8675d5bed857138f49cdf717bd4c696aad7e4e42c5f14cd41b4623b140a6e5d`.
- Model: verified local C08B Q8_0, SHA-256
  `51b63a132c73a592d954e96b15c1d28176f0cc3e5f05533304e92a6fb40ad304`,
  one local CPU inference slot, C12 registered paired-observation development
  contracts. Model-session ownership was transferred to an operator-pinned
  backend instance for each job.
- The new Docker baseline admissions were produced from the actual clean
  source HEAD, exact registered local test definitions, Docker daemon, image,
  container identities and source hashes, then externally SHA-pinned.
  These are **operator-controlled development admissions**, not independent
  blinded research approvals.

## Real registered vulnerable-baseline execution

| Scenario | Fresh reviewed job | Registered test | Result |
| --- | --- | --- | --- |
| XSS | `ae1c2518-3787-4ca1-918e-cbe7e2d2a61e` | `xss-reflection-001` | `baseline_exploit_confirmed` |
| Traversal | `6fdd62e5-5c9b-4144-aae8-9bab8cb51f58` | `path-traversal-private-file-001` | `baseline_exploit_confirmed` |

Archived Red receipt SHA-256 values:

- XSS: `4203e8fd579014fa7ae94c9b7e0c39947f79f3ed95a4a6a6b3d4ba72fa4e1ac6`.
- Traversal: `137a515473fc72d36b7ba35369eca0f0d45d3d2c19f1f6eb514420c1c65c3a19`.

The external admission, write-once receipt, raw executor output,
registered endpoint/step identities and source were revalidated before
building each model input. The previous Red+preview jobs were **not** reused.

## Genuine Q8 classification and source localization

| Scenario | Raw classification | Model confidence | Selected source line | Verified unsafe sink line | Localization |
| --- | --- | ---: | ---: | ---: | --- |
| XSS | `xss` | 0.90 | 86 | 84 | Rejected |
| Traversal | `path_traversal` | 0.90 | 101 | 104 | Rejected |

Both outputs were genuine one-attempt Q8 completions. The XSS model
selected the HTML body construction's closing line instead of the
unescaped interpolation. The traversal model selected a comment instead
of the executable containment call. The existing trusted AST/source-sink
validator refused both and the POST API returned HTTP 409.

Evaluator ground-truth labels were not included in the model prompts. In both jobs the model's correct **class** did not
grant **source analysis or repair** authority. Both one-shot probe intents
remain `outcome_unknown` because the unaccepted localization cannot be
represented as verified. Raw classification and localization answers,
prompts, and rejection outputs remain outside Git under the two
`probe-*` model archive directories linked in `outcome.json`.
There was **no retry** or post-hoc correction.

On these **two selected positive development cases only**, Q8 returned
the correct attack class on 2/2 and passed independently checked source
localization on 0/2. These are not independent generalization metrics,
and no benign restraint or final RQ2 score is inferred.

## Actual registered patched-Docker replays

Separate, previously existing images were checked against the **exact**
trusted deterministic source replacements, pinned by image digest and
replayed in two fresh internal-network Docker Compose projects. Neither
image is model-authored.

| Scenario | Patched source SHA-256 | Registered exploit evidence | Functional checks |
| --- | --- | --- | --- |
| XSS | `546382c5b95df179daa1fdd74ec55b247e510a290056a3a722530c97ae9eacee` | None | Normal search, HTML text escaping, health: passed |
| Traversal | `3e68b72de0aa09110f8f806238b2050b1f3099899ae24cd1b5927b335315ecea` | None | Public file served, private file HTTP 403, health: passed |

Docker replay receipts are individually write-once:

- XSS: `77cd5fa9406066c8294b8b5feb9e011e05c3b68b452e48ce4f8c37acb65485ed`.
- Traversal: `d04cbe08a79a9d4d7513e9f65012392e2b3248b0fc607bb82e8d6d729a56c8a4`.

For each replay, the operator-side runner checked the hardened container
identities, internal-only network, pinned image, in-container source
fingerprints, two fixed registered request steps and recomputed
security-test evidence. It reserved a durable one-shot intent before
running the registered test; verified the same runtime afterward; and
saved raw stdout and a hash-pinned report. Both replays returned
`passed`, `docker_replayed=true`,
`patch_origin=trusted_deterministic_builder`,
`model_localization_used=false`, `final_repair_accepted=false`, and
`final_research_qualified=false`.

These are **real Docker security/functional development replays for
deterministic trusted templates**, not model-directed repairs and not
independently approved final scientific patch outcomes.

## Remaining original research

Model quality is the blocker. This Q8 candidate's two-case localization
behavior does not warrant automatic repair. Blind qualification must prospectively
establish benign specificity, attack-class recall, unknown handling,
source localization and accepted model-authored remediation, with all
failures retained. The original RQ1 architecture comparison and RQ2
60-event/three-condition freeze must then be approved and executed
under the original M20/M21 protocol. No existing development
demonstration is to be promoted into those results.

The live deliberately vulnerable repository source, frozen M18 dataset
and previous historical research receipts were not edited.
