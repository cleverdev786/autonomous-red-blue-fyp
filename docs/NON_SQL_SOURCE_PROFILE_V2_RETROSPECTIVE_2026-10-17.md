# C12 executable-line profile V2: retrospective development diagnosis

**Status:** source-localization hypothesis rejected on the two examined
historical positive cases. Not a prospective evaluation, not a blinded
qualification, not new Red evidence and not a repeat attempt on either
original MARS job.

## Provenance and read-only procedure

The original 2026-10-17 independently admitted development Red/model
record is preserved verbatim:
`~/.local/state/sentinel-fyp/mars-nonsql-live-20261017-v1/outcome.json`
(SHA-256 `7bd9b048dff60d1c7a50e43d706de167e1acccbd6296f4bc86120cf12a95f545`).

A separate **retrospective diagnostic** used a read-only copy of the two
previously archived registered HTTP observation pairs and the existing
`services.q8_c12_development_bridge.SOURCE_PROFILE_V2`
(`q8-executable-lines-v2`). This profile excludes blank/comment-only
lines from the immutable candidate source view but preserves original line
numbers, all three registered route functions and the exact protected
source SHA-256. The frozen external C12 model contract and the existing
`q8-localization-v3-ast` prompt wrapper were not edited.

The original Q8 GGUF identity remained
`51b63a132c73a592d954e96b15c1d28176f0cc3e5f05533304e92a6fb40ad304`.
Each profile-V2 invocation was made **once** and its request, prompt, raw
completion, selected source line and validator verdict were saved
write-once, outside Git and separately from the original job database.

Retrospective output root:
`~/.local/state/sentinel-fyp/mars-source-profile-v2-retrospective-20261017/`

Write-once external audit index `audit.json` SHA-256:
`1066fb310b94e241911e6c675fe25fd6eb550647057f66db43e696918bcd0e8f`.
It contains per-file SHA-256 fingerprints for both runs, including
original source-pair linkage and newly captured raw Q8 responses.

## Results

| Scenario | Original selected line | Retrospective V2 selected line | Pre-existing trusted repair anchor | V2 validator |
| --- | ---: | ---: | ---: | --- |
| XSS | 86 | 85 | 84 | Rejected |
| Traversal | 101 | 108 | 104 | Rejected |

- **XSS:** V2 selected the trailing HTML literal at line 85, not the
  unescaped interpolation at line 84. The AST/source-anchor validator
  refused the candidate.
- **Traversal:** V2 selected the event-reporting statement at line 108,
  not the relevant containment check at line 104. The same validator
  refused the candidate.

Both completions were valid JSON with model confidence 0.90.
**Zero of two** retrospective localizations passed trusted source
grounding, even with comments filtered. This is a developer-controlled
retest on *seen cases*, not an independent accuracy estimate or an
improvement claim. The outcomes were not substituted into the original
`outcome_unknown` records and the original model selections and
write-once evidence remain unchanged.

The result suggests that simply hiding comments is **insufficient** for
reliable sink selection: on the inspected cases Q8 still confuses a nearby
non-causal line with the executable operation. Do not deploy V2 as a
qualified replacement prompt, auto-correct the lines with a trusted
compiler anchor, lower acceptance standards, or grant model-authored
patch authority on this evidence.

## Next engineering/research work

Qualify a materially stronger independently evaluated source-localization
strategy and benign restraint on prospectively held-out examples. Record
all errors, abstentions, class and source failures before considering any
real model-directed repair. Keep the original M20/M21 single-event RQ2
freeze and genuine RQ1/RQ2 research distinct from both this retrospective
analysis and the trusted-template Docker demonstration.
