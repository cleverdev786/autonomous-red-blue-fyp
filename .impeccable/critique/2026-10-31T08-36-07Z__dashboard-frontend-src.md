---
target: Overview and Red Team
total_score: 27
max_score: 40
na_heuristics: ""
p0_count: 0
p1_count: 1
target_identity: "file:/home/zain/Documents/RED FYP/autonomous-red-blue-fyp/dashboard/frontend/src"
timestamp: 2026-10-31T08-36-07Z
slug: dashboard-frontend-src
closed: true
---
Method: dual-agent (A: /root/design_review · B: /root/detector_review), followed by parent live review.

# Overview and Red Team critique

Scope: Overview and Red Team only. Provisional source-informed scores; independent A inspected current source and historical workspace screenshot. Independent B inspected current fixtures. Parent subsequently signed in and inspected live dark Overview, Red dashboard, and completed Autonomous workspace. Manual remains source-reviewed. No application changes or assessment operations.

## Design health

| Heuristic | Score /4 | Observation |
|---|---:|---|
| Visibility of system status | 3 | Clear status and terminal feedback |
| Match with real world | 2 | Incorrect coverage unit and Blue availability wording |
| User control | 3 | Deliberate commands, cancellation, navigation |
| Consistency | 3 | Cohesive shell with terminology mismatches |
| Error prevention | 3 | Explicit scope and authorization |
| Recognition over recall | 3 | History and persistent context |
| Flexibility and efficiency | 3 | Search, filters, sorting, paging |
| Aesthetic and minimalist design | 2 | Repeated introductions and diagnostics |
| Error recovery | 3 | Retry and retained selections |
| Help and documentation | 2 | Mode/stage explanations need context |
| Total | 27/40 | Acceptable |

## Specificity and impression

The Red workspace is authored for MARS through four bounded stages, evidence provenance, and separate completion/coverage. Overview headline and duplicate Red entry copy are generic. Preserve the approved hero/team-card composition. Improve accurate meaning and next-action hierarchy before pursuing decorative changes.

Detector: 0 findings for dashboard/frontend/src/overview and dashboard/frontend/src/red; separate App.tsx scan also 0. No false positives. Fixture dashboard axe: 0 violations, 0 incomplete, 20 passes. These do not certify live accessibility or workflow meaning.

## Strengths

- Explicit authorization and fixed scope make consequential actions deliberate.
- Verified outcomes, coverage, and completion are distinct.
- History controls and technical disclosures support repeat operators.

## Priority issues

1. [P1] Endpoint coverage uses the wrong unit. RedDashboardView.tsx:132 labels sums of executed/eligible tests as endpoint coverage; services/red_read_service.py:369-370 sums assessment coverage counters. Live dashboard shows 3/3 while workspace says eligible tests executed. Rename to Eligible tests executed or Test coverage, preserving aggregation caveat. Command: impeccable clarify.
2. [P2] Overview overstates deferred Blue scope. RedOverview.tsx:50 says all Blue functionality deferred despite existing agents/services. Describe primary Blue workspace page as deferred, preserving card/entry. Command: impeccable clarify.
3. [P2] Repeated context pushes work downward. Live dashboard history follows introduction, caution, metrics, and large filters. Workspace first screen repeats identity before timeline/findings. AssessmentWorkspace.tsx:147-176 repeats Last action/Task count/Failure state including None across manual stages. Tighten spacing and repeated introductions; disclose uneventful diagnostics through Inspect while retaining safety/blocking reasons. Commands: impeccable layout, impeccable distill.
4. [P2] Mode selection lacks immediate execution-responsibility explanation. NewAssessmentView.tsx:54-59 labels Manual/Autonomous without concise distinction. Explain deliberate per-stage commands versus progression within authorized scope. Group eight scope budget fields by purpose while keeping all limits reviewable. Command: impeccable onboard.

## Cognitive load and emotional journey

Moderate in complex Manual/review states: repeated diagnostics and eight budget values weaken chunking, single focus, and minimal simultaneous information. Persistent context and progressive disclosure are strengths. Authorization reassures. Blocked/stale manual recovery is the emotional valley because diagnostics require translation into next actions. Completion appropriately retains coverage qualifications.

## Persona red flags

- Jordan, first-time student: unclear mode responsibility and technical blocked-stage terminology.
- Alex, repeat operator: useful history tools but excessive scanning through introductions/diagnostics.
- Sam, keyboard/low-vision operator: good labels and text states; small history labels require fresh zoom/mobile review. No current live accessibility failure verified.

## Minor observations

Overview hero and team card could use complementary copy. Implementation terms such as non-terminal can be secondary. Preserve the approved scrollable semantic history table. No demand for unrequested keyboard shortcuts or new UI framework.

## Questions to consider

- Prioritize truthful coverage/availability wording, hierarchy and density, or first-time mode guidance?
- Start with copy-only changes, or include layout/grouping across Overview and Red Team?
