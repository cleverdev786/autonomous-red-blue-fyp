# MARS UI/UX implementation checklist (Tailwind + shadcn)

**Status:** Phase 5 engineering and automated checks implemented; **22/27** tasks accepted. Real zoom/forced-colors, screen-reader review, owner signoff and the corresponding UI-02/UI-14 evidence remain open.
**Parent:** `plan_ui.md` (2026-10-30 revision).
**Baseline:** `development` HEAD `56ff2af` at review, `D agents.md` preserved. Current local app may be offline.
**Scope:** Overview, Red Team, and safe shared shell/theme; Blue functionality, legacy deletion and backend cleanup deferred.

## Phase 0 — Baseline and design verification

- [x] **UI-01 · Baseline Git, routes, and account state.** Read `AGENTS.md`, current Git status, `tasks/plan.md`, `tasks/todo.md`, `routes.ts` and auth/runtime handoff. Inventory 3 current pages + legacy URLs. **Acceptance:** explicit clean/dirty report, route map, no file mutation, no scan. **Evidence:** `ui_baseline_audit.md` (2026-10-30).
- [ ] **UI-02 · Capture real visual matrix.** Read-only captures of login, Overview, Red landing, setup/scope, Manual/Autonomous workspace and finding detail at 1440×900 and 390×844 in both themes. Track viewport, commit, date, route and readiness. Use user screenshots as visual baseline where local app unavailable. **Acceptance:** named comparable captures and missing cases logged. **Progress:** real named captures and all unmet states are logged in `ui_baseline_audit.md`; the task stays open until the listed missing states are captured.
- [x] **UI-03 · Theme/UX defect register.** Inspect computed CSS and screenshot comparisons against `tokens.css`, `styles.css`, `product.css`, current `check-theme.cjs`; separate confirmed failures from inferred risks, including keyboard/focus and stale text. **Acceptance:** severity, selector/component, light/dark repro, proposed fix and tests documented. **Evidence:** `ui_baseline_audit.md` (2026-10-30).
- [x] **UI-04 · Approve reference moodboard and hierarchy.** Evaluate linked public Figma shadcn/SOC/analytics kits and 21st.dev timeline/table, choose MARS's calm operator aesthetic, no AI-glow template. **Acceptance:** layout/typography/status grammar, allowed motion and 2–3 sample states accepted before coding. **Evidence:** `ui_baseline_audit.md` (2026-10-30).

## Phase 1 — Incremental Tailwind/shadcn foundations

- [x] **UI-05 · Dependency compatibility preflight.** Check Node/npm lock, React 18, Vite 6 and shadcn/Tailwind v4 official guidance; document exact planned dependencies, CSS interaction and rollback. **Acceptance:** minimal dependency proposal, no unnecessary React 19 upgrade, baseline tests unchanged. **Evidence:** `ui_baseline_audit.md`, Phase 1 record (2026-10-30).
- [x] **UI-06 · Add a coexisting Tailwind v4 shell slice.** After authorization, integrate Tailwind compilation with Vite and prove utilities in one isolated component while legacy screens render unchanged. **Acceptance:** `npm test`, `npm run build`, route/theme snapshots and easy rollback pass. **Evidence:** Tailwind Vite plugin; utility-only import without Preflight; shadcn Button adapter; `check-ui-foundation.cjs`.
- [x] **UI-07 · Map semantic theme tokens.** Make existing `tokens.css` MARS semantic roles compatible with shadcn, using one `data-theme="dark"`/Tailwind strategy and `mars-theme` storage; avoid competing `.dark` selectors. **Acceptance:** stable light/dark first paint, login parity, current native controls, computed token checks. **Evidence:** `@theme inline` maps MARS semantic variables and one Tailwind `dark` custom variant targets the existing root attribute.
- [x] **UI-08 · Introduce essential shadcn primitives only.** Button, Input, Select, RadioGroup, Dialog/Sheet, DropdownMenu, Table, Alert, Skeleton, Tooltip/Badge where needed. **Acceptance:** component API contract, no forked duplicates, accessibility behavior and limited dependency footprint. **Evidence:** selected local shadcn source under `src/components/ui/`; TooltipProvider mounted once; Button adapter replaces the former duplicate base implementation.
- [x] **UI-09 · Theme QA and cascade consolidation.** Fix verified conflicts in touched shared CSS, leave legacy compatibility rules until safely unused. **Acceptance:** computed WCAG contrast 4.5:1 ordinary text and 3:1 essential UI, hover/focus/disabled parity in both themes; no dark/light regression. **Evidence:** removed redundant `.ui-button` base/variant block from `styles.css`; computed primary-button contrast was 5.17:1 light and 6.48:1 dark in the live Red page; token checks, browser smoke, and regression suite passed. Full browser-state/zoom/forced-colors matrix remains UI-24/25 work.

## Phase 2 — App shell and Overview

- [x] **UI-10 · Navigation hierarchy.** Primary Overview, Red Team, Blue Team only; keep old URLs and accessible System/account/logout utilities. **Acceptance:** keyboard/active state, browser history, unknown route, mobile menu, old deep-link smoke pass.
- [x] **UI-11 · Shared shell and typography.** Refine rail, breadcrumb, header, content max-width, grid and responsive spacing, preserving MARS mark. **Acceptance:** 320/390/768/1024/1440/1920 no unexpected horizontal overflow or clipped navigation.
- [x] **UI-12 · Overview content truth.** Replace legacy Browse assessments CTA and “tools coming later” Red label; put Red readiness, last/current assessment and trustworthy user action up top; treat Blue neutrally. **Acceptance:** no fake success/readiness/metrics; mock and real read-only API states validated.
- [x] **UI-13 · Overview real states.** First visit empty, loading, running, completed with limitations, Red API offline, legacy stored-run DB absent, unauthenticated and retry. **Acceptance:** each state tells user what it means and what can be safely done, no silent blank panel.
- [ ] **UI-14 · Overview interaction QA.** Verify all cards/links actionable, legible typography, accessible descriptions and mobile state, light/dark. **Acceptance:** keyboard/screen reader, screenshot comparison, focused frontend tests pass.

**Phase 2 evidence:** See `ui_phase2_report.md` for implementation, checks and remaining browser acceptance. Phase 3 supplied live navigation and visual checks; UI-14 still needs screen-reader and full acceptance review.

## Phase 3 — Red Team assessment journey

- [x] **UI-15 · Red dashboard-first landing.** Move new-assessment form behind clear primary action; show current/last run, real counts and history first. **Acceptance:** operator sees next action in first viewport; no surprise authorization.
- [x] **UI-16 · Guided registered assessment setup.** Use shadcn Select/RadioGroup and compact scope review, never sliders for fixed Standard budget. Preserve Manual vs Autonomous and approval semantics. **Acceptance:** no backend policy change, keyboard+errors+long labels tested.
- [x] **UI-17 · Navigation after start and recoverability.** On successful acknowledged authorization/start navigate to correct workspace; review the existing queued recovery effect and protect against double dispatch. **Acceptance:** one intentional user command, idempotent retries, no scan on mount or dialog open.
- [x] **UI-18 · Canonical workspace route.** Define `/dashboard/red-team/assessments/:id` with auth-aware reload, back/forward, invalid ID, read-only deep link; retain current API contracts. **Acceptance:** URL is stable, opening URL alone never starts a job.
- [x] **UI-19 · Assessment list/table.** Target/mode/status/findings/coverage/updated/open, meaningful sorting/filtering only if supported, truncatable ID with copy/full detail. **Acceptance:** empty, loading, pages, long strings, responsive table and data provenance pass.

**Phase 3 evidence:** `ui_phase3_report.md` records route/recovery tests, live read-only browser checks, captures, owner-directed Overview changes, and DTO limitations. UI-19 uses available status/coverage fields; the API does not supply per-row finding counts or timestamps.

## Phase 4 — Live stages, findings and evidence

- [x] **UI-20 · Four-stage operational timeline.** Compact rows based on supplied reference; show accurate stage status, last event, tasks completed, error, permitted inspect/cancel/rerun. Rename “Live” to “Assessment timeline” after terminal state. **Acceptance:** all queue/blocked/stale/cancelled states, Manual vs Autonomous, no fake progress, reduced motion.
- [x] **UI-21 · Findings table.** Human-readable category, route, source-backed severity, verified outcome, distinct coverage gaps and selected test ID. **Acceptance:** suspected/inconclusive/not confirmed never displayed as confirmed; paths wrap/truncate appropriately.
- [x] **UI-22 · Evidence detail view.** Short metadata via accessible shadcn Dialog/Sheet; long/auditable evidence via linkable route. Keep hashes and exact receipts in secondary technical section. **Acceptance:** focus trap/return/Escape/overlay behavior, no sensitive body leaked, mobile support.
- [x] **UI-23 · Recovery and edge states.** Handle stale plans, duplicate commands, queue delays, server offline, missing receipt, session expiry, request-ID retry, no registered target, partial coverage. **Acceptance:** safe, specific inline feedback and zero unexpected dispatch.

**Phase 4 evidence:** See `ui_phase4_report.md` for stage/evidence implementation, requested refinements, tests, browser observations and remaining release-wide checks.

## Phase 5 — Production verification and acceptance

- [ ] **UI-24 · Browser automation.** Capture snapshots/light/dark at 320, 390, 768, 1024, 1440, 1920, 200% zoom; include overlays, native selects, tables, login, empty/error states. **Acceptance:** computed style tests and axe/WCAG AA audit logged, no blocking defects.
- [ ] **UI-25 · Accessibility review.** All actions keyboard reachable; 2–3px visible focus; semantic headings, labels, alt/sr text; no color-only status; focus retention, Escape; reduced motion/forced colors. **Acceptance:** documented keyboard-only journey and any residual gaps.
- [x] **UI-26 · Regression and UX quality gates.** Frontend `npm test`, `npm run build`, theme/routes/red/workspace scripts; relevant backend/auth smoke if contracts touched; compare screenshot diffs. **Acceptance:** exact commands/results/warnings, tested vs skipped, no Blue/legacy regression.
- [ ] **UI-27 · Human walkthrough and signoff.** Login → Overview → New Red assessment → Standard review → explicit start → workspace → stages → findings → evidence → coverage in Manual and Autonomous (read-only fixtures unless live authorized). **Acceptance:** reviewer verifies clarity, dark/light quality, no false claims, provenance and stable routes.

**Phase 5 evidence:** `ui_phase5_report.md` records fixes, 16 desktop axe audits, mobile/dialog audits, 60 responsive checks and 20 fixture captures. UI-24/25 remain unchecked for real 200% zoom, OS forced-colors and screen-reader checks; UI-27 awaits owner walkthrough/signoff. Engineering completion is not claimed as human acceptance.

**Owner follow-up (2026-10-30):** Login theme/password controls, centered branding, stronger table headers, bounded Dashboard link, dropdown visibility, toast entry motion, manual operation selection and sequential polling are implemented. `ui_completion_report.md` records 18 passing backend tests, the full frontend suite/build, six updated axe audits and 60 updated light/dark layout checks. Commit authorized by the owner; push remains unauthorized. Human acceptance items above remain open.

## Deferred, **not** authorized within UI project

- [ ] **DEFER-01:** separate cleanup plan for old Red architecture, legacy frontend routes and documentation after dependency tracing, research provenance and Blue impacts.
- [ ] **DEFER-02:** Blue Team product design/implementation (shared style must not break it but do not work on Blue behavior).
- [ ] **DEFER-03:** new testing profiles, vulnerability classes, scanners, auth scheme, queue or backend architecture changes.

## Definition of done for each UI slice

- [ ] Scope agreed; no unrequested changes to tracked/untracked files.
- [ ] Code/API behavior and command security preserved.
- [ ] Visual before/after in both themes, desktop and mobile.
- [ ] Test command and result, accessibility checks, limitations and any omissions recorded.
- [ ] Human readable changelog, exact diff and rollback path; no commit/push without separate authorization.
