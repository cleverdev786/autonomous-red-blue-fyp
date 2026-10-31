# Phase 4 — stages, findings, evidence and requested refinements

Date: 2026-10-30. Based on development 56ff2af plus the existing UI working tree.

## Implemented

- UI-20: compact Manual stage rows and Autonomous timeline, expandable safe history, readable transition labels, explicit task/record counts, status text and terminal “Assessment timeline” heading. Security coverage is a separate summary with scope warnings.
- UI-21: human-readable categories, exact outcome/severity labels, wrapped routes, suspected-observation warning, and real server-backed status filtering/paging. No suspected, inconclusive or not-confirmed outcome is promoted to confirmed.
- UI-22: shadcn evidence Dialog with loading/error/retry feedback, focus containment, Escape and return focus. The audit permalink uses the existing assessment URL plus a finding query parameter. It survives reload and checks that the finding belongs to the current assessment. Full test/oracle/operation/plan references, receipt IDs and hashes remain in a technical disclosure. No response bodies are rendered.
- UI-23: synchronous workspace command guard; retained request IDs on failure; aborted evidence/page requests cannot replace newer selections; explicit retries for failed evidence/pages; session-expiry and unavailable-record messages; current-plan/current-surface validation before Manual Execution. Backend authorization and its one-approved-operation prerequisite remain authoritative and unchanged.

## Owner-requested refinements

- Replaced the persisted-outcomes/Blue handoff paragraph with an Open reports button-styled anchor.
- Findings Inspect controls are proper buttons with finding-specific accessible names.
- The return link is a button-styled Dashboard link with restrained hover movement and reduced-motion support.
- Sign out is a red labelled icon with a hover surface; theme uses labelled sun/moon icons and its existing pressed state.
- Mode radios are circular 18×18px controls in aligned 44px rows. A global button minimum height had caused their stretched shape.
- Scope review uses a horizontal grid for target, classes and budget, stacking responsively. Its persistent status hint is five words per mode, rather than an auto-dismissed notice hiding an authorization boundary.
- Primary-button glow rules were removed, weights reduced, borders aligned and secondary surfaces quieted. The light navigation rail uses pale gray (#edf1f5).
- Narrow workspace tracks, long-ID wrapping and positioned table scrolling contain the findings table on mobile.

## Verification

- Full npm test passed; tests include terminal wording, status variants, safe escaping, complete evidence hashes/receipts, server finding pagination and the existing authorization/recovery/route regressions.
- npm run build passed. git diff --check passed.
- Live browser: existing terminal assessment shows separate coverage, renamed timeline and humanized categories; no write command was invoked.
- Evidence dialog loaded the stored registered test metadata. Escape closed it and returned focus to the exact Inspect control. Tab remained within the dialog.
- Audit permalink loaded the same finding in a linkable assessment audit section.
- Computed Manual/Autonomous radio geometry: 18px wide, 18px high, 18px minimum height. Computed primary-button shadow: none. Light sidebar: rgb(237,241,245); sign-out ink: rgb(180,35,24).
- Scope review checked at 1440×900 light and 390×844 dark. Mobile scope had no document horizontal overflow.
- Final mobile audit page: document width 375px at a 390px viewport, with the table scrolling inside its own positioned container. Desktop workspace also had no document overflow.
- Evidence dialog checked in both themes; the light dialog uses the light surface/text roles. Dark and light evidence screenshots were captured.

Screenshots: /tmp/mars-phase4-scope-light.jpg, /tmp/mars-phase4-scope-dark-mobile.jpg, /tmp/mars-phase4-workspace-dark.jpg, /tmp/mars-phase4-evidence-dark.jpg and /tmp/mars-phase4-evidence-light.jpg.

## Remaining release-wide checks

Full axe/screen-reader/zoom/forced-colors and exhaustive visual fixture acceptance remain Phase 5. Browser operation is read-only; failed/blocked/stale states and authorization/start retries use fixtures/controller tests. No live assessment was created, authorized, started or cancelled.

No backend contract changes, migrations, Docker operations, commits or pushes. Existing agents.md deletion is preserved.
