# Phase 5 — verification and reported usability fixes

Date: 2026-10-30. Base: development 56ff2af plus the existing UI working tree.

## Implemented fixes

- New assessment no longer switches to an unrelated active run. A failing controller regression reproduced the recovery takeover before it was removed. Existing runs remain accessible from their own workspace links; no automatic command is issued.
- Registered-target Select opens below its trigger with explicit popover surfaces and hover states. Review is a deliberate button using selected React state, independent of hidden native-select form validation. Missing selection is guarded; scope review sends no write.
- Dashboard moved outside the target card into a left-aligned assessment navigation row below the page heading.
- Dark mode now uses neutral slate surfaces and a muted blue action palette. Removed the old SOC gradient/shadow override blocks that were defeating theme tokens.
- History rows use readable type, spacing, separate card-like surfaces, restrained status colors, and labelled coverage progress bars based on actual executed/eligible counts.
- Primary row labels are numbered list positions (Assessment 01, 02, …). They are explicitly labelled List position because filters/paging can change positions. Persisted IDs remain unchanged in URLs, accessible references and technical disclosures; these are not new stable database IDs.
- Added restrained New assessment hover/pressed feedback, with reduced-motion support.
- Toasts acknowledge scope review, accepted/rejected commands and explicit dashboard/workspace/runtime refresh completion. Durable errors remain inline. Background polling does not generate runtime/workspace refresh toasts.
- Dashboard target/summary/list loading is coordinated, preventing competing effects from overwriting failures. Workspace refresh displays busy state and refreshes filtered finding pages. Runtime refresh also displays busy state. All three Refresh surfaces were exercised against live read-only APIs and showed completion toasts.
- Fixed narrow-grid overflow for long registered target names and active continuation links. Added forced-color system-color fallbacks.

## Checks actually completed

- Full npm test passed after the active-run fix; targeted scope-review tests cover selected and missing targets, and direct button semantics.
- npm run build passed; git diff --check passed.
- Installed axe-core as a development dependency. qa.html / verification-ui.tsx is a labelled development-only fixture page, excluded from the default production index build. It refuses writes and unknown network requests.
- 16 desktop fixture/theme audits (Manual, Autonomous, setup, empty, error, dashboard, Overview, login; light and dark) reported zero violations and zero incomplete checks for the selected WCAG 2 A/AA and 2.1 A/AA rules.
- Mobile fixture audits reported zero violations. Some clipped table content produced incomplete contrast checks; the equivalent fully visible desktop content passed. Mobile evidence dialog audit reported zero violations and zero incomplete checks.
- 60 responsive geometry checks: five surfaces × six widths (320, 390, 768, 1024, 1440, 1920) × both themes. Final run recorded no document horizontal overflow and no viewport mismatches. Twenty named fixture captures were saved at 390 and 1440 widths.
- Keyboard target selection (Space/Enter) reached Standard scope review and its toast.
- Evidence dialog Escape returned focus to the exact Inspect trigger; previous Tab containment checks remain valid.
- Live application: restored the authorized local session, opened setup while an existing assessment was active, selected the target and reviewed scope successfully. No assessment was created, authorized, started or cancelled by this work.
- Live dashboard, terminal workspace, and System refresh each completed and displayed the appropriate toast.

## Local verification artifacts

- /tmp/mars-phase5-axe-final.json — desktop light/dark fixture audits.
- /tmp/mars-phase5-axe-mobile-final.json — mobile audits, including incomplete counts.
- /tmp/mars-phase5-axe-evidence.json — evidence dialog audit.
- /tmp/mars-phase5-responsive-final.json — final 60-case geometry matrix.
- /tmp/mars-phase5-captures/ — twenty labelled fixture screenshots.
- /tmp/mars-phase5-table-final.jpg — live numbered assessment history.
- /tmp/mars-phase5-complete-tests.log — full regression output.
- /tmp/mars-phase5-handoff-build.log — final build output.

## Acceptance still requiring human/environment support

This is not a full WCAG certification or owner signoff. Browser Ctrl-plus produced no zoom change in the available in-app browser; real 200% browser zoom was therefore not verified. Forced-color fallbacks were implemented, but OS forced-colors emulation was unavailable. No screen-reader software walkthrough was performed. UI-24/25 retain these explicit gaps; UI-27 remains for an owner walkthrough and acceptance. UI-02/14's corresponding outstanding evidence is not silently checked off.

Start/authorization/error/retry journeys use existing API/controller mocks; no live scan or write journey was performed. Backend/auth contracts were not changed, so backend scan/auth suites were not rerun. npm still reports the two pre-existing dependency advisories (one moderate, one high); no forced dependency upgrade was applied.

No migration, Docker operation, research-data change, commit or push. Existing agents.md deletion is preserved.
