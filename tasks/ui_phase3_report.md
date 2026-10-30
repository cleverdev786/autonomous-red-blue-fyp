# Phase 3 — assessment journey and Overview correction

Date: 2026-10-30. Baseline: development at 56ff2af plus existing Phase 1/2 working changes.

## Plan alignment

The implementation follows the plan's main boundaries: one application login, Tailwind v4 with selected local shadcn components, fixed server-owned Standard scope, no navigation-triggered operations, independent coverage and workflow outcomes, preserved Blue/legacy routes and no backend changes.

The detailed Phase 2 Overview exceeded the owner's intended scope. The owner clarified that Overview should have a hero and two team-entry bento cards. That clarification is recorded in plan_ui.md and now replaces the earlier detailed metrics/history composition. Red details belong inside Red Team.

## Implemented

- UI-15: dashboard-first landing with a deliberate New assessment toggle. Counts, history, filters and non-terminal continuation links remain available. Opening setup performs no write.
- UI-16: registered target uses shadcn Select; Manual/Autonomous uses labelled RadioGroup. Standard scope comes from the registered target response. Empty registry feedback and disabled review prevent proceeding without a target.
- UI-17: removed the queued recovery effect that invoked start. A recovered queued autonomous workspace instead offers an explicit Start authorized assessment action. A synchronous guard prevents rapid double submissions during creation/authorization/start. Successful authorization/start invokes workspace navigation once; failed commands retain request IDs for retry.
- UI-18: canonical /dashboard/red-team/assessments/:id URLs retain Red navigation state, authenticated reload and browser history. Malformed paths resolve as unknown routes. Workspace errors explain missing assessments and expired sessions. Opening an assessment reads data only.
- UI-19: semantic history table retains server paging/filtering, shortened IDs with full title/accessibility labels and detail, and button-styled anchor navigation supporting modified clicks. Active records have continuation links. Metrics warn that repeated findings across assessments are possible.
- Overview: hero above a responsive Red/Blue bento grid. Explicit Open Red Team and Open Blue Team anchors use shadcn Button styling. Blue remains described as deferred.
- Navigation: replaced hover-dependent rail expansion with a labelled desktop collapse/expand button. Mobile drawer includes disclosure summaries in its focus loop, locks background scrolling, makes main inert, closes on Escape and returns focus to Menu. Resizing to desktop closes the drawer.
- Cleanup: removed obsolete desktop hover expansion CSS and the unused old Overview bento layout; removed the detailed Phase 2 Overview styling. Legacy route styles remain where still used.

## Verification

- Full npm test passed, including Overview, navigation, Red API, workspace, creation, auth/security receipt and route checks.
- New failing route test was run before route implementation; it failed on missing assessmentId as expected, then passed.
- Recovery controller test verifies repeated renders of a queued autonomous assessment send zero POSTs.
- Rapid double authorization test verifies one start request and one navigation callback.
- Production npm run build passed. git diff --check passed.
- Live read-only browser review verified the new hero/team cards, registered-target Select, fixed Manual scope review, and existing terminal Autonomous workspace.
- Canonical existing workspace survived reload; Back returned to Red landing and Forward restored the same assessment URL.
- Mobile 390px drawer: focus moved to Close navigation; main was inert; body scrolling was locked; Escape restored Menu focus and released inert/scroll lock.
- Desktop collapse measured 76px and expansion measured 224px with matching aria-expanded.
- Overview had no document horizontal overflow at 320, 390, 768, 1024, 1440 and 1920 widths in dark mode. 1440px light and 390px dark screenshots were captured; mobile scope review also had no document overflow.

Capture files (local, generated; not committed):

- /tmp/mars-phase3-overview-light.jpg
- /tmp/mars-phase3-overview-dark-mobile.jpg
- /tmp/mars-phase3-scope-dark-mobile.jpg

## Limits and deferred verification

The assessment-list DTO does not provide per-record finding counts or timestamps. No fake Updated/findings values or extra per-row workspace fetches were introduced; available coverage/status fields are displayed. Full authenticated browser write journeys use mocked controller/API tests; no live assessment was created, authorized or started.

Automated axe, screen-reader review, 200% zoom, forced colors and the exhaustive visual/error fixture matrix remain UI-24/25/27 work. UI-02's missing historical baseline cases remain open. The terminal timeline wording and finding inspector belong to Phase 4 and were not silently changed.

No commit or push. Existing agents.md deletion and unrelated data remain untouched.
