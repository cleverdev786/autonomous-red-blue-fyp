# UI-24 / UI-25 verification slice — 2026-10-30

## Scope and preservation

The owner requested completion of UI-24, UI-25 and the four delivery checks, and authorized a local commit. This slice covers browser verification, accessibility fixes found by that verification, and reproducible evidence. The starting commit is `2c413db`; the only preexisting working-tree change was the deletion of `agents.md`, which is excluded from this commit.

No command-service, API, authorization, target, budget, worker, dataset or stored assessment changes are included. Browser interactions use synthetic fixtures that reject all writes and unknown network requests. No live assessment was created, authorized, started, advanced or cancelled. No push is authorized or performed.

## Defects found and fixed

- Loading text in dark mode had a measured 3.18:1 contrast ratio. Removed the hardcoded legacy color so the existing semantic muted token applies in both themes.
- Red setup, dashboard and workspace headings skipped level 2. Corrected the hierarchy while retaining the intended visual sizes; added regression assertions.
- The mobile findings table compressed long routes and headings into narrow columns. Added a readable table minimum width and labelled, focusable scroll regions for findings and history. Keyboard users can reveal overflow columns using ArrowRight; focus has a 3px outline.

The development-only fixture page now includes loading state, functional mode selection, notification preview, query-selected surfaces/themes and detailed popup audit output. These controls are test scaffolding and are excluded from the production Vite entry point.

## Reproduction

Use the existing frontend dependencies and Mozilla's temporary test driver; no new product dependency is required:

```bash
.venv/bin/python -m pip install --target /tmp/mars-ui-qa-tools marionette_driver==3.7.1
cd dashboard/frontend
npm run dev -- --port 5173 --strictPort
```

From the repository root in a second terminal:

```bash
PYTHONPATH=/tmp/mars-ui-qa-tools .venv/bin/python verification/check_ui_browser.py
```

The runner starts Firefox with a disposable profile and closes it afterward. Its privileged browser context is limited to test-window sizing and Firefox's own zoom setting. It never attaches to a personal browser profile. The driver follows [Mozilla's Marionette API](https://firefox-source-docs.mozilla.org/python/marionette_driver.html).

`--interactions-only` reruns keyboard checks. `--baseline` captures the previous committed UI on port 5174 without asserting its known contrast defect. The before server was produced by archiving `2c413db` to `/tmp/mars-ui-before`, reusing installed node modules and copying only the current synthetic harness into that temporary checkout. Production source in that baseline remains unchanged.

## Verification and evidence

Final results on Firefox 149.0:

| Check | Result |
| --- | --- |
| Normal light/dark matrix | 108 captures/audits; no document overflow |
| Genuine 200% zoom | 18 captures/audits; 1440px → 720 CSS px, DPR 2 |
| Active forced colors + reduced motion | 9 captures/audits |
| Dropdown and evidence overlays | 8 captures/audits at 390/1440px in both themes |
| Axe | Zero violations across 143 cases; 12 cases have logged incomplete contrast checks |
| Dialog computed contrast | At least 6.05:1 across the checked visible text, above 4.5:1 |
| Keyboard | Five passing journeys; 3px focus outline; overflow columns reachable |
| Frontend | `npm test` and `npm run build` passed |
| Backend/auth preservation | `.venv/bin/python -m pytest tests/test_red_read_api.py tests/test_local_auth.py -q`: 18 passed |
| Static checks | `.venv/bin/ruff check verification/check_ui_browser.py` and `git diff --check` passed |

Build output: 2173 modules, CSS 107.96 kB and JS 418.54 kB (131.96 kB gzip). The exact commands and results are retained with the artifacts.

The full runner covers nine surfaces—login, Overview entry cards, dashboard, setup, Manual workspace, Autonomous workspace, empty, error and loading—at 320, 390, 768, 1024, 1440 and 1920px in light/dark themes. It also captures genuine 200% browser zoom, active forced-colors rendering and dropdown/evidence overlays at mobile and desktop widths. Normal viewport assertions prevent a minimum browser-window size from being mistaken for a 320px test.

At 200%, Firefox's `browsingContext.fullZoom` is asserted to equal 2 and the CSS viewport halves relative to 100%; this is not a CSS transform or viewport-only approximation. Forced colors are activated in the disposable profile and confirmed through `matchMedia('(forced-colors: active)')`. Reduced motion is similarly activated and confirmed. No system-wide theme, accessibility or normal browser-profile setting is changed.

Keyboard-only journeys exercise:

1. Login theme → username → password → show/hide, with focus retained and a measured 3px outline.
2. Target Select using Space/Down/Enter → mode using ArrowRight → scope review using Enter.
3. The labelled findings scroll region using ArrowRight to reveal overflow columns.
4. Finding inspector using Enter → eight Tabs confined to the dialog → Escape → exact initiating button.
5. A notification rendered without animation when reduced motion is active.

The generated JSON records viewport, actual media state, axe findings and keyboard results. A curated before/after set and audit results are under `ui_evidence/`; the complete capture set is retained in the task's visualization artifacts. Before/after evidence refers to this verification slice, not an invented historical screenshot matrix for the original redesign. UI-02 still tracks the missing real-record baseline states.

Complete artifact directory: `/home/zain/.codex/visualizations/2026/10/30/01a18bd6-2d69-7722-90f4-26948ea19bc7/ui-acceptance/`. `before/` contains 16 baseline captures. `after/` contains the 143 matrix/overlay captures, an additional forced-colors keyboard-dialog capture and the machine-readable results. Test/build/backend logs sit beside them. `ui_evidence/visual-manifest.json` records hashes for the 16 committed comparison images.

## Limits and disposition

An audible screen-reader walkthrough is not certified. Orca was attempted, but its Speech Dispatcher connection failed; no successful application announcement is claimed. UI-14 and UI-27 remain open for the outstanding screen-reader/owner review. UI-25's documented keyboard, semantics, focus, status, reduced-motion and forced-colors checks are separate from that human acceptance.

Axe can report incomplete contrast checks for cells clipped by a horizontal scroll container and for overlapping fixed dialog layers. These are logged rather than labelled automatic passes. Equivalent fully visible cells are audited at desktop width; dialog text is additionally checked against its opaque computed background with a 4.5:1 assertion. Status text remains explicit, so recognition does not depend only on color. This is engineering accessibility verification, not a blanket WCAG conformance certificate or a claim of OS-wide high-contrast testing.

Legacy/Blue functionality and the original redesign's human acceptance are outside this slice. Only the current verification slice's definition-of-done boxes are closed by this evidence.

## Review and rollback

Review the verification commit with `git show --stat` and `git diff 2c413db..HEAD -- dashboard/frontend verification/check_ui_browser.py tasks`. The report, runner, fixture controls and regression assertions document the delivered behavior. To roll back later, review and revert this verification commit by its hash; do not reset the checkout or restore the unrelated `agents.md` deletion. No persisted application data needs rollback.
