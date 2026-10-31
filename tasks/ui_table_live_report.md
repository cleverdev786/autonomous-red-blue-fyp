# Assessment history table follow-up — 2026-10-31

Scope: the owner's latest request stops the wider application walkthrough and focuses on assessment history. Adapt the supplied compact table to MARS data, restore ascending assessment-number order, and retain the preceding selection-only deletion improvements. No commit or push is authorized for this follow-up. The preexisting `agents.md` deletion remains untouched.

Implemented:

- Persistent creation numbers replace list-position labels. Default order is ascending; deleting or filtering a record does not renumber its neighbors. Technical IDs remain available in the workspace and link targets.
- Six sortable data headers cycle none → ascending → descending → none. Enter/Space, `aria-sort`, animated caret and stable tie order are supported. The comparison helper handles strings with base/numeric locale comparison, numbers and dates; no date column is invented because the current assessment API supplies no per-row timestamp. Coverage sorts by executed/eligible ratio.
- A 150ms debounced, case-insensitive substring search filters all matching history before pagination. Displayed cell matches use escaped React text inside `<mark>`. Clear restores focus to the search input. Search and sort are server-backed so the browser receives only the selected page, initially ten records.
- Page sizes 10/25/50, previous/next and first/last/current ±1 page numbers with ellipsis gaps replace the earlier range slider. Search clamps an out-of-range page; live result counts and no-results table state remain visible. Select-all is page-scoped; the deletion command allows at most 50 records with its own bounded request size.
- Compact 13px body, 11px uppercase tracked labels, subtle zebra/hover tint, status pills with dots, 420px scroll region, opaque sticky headers and scroll shadow. Narrow layouts keep overflow inside the table and stack the toolbar. Cyan focus outlines and reduced-motion handling are included.
- Selection reveals one delete action; the confirmation identifies the selected stable numbers and contains the active-assessment/page-scope guidance. The pending loader remains in the dialog while history and totals update in place. No per-row delete control or browser reload is used during deletion.

Live checks used actual local application controls through the browser, not scripted fixture journeys or screenshot-based acceptance:

- Signed in to the rebuilt console. Default records were 01, 02, 03, 05, 06 with the original matching workspace links.
- Assessment header click, Enter and Space verified ascending, descending (06, 05, 03, 02, 01), then no-sort/default ascending. Mode sorting preserved creation order within equal-mode groups in both directions; inactive headers retained `aria-sort="none"`.
- Search `COMPLETED` returned 02/05 and highlighted both statuses. A nonexistent query showed zero results with disabled next/previous controls; Clear restored all five records.
- Actual page-size controls accepted 10, 25 and 50. Selected 03 and checked that the confirmation named 03, initially focused Cancel, then cancelled without deleting it. Delete control disappeared after deselection.
- Light theme/mobile 390px and desktop/dark were checked live. DOM layout inspection reported 375px document/client width, a 310px table scroll area and an 859px internal table, with no page overflow. Actual computed body/header sizes were 13px/11px, header spacing .66px, sticky positioning and max-height 420px. Restored desktop, dark theme, ten rows and default sort.
- During the preceding deletion verification, six new unstarted manual test drafts were cancelled and used exclusively for single/bulk deletion testing. Only the selected test IDs disappeared; surviving labels/links stayed fixed, pending feedback was visible, navigation state was retained, and the original five history records were preserved. No scan was authorized or executed.

Automated checks supplement the live checks:

- `npm --prefix dashboard/frontend test`: all 15 frontend script groups passed.
- `npm --prefix dashboard/frontend run test:red-dashboard`: passed after adding comparator, stable ties, date/number/string ordering, ellipsis ranges, ARIA, highlighting and escaped no-result checks. The focused test initially failed against the old unsortable table.
- `npm --prefix dashboard/frontend run build`: passed.
- `.venv/bin/pytest tests/test_red_read_api.py tests/test_local_auth.py -q`: 30 passed in 37.56s. Includes default/global sort, stable ties, search, page clamp, invalid sort rejection, deletion boundaries and authorization checks.
- Ruff on changed Python files and `git diff --check`: passed.

Limits and omissions:

- Only five original records remain, so multi-page numbered navigation/ellipsis is covered by automated checks rather than by adding more live history solely for pagination. The preceding ten-record/page-slider implementation was exercised live with eleven records before the latest numbered-navigation request.
- No new screenshot matrix or audible screen-reader certification is claimed. The owner's current instruction requests direct live checks without images or browser test scripts. Existing historical UI-24/UI-25 evidence remains separate.
- The wider walkthrough was stopped as requested. Earlier observations include deferred Blue Team behavior and unavailable legacy stored-run/findings database; this report does not claim every application feature works. No model loading, scan execution or patch application was performed.
- Vanilla CSS migration is incomplete: all five imported CSS files still support live routes/theme/layout. Only obsolete table rules were replaced; active stylesheet files/dependencies were retained after reference checks.
- A previously reproduced unrelated write-API timestamp test failure remains documented in `ui_history_deletion_report.md`.
