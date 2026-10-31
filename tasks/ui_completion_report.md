# MARS UI follow-up verification — 2026-10-30

The owner authorized the remaining implementation fixes and a local commit. No push, live scan, assessment start, cancellation, Docker operation or data migration was performed. The preexisting `agents.md` deletion is excluded from the commit.

## Delivered

- Login offers a persisted theme toggle and accessible show/hide password control. The MARS mark and workspace label are centered together; entered credentials are retained when toggling visibility.
- Assessment history headers have larger, stronger text. Wide tables scroll inside their containers. The Dashboard link is content sized (measured 102.5px inside a 1377px navigation container).
- Dashboard filters use the existing shadcn Select with readable selected values, wrapped options, keyboard navigation and theme-aware popup colors. Native operation selectors also use semantic colors.
- Toast notifications slide in; reduced-motion users receive a static notification.
- Manual planning can yield several approved operations. Previously the frontend disabled execution whenever the total operation count was not exactly one. Workspace reads now expose only operation ID, plan version, registered test ID and status. The UI selects one approved operation on the current plan and supplies its ID to the existing stage command. Server approval, current-plan, receipt, scope, CSRF and queue checks remain intact. No automatic stage execution was added.
- Polling schedules its next read after the previous read settles, avoiding repeated cancellation of slow requests. Terminal records stop polling. Explicit refresh retains its feedback.

## Checks actually run

- `cd dashboard/frontend && npm test`: all 15 script groups passed. Added multiple-operation/blocked-operation, explicit command payload and polling lifecycle regression checks; login privacy checks remain.
- `cd dashboard/frontend && npm run build`: passed, 2173 modules; CSS 107.82 kB and JS 418.42 kB (131.93 kB gzip).
- `.venv/bin/python -m pytest tests/test_red_read_api.py tests/test_local_auth.py -q`: 18 passed. Includes multiple-operation selection, rejection of ambiguous/unknown selection and unchanged database bytes during reads/selection. The read test helper now supplies the current local session cookie; unauthenticated requests still fail closed.
- `.venv/bin/ruff check services/red_read_service.py schemas/red_team_state.py tests/test_red_read_api.py`: passed.
- `git diff --check`: passed.
- Browser fixture checks: 60 cases, five surfaces at 320/390/768/1024/1440/1920px in both themes, zero document overflow. Real wide tables deliberately retain local horizontal scrolling.
- Six desktop axe audits (login, dashboard, workspace × both themes): zero violations and zero incomplete checks. Password visibility/theme switching and status-popup contents were checked through the browser. These audits do not certify all WCAG requirements.

Local evidence: `/tmp/mars-final-tests.log`, `/tmp/mars-final-python.log`, `/tmp/mars-final-build.log`, `/tmp/mars-final-axe.json`, `/tmp/mars-final-responsive.json`, `/tmp/mars-final-login.jpg`, `/tmp/mars-final-workspace.jpg`. Earlier Phase 5 evidence remains documented in `ui_phase5_report.md`.

## Remaining acceptance and runtime limits

Real 200% browser zoom, OS forced-colors mode, a screen-reader walkthrough and owner signoff remain unverified. Their checklist items stay open. No live manual or autonomous security run was used for verification; command behavior was checked with mocks and isolated test databases.

The running Python console must load the updated code to expose operation metadata. Restart the console through its normal launcher if it does not reload Python changes automatically; the frontend safely retains the older single-operation guard when that metadata is absent. No running worker was restarted during this UI task.

Legacy CSS remains for legacy routes; the migration removed conflicting rules in touched surfaces, not every vanilla stylesheet. Blue Team behavior and the separately deferred architecture cleanup remain outside scope. Previously recorded dependency advisories were not resolved through an unrelated bulk upgrade.
