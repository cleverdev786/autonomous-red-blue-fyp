# Assessment history deletion — 2026-10-31

Single and page-scoped bulk deletion are available in Red Team history through checkbox selection. Select all covers deletable records on the current page (10/25/50 records). The Delete action appears only after selection. The confirmation lists stable assessment numbers, initially focuses Cancel, supports Escape and restores focus. Errors retain the selection; successful deletion refreshes history and totals in place and preserves the current page when it remains valid. See `ui_table_live_report.md` for the subsequent live verification and table refinements.

Deletion is logical history removal. Assessment state, queue history, findings, receipts, evidence files, exports and direct audit links remain intact. Deleted records are excluded from the dashboard list and summary. Active assessments must first be explicitly stopped; terminal status alone is insufficient if a queued/running stage or queue lease remains.

`POST /api/red/assessments/delete-history` accepts `{"assessment_ids":["assessment-id"]}` for one or several records. Existing session, trusted-Origin, CSRF, JSON/body-size and identifier checks apply. A SQLite transaction validates the entire selection before inserting history-deletion metadata; mixed invalid/active selections change no history entries. Repeated requests are idempotent. Older databases remain readable without schema writes on GET; the small metadata table is created through normal writable-store initialization. Implementation initially used isolated tests; subsequent live deletion verification is recorded in `ui_table_live_report.md`.

Verification:

- Frontend `npm test`, focused `npm run test:red-dashboard` and `npm run build` passed.
- `tests/test_red_read_api.py` + `tests/test_local_auth.py`: 29 passed, including successful bulk removal, retained evidence/audit links, mixed-batch rollback, active leases, invalid selections, retries, auth/CSRF denial and old-database reads.
- `tests/test_red_store.py`, `tests/test_red_queue.py`, `tests/test_red_evidence_store.py`: 32 passed.
- `tests/test_red_write_api.py` excluding `test_autonomous_start_sequences_every_approved_operation`: 14 passed. That one existing test fails because its fixed claim timestamp precedes the real enqueue time. The same failure was reproduced with the unchanged API/read/store modules from HEAD; queue behavior and that unrelated test were left unchanged.
- Ruff and `git diff --check` passed for the affected code.
- `verification/check_history_deletion.py`: single/bulk deletion, cancellation, exact focus return, disabled active-row actions and failure retention passed on synthetic fixtures at 390/1440px in light/dark. Four dialog axe audits found zero violations. No real assessment or history record was changed by those fixture checks.

To rerun the browser checks, start the frontend fixture server on port 5173 and run `PYTHONPATH=/tmp/mars-ui-qa-tools .venv/bin/python verification/check_history_deletion.py` using the temporary Mozilla driver described in `ui_acceptance_report.md`.

The console backend must load the updated Python code before the new endpoint is available; restart it through its normal launcher if it does not auto-reload. No running worker was restarted. No commit or push was made for this feature. The preexisting `agents.md` deletion remains untouched.
