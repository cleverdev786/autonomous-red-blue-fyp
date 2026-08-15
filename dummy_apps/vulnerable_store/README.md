# Vulnerable Store — Controlled Local Dummy Application

This is the deliberately controlled web application used by the FYP.

It contains two kinds of routes:

1. **normal baseline routes** used for functional/regression checks;
2. **separate deliberately vulnerable scenario routes** used only for the approved local experiments.

## Normal Baseline Routes

- `GET /health`
- `POST /login`
- `GET /search?q=...`
- `GET /documents`
- `GET /files/{document_id}`

## Deliberately Vulnerable Scenario Routes

- `POST /scenarios/sql-injection/login`
- `GET /scenarios/xss/search?q=...`
- `GET /scenarios/path-traversal/read?path=...`

The scenario routes are intentionally unsafe and must never be exposed publicly.

## Synthetic Accounts

```text
student1 / demo-pass-1
student2 / demo-pass-2
```

These credentials are fabricated and must never be reused anywhere else.

## Run Locally

From repository root:

```bash
python -m dummy_apps.vulnerable_store.app.reset
uvicorn dummy_apps.vulnerable_store.app.main:app --host 127.0.0.1 --port 8000
```

The localhost binding is intentional.

## Reset

```bash
python -m dummy_apps.vulnerable_store.app.reset
```

Reset restores:

- synthetic users;
- synthetic products;
- baseline download files;
- traversal-scenario public/private files.

## Path-Traversal Safety Design

The traversal scenario intentionally allows a path to move from:

```text
scenario_files/public/
```

to:

```text
scenario_files/private/
```

This proves the vulnerability.

A separate outer guard still blocks escaping the complete:

```text
scenario_files/
```

sandbox. This keeps the scenario educational and reproducible without exposing arbitrary host paths.

## Ground Truth

See:

```text
dummy_apps/vulnerable_store/scenarios/
```

Ground-truth files are for deterministic verification/research evaluation and must not be silently passed to LLM agents during final experiments.
