# Controlled Vulnerability Scenarios

This directory contains the frozen ground truth for the first three deliberately vulnerable scenarios.

## Scenarios

### `sqli-login-001`

Endpoint:

```text
POST /scenarios/sql-injection/login
```

Purpose:

Demonstrates authentication bypass caused by raw SQL string construction using the synthetic `username` input.

### `xss-search-001`

Endpoint:

```text
GET /scenarios/xss/search?q=...
```

Purpose:

Demonstrates reflected XSS by returning synthetic query text inside an HTML response without escaping.

### `path-traversal-read-001`

Endpoint:

```text
GET /scenarios/path-traversal/read?path=...
```

Purpose:

Demonstrates traversal from the scenario's intended `public/` directory into its synthetic `private/` directory.

## Important Safety Boundary

The traversal scenario is deliberately vulnerable **inside the scenario sandbox only**.

It allows:

```text
public/../private/demo-secret.txt
```

It still blocks paths that resolve outside:

```text
dummy_apps/vulnerable_store/scenario_files/
```

Therefore the experiment can reproduce path traversal without providing access to arbitrary repository or host files.

## Ground Truth

Each JSON file records:

- scenario ID;
- deterministic test ID;
- vulnerability class;
- endpoint/method/input;
- vulnerable source location;
- root cause;
- expected evidence;
- expected secure behavior;
- normal behavior;
- reset operation.

Ground truth must remain separate from future model-visible prompts during final evaluation.
