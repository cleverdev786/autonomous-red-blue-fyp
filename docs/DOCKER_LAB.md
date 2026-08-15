# DOCKER LAB

## Purpose

Milestone 5 isolates the deliberately vulnerable application and future
security-test execution path inside Docker.

## Runtime Services

### `vulnerable-store`

Runs the local deliberately vulnerable FastAPI app.

Host access:

```text
http://127.0.0.1:8000
```

The port is intentionally bound to loopback only.

### `controlled-executor`

A restricted container reserved for the deterministic security-test harness.

At Milestone 5 it runs only an idle process plus fixed health/isolation probes.
It does **not** yet implement attack execution.

It has:

- no published port;
- no host bind mount;
- no Docker socket;
- read-only root filesystem;
- dropped Linux capabilities;
- `no-new-privileges`;
- CPU, memory, and PID limits;
- only the internal lab network.

## Network

```text
security-lab
```

Compose config:

```yaml
internal: true
attachable: false
```

Both services use only this network.

## Runtime Data

The dummy app receives one named volume:

```text
store-runtime:/runtime
```

The application source remains part of the read-only image.

Runtime SQLite and synthetic scenario files live under `/runtime`.

## Start

Linux:

```bash
bash scripts/start_environment.sh
```

Windows PowerShell:

```powershell
.\scripts\start_environment.ps1
```

## Verify Isolation

Linux:

```bash
bash scripts/verify_docker_isolation.sh
```

Windows:

```powershell
.\scripts\verify_docker_isolation.ps1
```

The runtime probe verifies:

1. `controlled-executor` can reach `vulnerable-store`;
2. the executor cannot reach a fixed public HTTP probe destination.

## Full Reset

Linux:

```bash
bash scripts/reset_environment.sh
```

Windows:

```powershell
.\scripts\reset_environment.ps1
```

The reset deletes the runtime named volume and recreates the services, forcing
the application to seed a clean synthetic state.

## Important Build-vs-Runtime Distinction

The Docker image build may require normal internet access to obtain the trusted
Python base image and declared Python packages.

The safety requirement applies to the **runtime controlled security-test
container**, whose Compose network is externally isolated.

## Do Not Change Without Reviewing the Threat Model

Do not:

- add `network_mode: host`;
- set `privileged: true`;
- mount the Docker socket;
- mount the whole host repository into the executor;
- connect the executor to another non-internal network;
- publish an executor port;
- change the vulnerable app port binding from `127.0.0.1` to `0.0.0.0`.
