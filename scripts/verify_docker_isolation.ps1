$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

docker compose config -q
if ($LASTEXITCODE -ne 0) { throw "Compose configuration validation failed." }

$appStatus = docker inspect --format='{{.State.Health.Status}}' fyp-vulnerable-store
$executorStatus = docker inspect --format='{{.State.Health.Status}}' fyp-controlled-executor

if ($appStatus -ne "healthy") {
    throw "vulnerable-store is not healthy: $appStatus"
}

if ($executorStatus -ne "healthy") {
    throw "controlled-executor is not healthy: $executorStatus"
}

Write-Host "PASS: both services are healthy."

docker compose exec -T controlled-executor python -m infrastructure.executor.isolation_probe
if ($LASTEXITCODE -ne 0) { throw "Runtime isolation probe failed." }

Write-Host "PASS: Docker lab isolation checks completed."
