$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "Docker is not installed or not on PATH."
}

docker compose config -q
if ($LASTEXITCODE -ne 0) { throw "Compose configuration validation failed." }

docker compose up -d --build
if ($LASTEXITCODE -ne 0) { throw "Docker Compose startup failed." }

Write-Host ""
Write-Host "Waiting for services to become healthy..."

for ($i = 0; $i -lt 30; $i++) {
    $appStatus = docker inspect --format='{{.State.Health.Status}}' fyp-vulnerable-store 2>$null
    $executorStatus = docker inspect --format='{{.State.Health.Status}}' fyp-controlled-executor 2>$null

    if ($appStatus -eq "healthy" -and $executorStatus -eq "healthy") {
        Write-Host "Environment is healthy."
        Write-Host "Dummy app: http://127.0.0.1:8000"
        exit 0
    }

    Start-Sleep -Seconds 2
}

docker compose ps
throw "Services did not become healthy in time."
