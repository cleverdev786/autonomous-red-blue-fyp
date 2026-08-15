$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "Docker is not installed or not on PATH."
}

Write-Host "Stopping lab and deleting runtime volume..."
docker compose down --volumes --remove-orphans
if ($LASTEXITCODE -ne 0) { throw "Docker Compose shutdown/reset failed." }

& (Join-Path $PSScriptRoot "start_environment.ps1")
