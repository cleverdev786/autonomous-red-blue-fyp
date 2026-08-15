$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

docker compose config -q
if ($LASTEXITCODE -ne 0) { throw "Compose configuration validation failed." }

$tests = @(
    "sqli-login-bypass-001",
    "xss-reflection-001",
    "path-traversal-private-file-001"
)

foreach ($testId in $tests) {
    Write-Host ""
    Write-Host "===== $testId ====="
    docker compose exec -T controlled-executor `
        python -m infrastructure.executor.run_registered_test `
        --test-id $testId `
        --attempt-number 1

    if ($LASTEXITCODE -ne 0) {
        throw "Registered security test failed: $testId"
    }
}

Write-Host ""
Write-Host "PASS: all three registered security tests produced deterministic evidence."
