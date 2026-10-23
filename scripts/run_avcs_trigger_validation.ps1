$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

conda activate codesentry310

function Assert-ExitCode {
    param(
        [int]$Code,
        [string]$Step
    )

    if ($Code -ne 0) {
        Write-Host ""
        Write-Host "[FAIL] $Step"
        exit $Code
    }
}

Write-Host ""
Write-Host "============================================================"
Write-Host "[0/6] Trigger Evidence Schema Validation"
Write-Host "============================================================"

python .\src\check_avcs_trigger_schema.py
Assert-ExitCode $LASTEXITCODE "Trigger Evidence Schema"


Write-Host ""
Write-Host "============================================================"
Write-Host "[1/6] PyYAML Trigger Validation"
Write-Host "============================================================"

python .\src\check_avcs_yaml_load_trigger_e2e.py
Assert-ExitCode $LASTEXITCODE "PyYAML Trigger"


Write-Host ""
Write-Host "============================================================"
Write-Host "[2/6] aiohttp Trigger Validation"
Write-Host "============================================================"

python .\src\check_avcs_aiohttp_trigger_e2e.py
Assert-ExitCode $LASTEXITCODE "aiohttp Trigger"


Write-Host ""
Write-Host "============================================================"
Write-Host "[3/6] NumPy Trigger Validation"
Write-Host "============================================================"

python .\src\check_avcs_numpy_trigger_e2e.py
Assert-ExitCode $LASTEXITCODE "NumPy Trigger"


Write-Host ""
Write-Host "============================================================"
Write-Host "[4/6] PyJWT Trigger Validation"
Write-Host "============================================================"

python .\src\check_avcs_pyjwt_trigger_e2e.py
Assert-ExitCode $LASTEXITCODE "PyJWT Trigger"


Write-Host ""
Write-Host "============================================================"
Write-Host "[5/6] Requests Trigger Validation"
Write-Host "============================================================"

python .\src\check_avcs_requests_trigger_e2e.py
Assert-ExitCode $LASTEXITCODE "Requests Trigger"


Write-Host ""
Write-Host "============================================================"
Write-Host "[6/6] urllib3 Trigger Validation"
Write-Host "============================================================"

python .\src\check_avcs_urllib3_trigger_e2e.py
Assert-ExitCode $LASTEXITCODE "urllib3 Trigger"


Write-Host ""
Write-Host "============================================================"
Write-Host "[OK] AVCS Trigger Evidence Validation ALL PASS"
Write-Host "============================================================"