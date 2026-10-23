Write-Host ""
Write-Host "============================================================"
Write-Host "[1/2] Build SCEG v0 pre-mismatch outputs"
Write-Host "============================================================"

powershell -ExecutionPolicy Bypass -File `
  .\scripts\run_sceg_v0_pre_mismatch_build.ps1

if ($LASTEXITCODE -ne 0) {
    Write-Host "[FAIL] SCEG v0 pre-mismatch build failed"
    exit 1
}


Write-Host ""
Write-Host "============================================================"
Write-Host "[2/2] Check SCEG v0 pre-mismatch outputs"
Write-Host "============================================================"

python .\src\check_sceg_v0_pre_mismatch_outputs.py

if ($LASTEXITCODE -ne 0) {
    Write-Host "[FAIL] SCEG v0 pre-mismatch validation failed"
    exit 1
}


Write-Host ""
Write-Host "============================================================"
Write-Host "SCEG v0 pre-mismatch validation finished"
Write-Host "============================================================"