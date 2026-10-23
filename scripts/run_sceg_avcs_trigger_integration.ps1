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
Write-Host "[0/3] Build AVCS Trigger Evidence"
Write-Host "============================================================"

python .\src\enrich_avcs_evidence.py `
  --evaluation .\output\avcs_control_full_load_evaluation_v0.json `
  --out .\output\avcs_control_full_load_trigger_for_sceg_v0.json

Assert-ExitCode `
  $LASTEXITCODE `
  "Build AVCS Trigger Evidence"


Write-Host ""
Write-Host "============================================================"
Write-Host "[1/3] Attach Trigger Evidence to Dependency Record"
Write-Host "============================================================"

python .\src\enrich_dependency_records_with_avcs_trigger.py `
  --input .\data\avcs_validation\sceg\avcs_control_full_load_dependency_v0.jsonl `
  --trigger-evidence .\output\avcs_control_full_load_trigger_for_sceg_v0.json `
  --out .\output\avcs_control_full_load_dependency_trigger_enriched_v0.jsonl

Assert-ExitCode `
  $LASTEXITCODE `
  "Attach AVCS Trigger Evidence"


Write-Host ""
Write-Host "============================================================"
Write-Host "[2/3] Build Trigger-aware SCEG"
Write-Host "============================================================"

python .\src\build_sceg_v0.py `
  --input .\output\avcs_control_full_load_dependency_trigger_enriched_v0.jsonl `
  --risk-cards .\output\avcs_control_full_load_risk_cards_v0.jsonl `
  --out .\output\sceg_avcs_control_full_load_v0.jsonl `
  --summary .\output\sceg_avcs_control_full_load_v0_summary.md `
  --dataset-label avcs_control_full_load_trigger_positive

Assert-ExitCode `
  $LASTEXITCODE `
  "Build Trigger-aware SCEG"


Write-Host ""
Write-Host "============================================================"
Write-Host "[3/3] Validate SCEG AVCS Trigger Integration"
Write-Host "============================================================"

python .\src\check_sceg_avcs_trigger_integration.py

Assert-ExitCode `
  $LASTEXITCODE `
  "SCEG AVCS Trigger Integration"


Write-Host ""
Write-Host "============================================================"
Write-Host "[OK] SCEG AVCS Trigger Integration ALL PASS"
Write-Host "============================================================"