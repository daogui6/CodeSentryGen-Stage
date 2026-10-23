param(
    [switch]$Refresh
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root


function Assert-ExitCode {
    param(
        [int]$Code,
        [string]$Step
    )

    if ($Code -ne 0) {
        Write-Host ""
        Write-Host "[FAIL] $Step | exit code = $Code"
        exit $Code
    }
}


function Assert-FileExists {
    param(
        [string]$Path,
        [string]$Description
    )

    if (-not (Test-Path $Path)) {
        Write-Host ""
        Write-Host "[FAIL] missing $Description"
        Write-Host "[FAIL] expected path: $Path"
        exit 1
    }
}


$ApiCalls = (
    ".\output\pyjwt_default_algorithms_true_api_calls_v0.json"
)

Assert-FileExists `
    $ApiCalls `
    "frozen PyJWT API call evidence"


$TimeView = (
    Get-Date
).ToUniversalTime().ToString(
    "yyyy-MM-ddTHH:mm:ssZ"
)


Write-Host ""
Write-Host "============================================================"
Write-Host "[1/7] Resolve full PyJWT release history"
Write-Host "============================================================"

$ReleaseArgs = @(
    ".\src\resolve_avcs_release_history.py",
    "--distribution",
    "PyJWT",
    "--time-view",
    $TimeView,
    "--out",
    ".\output\avcs_pyjwt_full_release_history_probe_v0.json"
)

if ($Refresh) {
    $ReleaseArgs += "--refresh"
}

python @ReleaseArgs

Assert-ExitCode `
    $LASTEXITCODE `
    "PyJWT release history resolution"


Write-Host ""
Write-Host "============================================================"
Write-Host "[2/7] Collect full stable API release history"
Write-Host "============================================================"

python .\src\collect_python_api_release_history.py `
    --release-history .\output\avcs_pyjwt_full_release_history_probe_v0.json `
    --distribution PyJWT `
    --api-symbol jwt.decode `
    --out .\output\avcs_pyjwt_jwt_decode_api_release_history_full_stable_v0.json

Assert-ExitCode `
    $LASTEXITCODE `
    "Full stable API release history collection"


Write-Host ""
Write-Host "============================================================"
Write-Host "[3/7] Refine release compatibility states"
Write-Host "============================================================"

python .\src\refine_python_api_release_history.py `
    --release-history-batch .\output\avcs_pyjwt_jwt_decode_api_release_history_full_stable_v0.json `
    --api-calls $ApiCalls `
    --parameter algorithms `
    --out .\output\avcs_pyjwt_jwt_decode_api_release_history_refined_full_stable_v0.json

Assert-ExitCode `
    $LASTEXITCODE `
    "API release history refinement"


Write-Host ""
Write-Host "============================================================"
Write-Host "[4/7] Compile full-history API candidate"
Write-Host "============================================================"

python .\src\compile_python_api_release_history_candidate.py `
    --refined-release-history .\output\avcs_pyjwt_jwt_decode_api_release_history_refined_full_stable_v0.json `
    --out .\output\avcs_pyjwt_jwt_decode_api_history_candidate_full_stable_v0.json

Assert-ExitCode `
    $LASTEXITCODE `
    "Full-history candidate compilation"


Write-Host ""
Write-Host "============================================================"
Write-Host "[5/7] Compile candidate into AVCS API History evidence"
Write-Host "============================================================"

python .\src\compile_api_history_candidate_to_evidence.py `
    --candidate .\output\avcs_pyjwt_jwt_decode_api_history_candidate_full_stable_v0.json `
    --base-history .\data\avcs_validation\api_history\pyjwt_api_history_evidence_v0.json `
    --rule-id pyjwt_decode_algorithms_keyword `
    --out .\output\avcs_pyjwt_api_history_evidence_auto_v0.json

Assert-ExitCode `
    $LASTEXITCODE `
    "API History evidence compilation"


Write-Host ""
Write-Host "============================================================"
Write-Host "[6/7] Resolve S_api with existing AVCS resolver"
Write-Host "============================================================"

python .\src\resolve_api_version_constraints.py `
    --api-calls $ApiCalls `
    --history .\output\avcs_pyjwt_api_history_evidence_auto_v0.json `
    --out .\output\avcs_pyjwt_api_constraints_auto_history_v0.json

Assert-ExitCode `
    $LASTEXITCODE `
    "S_api resolution with automatic API History"


Write-Host ""
Write-Host "============================================================"
Write-Host "[7/7] Run automatic API History regression checker"
Write-Host "============================================================"

python .\src\check_avcs_api_history_automation.py

Assert-ExitCode `
    $LASTEXITCODE `
    "Automatic API History regression checker"


Write-Host ""
Write-Host "============================================================"
Write-Host "[OK] AVCS API History Automation Validation ALL PASS"
Write-Host "============================================================"

exit 0