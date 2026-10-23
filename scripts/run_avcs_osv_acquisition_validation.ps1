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


Write-Host ""
Write-Host "============================================================"
Write-Host "[1/5] Fetch urllib3 OSV package evidence"
Write-Host "============================================================"

$FetchArgs = @(
    ".\src\fetch_osv_package_vulnerabilities.py",
    "--distribution",
    "urllib3",
    "--ecosystem",
    "PyPI",
    "--out",
    ".\output\avcs_urllib3_osv_package_snapshot_v0.json"
)

if ($Refresh) {
    $FetchArgs += "--refresh"
}

python @FetchArgs
Assert-ExitCode $LASTEXITCODE "OSV package acquisition"


Write-Host ""
Write-Host "============================================================"
Write-Host "[2/5] Build urllib3 OSV package catalog"
Write-Host "============================================================"

python .\src\build_osv_package_catalog.py `
    --snapshot .\output\avcs_urllib3_osv_package_snapshot_v0.json `
    --out .\output\avcs_urllib3_osv_package_catalog_v0.json

Assert-ExitCode $LASTEXITCODE "OSV package catalog build"


Write-Host ""
Write-Host "============================================================"
Write-Host "[3/5] Resolve package-level vulnerability constraints"
Write-Host "============================================================"

python .\src\resolve_osv_package_catalog_constraints.py `
    --catalog .\output\avcs_urllib3_osv_package_catalog_v0.json `
    --distribution urllib3 `
    --out .\output\avcs_urllib3_osv_package_constraints_v0.json

Assert-ExitCode $LASTEXITCODE "OSV catalog constraint resolution"


Write-Host ""
Write-Host "============================================================"
Write-Host "[4/5] Resolve AVCS exposed releases"
Write-Host "============================================================"

python .\src\resolve_avcs_exposed_releases.py `
    --api-compatible-releases .\output\avcs_urllib3_poolmanager_retries_true_api_compatible_releases_v0.json `
    --manifest-compatible-releases .\output\avcs_urllib3_poolmanager_retries_true_manifest_compatible_releases_v0.json `
    --vulnerability-constraints .\output\avcs_urllib3_osv_package_constraints_v0.json `
    --out .\output\avcs_urllib3_osv_catalog_exposed_releases_v0.json

Assert-ExitCode $LASTEXITCODE "AVCS exposed release resolution"


Write-Host ""
Write-Host "============================================================"
Write-Host "[5/5] Validate automatic OSV acquisition chain"
Write-Host "============================================================"

python .\src\check_avcs_osv_package_acquisition.py

Assert-ExitCode $LASTEXITCODE "OSV acquisition regression checker"


Write-Host ""
Write-Host "============================================================"
Write-Host "[OK] AVCS OSV Acquisition Validation ALL PASS"
Write-Host "============================================================"

exit 0