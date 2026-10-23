$ErrorActionPreference = "Stop"

# 无论从哪个目录调用脚本，都切换到项目根目录。
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
Write-Host "[1/5] Validate API call extraction"
Write-Host "============================================================"

python .\src\check_api_call_extraction.py
Assert-ExitCode $LASTEXITCODE "API call extraction validation"


Write-Host ""
Write-Host "============================================================"
Write-Host "[2/5] Run AVCS controlled positive"
Write-Host "============================================================"

python .\src\extract_api_calls.py `
    --code .\data\avcs_control_full_load.py `
    --sample-id avcs_control_full_load `
    --out .\output\avcs_control_full_load_api_calls_v0.json
Assert-ExitCode $LASTEXITCODE "positive API extraction"

python .\src\resolve_api_version_constraints.py `
    --api-calls .\output\avcs_control_full_load_api_calls_v0.json `
    --history .\config\avcs_api_history_seed.json `
    --out .\output\avcs_control_full_load_api_constraints_v0.json
Assert-ExitCode $LASTEXITCODE "positive API constraint resolution"

python .\src\resolve_vulnerability_constraints.py `
    --distribution PyYAML `
    --vulnerability .\config\avcs_vulnerability_seed.json `
    --out .\output\avcs_control_full_load_vulnerability_constraints_v0.json
Assert-ExitCode $LASTEXITCODE "positive vulnerability resolution"

python .\src\evaluate_avcs_overlap.py `
    --api-constraints .\output\avcs_control_full_load_api_constraints_v0.json `
    --vulnerability-constraints .\output\avcs_control_full_load_vulnerability_constraints_v0.json `
    --sample-records .\data\avcs_validation\avcs_validation_samples.jsonl `
    --out .\output\avcs_control_full_load_evaluation_v0.json
Assert-ExitCode $LASTEXITCODE "positive AVCS evaluation"

python .\src\build_avcs_risk_cards.py `
    --evaluation .\output\avcs_control_full_load_evaluation_v0.json `
    --out .\output\avcs_control_full_load_risk_cards_v0.jsonl
Assert-ExitCode $LASTEXITCODE "positive Risk Card generation"


Write-Host ""
Write-Host "============================================================"
Write-Host "[3/5] Run AVCS real safe negative"
Write-Host "============================================================"

python .\src\extract_api_calls.py `
    --code .\data\auto_generated_code_files\auto_pilot50_018.py `
    --sample-id auto_pilot50_018 `
    --out .\output\auto_pilot50_018_api_calls_v0.json
Assert-ExitCode $LASTEXITCODE "negative API extraction"

python .\src\resolve_api_version_constraints.py `
    --api-calls .\output\auto_pilot50_018_api_calls_v0.json `
    --history .\config\avcs_api_history_seed.json `
    --out .\output\auto_pilot50_018_api_constraints_v0.json
Assert-ExitCode $LASTEXITCODE "negative API constraint resolution"

python .\src\resolve_vulnerability_constraints.py `
    --distribution PyYAML `
    --vulnerability .\config\avcs_vulnerability_seed.json `
    --out .\output\auto_pilot50_018_vulnerability_constraints_v0.json
Assert-ExitCode $LASTEXITCODE "negative vulnerability resolution"

python .\src\resolve_avcs_manifest_constraints.py `
    --samples .\data\samples\auto_qwen37_100_generated_codes.jsonl `
    --sample-id auto_pilot50_018 `
    --distribution PyYAML `
    --out .\output\auto_pilot50_018_manifest_constraints_v0.json
Assert-ExitCode $LASTEXITCODE "negative manifest constraint resolution"

python .\src\resolve_avcs_api_compatible_releases.py `
    --release-history .\output\auto_pilot50_018_pyyaml_release_history_v0.json `
    --api-constraints .\output\auto_pilot50_018_api_constraints_v0.json `
    --out .\output\auto_pilot50_018_api_compatible_releases_v0.json
Assert-ExitCode $LASTEXITCODE "negative API-compatible release resolution"

python .\src\resolve_avcs_manifest_compatible_releases.py `
    --api-compatible-releases .\output\auto_pilot50_018_api_compatible_releases_v0.json `
    --manifest-constraints .\output\auto_pilot50_018_manifest_constraints_v0.json `
    --out .\output\auto_pilot50_018_manifest_compatible_releases_v0.json
Assert-ExitCode $LASTEXITCODE "negative manifest-compatible release resolution"

python .\src\resolve_avcs_exposed_releases.py `
    --api-compatible-releases .\output\auto_pilot50_018_api_compatible_releases_v0.json `
    --manifest-compatible-releases .\output\auto_pilot50_018_manifest_compatible_releases_v0.json `
    --vulnerability-constraints .\output\auto_pilot50_018_vulnerability_constraints_v0.json `
    --out .\output\auto_pilot50_018_exposed_releases_v0.json
Assert-ExitCode $LASTEXITCODE "negative exposed release resolution"

python .\src\evaluate_avcs_overlap.py `
    --api-constraints .\output\auto_pilot50_018_api_constraints_v0.json `
    --vulnerability-constraints .\output\auto_pilot50_018_vulnerability_constraints_v0.json `
    --sample-records .\data\samples\auto_qwen37_100_generated_codes.jsonl `
    --exposed-releases .\output\auto_pilot50_018_exposed_releases_v0.json `
    --out .\output\auto_pilot50_018_avcs_evaluation_v0.json
Assert-ExitCode $LASTEXITCODE "negative AVCS evaluation"

python .\src\build_avcs_risk_cards.py `
    --evaluation .\output\auto_pilot50_018_avcs_evaluation_v0.json `
    --out .\output\auto_pilot50_018_avcs_risk_cards_v0.jsonl
Assert-ExitCode $LASTEXITCODE "negative Risk Card generation"


Write-Host ""
Write-Host "============================================================"
Write-Host "[4/5] Run AVCS unresolved control"
Write-Host "============================================================"

python .\src\extract_api_calls.py `
    --code .\data\avcs_validation\avcs_unresolved_yaml_load.py `
    --sample-id avcs_unresolved_yaml_load `
    --out .\output\avcs_unresolved_yaml_load_api_calls.json
Assert-ExitCode $LASTEXITCODE "unresolved API extraction"

python .\src\resolve_api_version_constraints.py `
    --api-calls .\output\avcs_unresolved_yaml_load_api_calls.json `
    --history .\config\avcs_api_history_seed.json `
    --out .\output\avcs_unresolved_yaml_load_api_constraints.json
Assert-ExitCode $LASTEXITCODE "unresolved API constraint resolution"

python .\src\resolve_vulnerability_constraints.py `
    --distribution PyYAML `
    --vulnerability .\config\avcs_vulnerability_seed.json `
    --out .\output\avcs_unresolved_yaml_load_vulnerability_constraints.json
Assert-ExitCode $LASTEXITCODE "unresolved vulnerability resolution"

python .\src\evaluate_avcs_overlap.py `
    --api-constraints .\output\avcs_unresolved_yaml_load_api_constraints.json `
    --vulnerability-constraints .\output\avcs_unresolved_yaml_load_vulnerability_constraints.json `
    --sample-records .\data\avcs_validation\avcs_validation_samples.jsonl `
    --out .\output\avcs_unresolved_yaml_load_evaluation_v0.json
Assert-ExitCode $LASTEXITCODE "unresolved AVCS evaluation"

python .\src\build_avcs_risk_cards.py `
    --evaluation .\output\avcs_unresolved_yaml_load_evaluation_v0.json `
    --out .\output\avcs_unresolved_yaml_load_risk_cards_v0.jsonl
Assert-ExitCode $LASTEXITCODE "unresolved Risk Card generation"


Write-Host ""
Write-Host "============================================================"
Write-Host "[5/5] Run AVCS minimal regression checks"
Write-Host "============================================================"

python .\src\check_avcs_minimal_pipeline.py
Assert-ExitCode $LASTEXITCODE "AVCS minimal pipeline validation"


Write-Host ""
Write-Host "============================================================"
Write-Host "[OK] AVCS minimal validation ALL PASS"
Write-Host "============================================================"

exit 0