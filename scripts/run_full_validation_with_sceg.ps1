$ErrorActionPreference = "Stop"

# 当前脚本位于 scripts 目录下。
# $PSScriptRoot 表示当前脚本所在目录。
# 项目根目录就是 scripts 的上一级目录。
$ROOT = Resolve-Path (Join-Path $PSScriptRoot "..")

Set-Location $ROOT

Write-Host ""
Write-Host "============================================================"
Write-Host "[1/2] Run THO validation"
Write-Host "============================================================"
Write-Host ""

powershell -ExecutionPolicy Bypass -File .\scripts\run_all_tho_validation.ps1

Write-Host ""
Write-Host "============================================================"
Write-Host "[2/2] Run SCEG v0 validation"
Write-Host "============================================================"
Write-Host ""

powershell -ExecutionPolicy Bypass -File .\scripts\run_sceg_v0_validation.ps1

Write-Host ""
Write-Host "============================================================"
Write-Host "[OK] Full THO + SCEG validation finished"
Write-Host "============================================================"
Write-Host ""
Write-Host "Key outputs:"
Write-Host "- output\tho_validation_final_summary_v2.md"
Write-Host "- output\sceg_v0_final_summary.md"
Write-Host ""