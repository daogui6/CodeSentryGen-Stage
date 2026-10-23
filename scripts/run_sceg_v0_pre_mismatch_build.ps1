Write-Host ""
Write-Host "============================================================"
Write-Host "[1/3] Build qwen37_100 SCEG v0 before mismatch rule"
Write-Host "============================================================"

python .\src\build_sceg_v0.py `
  --input .\output\auto_qwen37_100_reachability_v2_enriched.jsonl `
  --out .\output\sceg_qwen37_100_v0_pre_mismatch.jsonl `
  --summary .\output\sceg_qwen37_100_v0_pre_mismatch_summary.md `
  --dataset-label qwen37_100_natural_negative


Write-Host ""
Write-Host "============================================================"
Write-Host "[2/3] Build positive-control SCEG v0 before mismatch rule"
Write-Host "============================================================"

python .\src\build_sceg_v0.py `
  --input .\output\risk_seed_validation_reachability_v2_enriched.jsonl `
  --risk-cards .\output\risk_seed_validation_temporal_risk_cards_v2.jsonl `
  --out .\output\sceg_risk_seed_validation_v0_pre_mismatch.jsonl `
  --summary .\output\sceg_risk_seed_validation_v0_pre_mismatch_summary.md `
  --dataset-label risk_seed_positive_control


Write-Host ""
Write-Host "============================================================"
Write-Host "[3/3] Build hard-negative SCEG v0 before mismatch rule"
Write-Host "============================================================"

python .\src\build_sceg_v0.py `
  --input .\output\hard_negative_validation_reachability_v2_enriched.jsonl `
  --out .\output\sceg_hard_negative_validation_v0_pre_mismatch.jsonl `
  --summary .\output\sceg_hard_negative_validation_v0_pre_mismatch_summary.md `
  --dataset-label hard_negative_control


Write-Host ""
Write-Host "============================================================"
Write-Host "SCEG v0 pre-mismatch build finished"
Write-Host "============================================================"