python .\src\build_sceg_v0.py `
  --input .\output\auto_qwen37_100_manifest_evidence_enriched.jsonl `
  --risk-cards .\output\auto_qwen37_100_temporal_risk_cards_calibrated.jsonl `
  --out .\output\sceg_qwen37_100_calibrated_v0.jsonl `
  --summary .\output\sceg_qwen37_100_calibrated_v0_summary.md `
  --dataset-label qwen37_100_manifest_calibrated

python .\src\build_sceg_v0.py `
  --input .\output\risk_seed_validation_reachability_v2_enriched.jsonl `
  --risk-cards .\output\risk_seed_validation_temporal_risk_cards_v2.jsonl `
  --out .\output\sceg_risk_seed_validation_v0.jsonl `
  --summary .\output\sceg_risk_seed_validation_v0_summary.md `
  --dataset-label risk_seed_positive_control

python .\src\build_sceg_v0.py `
  --input .\output\hard_negative_validation_reachability_v2_enriched.jsonl `
  --risk-cards .\output\hard_negative_validation_temporal_risk_cards_v2.jsonl `
  --out .\output\sceg_hard_negative_validation_v0.jsonl `
  --summary .\output\sceg_hard_negative_validation_v0_summary.md `
  --dataset-label hard_negative_control

python .\src\check_sceg_v0_outputs.py