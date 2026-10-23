python .\src\make_hard_negative_validation_dataset.py

python .\src\run_pilot.py `
  --samples .\data\samples\hard_negative_validation_dataset.jsonl `
  --repo .\data\hard_negative_local_repo `
  --out .\output\hard_negative_validation_pilot_results.jsonl `
  --risk-out .\output\hard_negative_validation_initial_risk_cards.jsonl

python .\src\enrich_temporal_status.py `
  --input .\output\hard_negative_validation_pilot_results.jsonl `
  --output .\output\hard_negative_validation_temporal_enriched.jsonl `
  --summary .\output\hard_negative_validation_temporal_summary.md

python .\src\enrich_reachability_v2.py `
  --input .\output\hard_negative_validation_temporal_enriched.jsonl `
  --output .\output\hard_negative_validation_reachability_v2_enriched.jsonl `
  --summary .\output\hard_negative_validation_reachability_v2_summary.md `
  --requirements-dir .\data\hard_negative_requirements_files

python .\src\build_temporal_risk_cards.py `
  --input .\output\hard_negative_validation_reachability_v2_enriched.jsonl `
  --output .\output\hard_negative_validation_temporal_risk_cards_v2.jsonl `
  --summary .\output\hard_negative_validation_temporal_risk_summary.md

python .\src\check_hard_negative_validation.py
