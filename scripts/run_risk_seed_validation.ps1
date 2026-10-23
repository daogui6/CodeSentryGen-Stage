python .\src\run_pilot.py `
  --samples .\data\samples\risk_seed_validation_dataset.jsonl `
  --out .\output\risk_seed_validation_pilot_results.jsonl `
  --risk-out .\output\risk_seed_validation_initial_risk_cards.jsonl

python .\src\enrich_temporal_status.py `
  --input .\output\risk_seed_validation_pilot_results.jsonl `
  --output .\output\risk_seed_validation_temporal_enriched.jsonl `
  --summary .\output\risk_seed_validation_temporal_summary.md

python .\src\enrich_reachability_v2.py `
  --input .\output\risk_seed_validation_temporal_enriched.jsonl `
  --output .\output\risk_seed_validation_reachability_v2_enriched.jsonl `
  --summary .\output\risk_seed_validation_reachability_v2_summary.md `
  --requirements-dir .\data\risk_seed_validation_requirements_files

python .\src\build_temporal_risk_cards.py `
  --input .\output\risk_seed_validation_reachability_v2_enriched.jsonl `
  --output .\output\risk_seed_validation_temporal_risk_cards_v2.jsonl `
  --summary .\output\risk_seed_validation_temporal_risk_summary.md

python .\src\check_risk_seed_validation.py
