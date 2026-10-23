# SCEG v0 Build Summary

- input: `output\risk_seed_validation_reachability_v2_enriched.jsonl`
- output: `output\sceg_risk_seed_validation_v0_pre_mismatch.jsonl`
- input_records: 4
- sceg_records: 4
- risk_candidate_records: 4
- linked_risk_cards: 4

## temporal_status_v2

- created_after_tg: 2
- nonexistent_now: 2

## install_reachability_v2

- ci_installable: 2
- manifest_declared: 2

## source_type

- import: 4

## Notes

SCEG v0 is a lightweight intermediate evidence graph. It does not change THO detection decisions. It reorganizes existing dependency records into sample, dependency entity, registry evidence, temporal evidence, reachability evidence, and risk-card links.