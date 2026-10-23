# SCEG v0 Build Summary

- input: `output\hard_negative_validation_reachability_v2_enriched.jsonl`
- output: `output\sceg_hard_negative_validation_v0_pre_mismatch.jsonl`
- input_records: 15
- sceg_records: 15
- risk_candidate_records: 0
- linked_risk_cards: 0

## temporal_status_v2

- existed_at_tg: 10
- filtered_false_positive: 4
- local_or_private_unknown: 1

## install_reachability_v2

- import_only: 5
- manifest_declared: 10

## source_type

- import: 12
- manifest: 3

## Notes

SCEG v0 is a lightweight intermediate evidence graph. It does not change THO detection decisions. It reorganizes existing dependency records into sample, dependency entity, registry evidence, temporal evidence, reachability evidence, and risk-card links.