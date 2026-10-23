# SCEG v0 Final Summary

ALL_PASS = True

- schema: `schemas\sceg_schema_v0.json`
- total_sceg_records: 279
- total_linked_risk_cards: 12
- total_edges: 1706

## 1. Dataset Overview

| dataset | records | expected_records | linked_risk_cards | expected_linked_risk_cards | declaration_records | expected_declaration_records | declaration_records_ok | declaration_labels_ok | edge_count | bad_schema_count | bad_shape_count | bad_edges_count | pass |
|---|---:|---:|---:|---:|---:|---:|---|---|---:|---:|---:|---:|---|
| qwen37_100_manifest_calibrated | 260 | 260 | 5 | 5 | 20 | 20 | True | True | 1585 | 0 | 0 | 0 | True |
| risk_seed_positive_control | 4 | 4 | 4 | 4 | 0 | 0 | True | True | 28 | 0 | 0 | 0 | True |
| hard_negative_control | 15 | 15 | 3 | 3 | 0 | 0 | True | True | 93 | 0 | 0 | 0 | True |

## 2. Total temporal_status_v2

- created_after_tg: 2
- existed_at_tg: 157
- filtered_false_positive: 117
- local_or_private_unknown: 1
- nonexistent_now: 2

## 3. Total install_reachability_v2

- ci_installable: 2
- import_only: 143
- manifest_declared: 134

## 4. Total edge types

- contains_dependency: 279
- has_declaration_consistency_evidence: 20
- has_reachability_evidence: 279
- has_registry_evidence: 279
- has_structural_evidence: 279
- has_temporal_evidence: 279
- maps_to_package: 279
- supports_risk_card: 12

## 5. Per-dataset Details

### qwen37_100_manifest_calibrated

temporal_status_v2:
- existed_at_tg: 147
- filtered_false_positive: 113

install_reachability_v2:
- import_only: 138
- manifest_declared: 122

source_type:
- import: 240
- manifest: 20

declaration_consistency:
- actual_records: 20
- expected_records: 20
- records_ok: True
- labels_ok: True

declaration_consistency_labels:
- direct_import_backed: actual=15, expected=15
- no_dependency_evidence: actual=1, expected=1
- optional_extra_dependency: actual=1, expected=1
- transitive_dependency_backed: actual=3, expected=3

edge_type:
- contains_dependency: 260
- has_declaration_consistency_evidence: 20
- has_reachability_evidence: 260
- has_registry_evidence: 260
- has_structural_evidence: 260
- has_temporal_evidence: 260
- maps_to_package: 260
- supports_risk_card: 5

### risk_seed_positive_control

temporal_status_v2:
- created_after_tg: 2
- nonexistent_now: 2

install_reachability_v2:
- ci_installable: 2
- manifest_declared: 2

source_type:
- import: 4

declaration_consistency:
- actual_records: 0
- expected_records: 0
- records_ok: True
- labels_ok: True

declaration_consistency_labels:
- none

edge_type:
- contains_dependency: 4
- has_reachability_evidence: 4
- has_registry_evidence: 4
- has_structural_evidence: 4
- has_temporal_evidence: 4
- maps_to_package: 4
- supports_risk_card: 4

### hard_negative_control

temporal_status_v2:
- existed_at_tg: 10
- filtered_false_positive: 4
- local_or_private_unknown: 1

install_reachability_v2:
- import_only: 5
- manifest_declared: 10

source_type:
- import: 12
- manifest: 3

declaration_consistency:
- actual_records: 0
- expected_records: 0
- records_ok: True
- labels_ok: True

declaration_consistency_labels:
- none

edge_type:
- contains_dependency: 15
- has_reachability_evidence: 15
- has_registry_evidence: 15
- has_structural_evidence: 15
- has_temporal_evidence: 15
- maps_to_package: 15
- supports_risk_card: 3

## 6. Notes

SCEG v0 is a lightweight intermediate evidence graph built from existing THO mini outputs. It does not change detection decisions. It reorganizes dependency records into sample nodes, dependency entity nodes, package nodes, registry evidence, temporal evidence, reachability evidence, risk-card links, and explicit evidence edges. This check also validates records against the SCEG v0 schema definition.