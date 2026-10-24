# SCEG v0 Build Summary

<!-- csg-reader-context:start; original-sha256=9822d8b8cc3995c88cd4ebb1e926d8638c447d771a097479ad25eb8418721d3e -->

> **记录定位：历史验证存档。** 四条受控正例的 SCEG 构建记录及四张 Risk Card 关联。
> 本页正文和表格保留原记录口径；当前阶段复现命令与覆盖范围见[运行与验证说明](../docs/VALIDATION.md)，项目入口见 [README](../README.md)。

<!-- csg-reader-context:end -->

- input: `output\risk_seed_validation_reachability_v2_enriched.jsonl`
- output: `output\sceg_risk_seed_validation_v0.jsonl`
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