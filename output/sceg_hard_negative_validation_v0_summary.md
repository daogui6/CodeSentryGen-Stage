# SCEG v0 Build Summary

<!-- csg-reader-context:start; original-sha256=8f57ef3068aa2a5740941111f284baed4eb61c39e97192d7c3327e2507805f86 -->

> **记录定位：历史验证存档。** 声明一致性增强口径下的 hard negative SCEG 构建记录，含 3 张关联卡。
> 本页正文和表格保留原记录口径；当前阶段复现命令与覆盖范围见[运行与验证说明](../docs/VALIDATION.md)，项目入口见 [README](../README.md)。

<!-- csg-reader-context:end -->

- input: `output\hard_negative_validation_reachability_v2_enriched.jsonl`
- output: `output\sceg_hard_negative_validation_v0.jsonl`
- input_records: 15
- sceg_records: 15
- risk_candidate_records: 0
- linked_risk_cards: 3

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