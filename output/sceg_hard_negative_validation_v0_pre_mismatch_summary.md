# SCEG v0 Build Summary

<!-- csg-reader-context:start; original-sha256=04e32f272c31deb87366e6f9c28c9741ebd32f44c52f50c3da69f9229c38d602 -->

> **记录定位：历史验证存档。** pre_mismatch 口径下的 hard negative SCEG 构建记录。
> 本页正文和表格保留原记录口径；当前阶段复现命令与覆盖范围见[运行与验证说明](../docs/VALIDATION.md)，项目入口见 [README](../README.md)。

<!-- csg-reader-context:end -->

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