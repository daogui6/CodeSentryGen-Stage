# SCEG v0 Build Summary

<!-- csg-reader-context:start; original-sha256=8dd12423d06e3c4913dd07aca7643c9696f050a63e084fb922dd162abde6b310 -->

> **记录定位：历史验证存档。** 单条 yaml.full_load 受控 AVCS 案例接入 SCEG v0 的构建存档。
> 本页正文和表格保留原记录口径；当前阶段复现命令与覆盖范围见[运行与验证说明](../docs/VALIDATION.md)，项目入口见 [README](../README.md)。

<!-- csg-reader-context:end -->

- input: `output\avcs_control_full_load_dependency_trigger_enriched_v0.jsonl`
- output: `output\sceg_avcs_control_full_load_v0.jsonl`
- input_records: 1
- sceg_records: 1
- risk_candidate_records: 1
- linked_risk_cards: 1

## temporal_status_v2

- existed_at_tg: 1

## install_reachability_v2

- not_evaluated: 1

## source_type

- import: 1

## Notes

SCEG v0 is a lightweight intermediate evidence graph. It does not change THO detection decisions. It reorganizes existing dependency records into sample, dependency entity, registry evidence, temporal evidence, reachability evidence, and risk-card links.