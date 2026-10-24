# Install Reachability v2 Summary

<!-- csg-reader-context:start; original-sha256=a149f4f732ca4b57c0dd6943709c39d54e2730547ebb6457c9f2e42c397415d4 -->

> **记录定位：历史验证存档。** 15 条 hard negative 依赖记录的安装可达性增强结果。
> 本页正文和表格保留原记录口径；当前阶段复现命令与覆盖范围见[运行与验证说明](../docs/VALIDATION.md)，项目入口见 [README](../README.md)。

<!-- csg-reader-context:end -->

- input: `output\hard_negative_validation_temporal_enriched.jsonl`
- output: `output\hard_negative_validation_reachability_v2_enriched.jsonl`
- total_records: 15
- changed_records: 0
- docker_installable_records: 0
- ci_installable_records: 0
- both_docker_and_ci_evidence_records: 0

## Original install_reachability

- import_only: 5
- manifest_declared: 10

## install_reachability_v2

- import_only: 5
- manifest_declared: 10

## Changed Records

No records changed.

## Controlled Evidence Check: pilot50_047

No records found for pilot50_047.

## Notes

- The original `install_reachability` field is preserved.
- v2 adds `install_reachability_v2` and `reachability_v2_evidence`.
- Docker/CI upgrade requires the package to be declared in requirements.
- If both Docker and CI evidence exist, the final level is `ci_installable`, while both evidence types are recorded.