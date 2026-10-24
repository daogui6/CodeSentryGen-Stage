# Install Reachability v2 Summary

<!-- csg-reader-context:start; original-sha256=1f96f776f8c1eb55e52205b6f85b324e77e59373b9b8f4176e0c84b583b30c41 -->

> **记录定位：历史验证存档。** 四条受控正例的可达性增强，包含 manifest 以及 Docker/CI 路径证据。
> 本页正文和表格保留原记录口径；当前阶段复现命令与覆盖范围见[运行与验证说明](../docs/VALIDATION.md)，项目入口见 [README](../README.md)。

<!-- csg-reader-context:end -->

- input: `output\risk_seed_validation_temporal_enriched.jsonl`
- output: `output\risk_seed_validation_reachability_v2_enriched.jsonl`
- total_records: 4
- changed_records: 2
- docker_installable_records: 2
- ci_installable_records: 2
- both_docker_and_ci_evidence_records: 2

## Original install_reachability

- manifest_declared: 4

## install_reachability_v2

- ci_installable: 2
- manifest_declared: 2

## Changed Records

| sample_id | package | original | v2 | requirements | docker | ci |
|---|---|---|---|---|---|---|
| risk_seed_nonexistent_ci_001 | codesentry-fake-dep-nonexistent-validation-zzzxq-20260622 | manifest_declared | ci_installable | True | True | True |
| risk_seed_created_ci_001 | rich | manifest_declared | ci_installable | True | True | True |

## Controlled Evidence Check: pilot50_047

No records found for pilot50_047.

## Notes

- The original `install_reachability` field is preserved.
- v2 adds `install_reachability_v2` and `reachability_v2_evidence`.
- Docker/CI upgrade requires the package to be declared in requirements.
- If both Docker and CI evidence exist, the final level is `ci_installable`, while both evidence types are recorded.