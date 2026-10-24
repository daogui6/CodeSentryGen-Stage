# Risk Seed Validation Expected Check

<!-- csg-reader-context:start; original-sha256=1ee4720883714cb5e773abd9124f0e08fa17f26762672c454c59e9f6707aefb3 -->

> **记录定位：历史验证存档。** 四条受控正例的时态、可达性和 Risk Card 预期/实际核对。
> 本页正文和表格保留原记录口径；当前阶段复现命令与覆盖范围见[运行与验证说明](../docs/VALIDATION.md)，项目入口见 [README](../README.md)。

<!-- csg-reader-context:end -->

| sample_id | expected_temporal | actual_temporal | expected_reachability | actual_reachability | expected_card | actual_card | pass |
|---|---|---|---|---|---:|---:|---|
| risk_seed_nonexistent_manifest_001 | nonexistent_now | nonexistent_now | manifest_declared | manifest_declared | 1 | 1 | True |
| risk_seed_nonexistent_ci_001 | nonexistent_now | nonexistent_now | ci_installable | ci_installable | 1 | 1 | True |
| risk_seed_created_manifest_001 | created_after_tg | created_after_tg | manifest_declared | manifest_declared | 1 | 1 | True |
| risk_seed_created_ci_001 | created_after_tg | created_after_tg | ci_installable | ci_installable | 1 | 1 | True |

- ALL_PASS: `True`
- samples: 4
- reachability_records: 4
- risk_cards: 4
