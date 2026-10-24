# 时态状态增强结果

<!-- csg-reader-context:start; original-sha256=43d145822999ccdb3b4228a8e6703d6addf5d23747d822bf7671681286b9d51d -->

> **记录定位：历史验证存档。** 两条 nonexistent_now 与两条 created_after_tg 受控输入的时态判定。
> 本页正文和表格保留原记录口径；当前阶段复现命令与覆盖范围见[运行与验证说明](../docs/VALIDATION.md)，项目入口见 [README](../README.md)。

<!-- csg-reader-context:end -->

- 输入文件：`output\risk_seed_validation_pilot_results.jsonl`
- 输出文件：`output\risk_seed_validation_temporal_enriched.jsonl`
- 总记录数：4

## 1. 原始 status 分布

| status | count |
|---|---:|
| nonexistent_now | 2 |
| created_after_tg | 2 |

## 2. temporal_status_v2 分布

| temporal_status_v2 | count |
|---|---:|
| nonexistent_now | 2 |
| created_after_tg | 2 |

## 3. created_after_tg 样本

| sample_id | package | generation_time | first_release_time |
|---|---|---|---|
| risk_seed_created_manifest_001 | rich | 2018-01-01T00:00:00+08:00 | 2019-11-10T15:57:05.567678+00:00 |
| risk_seed_created_ci_001 | rich | 2018-01-01T00:00:00+08:00 | 2019-11-10T15:57:05.567678+00:00 |

## 4. 说明

本步骤没有覆盖原始 `status` 字段，而是新增 `temporal_status_v2` 字段。该字段根据 `generation_time` 和 PyPI `first_release_time` 进行重新判断，用于后续支持 `created_after_tg` 时态风险检测。