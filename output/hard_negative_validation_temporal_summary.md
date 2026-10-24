# 时态状态增强结果

<!-- csg-reader-context:start; original-sha256=ab4899dbdd823a30e3e0ed6391a8b4562f5c448e9a2dffe83926221b40043102 -->

> **记录定位：历史验证存档。** 15 条 hard negative 依赖记录的时态状态、过滤与本地模块状态。
> 本页正文和表格保留原记录口径；当前阶段复现命令与覆盖范围见[运行与验证说明](../docs/VALIDATION.md)，项目入口见 [README](../README.md)。

<!-- csg-reader-context:end -->

- 输入文件：`output\hard_negative_validation_pilot_results.jsonl`
- 输出文件：`output\hard_negative_validation_temporal_enriched.jsonl`
- 总记录数：15

## 1. 原始 status 分布

| status | count |
|---|---:|
| existed_at_tg | 10 |
| filtered_false_positive | 4 |
| local_module | 1 |

## 2. temporal_status_v2 分布

| temporal_status_v2 | count |
|---|---:|
| existed_at_tg | 10 |
| filtered_false_positive | 4 |
| local_or_private_unknown | 1 |

## 3. created_after_tg 样本


当前 pilot_v0 中暂未发现 `created_after_tg` 样本。


## 4. 说明

本步骤没有覆盖原始 `status` 字段，而是新增 `temporal_status_v2` 字段。该字段根据 `generation_time` 和 PyPI `first_release_time` 进行重新判断，用于后续支持 `created_after_tg` 时态风险检测。