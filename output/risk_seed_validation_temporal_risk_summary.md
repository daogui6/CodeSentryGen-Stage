# temporal risk cards v2 生成结果

- 输入文件：`output\risk_seed_validation_reachability_v2_enriched.jsonl`
- 输出文件：`output\risk_seed_validation_temporal_risk_cards_v2.jsonl`
- 输入记录数：4
- 风险卡片数：4

## 1. temporal_status_v2 分布

| temporal_status_v2 | count |
|---|---:|
| nonexistent_now | 2 |
| created_after_tg | 2 |

## 2. 风险类型分布

| risk_type | count |
|---|---:|
| temporal_package_hallucination | 4 |

## 3. 严重程度分布

| severity | count |
|---|---:|
| high | 4 |

## 4. 风险卡片列表

| risk_id | sample_id | package | temporal_status | reachability | severity | status |
|---|---|---|---|---|---|---|
| 62bd6eb07a581ef4 | risk_seed_nonexistent_manifest_001 | codesentry-fake-dep-nonexistent-validation-zzzxq-20260622 | nonexistent_now | manifest_declared | high | confirmed |
| 4926ae727f6420bf | risk_seed_nonexistent_ci_001 | codesentry-fake-dep-nonexistent-validation-zzzxq-20260622 | nonexistent_now | ci_installable | high | confirmed |
| 35c56764753eb7a9 | risk_seed_created_manifest_001 | rich | created_after_tg | manifest_declared | high | probable |
| 2f956ebcab22c518 | risk_seed_created_ci_001 | rich | created_after_tg | ci_installable | high | probable |

## 5. 说明

本步骤根据 `temporal_status_v2` 和安装可达性字段生成 THO 最小版风险卡片；如果存在 `install_reachability_v2`，则优先使用 v2 字段。`nonexistent_now` 表示包在审计时 PyPI 当前不存在；`created_after_tg` 表示包当前存在，但首次发布时间晚于代码生成时间。当前输出用于 pilot 阶段验证风险链路，不用于估计真实 LLM 风险比例。