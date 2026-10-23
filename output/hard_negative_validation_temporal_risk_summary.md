# temporal risk cards v2 生成结果

- 输入文件：`output\hard_negative_validation_reachability_v2_enriched.jsonl`
- 输出文件：`output\hard_negative_validation_temporal_risk_cards_v2.jsonl`
- 输入记录数：15
- 风险卡片数：3

## 1. temporal_status_v2 分布

| temporal_status_v2 | count |
|---|---:|
| existed_at_tg | 10 |
| filtered_false_positive | 4 |
| local_or_private_unknown | 1 |

## 2. 风险类型分布

| risk_type | count |
|---|---:|
| dependency_declaration_mismatch | 3 |

## 3. 严重程度分布

| severity | count |
|---|---:|
| medium | 3 |

## 4. 风险卡片列表

| risk_id | sample_id | package | temporal_status | reachability | severity | status |
|---|---|---|---|---|---|---|
| 9e9fa3bfc331aec8 | hard_negative_manifest_only_normal_001 | requests | existed_at_tg | manifest_declared | medium | probable |
| 42efa1bf8810557c | hard_negative_pep503_normalize_001 | python-dateutil | existed_at_tg | manifest_declared | medium | probable |
| 2a6e97048225ba35 | hard_negative_requirements_marker_001 | requests | existed_at_tg | manifest_declared | medium | probable |

## 5. 说明

本步骤根据 `temporal_status_v2` 和安装可达性字段生成 THO 最小版风险卡片；如果存在 `install_reachability_v2`，则优先使用 v2 字段。`nonexistent_now` 表示包在审计时 PyPI 当前不存在；`created_after_tg` 表示包当前存在，但首次发布时间晚于代码生成时间。当前输出用于 pilot 阶段验证风险链路，不用于估计真实 LLM 风险比例。