# Risk Seed Validation Expected Check

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
