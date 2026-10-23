# Hard Negative Validation Expected Check

## 1. Summary

- samples: 13
- dependency_records: 15
- risk_cards: 3
- expected_total_cards: 3
- temporal_status_v2: {'filtered_false_positive': 4, 'existed_at_tg': 10, 'local_or_private_unknown': 1}
- install_reachability_v2: {'import_only': 5, 'manifest_declared': 10}
- code_parse_status: {'ok': 15}
- bad_status_count: 0
- fake_text_extracted: False
- mapping_google_ok: True
- mapping_yaml_ok: True
- ALL_PASS: `True`

## 2. Per-sample Risk Card Check

| sample_id | expected_risk_card | actual_risk_card | pass |
|---|---:|---:|---|
| hard_negative_stdlib_001 | 0 | 0 | True |
| hard_negative_comment_string_001 | 0 | 0 | True |
| hard_negative_googleapiclient_mapping_001 | 0 | 0 | True |
| hard_negative_yaml_mapping_001 | 0 | 0 | True |
| hard_negative_pil_mapping_001 | 0 | 0 | True |
| hard_negative_bs4_mapping_001 | 0 | 0 | True |
| hard_negative_sklearn_mapping_001 | 0 | 0 | True |
| hard_negative_cv2_mapping_001 | 0 | 0 | True |
| hard_negative_dotenv_mapping_001 | 0 | 0 | True |
| hard_negative_manifest_only_normal_001 | 1 | 1 | True |
| hard_negative_local_module_001 | 0 | 0 | True |
| hard_negative_pep503_normalize_001 | 1 | 1 | True |
| hard_negative_requirements_marker_001 | 1 | 1 | True |

## 3. Dependency Records

| sample_id | raw_name | package | temporal_status | reachability |
|---|---|---|---|---|
| hard_negative_stdlib_001 | json | json | filtered_false_positive | import_only |
| hard_negative_stdlib_001 | pathlib | pathlib | filtered_false_positive | import_only |
| hard_negative_stdlib_001 | http | http | filtered_false_positive | import_only |
| hard_negative_comment_string_001 | re | re | filtered_false_positive | import_only |
| hard_negative_googleapiclient_mapping_001 | googleapiclient | google-api-python-client | existed_at_tg | manifest_declared |
| hard_negative_yaml_mapping_001 | yaml | pyyaml | existed_at_tg | manifest_declared |
| hard_negative_pil_mapping_001 | PIL | pillow | existed_at_tg | manifest_declared |
| hard_negative_bs4_mapping_001 | bs4 | beautifulsoup4 | existed_at_tg | manifest_declared |
| hard_negative_sklearn_mapping_001 | sklearn | scikit-learn | existed_at_tg | manifest_declared |
| hard_negative_cv2_mapping_001 | cv2 | opencv-python | existed_at_tg | manifest_declared |
| hard_negative_dotenv_mapping_001 | dotenv | python-dotenv | existed_at_tg | manifest_declared |
| hard_negative_manifest_only_normal_001 | requests | requests | existed_at_tg | manifest_declared |
| hard_negative_local_module_001 | fake_internal_helper | fake-internal-helper | local_or_private_unknown | import_only |
| hard_negative_pep503_normalize_001 | python_dateutil | python-dateutil | existed_at_tg | manifest_declared |
| hard_negative_requirements_marker_001 | requests | requests | existed_at_tg | manifest_declared |
