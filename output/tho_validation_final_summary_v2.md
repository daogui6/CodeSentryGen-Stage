# THO Validation Final Summary v2

## 1. Validation Overview

| validation | dataset | samples/records | temporal_status_v2 | reachability_v2 | risk_cards | pass |
|---|---|---:|---|---|---:|---|
| Positive control | risk_seed_validation_dataset | 4 samples / 4 records | {'nonexistent_now': 2, 'created_after_tg': 2} | {'manifest_declared': 2, 'ci_installable': 2} | 4 | True |
| Natural negative control | qwen real generated 100 samples | 100 samples / 260 records | {'filtered_false_positive': 113, 'existed_at_tg': 147} | {'import_only': 138, 'manifest_declared': 122} | 20 total; temporal=0; mismatch=20 | True |
| Hard negative control | hard_negative_validation_dataset | 13 samples / 15 records | {'filtered_false_positive': 4, 'existed_at_tg': 10, 'local_or_private_unknown': 1} | {'import_only': 5, 'manifest_declared': 10} | 3 total; temporal=0; mismatch=3 | True |

- positive_pass: `True`
- natural_negative_pass: `True`
- hard_negative_pass: `True`
- ALL_PASS: `True`

## 2. Positive Control

The controlled risk seed dataset contains four known-risk cases: `nonexistent_now + manifest_declared`, `nonexistent_now + ci_installable`, `created_after_tg + manifest_declared`, and `created_after_tg + ci_installable`. All four cases generated Risk Cards and matched the expected labels.

## 3. Natural Negative Control

The qwen real generated samples produced 260 dependency records. No `nonexistent_now`, `created_after_tg`, or `registry_query_error` records were observed, and no temporal package hallucination Risk Cards were generated. Under the updated manifest-only rule, 20 dependency declaration mismatch Risk Cards were generated.

## 4. Hard Negative Control

The hard negative dataset covers standard-library imports, fake package names appearing only in comments/strings, import-to-distribution mapping cases, manifest-only normal dependencies, local modules, PEP503 normalization, and requirements version/marker parsing cases. Under the updated manifest-only rule, 3 expected dependency declaration mismatch Risk Cards were generated, while no temporal package hallucination Risk Cards were generated.

## 5. Conclusion

The current THO pipeline passes three validation checks: it reports controlled temporal dependency risks when risks are present, reports updated manifest-only dependency declaration mismatch cases, and still avoids temporal package hallucination false alarms on qwen real-generation and curated boundary cases.

Controlled risk seeds are used for recall/regression testing and should not be mixed into natural prevalence estimates.
