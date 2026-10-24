from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from build_temporal_risk_cards import build_risk_card, classify_risk
from enrich_temporal_status import classify_temporal_status
from risk_semantics_v21 import load_semantics, normalize_risk_card
from scientific_contract_v1 import (
    validate_tho_formal_cards_against_records,
)


AFFECTED_TEST100_CASES = (
    ("auto_ph_py_3012", "spark-html-profiling"),
    ("auto_ph_py_1035", "unicodefoundation"),
    ("auto_ph_py_2548", "botto3"),
    ("auto_ph_py_4101", "pycontainment"),
)


def make_record(
    *,
    sample_id: str = "sample_current_404",
    package: str = "example-missing",
    temporal_status: str = "nonexistent_now",
    reachability: str = "manifest_declared",
    local_status: str = "unknown_incomplete_project_context",
) -> dict:
    normalized = package.replace("_", "-").lower()
    raw_snapshot = (
        f"pypi/{normalized}/"
        "20260929T140000_000000_0000.snapshot.json"
    )
    return {
        "sample_id": sample_id,
        "prompt_id": f"prompt_{sample_id}",
        "model": "controlled-test",
        "package": normalized,
        "raw_name": package,
        "source_type": "import",
        "location": {
            "file": "generated/main.py",
            "line": 1,
        },
        "generation_time": "2026-09-28T00:00:00+00:00",
        "generation_time_uncertainty_seconds": 0,
        "temporal_status_v2": temporal_status,
        "install_reachability_v2": reachability,
        "install_time_evidence": {
            "status": "unknown",
            "t_install": None,
            "source": None,
            "reason": "not observed",
        },
        "package_identity": {
            "schema_version": "codesentry_gen_package_identity_record_v1",
            "policy_version": "package_identity_v1",
            "ecosystem": "pypi",
            "source_type": "import",
            "raw_name": package,
            "distribution": normalized,
            "normalized_distribution": normalized,
            "identity_status": "distribution_candidate",
            "mapping_source": "literal_fallback",
            "mapping_confidence": "fallback",
            "private_registry_status": "unknown_not_inferred",
            "local_module_exclusion_status": local_status,
        },
        "pypi": {
            "package": normalized,
            "exists_now": temporal_status not in {
                "nonexistent_now",
                "nonexistent_at_tg",
            },
            "query_url": f"https://pypi.org/pypi/{normalized}/json",
            "audit_time": "2026-09-29T14:00:00+00:00",
            "first_release_time": (
                "2026-09-29T00:00:00+00:00"
                if temporal_status == "created_after_tg"
                else None
            ),
            "status_code": (
                404 if temporal_status == "nonexistent_now" else 200
            ),
            "registry_run_id": "step9_fresh_test100_v4_r5_r13",
            "raw_snapshot_file": raw_snapshot,
            "raw_response_sha256": "a" * 64,
            "snapshot_record_sha256": "b" * 64,
        },
    }


class TemporalCurrent404SemanticsTest(unittest.TestCase):
    def test_proven_generation_presence_is_not_overwritten_by_current_retained_releases(self) -> None:
        for first_release in ("2026-09-29T00:00:00Z", None):
            with self.subTest(first_release=first_release):
                record = make_record(temporal_status="created_after_tg")
                record["pypi"]["first_release_time"] = first_release
                record["registry_view_tg"] = {"exists": True, "evidence_status": "observed"}
                self.assertEqual(classify_temporal_status(record), "existed_at_tg")
                record["temporal_status_v2"] = classify_temporal_status(record)
                self.assertIsNone(classify_risk(record))

    def test_active_semantics_contract_matches_current_404_runtime(self) -> None:
        semantics = load_semantics()
        policy = semantics["temporal_status_policy"]
        self.assertNotIn(
            "nonexistent_now",
            policy["formal_positive_statuses"],
        )
        self.assertIn(
            "nonexistent_now",
            policy["auxiliary_audit_statuses"],
        )
        self.assertEqual(
            semantics["avcs_formal_risk_time_views"],
            {
                "api_induced_vulnerable_dependency": {
                    "view_id": "as_of_tg",
                    "metric_channel": "generation_time",
                },
                "temporal_drift": {
                    "view_id": "as_of_audit",
                    "metric_channel": "audit_time",
                },
            },
        )

        decision = classify_risk(make_record())
        self.assertIsNotNone(decision)
        assert decision is not None
        self.assertFalse(decision["formal_eligible"])
        self.assertEqual(decision["claim_strength"], "audit_time_absence_only")

    def test_temporal_classifier_generation_current_view_matrix(self) -> None:
        cases = (
            (False, False, None, "nonexistent_at_tg"),
            (
                False,
                True,
                "2026-09-29T00:00:00+00:00",
                "created_after_tg",
            ),
            (True, False, None, "nonexistent_now"),
            (
                True,
                True,
                "2026-09-27T00:00:00+00:00",
                "existed_at_tg",
            ),
        )
        for tg_exists, current_exists, first_release, expected in cases:
            with self.subTest(
                tg_exists=tg_exists,
                current_exists=current_exists,
            ):
                record = make_record()
                record.pop("temporal_status_v2", None)
                record["registry_view_tg"] = {
                    "exists": tg_exists,
                    "evidence_status": "observed",
                }
                record["pypi"]["exists_now"] = current_exists
                record["pypi"]["status_code"] = (
                    200 if current_exists else 404
                )
                record["pypi"]["first_release_time"] = first_release
                self.assertEqual(
                    classify_temporal_status(
                        record,
                        uncertainty_seconds=0,
                    ),
                    expected,
                )

    def test_proven_tg_absence_current_404_remains_formal_e2e(
        self,
    ) -> None:
        record = make_record()
        record.pop("temporal_status_v2", None)
        record["registry_view_tg"] = {
            "exists": False,
            "evidence_status": "observed",
        }

        record["temporal_status_v2"] = classify_temporal_status(
            record,
            uncertainty_seconds=0,
        )
        self.assertEqual(
            record["temporal_status_v2"],
            "nonexistent_at_tg",
        )
        self.assertIs(record["pypi"]["exists_now"], False)

        decision = classify_risk(record)
        self.assertIsNotNone(decision)
        assert decision is not None
        self.assertEqual(
            decision["claim_strength"],
            "generation_time_nonexistence",
        )
        card = build_risk_card(record, decision)
        self.assertEqual(card["channel"], "formal")
        self.assertTrue(card["formal_eligible"])
        normalized = normalize_risk_card(card, pipeline_origin="THO")
        self.assertTrue(normalized["formal_positive"])
        self.assertEqual(
            validate_tho_formal_cards_against_records(
                cards=[normalized],
                reachability_records=[record],
            ),
            [],
        )

    def test_exact_test100_current_404_cases_are_auxiliary(self) -> None:
        for sample_id, package in AFFECTED_TEST100_CASES:
            with self.subTest(sample_id=sample_id, package=package):
                record = make_record(
                    sample_id=sample_id,
                    package=package,
                )
                decision = classify_risk(record)
                self.assertIsNotNone(decision)
                assert decision is not None
                self.assertEqual(
                    decision["risk_type"],
                    "temporal_package_hallucination",
                )
                self.assertEqual(
                    decision["subtype"],
                    "audit_time_registry_absence",
                )
                self.assertEqual(decision["status"], "probable")
                self.assertEqual(decision["severity"], "high")
                self.assertFalse(decision["formal_eligible"])
                self.assertNotIn("confidence", decision)
                self.assertEqual(
                    decision["claim_strength"],
                    "audit_time_absence_only",
                )
                self.assertEqual(
                    decision["unknowns"][
                        "generation_time_registry_state"
                    ],
                    "unproven",
                )
                self.assertEqual(
                    decision["unknowns"]["ground_truth_adjudication"],
                    "required",
                )

                card = build_risk_card(record, decision)
                self.assertEqual(card["channel"], "auxiliary")
                self.assertFalse(card["formal_eligible"])
                self.assertNotIn("confidence", card)
                self.assertEqual(
                    card["unknowns"]["later_deletion_or_yank"],
                    "not_ruled_out",
                )

                normalized = normalize_risk_card(
                    card,
                    pipeline_origin="THO",
                )
                self.assertEqual(normalized["channel"], "auxiliary")
                self.assertFalse(normalized["formal_positive"])
                expected_ref = (
                    "output/step9_fresh_test100_v4_r5_r13/"
                    "tho/registry_snapshot/"
                    f"pypi/{package}/"
                    "20260929T140000_000000_0000.snapshot.json"
                )
                self.assertIn(
                    expected_ref,
                    normalized["evidence_refs"],
                )

    def test_low_reach_current_404_is_medium_auxiliary(self) -> None:
        record = make_record(
            reachability="import_only",
            local_status="confirmed_not_local",
        )
        decision = classify_risk(record)
        self.assertIsNotNone(decision)
        assert decision is not None
        self.assertEqual(decision["severity"], "medium")
        self.assertFalse(decision["formal_eligible"])
        self.assertEqual(decision["review_priority"], "medium")

    def test_generation_time_nonexistence_remains_formal(self) -> None:
        record = make_record(temporal_status="nonexistent_at_tg")
        decision = classify_risk(record)
        self.assertIsNotNone(decision)
        assert decision is not None
        self.assertEqual(
            decision["claim_strength"],
            "generation_time_nonexistence",
        )
        card = build_risk_card(record, decision)
        self.assertTrue(card["formal_eligible"])
        self.assertEqual(card["channel"], "formal")
        normalized = normalize_risk_card(card, pipeline_origin="THO")
        self.assertTrue(normalized["formal_positive"])
        self.assertTrue(normalized["evidence_refs"])

    def test_scientific_contract_excludes_current_404_from_formal(
        self,
    ) -> None:
        record = make_record()
        self.assertEqual(
            validate_tho_formal_cards_against_records(
                cards=[],
                reachability_records=[record],
            ),
            [],
        )

        decision = classify_risk(record)
        self.assertIsNotNone(decision)
        assert decision is not None
        source_card = build_risk_card(record, decision)
        source_card["channel"] = "formal"
        source_card["formal_eligible"] = True
        forged_formal = normalize_risk_card(
            source_card,
            pipeline_origin="THO",
        )
        errors = validate_tho_formal_cards_against_records(
            cards=[forged_formal],
            reachability_records=[record],
        )
        self.assertTrue(
            any(
                error.startswith("tho_card_not_supported_by_fact:")
                for error in errors
            )
        )

    def test_nonpositive_identity_and_lifecycle_states_stay_filtered(
        self,
    ) -> None:
        for status in ("deleted_or_yanked", "local_or_private_unknown"):
            with self.subTest(status=status):
                self.assertIsNone(
                    classify_risk(make_record(temporal_status=status))
                )

    def test_created_after_generation_without_install_time_is_bounded(
        self,
    ) -> None:
        decision = classify_risk(
            make_record(temporal_status="created_after_tg")
        )
        self.assertIsNotNone(decision)
        assert decision is not None
        self.assertEqual(
            decision["subtype"],
            "install_reachable_temporal_hallucination",
        )
        self.assertEqual(
            decision["claim_strength"],
            "bounded_temporal_hallucination",
        )
        self.assertNotIn(
            "hijack opportunity",
            decision["reason"].lower(),
        )


if __name__ == "__main__":
    unittest.main()
