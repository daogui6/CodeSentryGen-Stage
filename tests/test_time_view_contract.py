import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from time_view_contract_v1 import (
    TimeViewContractError,
    build_legacy_time_view_marker,
    build_time_view_contract,
    formal_generation_metric_eligible,
    validate_time_view_contract,
)

GEN = "2026-01-01T00:00:00Z"
AUDIT = "2026-02-01T00:00:00Z"
SHA = "a" * 64


def build(view_id: str, cutoff: str, namespace: str) -> dict:
    return build_time_view_contract(
        view_id=view_id,
        generation_time=GEN,
        evidence_cutoff=cutoff,
        evidence_snapshot_sha256=SHA,
        output_namespace=namespace,
    )


class TimeViewContractTests(unittest.TestCase):
    def test_as_of_tg_is_only_formal_generation_metric_channel(self) -> None:
        contract = build("as_of_tg", GEN, "as_of_tg/run-1")
        self.assertEqual(contract["release_state_cutoff"], GEN)
        self.assertIs(contract["formal_generation_metric_eligible"], True)
        self.assertEqual(
            contract["view_specific_metric_channel"], "generation_time"
        )
        self.assertIs(contract["may_overwrite_other_view"], False)

    def test_audit_and_oracle_are_separate_channels(self) -> None:
        audit = build("as_of_audit", AUDIT, "as_of_audit/run-1")
        oracle = build("oracle_now", AUDIT, "oracle_now/run-1")
        self.assertIs(audit["formal_generation_metric_eligible"], False)
        self.assertEqual(audit["view_specific_metric_channel"], "audit_time")
        self.assertIs(oracle["retrospective_only"], True)
        self.assertIs(oracle["oracle_may_enter_formal_denominator"], False)
        self.assertEqual(
            oracle["view_specific_metric_channel"], "oracle_retrospective"
        )

    def test_invalid_cross_view_bindings_fail_closed(self) -> None:
        cases = [
            ("as_of_tg", AUDIT, "as_of_tg/run-1"),
            ("as_of_audit", GEN, "as_of_audit/run-1"),
            ("oracle_now", AUDIT, "as_of_audit/run-1"),
        ]
        for view_id, cutoff, namespace in cases:
            with self.subTest(view_id=view_id, namespace=namespace):
                with self.assertRaises(TimeViewContractError):
                    build(view_id, cutoff, namespace)

    def test_snapshot_hash_and_legacy_boundary_are_explicit(self) -> None:
        with self.assertRaises(TimeViewContractError):
            build_time_view_contract(
                view_id="oracle_now",
                generation_time=GEN,
                evidence_cutoff=AUDIT,
                evidence_snapshot_sha256="not-a-hash",
                output_namespace="oracle_now/run-1",
            )
        legacy = build_legacy_time_view_marker()
        self.assertEqual(legacy["view_id"], "legacy_implicit")
        self.assertIs(legacy["main_experiment_eligible"], False)
        self.assertIs(formal_generation_metric_eligible(legacy), False)

    def test_downstream_cannot_forge_metric_eligibility(self) -> None:
        contract = build("as_of_audit", AUDIT, "as_of_audit/run-1")
        contract["formal_generation_metric_eligible"] = True
        with self.assertRaises(TimeViewContractError):
            validate_time_view_contract(contract)

        generation = build("as_of_tg", GEN, "as_of_tg/run-1")
        self.assertIs(formal_generation_metric_eligible(generation), True)
        generation["evidence_snapshot_sha256"] = "b" * 64
        # A different valid digest is a different contract, not silent drift.
        validated = validate_time_view_contract(generation)
        self.assertEqual(validated["evidence_snapshot_sha256"], "b" * 64)

    def test_avcs_exposes_persists_and_resume_binds_contract(self) -> None:
        source = (ROOT / "src/run_step8_unified_avcs.py").read_text(
            encoding="utf-8"
        )
        for token in (
            "time_view_id: str | None = None",
            "--time-view-id",
            "--time-view-snapshot-sha256",
            "--time-view-output-namespace",
            '"evaluation_time_view": evaluation_time_view',
            "evaluation_time_view=evaluation_time_view",
            "evaluation_time_view=validated_time_view",
            "time_view_not_formal_generation_metric",
        ):
            self.assertIn(token, source)

        resume_source = (ROOT / "src/scientific_contract_v1.py").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            '"evaluation_time_view": evaluation_time_view', resume_source
        )

        e2e_source = (ROOT / "src/run_codesentry_gen_e2e.py").read_text(
            encoding="utf-8"
        )
        for token in (
            "--time-view-id",
            "--time-view-snapshot-sha256",
            "--time-view-output-namespace",
            "build_sample_time_view_contract",
            "prospective protocol revision and Method Freeze are required",
        ):
            self.assertIn(token, e2e_source)


if __name__ == "__main__":
    unittest.main()
