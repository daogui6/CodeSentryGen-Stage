from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from run_step8_unified_avcs import (  # noqa: E402
    assess_constraint_satisfiability,
    build_package_coverage,
)
from time_view_contract_v1 import build_time_view_contract  # noqa: E402


def release(version: str, **extra: object) -> dict[str, object]:
    return {"version": version, **extra}


def manifest(
    specifier: str,
    *,
    kind: str = "version_specifier",
    matched_requirement_count: int = 1,
) -> dict[str, object]:
    return {
        "status": "resolved",
        "constraint_kind": kind,
        "specifier": specifier,
        "constraint_source": "manifest",
        "matched_requirements": [
            {"specifier": specifier}
            for _ in range(matched_requirement_count)
        ],
    }


def assess(
    *,
    snapshot: list[dict[str, object]],
    at_time: list[dict[str, object]],
    after_policy: list[dict[str, object]],
    manifest_value: dict[str, object],
    manifest_candidates: list[dict[str, object]],
    feasible: list[dict[str, object]],
) -> dict[str, object]:
    return assess_constraint_satisfiability(
        snapshot_releases=snapshot,
        time_releases=at_time,
        policy_releases=after_policy,
        manifest=manifest_value,
        manifest_candidates=manifest_candidates,
        feasible_releases=feasible,
    )


class ConstraintSatisfiabilityTests(unittest.TestCase):
    def test_contradictory_range_has_no_snapshot_match(self) -> None:
        releases = [release("2.3"), release("2.4"), release("2.5")]
        result = assess(
            snapshot=releases,
            at_time=releases,
            after_policy=releases,
            manifest_value=manifest(">=2.4,<2.4"),
            manifest_candidates=[],
            feasible=[],
        )
        self.assertEqual(
            result["status"],
            "manifest_constraint_no_snapshot_match",
        )
        self.assertFalse(result["formal_negative_eligible"])

    def test_future_only_range_is_distinct_from_snapshot_absence(self) -> None:
        old = release("1.0")
        future = release("2.0")
        result = assess(
            snapshot=[old, future],
            at_time=[old],
            after_policy=[old],
            manifest_value=manifest(">=2"),
            manifest_candidates=[],
            feasible=[],
        )
        self.assertEqual(
            result["status"],
            "manifest_constraint_no_match_as_of_time_view",
        )
        self.assertEqual(result["snapshot_match_count"], 1)
        self.assertEqual(result["time_match_count"], 0)

    def test_missing_exact_lock_target_is_explicit(self) -> None:
        releases = [release("1.0"), release("2.0")]
        result = assess(
            snapshot=releases,
            at_time=releases,
            after_policy=releases,
            manifest_value=manifest(
                "==9.9",
                kind="lockfile_exact_pin",
            ),
            manifest_candidates=[],
            feasible=[],
        )
        self.assertEqual(
            result["status"],
            "exact_lock_target_absent_from_snapshot",
        )

    def test_prerelease_only_match_excluded_by_default_policy(self) -> None:
        prerelease = release("2.5rc1")
        result = assess(
            snapshot=[prerelease],
            at_time=[prerelease],
            after_policy=[],
            manifest_value=manifest(">=2,<3"),
            manifest_candidates=[],
            feasible=[],
        )
        self.assertEqual(
            result["status"],
            "prerelease_only_match_excluded_by_policy",
        )

    def test_yanked_only_match_is_not_formal_negative(self) -> None:
        yanked = release("2.1", yanked=True)
        result = assess(
            snapshot=[yanked],
            at_time=[yanked],
            after_policy=[yanked],
            manifest_value=manifest(">=2,<3"),
            manifest_candidates=[yanked],
            feasible=[yanked],
        )
        self.assertEqual(
            result["status"],
            "yanked_only_release_match",
        )
        self.assertFalse(result["formal_negative_eligible"])

    def test_multiple_manifest_constraints_are_identifiable(self) -> None:
        releases = [release("1.0"), release("2.0")]
        result = assess(
            snapshot=releases,
            at_time=releases,
            after_policy=releases,
            manifest_value=manifest(
                ">=2,<2",
                matched_requirement_count=2,
            ),
            manifest_candidates=[],
            feasible=[],
        )
        self.assertEqual(
            result["status"],
            "multiple_manifest_constraints_no_snapshot_match",
        )

    def test_api_constraints_can_eliminate_all_manifest_candidates(self) -> None:
        candidate = release("2.0")
        result = assess(
            snapshot=[candidate],
            at_time=[candidate],
            after_policy=[candidate],
            manifest_value=manifest(">=2,<3"),
            manifest_candidates=[candidate],
            feasible=[],
        )
        self.assertEqual(
            result["status"],
            "api_constraints_eliminate_all_manifest_candidates",
        )
        self.assertFalse(result["formal_negative_eligible"])

    def test_satisfiable_constraint_remains_formal_negative_eligible(self) -> None:
        candidate = release("2.0")
        result = assess(
            snapshot=[candidate],
            at_time=[candidate],
            after_policy=[candidate],
            manifest_value=manifest(">=2,<3"),
            manifest_candidates=[candidate],
            feasible=[candidate],
        )
        self.assertEqual(result["status"], "satisfiable_in_time_view")
        self.assertTrue(result["formal_negative_eligible"])


class CoverageWiringTests(unittest.TestCase):
    def _coverage(
        self,
        constraint_satisfiability: dict[str, object],
    ) -> dict[str, object]:
        return build_package_coverage(
            kb={
                "kb_id": "test-kb",
                "vulnerability_catalog": [
                    {
                        "vulnerability_id": "CVE-TEST",
                        "published_at": "2020-01-01T00:00:00Z",
                        "trigger_assessment": {"status": "not_available"},
                    }
                ],
                "trigger_rules": [],
            },
            api_history_adapter={
                "status": "resolved",
                "scope_policy": "declared_scope_only",
                "entries": [],
                "entry_count": 0,
                "scope_semantics": {
                    "resolved_does_not_imply_package_wide_coverage": True,
                },
            },
            release_view={
                "knowledge_complete_to_requested_time": True,
                "release_evidence_complete": True,
                "snapshot_covers_requested_time": True,
            },
            filtered_calls={
                "api_call_count": 0,
                "syntax_parse_status": "parseable",
            },
            api_meta={
                "status": "not_found",
                "resolved_api_call_count": 0,
                "unresolved_api_call_count": 0,
            },
            manifest=manifest(">=2,<3"),
            constraint_satisfiability=constraint_satisfiability,
            findings=[],
            risk_cards=[],
            trigger_matches={},
            evaluation_time_view=build_time_view_contract(
                view_id="as_of_tg",
                generation_time="2020-01-01T00:00:00Z",
                evidence_cutoff="2020-01-01T00:00:00Z",
                evidence_snapshot_sha256="a" * 64,
                output_namespace="as_of_tg/constraint-satisfiability-test",
            ),
        )

    def test_empty_feasible_is_unknown_review_not_negative(self) -> None:
        result = assess(
            snapshot=[release("1.0")],
            at_time=[release("1.0")],
            after_policy=[release("1.0")],
            manifest_value=manifest(">=2,<3"),
            manifest_candidates=[],
            feasible=[],
        )
        coverage = self._coverage(result)
        self.assertEqual(
            coverage["main_metric_outcome"],
            "unknown_review",
        )
        self.assertFalse(coverage["main_metric_eligible"])
        self.assertIn(
            "constraint_satisfiability:"
            "manifest_constraint_no_snapshot_match",
            coverage["blocking_unknown_reasons"],
        )

    def test_nonempty_feasible_can_remain_formal_negative(self) -> None:
        candidate = release("2.0")
        result = assess(
            snapshot=[candidate],
            at_time=[candidate],
            after_policy=[candidate],
            manifest_value=manifest(">=2,<3"),
            manifest_candidates=[candidate],
            feasible=[candidate],
        )
        coverage = self._coverage(result)
        self.assertEqual(
            coverage["main_metric_outcome"],
            "formal_negative",
        )
        self.assertTrue(coverage["main_metric_eligible"])


if __name__ == "__main__":
    unittest.main()
