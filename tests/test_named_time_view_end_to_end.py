import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import jsonschema


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from risk_semantics_v21 import (
    avcs_formal_risk_view_eligible,
    normalize_risk_card,
)
from run_codesentry_gen_e2e import (
    build_sample_time_view_contract,
    build_step8_avcs_command,
    resolve_requested_time_view_binding,
    summarize_avcs_coverage,
)
from run_step8_unified_avcs import (
    build_final_output_coverage,
    build_package_coverage,
    risk_type_for_actionable_finding,
)
from sceg_ir_v21 import _risk_time_view
from scientific_contract_v1 import (
    evaluate_avcs_method_coverage,
    project_avcs_final_output_coverage,
)
from time_view_contract_v1 import TimeViewContractError


GEN = "2026-01-01T00:00:00Z"
AUDIT = "2026-02-01T00:00:00Z"
SHA = "a" * 64
SAMPLE_ID = "sample-view-001"


def binding(view_id: str) -> dict[str, str]:
    return {
        "view_id": view_id,
        "evidence_snapshot_sha256": SHA,
        "output_namespace": f"{view_id}/controlled-run",
    }


def contract(view_id: str) -> dict:
    return build_sample_time_view_contract(
        binding=binding(view_id),
        sample_id=SAMPLE_ID,
        generation_time=GEN,
        audit_knowledge_time=AUDIT,
    )


def complete_negative_coverage(
    evaluation_time_view: dict | None,
    risk_cards: list[dict] | None = None,
) -> dict:
    return build_package_coverage(
        kb={
            "kb_id": "controlled-kb",
            "vulnerability_catalog": [
                {
                    "vulnerability_id": "CVE-CONTROLLED",
                    "published_at": GEN,
                }
            ],
            "trigger_rules": [],
        },
        api_history_adapter={
            "status": "resolved",
            "scope_policy": "controlled_scope",
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
            "syntax_parse_status": "parsed",
        },
        api_meta={
            "status": "resolved",
            "resolved_api_call_count": 0,
            "unresolved_api_call_count": 0,
        },
        manifest={"status": "not_declared"},
        constraint_satisfiability={
            "status": "satisfiable",
            "formal_negative_eligible": True,
        },
        findings=[],
        risk_cards=list(risk_cards or []),
        trigger_matches={},
        evaluation_time_view=evaluation_time_view,
    )


def raw_auxiliary_card(evaluation_time_view: dict) -> dict:
    return {
        "schema_version": "step8_avcs_risk_card_v0.2",
        "risk_id": "source-risk-controlled",
        "sample_id": SAMPLE_ID,
        "distribution": "requests",
        "type": "temporal_drift",
        "status": "probable",
        "severity": "not_calibrated",
        "generation_time": GEN,
        "knowledge_time": AUDIT,
        "temporal_classification": "post_generation_disclosure",
        "evaluation_time_view": copy.deepcopy(evaluation_time_view),
        "channel": "auxiliary",
        "formal_eligible": False,
        "introduced_by": {
            "source_type": "manifest",
            "file": "requirements.txt",
            "line": 1,
            "column": 1,
            "entity": "requests",
        },
        "evidence": {},
        "unknowns": {},
        "repair": {},
    }


def write_coverage_sample(sample_dir: Path, coverage: dict) -> None:
    sample_dir.mkdir(parents=True)
    manifest = {
        "schema_version": "step8_unified_avcs_run_v0.3",
        "sample_id": sample_dir.name,
        "api_parse_status": "parsed",
        "package_analysis_count": 1,
        "dependency_candidate_distributions": ["requests"],
        "in_curated_scope_candidate_distributions": ["requests"],
        "out_of_curated_scope_candidate_distributions": [],
        "unsupported_candidate_distributions": [],
        "packages": [
            {
                "distribution": "requests",
                "normalized_distribution": "requests",
                "coverage": copy.deepcopy(coverage),
                "analysis_file": "pyproject.toml",
                "knowledge_complete_to_requested_time": True,
                "risk_card_count": 0,
                "source_release_snapshot_manifest_bound": True,
                "vulnerability_catalog_count": 1,
                "vulnerability_published_at_count": 1,
            }
        ],
    }
    (sample_dir / "manifest.json").write_text(
        json.dumps(manifest),
        encoding="utf-8",
    )
    (sample_dir / "coverage_outcomes.jsonl").write_text(
        json.dumps(
            {
                "sample_id": sample_dir.name,
                "distribution": "requests",
                "support_status": "supported",
                **copy.deepcopy(coverage),
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (sample_dir / "risk_cards.jsonl").write_text("", encoding="utf-8")


class NamedTimeViewEndToEndTests(unittest.TestCase):
    def test_formal_negative_schema_requires_all_metric_authority(self) -> None:
        schema = json.loads(
            (ROOT / "schemas/risk_card_schema_v2_1.json").read_text(
                encoding="utf-8"
            )
        )
        coverage_schema = schema["properties"]["coverage"]["oneOf"][1]
        for field in (
            "evaluation_time_view",
            "generation_metric",
            "audit_drift_metric",
        ):
            with self.subTest(field=field):
                coverage = complete_negative_coverage(contract("as_of_tg"))
                coverage.pop(field)
                projected = project_avcs_final_output_coverage(coverage)
                with self.assertRaises(jsonschema.ValidationError):
                    jsonschema.validate(projected, coverage_schema)

    def test_e2e_summary_rejects_formal_negative_without_authority(self) -> None:
        coverage = complete_negative_coverage(contract("as_of_tg"))
        for field in (
            "evaluation_time_view",
            "generation_metric",
            "audit_drift_metric",
        ):
            coverage.pop(field)
        with tempfile.TemporaryDirectory() as raw_tmp:
            sample_dir = Path(raw_tmp) / SAMPLE_ID
            write_coverage_sample(sample_dir, coverage)
            with self.assertRaisesRegex(
                ValueError,
                "coverage metric authority",
            ):
                summarize_avcs_coverage([sample_dir])

    def test_scientific_consumer_rejects_formal_negative_without_authority(
        self,
    ) -> None:
        coverage = complete_negative_coverage(contract("as_of_tg"))
        for field in (
            "evaluation_time_view",
            "generation_metric",
            "audit_drift_metric",
        ):
            coverage.pop(field)
        with tempfile.TemporaryDirectory() as raw_tmp:
            avcs_dir = Path(raw_tmp) / "avcs"
            write_coverage_sample(
                avcs_dir / "samples" / SAMPLE_ID,
                coverage,
            )
            acceptance = {
                "schema_version": "avcs_coverage_acceptance_v2",
                "require_explicit_outcome_per_sample": True,
                "allow_no_dependency_candidate_samples": True,
                "allow_out_of_curated_scope_only_samples": True,
                "in_scope_missing_method_support_is_contract_failure": True,
                "in_scope_unknown_review_is_valid_non_metric_outcome": True,
                "metric_evaluability_is_measurement_not_correctness": True,
                "out_of_curated_scope_is_not_negative": True,
                "in_scope_syntax_unavailable_is_valid_non_metric_outcome": True,
            }
            with patch(
                "scientific_contract_v1._verify_avcs_manifest_hash_closure",
                return_value=[],
            ):
                ok, detail = evaluate_avcs_method_coverage(
                    avcs_dir=avcs_dir,
                    expected_samples=1,
                    coverage_acceptance_rule=acceptance,
                    require_coverage_acceptance_rule=True,
                )

        self.assertFalse(ok)
        self.assertTrue(
            any(
                "coverage_metric_authority" in error
                for error in detail["errors"]
            ),
            detail["errors"],
        )

    def test_same_sample_three_views_isolate_generation_denominator(self) -> None:
        views = {
            view_id: contract(view_id)
            for view_id in ("as_of_tg", "as_of_audit", "oracle_now")
        }
        coverage = {
            view_id: complete_negative_coverage(value)
            for view_id, value in views.items()
        }

        self.assertEqual(
            coverage["as_of_tg"]["main_metric_outcome"],
            "formal_negative",
        )
        self.assertIs(
            coverage["as_of_tg"]["main_metric_eligible"], True
        )
        for view_id in ("as_of_audit", "oracle_now"):
            with self.subTest(view_id=view_id):
                self.assertEqual(
                    coverage[view_id]["main_metric_outcome"],
                    "unknown_review",
                )
                self.assertIs(
                    coverage[view_id]["main_metric_eligible"], False
                )
                self.assertEqual(
                    coverage[view_id]["view_specific_metric_outcome"][
                        "outcome"
                    ],
                    "formal_negative",
                )
                self.assertIn(
                    "time_view_not_formal_generation_metric:" + view_id,
                    coverage[view_id]["blocking_unknown_reasons"],
                )
        self.assertEqual(
            coverage["as_of_audit"]["audit_drift_metric"]["outcome"],
            "formal_negative",
        )
        self.assertIs(
            coverage["as_of_audit"]["audit_drift_metric"]["eligible"],
            True,
        )
        self.assertEqual(
            coverage["oracle_now"]["audit_drift_metric"]["outcome"],
            "not_applicable",
        )

        legacy = complete_negative_coverage(None)
        self.assertIs(legacy["main_metric_eligible"], False)
        self.assertEqual(
            legacy["evaluation_time_view"]["view_id"],
            "legacy_implicit",
        )
        self.assertIn(
            "time_view_not_formal_generation_metric:legacy_implicit",
            legacy["blocking_unknown_reasons"],
        )

    def test_risk_card_and_sceg_projection_keep_views_distinct(self) -> None:
        schema = json.loads(
            (ROOT / "schemas/risk_card_schema_v2_1.json").read_text(
                encoding="utf-8"
            )
        )
        cards = {}
        for view_id in ("as_of_tg", "as_of_audit", "oracle_now"):
            cards[view_id] = normalize_risk_card(
                raw_auxiliary_card(contract(view_id)),
                pipeline_origin="AVCS",
            )

        self.assertEqual(
            len({card["risk_identity"] for card in cards.values()}), 3
        )
        for view_id, card in cards.items():
            self.assertEqual(
                card["time_view"]["evaluation_contract"]["view_id"],
                view_id,
            )
            self.assertEqual(
                _risk_time_view(card)["evaluation_contract"]["view_id"],
                view_id,
            )
            jsonschema.validate(card, schema)

    def test_formal_avcs_metrics_are_isolated_by_risk_time_view(self) -> None:
        generation_view = contract("as_of_tg")
        generation = complete_negative_coverage(
            generation_view,
            [
                {
                    "type": "api_induced_vulnerable_dependency",
                    "channel": "formal",
                    "formal_eligible": True,
                    "evaluation_time_view": generation_view,
                }
            ],
        )
        self.assertEqual(generation["main_metric_outcome"], "formal_positive")
        self.assertIs(generation["main_metric_eligible"], True)
        self.assertIs(generation["formal_positive"], True)
        self.assertEqual(
            generation["audit_drift_metric"]["outcome"],
            "not_applicable",
        )

        audit_view = contract("as_of_audit")
        audit = complete_negative_coverage(
            audit_view,
            [
                {
                    "type": "temporal_drift",
                    "channel": "formal",
                    "formal_eligible": True,
                    "evaluation_time_view": audit_view,
                }
            ],
        )
        self.assertEqual(audit["main_metric_outcome"], "unknown_review")
        self.assertIs(audit["main_metric_eligible"], False)
        self.assertIs(audit["formal_positive"], False)
        self.assertEqual(audit["audit_drift_metric"]["outcome"], "formal_positive")
        self.assertIs(audit["audit_drift_metric"]["eligible"], True)
        self.assertIs(
            audit["audit_drift_metric"]["formal_positive"], True
        )

        raw_formal = raw_auxiliary_card(audit_view)
        raw_formal["channel"] = "formal"
        raw_formal["formal_eligible"] = True
        raw_formal["coverage"] = build_final_output_coverage(
            coverage=audit,
            support_status="supported",
        )
        normalized = normalize_risk_card(
            raw_formal,
            pipeline_origin="AVCS",
        )
        schema = json.loads(
            (ROOT / "schemas/risk_card_schema_v2_1.json").read_text(
                encoding="utf-8"
            )
        )
        jsonschema.validate(normalized, schema)

        wrong_view_drift = complete_negative_coverage(
            generation_view,
            [
                {
                    "type": "temporal_drift",
                    "channel": "formal",
                    "formal_eligible": True,
                    "evaluation_time_view": generation_view,
                }
            ],
        )
        self.assertIs(wrong_view_drift["formal_positive"], False)
        self.assertNotEqual(
            wrong_view_drift["main_metric_outcome"],
            "formal_positive",
        )
        invalid_raw = raw_auxiliary_card(generation_view)
        invalid_raw["channel"] = "formal"
        invalid_raw["formal_eligible"] = True
        invalid_raw["coverage"] = build_final_output_coverage(
            coverage=wrong_view_drift,
            support_status="supported",
        )
        with self.assertRaises(ValueError):
            normalize_risk_card(
                invalid_raw,
                pipeline_origin="AVCS",
            )

        oracle_view = contract("oracle_now")
        oracle = complete_negative_coverage(
            oracle_view,
            [
                {
                    "type": "temporal_drift",
                    "channel": "formal",
                    "formal_eligible": True,
                    "evaluation_time_view": oracle_view,
                }
            ],
        )
        self.assertEqual(
            oracle["audit_drift_metric"]["outcome"],
            "not_applicable",
        )
        self.assertIs(oracle["audit_drift_metric"]["eligible"], False)
        self.assertFalse(
            avcs_formal_risk_view_eligible(
                "temporal_drift",
                oracle_view,
            )
        )

    def test_pre_generation_disclosure_is_not_temporal_drift(self) -> None:
        risk_type = risk_type_for_actionable_finding(
            actionability="api_induced_vulnerable_dependency",
            temporal="published_by_time_view",
            manifest_kind="version_specifier",
        )
        self.assertEqual(
            risk_type,
            "api_induced_vulnerable_dependency",
        )

    def test_audit_metric_counts_as_method_coverage_not_generation(self) -> None:
        audit_view = contract("as_of_audit")
        coverage = complete_negative_coverage(
            audit_view,
            [
                {
                    "type": "temporal_drift",
                    "channel": "formal",
                    "formal_eligible": True,
                    "evaluation_time_view": audit_view,
                }
            ],
        )
        with tempfile.TemporaryDirectory() as raw_tmp:
            sample_dir = Path(raw_tmp) / SAMPLE_ID
            sample_dir.mkdir()
            manifest = {
                "package_analysis_count": 1,
                "dependency_candidate_distributions": ["requests"],
                "in_curated_scope_candidate_distributions": ["requests"],
                "out_of_curated_scope_candidate_distributions": [],
                "unsupported_candidate_distributions": [],
                "packages": [
                    {
                        "distribution": "requests",
                        "normalized_distribution": "requests",
                        "coverage": coverage,
                        "knowledge_complete_to_requested_time": True,
                        "risk_card_count": 1,
                        "source_release_snapshot_manifest_bound": True,
                        "vulnerability_catalog_count": 1,
                        "vulnerability_published_at_count": 1,
                    }
                ],
            }
            (sample_dir / "manifest.json").write_text(
                json.dumps(manifest),
                encoding="utf-8",
            )
            (sample_dir / "coverage_outcomes.jsonl").write_text(
                json.dumps(
                    {
                        "sample_id": SAMPLE_ID,
                        "distribution": "requests",
                        "support_status": "supported",
                        **coverage,
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            summary = summarize_avcs_coverage([sample_dir])

        self.assertEqual(summary["formal_metric_eligible_count"], 0)
        self.assertEqual(summary["audit_drift_metric_eligible_count"], 1)
        self.assertEqual(summary["authorized_metric_eligible_count"], 1)
        self.assertEqual(
            summary["analysis_support_state_counts"],
            {"metric_eligible": 1},
        )

    def test_scientific_consumer_accepts_isolated_audit_metric(self) -> None:
        audit_view = contract("as_of_audit")
        coverage = complete_negative_coverage(
            audit_view,
            [
                {
                    "type": "temporal_drift",
                    "channel": "formal",
                    "formal_eligible": True,
                    "evaluation_time_view": audit_view,
                }
            ],
        )
        with tempfile.TemporaryDirectory() as raw_tmp:
            avcs_dir = Path(raw_tmp) / "avcs"
            sample_dir = avcs_dir / "samples" / SAMPLE_ID
            sample_dir.mkdir(parents=True)
            manifest = {
                "schema_version": "step8_unified_avcs_run_v0.3",
                "sample_id": SAMPLE_ID,
                "api_parse_status": "parsed",
                "package_analysis_count": 1,
                "dependency_candidate_distributions": ["requests"],
                "in_curated_scope_candidate_distributions": ["requests"],
                "out_of_curated_scope_candidate_distributions": [],
                "unsupported_candidate_distributions": [],
                "packages": [
                    {
                        "distribution": "requests",
                        "normalized_distribution": "requests",
                        "coverage": coverage,
                        "analysis_file": "pyproject.toml",
                        "knowledge_complete_to_requested_time": True,
                        "source_release_snapshot_manifest_bound": True,
                    }
                ],
            }
            (sample_dir / "manifest.json").write_text(
                json.dumps(manifest),
                encoding="utf-8",
            )
            (sample_dir / "coverage_outcomes.jsonl").write_text(
                json.dumps(
                    {
                        "sample_id": SAMPLE_ID,
                        "distribution": "requests",
                        "support_status": "supported",
                        **coverage,
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (sample_dir / "risk_cards.jsonl").write_text(
                json.dumps(
                    {
                        "type": "temporal_drift",
                        "channel": "formal",
                        "formal_eligible": True,
                        "distribution": "requests",
                        "evaluation_time_view": audit_view,
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            acceptance = {
                "schema_version": "avcs_coverage_acceptance_v2",
                "require_explicit_outcome_per_sample": True,
                "allow_no_dependency_candidate_samples": True,
                "allow_out_of_curated_scope_only_samples": True,
                "in_scope_missing_method_support_is_contract_failure": True,
                "in_scope_unknown_review_is_valid_non_metric_outcome": True,
                "metric_evaluability_is_measurement_not_correctness": True,
                "out_of_curated_scope_is_not_negative": True,
                "in_scope_syntax_unavailable_is_valid_non_metric_outcome": True,
            }
            with patch(
                "scientific_contract_v1._verify_avcs_manifest_hash_closure",
                return_value=[],
            ):
                ok, detail = evaluate_avcs_method_coverage(
                    avcs_dir=avcs_dir,
                    expected_samples=1,
                    coverage_acceptance_rule=acceptance,
                    require_coverage_acceptance_rule=True,
                )

        self.assertTrue(ok, detail["errors"])
        self.assertEqual(detail["formal_metric_eligible_count"], 0)
        self.assertEqual(detail["audit_drift_metric_eligible_count"], 1)
        self.assertEqual(
            detail["audit_drift_metric_eligible_sample_count"],
            1,
        )
        self.assertEqual(detail["insufficient_method_coverage_count"], 0)

    def test_e2e_command_passes_exact_named_view_contract(self) -> None:
        view = contract("as_of_tg")
        command = build_step8_avcs_command(
            code_path=None,
            sample_id=SAMPLE_ID,
            samples_path=None,
            sample_out=Path("out") / SAMPLE_ID,
            knowledge_time=GEN,
            release_snapshot_manifest=Path("snapshot.json"),
            sceg_ir_path=Path("sceg.json"),
            identity_policy_path=Path("identity.json"),
            time_view_id=view["view_id"],
            time_view_snapshot_sha256=view[
                "evidence_snapshot_sha256"
            ],
            time_view_output_namespace=view["output_namespace"],
        )
        self.assertEqual(
            command[command.index("--time-view-id") + 1], "as_of_tg"
        )
        self.assertEqual(
            command[command.index("--time-view-snapshot-sha256") + 1],
            SHA,
        )
        self.assertEqual(
            command[command.index("--time-view-output-namespace") + 1],
            "as_of_tg/controlled-run/samples/" + SAMPLE_ID,
        )

        with self.assertRaises(ValueError):
            build_step8_avcs_command(
                code_path=None,
                sample_id=SAMPLE_ID,
                samples_path=None,
                sample_out=Path("out") / SAMPLE_ID,
                knowledge_time=GEN,
                release_snapshot_manifest=None,
                sceg_ir_path=Path("sceg.json"),
                identity_policy_path=Path("identity.json"),
                time_view_id="as_of_tg",
            )

    def test_snapshot_and_namespace_cross_contamination_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw_tmp:
            snapshot = Path(raw_tmp) / "snapshot.json"
            snapshot.write_text("{}\n", encoding="utf-8")
            digest = hashlib.sha256(snapshot.read_bytes()).hexdigest()
            resolved = resolve_requested_time_view_binding(
                time_view_id="as_of_tg",
                snapshot_sha256=digest,
                output_namespace="as_of_tg/run-1",
                release_snapshot_manifest=snapshot,
            )
            self.assertEqual(resolved["evidence_snapshot_sha256"], digest)
            with self.assertRaises(ValueError):
                resolve_requested_time_view_binding(
                    time_view_id="as_of_tg",
                    snapshot_sha256="0" * 64,
                    output_namespace="as_of_tg/run-1",
                    release_snapshot_manifest=snapshot,
                )

        contaminated = binding("oracle_now")
        contaminated["output_namespace"] = "as_of_audit/run-1"
        with self.assertRaises(TimeViewContractError):
            build_sample_time_view_contract(
                binding=contaminated,
                sample_id=SAMPLE_ID,
                generation_time=GEN,
                audit_knowledge_time=AUDIT,
            )


if __name__ == "__main__":
    unittest.main()
