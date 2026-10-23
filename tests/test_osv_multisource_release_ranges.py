"""Stage extraction of original range-repair tests; excludes later integration tests.
Created 2026-10-24 from commit 34d43873435d49da6b928f53a76fdb316118a884.
"""
from __future__ import annotations

import copy
import itertools
import json
import sys
import tempfile
import unittest
from pathlib import Path

from packaging.specifiers import SpecifierSet
from packaging.version import Version

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from build_osv_package_catalog import build_identity_groups  # noqa: E402
from normalize_osv_vulnerability import normalize_osv_vulnerability  # noqa: E402
from osv_pypi_release_ranges import analyze_sources  # noqa: E402
from resolve_avcs_exposed_releases import build_exposed_release_view  # noqa: E402
from evaluate_avcs_overlap import evaluate_avcs, intersect_simple_specifiers  # noqa: E402
from resolve_osv_package_catalog_constraints import (  # noqa: E402
    build_group_constraint,
    resolve_catalog_constraints,
)
from resolve_vulnerability_constraints import (  # noqa: E402
    build_single_osv_specifier,
    resolve_normalized_osv_evidence,
)


def ecosystem(*events: dict[str, str]) -> dict:
    return {"type": "ECOSYSTEM", "events": list(events)}


def git_range() -> dict:
    return {"type": "GIT", "repo": "https://github.com/example/package",
            "events": [{"introduced": "0"}, {"fixed": "a" * 40}]}


def source(record_id: str, ranges: list, versions: list | None = None) -> dict:
    return {"source_record_id": record_id, "identifiers": [record_id, "CVE-TEST"],
            "aliases": ["CVE-TEST"], "evidence_status": "resolved",
            "affected_ranges": ranges, "affected_versions": versions or [],
            "fixed_versions": [], "fixed_commits": [],
            "evidence_hash": "sha256:" + record_id.encode().hex(),
            "source_url": "https://api.osv.dev/v1/vulns/" + record_id}


def constraint(*records: dict) -> dict:
    return build_group_constraint(build_identity_groups(list(records))[0])


def member(row: dict, version: str) -> bool:
    return SpecifierSet(row["affected_version_specifier"]).contains(
        Version(version), prereleases=True)


def reference_affected(record: dict, version: str) -> bool:
    """Independent transcription of OSV's sorted-event evaluation pseudocode."""
    candidate = Version(version)
    if any(Version(value) == candidate for value in record["affected_versions"]):
        return True
    for entry in record["affected_ranges"]:
        if entry["type"] != "ECOSYSTEM":
            continue
        limits = [event["limit"] for event in entry["events"] if "limit" in event]
        if limits and not any(limit == "*" or candidate < Version(limit) for limit in limits):
            continue
        ordered = sorted((event for event in entry["events"] if "limit" not in event),
                         key=lambda event: (next(iter(event.values())) != "0" or
                                            "introduced" not in event,
                                            Version(next(iter(event.values())))))
        vulnerable = False
        for event in ordered:
            if "introduced" in event:
                if event["introduced"] == "0" or candidate >= Version(event["introduced"]):
                    vulnerable = True
            elif "fixed" in event:
                if candidate >= Version(event["fixed"]):
                    vulnerable = False
            elif "last_affected" in event:
                if candidate > Version(event["last_affected"]):
                    vulnerable = False
        if vulnerable:
            return True
    return False


class OSVMultisourceReleaseRangeTests(unittest.TestCase):
    def test_equal_ecosystem_with_extra_git_keeps_all_provenance(self) -> None:
        ranges = [ecosystem({"introduced": "0"}, {"fixed": "3.1.1"})]
        records = [source("GHSA-A", ranges, ["3.0"]),
                   source("PYSEC-B", ranges + [git_range()], ["3.0"])]
        row = constraint(*records)
        self.assertEqual(row["constraint_status"], "resolved")
        self.assertTrue(row["range_disagreement"])  # Retained legacy structural flag.
        self.assertFalse(row["release_range_disagreement"])
        self.assertEqual(row["source_record_ids"], ["GHSA-A", "PYSEC-B"])
        evidence = row["release_range_analysis"]["source_evidence"]
        self.assertEqual(evidence[1]["affected_ranges"][-1], git_range())
        self.assertEqual([e["evidence_hash"] for e in evidence],
                         [record["evidence_hash"] for record in records])
        self.assertEqual(row["fixed_version_specifier"], ">=3.1.1")
        self.assertTrue(member(row, "3.1.1rc1"))
        self.assertFalse(member(row, "3.1.1"))

    def test_pep440_equal_spellings_and_metadata_do_not_conflict(self) -> None:
        a = ecosystem({"introduced": "1.9.0"}, {"fixed": "v2.3.0"})
        b = ecosystem({"fixed": "2.3"}, {"introduced": "1.9"})
        b["database_specific"] = {"nonsemantic": "preserved"}
        row = constraint(source("GHSA-A", [a], ["1.9.0"]),
                         source("PYSEC-B", [b], ["1.9"]))
        self.assertEqual(row["constraint_status"], "resolved")
        self.assertEqual(row["affected_version_specifier"], ">=1.9,<=2.3,!=2.3")
        self.assertTrue(member(row, "2.3rc1"))
        self.assertFalse(member(row, "1.8.9"))

    def test_real_fixed_conflict_never_unions_claims(self) -> None:
        row = constraint(source("GHSA-A", [ecosystem({"introduced": "0"}, {"fixed": "2"})]),
                         source("PYSEC-B", [ecosystem({"introduced": "0"}, {"fixed": "3"})]))
        self.assertEqual(row["constraint_status"], "source_range_disagreement")
        self.assertTrue(row["release_range_disagreement"])
        self.assertEqual(row["affected_version_specifier"], "")
        self.assertEqual(row["fixed_version_specifier"], "")

    def test_enumerated_versions_inside_common_range_can_differ(self) -> None:
        ranges = [ecosystem({"introduced": "0"}, {"fixed": "2"})]
        row = constraint(source("GHSA-A", ranges, ["1"]),
                         source("PYSEC-B", ranges, ["1", "2rc1"]))
        self.assertEqual(row["constraint_status"], "resolved")
        self.assertTrue(row["affected_version_list_disagreement"])
        self.assertEqual(row["release_range_analysis"]["classification"],
                         "equivalent_explicit_version_lists")

    def test_git_mapped_release_outside_common_range_is_not_ignored(self) -> None:
        ranges = [ecosystem({"introduced": "1"}, {"fixed": "2"})]
        row = constraint(source("GHSA-A", ranges, ["1.5"]),
                         source("PYSEC-B", ranges + [git_range()], ["0.9", "1.5"]))
        self.assertEqual(row["constraint_status"], "source_affected_version_list_disagreement")
        self.assertFalse(row["release_range_disagreement"])
        self.assertTrue(row["release_range_analysis"]["affected_release_set_disagreement"])

    def test_only_git_or_only_explicit_versions_remain_unresolved(self) -> None:
        for ranges, versions in [([git_range()], []), ([git_range()], ["1"]), ([], ["1"])]:
            with self.subTest(ranges=ranges):
                row = constraint(source("GHSA-A", ranges, versions))
                self.assertEqual(row["constraint_status"], "release_range_evidence_missing")
                self.assertEqual(row["affected_version_specifier"], "")

    def test_missing_release_claim_in_one_source_blocks_consensus(self) -> None:
        row = constraint(source("GHSA-A", [ecosystem({"introduced": "0"}, {"fixed": "2"})]),
                         source("PYSEC-B", [git_range()]))
        self.assertNotEqual(row["constraint_status"], "resolved")

    def test_multisegment_equivalence_does_not_fill_the_safe_gap(self) -> None:
        a = [ecosystem({"introduced": "0"}, {"fixed": "1"}),
             ecosystem({"introduced": "2"}, {"fixed": "3"})]
        b = [ecosystem({"introduced": "2"}, {"fixed": "3"},
                       {"introduced": "0"}, {"fixed": "1"}), git_range()]
        row = constraint(source("GHSA-A", a), source("PYSEC-B", b))
        self.assertFalse(row["release_range_disagreement"])
        self.assertEqual(row["constraint_status"], "unsupported_multi_interval_release_set")
        intervals = row["release_range_analysis"]["affected_release_intervals"]
        self.assertEqual([(r["lower"], r["upper"]) for r in intervals], [(None, "1"), ("2", "3")])
        self.assertEqual(row["affected_version_specifier"], "")
        self.assertEqual(row["fixed_version_specifier"], "")

    def test_reintroduction_does_not_claim_all_after_first_fix_are_safe(self) -> None:
        row = constraint(source("GHSA-A", [ecosystem(
            {"introduced": "0"}, {"fixed": "1"}, {"introduced": "2"})]))
        self.assertEqual(row["constraint_status"], "unsupported_multi_interval_release_set")
        self.assertEqual(row["fixed_version_specifier"], "")

    def test_overlapping_ranges_union_only_within_each_source(self) -> None:
        a = [ecosystem({"introduced": "1"}, {"fixed": "3"}),
             ecosystem({"introduced": "2"}, {"fixed": "4"})]
        b = [ecosystem({"introduced": "1.0"}, {"fixed": "4.0"})]
        row = constraint(source("GHSA-A", a), source("PYSEC-B", b))
        self.assertEqual(row["constraint_status"], "resolved")
        self.assertTrue(member(row, "3"))
        self.assertFalse(member(row, "4"))
        self.assertEqual({Version(value) for value in row["fixed_versions"]}, {Version("4")})

    def test_prerelease_postrelease_epoch_and_fixed_boundaries(self) -> None:
        for introduced, fixed, before, excluded in [
                ("1rc1", "2", "2rc1", "2"),
                ("1", "2rc2", "2rc1", "2rc2"),
                ("1", "2.post1", "2", "2.post1"),
                ("1!1", "1!2", "1!2.dev1", "1!2")]:
            with self.subTest(fixed=fixed):
                row = constraint(source("GHSA-A", [ecosystem(
                    {"introduced": introduced}, {"fixed": fixed})]))
                self.assertEqual(row["constraint_status"], "resolved")
                self.assertTrue(member(row, before))
                self.assertFalse(member(row, excluded))

    def test_last_affected_is_inclusive_and_not_a_fix(self) -> None:
        row = constraint(source("GHSA-A", [ecosystem(
            {"introduced": "1"}, {"last_affected": "2rc1"})]))
        self.assertTrue(member(row, "2rc1"))
        self.assertFalse(member(row, "2rc2"))
        self.assertEqual(row["fixed_versions"], [])
        self.assertEqual(row["fixed_version_specifier"], "")

    def test_limit_is_an_or_ceiling_and_never_a_fixed_release(self) -> None:
        row = constraint(source("GHSA-A", [ecosystem(
            {"introduced": "1"}, {"limit": "2"}, {"limit": "3"})]))
        self.assertTrue(member(row, "2.5"))
        self.assertFalse(member(row, "3"))
        self.assertEqual(row["fixed_version_specifier"], "")

    def test_unfixed_open_range_is_valid_without_inventing_fix(self) -> None:
        row = constraint(source("GHSA-A", [ecosystem({"introduced": "0"})]))
        self.assertEqual(row["constraint_status"], "resolved")
        self.assertTrue(member(row, "0.dev0"))
        self.assertTrue(member(row, "99"))
        self.assertEqual(row["fixed_version_specifier"], "")

    def test_empty_malformed_missing_intro_and_unsupported_domains(self) -> None:
        bad = [[], [ecosystem()], [ecosystem({"fixed": "2"})],
               [ecosystem({"introduced": "0", "fixed": "2"})],
               [ecosystem({"introduced": "0"}, {"fixed": "2"}, {"last_affected": "1"})],
               [ecosystem({"introduced": "garbage"}, {"fixed": "2"})],
               [ecosystem({"introduced": "1+private"}, {"fixed": "2"})],
               [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}],
               [ecosystem({"introduced": "0"}, {"fixed": "2"}), {"type": "UNKNOWN"}],
               ["malformed"]]
        for ranges in bad:
            with self.subTest(ranges=ranges):
                row = constraint(source("GHSA-A", ranges))
                self.assertNotEqual(row["constraint_status"], "resolved")
                self.assertEqual(row["affected_version_specifier"], "")

    def test_fixed_release_explicitly_affected_is_not_resolved(self) -> None:
        row = constraint(source("GHSA-A", [ecosystem(
            {"introduced": "0"}, {"fixed": "2"})], ["2"]))
        self.assertEqual(row["constraint_status"], "inconsistent_fixed_release_evidence")

    def test_source_order_and_alias_transitivity_preserve_identity_and_bytes(self) -> None:
        records = [source("GHSA-A", [ecosystem({"introduced": "0"}, {"fixed": "2"})]),
                   source("PYSEC-B", [ecosystem({"fixed": "2.0"}, {"introduced": "0"}), git_range()]),
                   source("CVE-C", [ecosystem({"introduced": "0"}, {"fixed": "2"})])]
        records[2]["identifiers"] = ["CVE-C", "PYSEC-B"]
        expected = build_identity_groups(records)
        for reordered in itertools.permutations(records):
            self.assertEqual(build_identity_groups(list(reordered)), expected)
        self.assertEqual(len(expected), 1)
        self.assertEqual(expected[0]["source_record_count"], 3)

    def test_persisted_analysis_cannot_override_actual_conflicting_sources(self) -> None:
        group = build_identity_groups([
            source("GHSA-A", [ecosystem({"introduced": "0"}, {"fixed": "2"})]),
            source("PYSEC-B", [ecosystem({"introduced": "0"}, {"fixed": "3"})])])[0]
        group["release_range_analysis"] = {"constraint_status": "resolved"}
        group["range_disagreement"] = False
        self.assertEqual(build_group_constraint(group)["constraint_status"], "source_range_disagreement")

    def test_missing_or_misbound_source_records_fail_closed(self) -> None:
        group = build_identity_groups([source("GHSA-A", [ecosystem({"introduced": "0"}, {"fixed": "2"})])])[0]
        for mutation in [{"source_records": []}, {"source_record_ids": ["WRONG"]},
                         {"source_record_count": 2}]:
            with self.subTest(mutation=mutation):
                altered = {**group, **mutation}
                row = build_group_constraint(altered)
                self.assertEqual(row["constraint_status"], "source_record_provenance_mismatch")
                self.assertEqual(row["affected_version_specifier"], "")

    def test_other_ecosystem_is_not_parsed_as_pypi(self) -> None:
        records = [source("GHSA-A", [ecosystem({"introduced": "0"}, {"fixed": "2"})])]
        groups = build_identity_groups(records, ecosystem="npm")
        row = resolve_catalog_constraints({"distribution": "example", "ecosystem": "npm",
                                           "vulnerability_groups": groups}, "example")
        self.assertEqual(row["vulnerabilities"][0]["constraint_status"], "unsupported_release_ecosystem")

    def test_normalizer_retains_git_and_hash_but_flags_silently_dropped_input(self) -> None:
        raw = {"id": "GHSA-A", "affected": [{"package": {"ecosystem": "PyPI", "name": "example"},
               "ranges": [ecosystem({"introduced": "0"}, {"fixed": "2"}), git_range(), None],
               "versions": ["1"]}]}
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "raw.json"
            path.write_text(json.dumps(raw))
            evidence = normalize_osv_vulnerability(raw_record=raw, raw_file=path,
                        sample_id="control", ecosystem="PyPI", distribution="example", queried_at=None)
        self.assertEqual(evidence["normalization_issues"], ["non_object_range"])
        self.assertEqual(evidence["fixed_commits"], ["a" * 40])
        self.assertTrue(evidence["source"]["evidence_hash"].startswith("sha256:"))
        row = resolve_normalized_osv_evidence("example", evidence)["vulnerabilities"][0]
        self.assertEqual(row["constraint_status"], "incomplete_normalized_evidence")


    def test_unresolved_constraint_remains_unknown_in_discrete_avcs(self) -> None:
        row = constraint(source("GHSA-A", [git_range()]))
        view = build_exposed_release_view({"sample_id": "s", "normalized_distribution": "example",
                    "confirmed_api_compatible_releases": [{"version": "1"}]},
                    {"vulnerabilities": [row]})
        evaluation = view["evaluations"][0]
        self.assertIsNone(evaluation["confirmed_exposed_release_count"])
        self.assertNotEqual(evaluation["status"], "resolved")

    def test_real_pillow_snapshot_regression_and_provenance(self) -> None:
        path = ROOT / "output/step7_osv_catalogs_v0/pillow.json"
        if not path.exists():
            self.skipTest("historical snapshot unavailable in this checkout")
        catalog = json.loads(path.read_text())
        group = next(g for g in catalog["vulnerability_groups"] if g["display_id"] == "GHSA-3c5c-7235-994j")
        original = copy.deepcopy(group)
        row = build_group_constraint(group)
        self.assertEqual(row["constraint_status"], "resolved")
        self.assertEqual(row["source_record_ids"], ["GHSA-3c5c-7235-994j", "PYSEC-2016-19"])
        self.assertEqual({e["evidence_hash"] for e in row["release_range_analysis"]["source_evidence"]},
                         {r["evidence_hash"] for r in group["source_records"]})
        self.assertEqual(group, original)
        self.assertTrue(member(row, "3.1.1rc1"))
        self.assertFalse(member(row, "3.1.1"))

    def test_every_resolved_historical_group_matches_independent_osv_evaluator(self) -> None:
        paths = sorted((ROOT / "output/step7_osv_catalogs_v0").glob("*.json"))
        if not paths:
            self.skipTest("historical snapshots unavailable in this checkout")
        evaluated = 0
        for path in paths:
            catalog = json.loads(path.read_text())
            for group in catalog["vulnerability_groups"]:
                row = build_group_constraint(group)
                if row["constraint_status"] != "resolved":
                    continue
                versions = {"0.dev0", "0", "99"}
                for record in group["source_records"]:
                    versions.update(record["affected_versions"])
                    for entry in record["affected_ranges"]:
                        if entry["type"] != "ECOSYSTEM":
                            continue
                        for event in entry["events"]:
                            value = next(iter(event.values()))
                            if value == "*":
                                continue
                            v = Version(value)
                            versions.add(str(v))
                            if not v.is_prerelease and not v.is_postrelease:
                                versions.update([v.base_version + suffix for suffix in [".dev0", "rc1", ".post1"]])
                for version in versions:
                    for record in group["source_records"]:
                        self.assertEqual(member(row, version), reference_affected(record, version),
                                         (path.stem, row["vulnerability_id"], record["source_record_id"], version))
                evaluated += 1
        self.assertGreater(evaluated, 0)

    def test_invalid_git_only_does_not_create_a_release_fix(self) -> None:
        row = analyze_sources([source("GHSA-A", [git_range()])])
        self.assertEqual(row["fixed_versions"], [])
        self.assertEqual(row["fixed_version_specifier"], "")


    def test_withdrawn_or_partial_evidence_cannot_be_promoted(self) -> None:
        record = source("GHSA-A", [ecosystem({"introduced": "0"}, {"fixed": "2"})])
        for change in [{"withdrawn": "2020-01-01T00:00:00Z"}, {"evidence_status": "partial"}]:
            row = constraint({**record, **change})
            self.assertNotEqual(row["constraint_status"], "resolved")
            self.assertEqual(row["affected_version_specifier"], "")

    def test_release_labels_survive_internal_zero_padding_normalization(self) -> None:
        row = constraint(source("GHSA-A", [ecosystem(
            {"introduced": "0"}, {"fixed": "2.0.0"})], ["1.0.0"]))
        self.assertEqual(row["fixed_versions"], ["2.0.0"])
        self.assertEqual(row["affected_versions"], ["1.0.0"])
        self.assertFalse(member(row, "2"))
        self.assertFalse(member(row, "2.0.0"))

    def test_empty_public_release_set_is_not_a_complete_resolved_negative(self) -> None:
        row = constraint(source("GHSA-A", [ecosystem(
            {"introduced": "0"}, {"fixed": "0.dev0"})]))
        self.assertEqual(row["constraint_status"], "empty_release_range")

    def test_legacy_interval_fallback_cannot_turn_new_exclusion_into_false_negative(self) -> None:
        row = constraint(source("GHSA-A", [ecosystem({"introduced": "0"}, {"fixed": "2"})]))
        result = intersect_simple_specifiers(">=1", row["affected_version_specifier"])
        self.assertEqual(result["status"], "unsupported_specifier")
        self.assertIsNone(result["has_overlap"])
        api = {"sample_id": "s", "distribution_constraints": [{
            "normalized_distribution": "example", "status": "resolved",
            "s_api": {"simplified_specifier": ">=1"}}], "call_constraints": []}
        constraints = {"distribution": "example", "vulnerabilities": [row]}
        with tempfile.TemporaryDirectory() as folder:
            api_path, constraint_path, exposure_path = [Path(folder) / name for name in
                                                        ["api.json", "constraint.json", "exposure.json"]]
            api_path.write_text(json.dumps(api))
            constraint_path.write_text(json.dumps(constraints))
            evaluation = evaluate_avcs(api_path, constraint_path)["evaluations"][0]
            self.assertEqual(evaluation["s_api"], ">=1")
            self.assertIsNone(evaluation["has_version_exposure"])
            self.assertEqual(evaluation["assessment"], "version_range_requires_review")
            # Existing discrete releases remain exact for both positive and
            # fixed-only cohorts; fallback uncertainty never becomes zero.
            for labels, expected in [(["1", "2rc1", "2"], 2), (["2"], 0)]:
                compatible = {"sample_id": "s", "distribution": "example",
                              "normalized_distribution": "example",
                              "confirmed_api_compatible_releases": [{"version": v} for v in labels]}
                exposure = build_exposed_release_view(compatible, constraints)
                exposure_path.write_text(json.dumps(exposure))
                evaluation = evaluate_avcs(api_path, constraint_path,
                                exposed_releases_path=exposure_path)["evaluations"][0]
                self.assertEqual(evaluation["confirmed_exposed_release_count"], expected)
                self.assertEqual(evaluation["has_version_exposure"], bool(expected))


if __name__ == "__main__":
    unittest.main()
