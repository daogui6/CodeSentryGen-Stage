"""Reprocess persisted OSV catalogs offline into a new, nonauthoritative directory."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

from packaging.specifiers import SpecifierSet
from packaging.version import InvalidVersion, Version

from build_osv_package_catalog import SCHEMA_VERSION, build_identity_groups
from normalizer import pep503_normalize
from resolve_osv_package_catalog_constraints import resolve_catalog_constraints
from run_step8_unified_avcs import exposed_releases_for_vulnerability

ROOT = Path(__file__).resolve().parents[1]


def read(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected object: {path}")
    return value


def write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
                    encoding="utf-8")


def binding(path: Path, root: Path) -> dict[str, Any]:
    data = path.read_bytes()
    return {"path": path.relative_to(root).as_posix(), "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "git_blob_sha": hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()}


def identifiers(row: dict[str, Any]) -> set[str]:
    return {str(value).lower() for value in [row.get("vulnerability_id", ""), *row.get("aliases", [])]
            if value}


def compare_kb(root: Path, constraints: dict[str, dict[str, Any]],
               inputs: dict[str, dict[str, Any]]) -> dict[str, Any]:
    packages: list[dict[str, Any]] = []
    for path in sorted((root / "data/avcs_package_kb").glob("*_package_kb_v0.json")):
        kb = read(path)
        inputs[path.relative_to(root).as_posix()] = binding(path, root)
        package = pep503_normalize(kb.get("normalized_distribution", kb["distribution"]))
        doc = constraints.get(package)
        rows: list[dict[str, Any]] = []
        releases: dict[str, dict[str, Any]] = {}
        history_paths = []
        for artifact in kb["release_history"]["artifacts"]:
            history = root / artifact["path"]
            if not history.exists():
                continue
            inputs[artifact["path"]] = binding(history, root)
            history_paths.append(artifact["path"])
            for release in read(history).get("confirmed_releases_as_of_time_view", []):
                try:
                    version = Version(release["version"])
                except (KeyError, InvalidVersion):
                    continue
                if version.local is None:
                    releases[str(version)] = release
        for vulnerability in kb["vulnerability_catalog"]:
            matches = [row for row in (doc or {}).get("vulnerabilities", [])
                       if identifiers(row) & identifiers(vulnerability)]
            result: dict[str, Any] = {
                "vulnerability_id": vulnerability["vulnerability_id"],
                "trigger_assessment_status": vulnerability["trigger_assessment"]["status"],
                "old_affected_specifiers": [row.get("version_specifier")
                                            for row in vulnerability["affected_ranges"]],
                "status": "historical_constraint_match_unavailable",
            }
            if len(matches) == 1:
                updated = matches[0]
                result.update(constraint_vulnerability_id=updated["vulnerability_id"],
                              new_constraint_status=updated["constraint_status"],
                              new_affected_specifier=updated["affected_version_specifier"],
                              source_record_ids=updated["source_record_ids"])
                if updated["constraint_status"] == "resolved":
                    result["status"] = "prospective_range_update_requires_scope_review"
                    prospective = copy.deepcopy(vulnerability)
                    prospective["affected_ranges"] = [{
                        "version_specifier": updated["affected_version_specifier"]}]
                    candidates = list(releases.values())
                    before, _ = exposed_releases_for_vulnerability(candidates, vulnerability)
                    after, _ = exposed_releases_for_vulnerability(candidates, prospective)
                    old_versions = {row["version"] for row in before}
                    new_versions = {row["version"] for row in after}
                    result.update(added_affected_release_versions=sorted(new_versions - old_versions, key=Version),
                                  removed_affected_release_versions=sorted(old_versions - new_versions, key=Version))
                else:
                    result["status"] = "prospective_unresolved_do_not_carry_forward_as_resolved"
            rows.append(result)
        present = set().union(*(identifiers(row) for row in kb["vulnerability_catalog"]))
        newly_supported = [row["vulnerability_id"] for row in (doc or {}).get("vulnerabilities", [])
                           if row["constraint_status"] == "resolved" and not identifiers(row) & present]
        packages.append({"package": package, "kb_path": path.relative_to(root).as_posix(),
                         "candidate_release_count": len(releases), "release_history_paths": history_paths,
                         "range_comparison_scope": "all_retained_public_releases_not_sample_feasible_sets",
                         "vulnerabilities": rows,
                         "resolved_catalog_groups_absent_from_kb": newly_supported})
    all_rows = [row for package in packages for row in package["vulnerabilities"]]
    return {"status": "IMPACT_ASSESSMENT_ONLY_NOT_KB_PROMOTION",
            "packages": packages,
            "vulnerability_count": len(all_rows),
            "status_counts": dict(Counter(row["status"] for row in all_rows)),
            "vulnerabilities_with_membership_delta": sum(bool(row.get("added_affected_release_versions")
                                                              or row.get("removed_affected_release_versions"))
                                                         for row in all_rows),
            "newly_resolved_groups_absent_from_kb": sum(
                len(package["resolved_catalog_groups_absent_from_kb"]) for package in packages),
            "historical_results_recomputed": False,
            "trigger_rules_reused_as_new_authority": False}


def run_audit(snapshot_root: Path, out_dir: Path, input_commit: str,
              expected_manifest: Path | None = None) -> dict[str, Any]:
    snapshot_root = snapshot_root.resolve()
    out_dir = out_dir.resolve()
    catalog_dir = snapshot_root / "output/step7_osv_catalogs_v0"
    paths = sorted(catalog_dir.glob("*.json"))
    if not paths:
        raise ValueError("No persisted historical catalogs found; live OSV acquisition is forbidden here")
    if len(input_commit) != 40 or any(ch not in "0123456789abcdef" for ch in input_commit):
        raise ValueError("input-commit must be a full immutable commit SHA")
    # Prevent both silent overwrites and output nested inside historical input directories.
    protected = [catalog_dir, snapshot_root / "output/step7_osv_constraints_v0",
                 snapshot_root / "data/avcs_package_kb", snapshot_root / "freeze_evidence",
                 snapshot_root / "provenance", snapshot_root / "config"]
    if any(out_dir == p or p in out_dir.parents or out_dir in p.parents for p in protected):
        raise ValueError("Output overlaps a protected historical input directory")
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ValueError("Output already exists; use a new versioned directory")
    if expected_manifest is not None:
        for entry in json.loads(expected_manifest.read_text()):
            expected_path = snapshot_root / entry["path"]
            actual = binding(expected_path, snapshot_root)
            if actual["git_blob_sha"] != entry.get("sha", entry.get("git_blob_sha")):
                raise ValueError(f"Input Git blob mismatch: {entry['path']}")
    inputs: dict[str, dict[str, Any]] = {}
    constraints: dict[str, dict[str, Any]] = {}
    comparisons: list[dict[str, Any]] = []
    identity: list[dict[str, Any]] = []
    before_statuses: Counter[str] = Counter()
    after_statuses: Counter[str] = Counter()
    classification_counts: Counter[str] = Counter()
    package_counts: list[dict[str, Any]] = []
    source_count = 0
    for path in paths:
        catalog = read(path)
        baseline_path = snapshot_root / "output/step7_osv_constraints_v0" / path.name
        baseline = read(baseline_path)
        for artifact in [path, baseline_path]:
            inputs[artifact.relative_to(snapshot_root).as_posix()] = binding(artifact, snapshot_root)
        original_groups = {g["group_id"]: g for g in catalog["vulnerability_groups"]}
        groups = build_identity_groups(catalog["normalized_records"], catalog["ecosystem"])
        if {g["group_id"] for g in groups} != set(original_groups):
            raise ValueError(f"Identity group drift: {path}")
        for group in groups:
            original = original_groups[group["group_id"]]
            for key in ["display_id", "identifiers", "source_record_ids", "source_record_count"]:
                if group[key] != original[key]:
                    raise ValueError(f"Identity/source drift: {path}:{group['display_id']}:{key}")
            if group["source_records"] != original["source_records"]:
                raise ValueError(f"Normalized source bytes/values drift: {path}:{group['display_id']}")
        rebuilt = {**catalog, "schema_version": SCHEMA_VERSION, "vulnerability_groups": groups}
        current = resolve_catalog_constraints(rebuilt, catalog["distribution"])
        package = pep503_normalize(catalog["distribution"])
        constraints[package] = current
        before_by_id = {row["identity_group_id"]: row for row in baseline["vulnerabilities"]}
        if set(before_by_id) != set(original_groups):
            raise ValueError(f"Baseline constraint identities do not match catalog: {path}")
        before = Counter(row["constraint_status"] for row in baseline["vulnerabilities"])
        after = Counter(row["constraint_status"] for row in current["vulnerabilities"])
        before_statuses.update(before)
        after_statuses.update(after)
        source_count += len(catalog["normalized_records"])
        package_counts.append({"package": package, "source_record_count": len(catalog["normalized_records"]),
                               "vulnerability_group_count": len(groups), "before": dict(before), "after": dict(after)})
        for row in current["vulnerabilities"]:
            previous = before_by_id[row["identity_group_id"]]
            classification = row["release_range_analysis"]["classification"]
            if previous["constraint_status"] == "source_range_disagreement":
                classification_counts[classification] += 1
            fields = ["constraint_status", "affected_version_specifier", "fixed_version_specifier",
                      "fixed_versions", "affected_versions"]
            comparisons.append({"package": package, "vulnerability_id": row["vulnerability_id"],
                                "identity_group_id": row["identity_group_id"],
                                "source_record_ids": row["source_record_ids"],
                                "classification": classification,
                                "changed_fields": [key for key in fields if row[key] != previous[key]],
                                "before": {key: previous[key] for key in fields},
                                "after": {key: row[key] for key in fields},
                                "source_evidence": [
                                    {key: evidence[key] for key in ["source_record_id", "source_url", "evidence_hash",
                                     "status", "release_intervals", "affected_release_intervals",
                                     "mapped_versions_outside_release_ranges", "supplemental_range_types"]}
                                    for evidence in row["release_range_analysis"]["source_evidence"]]})
        identity.append({"package": package, "groups": [
            {key: group[key] for key in ["group_id", "display_id", "identifiers", "source_record_ids"]}
            for group in groups]})
    historical_path = snapshot_root / "output/step7_python_11pkg_osv_summary_v0.json"
    historical = read(historical_path)
    constraint_summary_path = snapshot_root / "output/step7_python_11pkg_constraint_summary_v0.json"
    historical_constraints = read(constraint_summary_path)
    for path in [historical_path, constraint_summary_path]:
        inputs[path.relative_to(snapshot_root).as_posix()] = binding(path, snapshot_root)
    missing = [row for row in historical["packages"]
               if pep503_normalize(row["package"]) not in constraints]
    kb_impact = compare_kb(snapshot_root, constraints, inputs)
    summary = {
        "schema_version": "osv_multisource_snapshot_audit_v1",
        "status": "SCOPED_REPAIR_VALIDATED_FULL_BASELINE_INCOMPLETE" if missing else "SCOPED_REPAIR_VALIDATED",
        "input_commit": input_commit, "provider_calls_made_by_audit": 0,
        "live_osv_queries_made": 0, "processing_mode": "remerge_persisted_normalized_sources",
        "historical_frozen_outputs_overwritten": False,
        "package_count_audited": len(constraints), "source_record_count": source_count,
        "vulnerability_identity_group_count": len(comparisons),
        "identity_and_source_records_unchanged": True,
        "before": {"resolved": before_statuses["resolved"],
                   "unresolved": len(comparisons) - before_statuses["resolved"], "statuses": dict(before_statuses)},
        "after": {"resolved": after_statuses["resolved"],
                  "unresolved": len(comparisons) - after_statuses["resolved"], "statuses": dict(after_statuses)},
        "historical_range_disagreement_reclassification": dict(classification_counts),
        "historical_range_disagreement_count_audited": sum(classification_counts.values()),
        "baseline_summary": historical_constraints,
        "baseline_osv_summary_counts": {key: historical[key] for key in [
            "package_count", "total_source_records", "total_vulnerability_groups", "total_range_disagreement_groups"]},
        "missing_historical_package_details": missing,
        "status_changed_group_count": sum(row["before"]["constraint_status"] != row["after"]["constraint_status"]
                                          for row in comparisons),
        "package_counts": package_counts,
        "kb_impact_summary": {key: value for key, value in kb_impact.items() if key != "packages"},
        "full_original_raw_records_available": False,
        "raw_provenance_note": "Historical catalogs retain normalized sources and original raw SHA-256 claims; "
                               "untracked raw cache files are not fabricated or fetched from live OSV.",
    }
    for package, doc in constraints.items():
        write(out_dir / "constraints" / f"{package}.json", doc)
    write(out_dir / "summary.json", summary)
    write(out_dir / "comparison.json", comparisons)
    write(out_dir / "identity_groups.json", identity)
    write(out_dir / "kb_impact.json", kb_impact)
    write(out_dir / "input_manifest.json", sorted(inputs.values(), key=lambda row: row["path"]))
    implementation_files = ["src/audit_osv_multisource_snapshot.py", "src/osv_pypi_release_ranges.py",
                            "src/build_osv_package_catalog.py", "src/resolve_osv_package_catalog_constraints.py",
                            "src/resolve_vulnerability_constraints.py", "src/normalize_osv_vulnerability.py",
                            "src/run_step8_unified_avcs.py"]
    write(out_dir / "reproducer_manifest.json", {
        "input_commit": input_commit, "status": "PROSPECTIVE_NONAUTHORITATIVE_DATA_CORRECTION",
        "implementation_files": [binding(ROOT / name, ROOT) for name in implementation_files],
        "outputs": [binding(path, out_dir) for path in sorted(out_dir.rglob("*.json"))],
        "reproduction": "python src/audit_osv_multisource_snapshot.py --snapshot-root <immutable-input-checkout> "
                        "--input-commit " + input_commit + " --out-dir <new-empty-directory>",
    })
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot-root", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--input-commit", required=True)
    parser.add_argument("--input-manifest", type=Path)
    args = parser.parse_args()
    summary = run_audit(args.snapshot_root, args.out_dir, args.input_commit, args.input_manifest)
    print(json.dumps({key: summary[key] for key in ["status", "source_record_count", "vulnerability_identity_group_count",
                    "before", "after", "historical_range_disagreement_reclassification"]}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
