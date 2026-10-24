from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from extract_api_calls import extract_api_calls
from freeze_hash_v1 import (
    canonical_sha256_file,
    hash_matches,
    verify_hash as verify_canonical_hash,
)
from normalizer import pep503_normalize
from avcs_curated_scope_v1 import (
    DEFAULT_CURATED_SCOPE,
    classify_candidates,
    load_curated_scope,
)
from package_identity_v1 import (
    DEFAULT_POLICY as DEFAULT_IDENTITY_POLICY,
    PackageIdentityService,
    identity_has_unresolved_local_context,
    is_avcs_candidate_identity,
)
from project_dependency_facts_v1 import (
    FACTS_SCHEMA_VERSION,
    collect_project_dependency_facts,
)
from sceg_ir_v21 import (
    api_call_evidence_for_sample,
    distributions_for_sample,
    project_dependency_facts_for_sample,
    sample_context_for_sample,
    read_json as read_sceg_json,
    verify_ir as verify_sceg_ir,
)
from resolve_api_version_constraints import resolve_api_version_constraints
from risk_semantics_v21 import (
    FORMAL_MAIN_RISK_TYPES,
    avcs_formal_risk_view_eligible,
)
from scientific_contract_v1 import (
    build_avcs_output_contract,
    build_avcs_resume_input,
)
from resolve_avcs_manifest_constraints import (
    lockfile_declared_distributions,
    resolve_manifest_constraints,
)
from run_avcs_trigger_matcher import match_trigger_entry
from time_contract_v1 import (
    parse_aware_utc,
    validate_generation_knowledge,
    validate_release_snapshot_timeline,
    vulnerability_knowledge_status_at_cutoff,
)
from time_view_contract_v1 import (
    FORMAL_TIME_VIEW_IDS,
    build_legacy_time_view_marker,
    build_time_view_contract,
    formal_generation_metric_eligible,
    validate_time_view_contract,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_KB_DIR = ROOT / "data/avcs_package_kb"
DEFAULT_MAPPING = ROOT / "config/import_mapping.json"
DEFAULT_THRESHOLD_POLICY = ROOT / "config/step8_avcs_threshold_policy_v2_f10_exposure_prerequisite.json"
DEFAULT_FREEZE_REPORT = (
    ROOT
    / "output/step7_batch_review_v0/step7_freeze_v1/step7_freeze_report.json"
)


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return value


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8-sig") as handle:
        for line_no, raw in enumerate(handle, 1):
            text = raw.strip()
            if not text:
                continue
            value = json.loads(text)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_no}: expected JSON object")
            rows.append(value)
    return rows


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def rel(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def sha256_file(path: Path) -> str:
    return canonical_sha256_file(path)


def load_release_snapshot_manifest(
    path: Path | None,
) -> dict[str, dict[str, Any]]:
    if path is None:
        return {}
    manifest = read_json(path)
    if manifest.get("status") != "FROZEN":
        raise ValueError("AVCS release snapshot manifest is not FROZEN")
    packages = manifest.get("packages", {})
    if not isinstance(packages, dict) or not packages:
        raise ValueError("AVCS release snapshot manifest has no packages")

    verified: dict[str, dict[str, Any]] = {}
    timeline_artifacts: dict[str, dict[str, Any]] = {}
    for raw_name, raw_entry in packages.items():
        normalized = pep503_normalize(str(raw_name))
        if not normalized or not isinstance(raw_entry, dict):
            raise ValueError("Invalid AVCS release snapshot manifest entry")
        artifact_text = str(raw_entry.get("path", "")).strip()
        expected_sha = str(raw_entry.get("sha256", "")).strip()
        if not artifact_text or not expected_sha:
            raise ValueError(
                f"Release snapshot entry incomplete for {raw_name}"
            )
        artifact = ROOT / artifact_text
        if not artifact.exists():
            raise FileNotFoundError(artifact)
        actual_sha = sha256_file(artifact)
        if not hash_matches(
            artifact,
            expected_sha,
            legacy_eol_compatible=True,
        ):
            raise ValueError(
                f"Release snapshot hash drift for {normalized}: "
                f"expected={expected_sha} actual={actual_sha}"
            )
        timeline_artifacts[normalized] = read_json(artifact)

        for path_key, sha_key, label in [
            ("raw_pypi_path", "raw_pypi_sha256", "raw PyPI snapshot"),
            ("package_kb_path", "package_kb_sha256", "Package KB"),
        ]:
            bound_path_text = str(raw_entry.get(path_key, "")).strip()
            bound_sha = str(raw_entry.get(sha_key, "")).strip()
            if bool(bound_path_text) != bool(bound_sha):
                raise ValueError(
                    f"Incomplete {label} hash binding for {normalized}"
                )
            if bound_path_text:
                bound_path = ROOT / bound_path_text
                if not bound_path.exists():
                    raise FileNotFoundError(bound_path)
                actual_bound_sha = sha256_file(bound_path)
                if not hash_matches(
                    bound_path,
                    bound_sha,
                    legacy_eol_compatible=True,
                ):
                    raise ValueError(
                        f"{label} hash drift for {normalized}: "
                        f"expected={bound_sha} actual={actual_bound_sha}"
                    )

        verified[normalized] = {
            **copy.deepcopy(raw_entry),
            "path": artifact_text,
            "sha256": actual_sha,
        }

    validate_release_snapshot_timeline(
        manifest,
        artifacts=timeline_artifacts,
        label=f"release_snapshot:{path}",
    )
    return verified


def parse_time(value: Any) -> datetime | None:
    # Optional historical evidence remains tri-state. Naive timestamps are
    # not silently repaired to UTC; required formal callers fail closed.
    return parse_aware_utc(value)


def time_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def verify_step7_freeze(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(
            f"Step7 freeze report not found: {path}. "
            "Step8 must not run before Step7 is frozen."
        )

    report = read_json(path)

    if report.get("freeze_status") != "PASS":
        raise ValueError("Step7 freeze report is not PASS")
    if report.get("step7_frozen") is not True:
        raise ValueError("Step7 freeze report does not authorize a frozen input")
    if report.get("step8_authorized") is not True:
        raise ValueError("Step7 freeze report does not authorize Step8")
    if report.get("step8_started") is not False:
        raise ValueError(
            "Frozen Step7 report unexpectedly says Step8 had already started"
        )

    required_gates = (
        "all_package_kb_validators",
        "zero_not_assessed",
        "zero_review_required",
        "final_status_vocabulary",
        "eligible_rule_ref_integrity",
        "batch004_full56_formal_sync",
        "historical_unresolved_closure",
        "final_exact_byte_promotion",
    )
    gates = report.get("gates", {})
    for gate in required_gates:
        if gates.get(gate) != "PASS":
            raise ValueError(f"Step7 freeze gate is not PASS: {gate}")

    return report


def load_threshold_policy(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Threshold policy not found: {path}")

    policy = read_json(path)
    status = str(policy.get("status", "")).strip()

    if status not in {"not_frozen", "frozen"}:
        raise ValueError(
            "Threshold policy status must be 'not_frozen' or 'frozen'"
        )

    theta_reduce = policy.get("theta_reduce")
    theta_expose = policy.get("theta_expose")

    if status == "frozen":
        for name, value in [
            ("theta_reduce", theta_reduce),
            ("theta_expose", theta_expose),
        ]:
            if not isinstance(value, (int, float)):
                raise ValueError(
                    f"Frozen threshold policy requires numeric {name}"
                )
            if not (0.0 <= float(value) <= 1.0):
                raise ValueError(f"Frozen {name} must be in [0,1]")

    return policy


def api_interval_quality_gate(
    threshold_policy: dict[str, Any],
) -> dict[str, Any]:
    raw = threshold_policy.get("api_interval_manual_validation", {})
    if not isinstance(raw, dict):
        raw = {}

    status = str(raw.get("status", "not_frozen")).strip()
    minimum = raw.get("minimum_accuracy")
    observed = raw.get("observed_accuracy")
    sample_manifest = raw.get("sample_manifest")

    passed = (
        status == "frozen"
        and isinstance(minimum, (int, float))
        and isinstance(observed, (int, float))
        and 0.0 <= float(minimum) <= 1.0
        and 0.0 <= float(observed) <= 1.0
        and float(observed) >= float(minimum)
        and bool(str(sample_manifest or "").strip())
    )

    return {
        "status": status,
        "minimum_accuracy": minimum,
        "observed_accuracy": observed,
        "sample_manifest": sample_manifest,
        "passed": passed,
    }


def api_induced_gate_decision(
    *,
    api_status: str,
    interval_quality_passed: bool,
    fixed_excluded: bool | None,
    threshold_pair_passed: bool,
    vulnerable_exposure_present: bool,
) -> dict[str, Any]:
    """Apply the advisor-confirmed F-10 rule with its reporting prerequisite.

    Mandatory prerequisite:
      V_exposed = V_feasible_after_API ∩ V_affected must be non-empty.

    After that prerequisite is satisfied:
      A = Reduction/ExposureRatio threshold pair.
      B = FixedExcluded.
      C = frozen global API-interval manual-validation quality gate.
      Formal API-induced reporting uses C AND (A OR B).

    C is a global quality prerequisite, not case-level causal evidence.
    FixedExcluded cannot create a vulnerability finding when the current
    API-compatible feasible set contains no affected release.
    """
    exposure_prerequisite_passed = vulnerable_exposure_present is True
    quality_gate_passed = (
        api_status == "resolved"
        and interval_quality_passed is True
    )

    if fixed_excluded is True:
        case_branch = "fixed_excluded"
    elif threshold_pair_passed:
        case_branch = "reduction_exposure_threshold_pair"
    else:
        case_branch = None

    passed = (
        exposure_prerequisite_passed
        and quality_gate_passed
        and case_branch is not None
    )
    return {
        "policy": "C_AND_(A_OR_B)",
        "formal_reporting_rule": "V_EXPOSED_NONEMPTY_AND_C_AND_(A_OR_B)",
        "passed": passed,
        "vulnerable_exposure_prerequisite_passed": (
            exposure_prerequisite_passed
        ),
        "global_quality_gate_passed": quality_gate_passed,
        "case_level_branch_passed": case_branch is not None,
        "case_level_branch": case_branch,
        "sufficient_condition": (
            "vulnerable_exposure_and_api_interval_quality_and_" + case_branch
            if passed and case_branch is not None
            else None
        ),
    }


def manifest_declared_distributions(sample: dict[str, Any] | None) -> list[str]:
    if sample is None:
        return []

    requirements_text = str(sample.get("requirements_text", "") or "")
    result: set[str] = set()

    for raw_line in requirements_text.splitlines():
        line = raw_line.strip().lstrip("\ufeff")
        if not line or line.startswith("#") or line.startswith("-"):
            continue

        line = line.split("#", 1)[0].strip()
        if not line:
            continue

        try:
            requirement = Requirement(line)
        except InvalidRequirement:
            continue

        normalized = pep503_normalize(requirement.name)
        if normalized:
            result.add(normalized)

    return sorted(result)


def select_sample(path: Path | None, sample_id: str) -> dict[str, Any] | None:
    if path is None:
        return None
    matches = [
        row
        for row in read_jsonl(path)
        if str(row.get("sample_id", "")) == sample_id
    ]
    if len(matches) != 1:
        raise ValueError(
            f"Expected exactly one sample_id={sample_id!r} in {path}, got {len(matches)}"
        )
    return matches[0]


def verify_declared_kb_artifact_hashes(
    value: Any,
    *,
    kb_path: Path,
    trail: str = "root",
) -> None:
    """Verify every local Package-KB artifact that declares path+sha256.

    Historical KB hashes may have been produced on Windows/CRLF, so the
    compatibility rule is restricted to line-ending equivalence only.
    """
    if isinstance(value, dict):
        path_text = str(value.get("path", "") or "").strip()
        digest = str(value.get("sha256", "") or "").strip()
        if path_text and digest:
            artifact = ROOT / path_text
            verify_canonical_hash(
                artifact,
                digest,
                label=(
                    f"Package KB artifact {kb_path.name}:{trail}"
                ),
                legacy_eol_compatible=True,
            )

        for key, child in value.items():
            verify_declared_kb_artifact_hashes(
                child,
                kb_path=kb_path,
                trail=f"{trail}.{key}",
            )
        return

    if isinstance(value, list):
        for index, child in enumerate(value):
            verify_declared_kb_artifact_hashes(
                child,
                kb_path=kb_path,
                trail=f"{trail}[{index}]",
            )


def load_package_kbs(kb_dir: Path) -> dict[str, tuple[Path, dict[str, Any]]]:
    result: dict[str, tuple[Path, dict[str, Any]]] = {}
    for path in sorted(kb_dir.glob("*_package_kb_v0.json")):
        kb = read_json(path)
        verify_declared_kb_artifact_hashes(
            kb,
            kb_path=path,
        )
        normalized = pep503_normalize(
            str(kb.get("normalized_distribution") or kb.get("distribution") or "")
        )
        if not normalized:
            raise ValueError(f"Package KB has no distribution: {path}")
        if normalized in result:
            raise ValueError(f"Duplicate Package KB for {normalized}")
        result[normalized] = (path, kb)
    if not result:
        raise ValueError(f"No Package KB files found under {kb_dir}")
    return result


def resolve_requested_time(
    *,
    explicit_time: str | None,
    sample: dict[str, Any] | None,
    release_history: dict[str, Any],
    authoritative_time: str | None = None,
    authoritative_time_source: str | None = None,
) -> tuple[datetime, str]:
    if authoritative_time is not None:
        parsed = parse_time(authoritative_time)
        if parsed is None:
            raise ValueError(
                f"Invalid authoritative time view: {authoritative_time!r}"
            )
        return (
            parsed,
            authoritative_time_source
            or "authoritative_generation_time",
        )

    if explicit_time:
        parsed = parse_time(explicit_time)
        if parsed is None:
            raise ValueError(f"Invalid --time-view: {explicit_time!r}")
        return parsed, "explicit"

    if sample is not None:
        for key in ("generation_time", "gen_time"):
            parsed = parse_time(sample.get(key))
            if parsed is not None:
                return parsed, f"sample.{key}"

    artifact_time = parse_time(release_history.get("time_view"))
    if artifact_time is None:
        raise ValueError(
            "No usable time view: provide --time-view or sample generation_time"
        )
    return artifact_time, "release_history_artifact_fallback"


def derive_release_history_view(
    *,
    release_history: dict[str, Any],
    requested_time: datetime,
    requested_time_source: str,
) -> dict[str, Any]:
    artifact_time = parse_time(release_history.get("time_view"))
    if artifact_time is None:
        raise ValueError("Release history artifact has invalid time_view")

    confirmed = release_history.get("confirmed_releases_as_of_time_view", [])
    if not isinstance(confirmed, list):
        confirmed = []

    snapshot_covers_requested_time = requested_time <= artifact_time

    if snapshot_covers_requested_time:
        selected = []
        for row in confirmed:
            if not isinstance(row, dict):
                continue
            upload = parse_time(row.get("first_upload_time"))
            if upload is not None and upload <= requested_time:
                selected.append(copy.deepcopy(row))
        status = "snapshot_covers_requested_time"
    else:
        selected = [
            copy.deepcopy(row)
            for row in confirmed
            if isinstance(row, dict)
        ]
        status = "artifact_older_than_requested_time"

    source_status = str(
        release_history.get("release_history_status", "")
    ).strip().lower()
    missing_file_evidence_raw = release_history.get(
        "release_count_without_file_evidence"
    )
    if isinstance(missing_file_evidence_raw, int):
        release_evidence_complete = missing_file_evidence_raw == 0
        completeness_source = "release_count_without_file_evidence"
    else:
        release_evidence_complete = source_status in {"resolved", "complete"}
        completeness_source = "release_history_status"

    knowledge_complete = (
        snapshot_covers_requested_time and release_evidence_complete
    )

    result = copy.deepcopy(release_history)
    result["source_time_view"] = release_history.get("time_view")
    result["time_view"] = time_text(requested_time)
    result["requested_time_source"] = requested_time_source
    result["online_time_view_status"] = status
    result["snapshot_covers_requested_time"] = snapshot_covers_requested_time
    result["source_release_history_status"] = source_status or None
    result["release_evidence_complete"] = release_evidence_complete
    result["release_evidence_completeness_source"] = completeness_source
    result["knowledge_complete_to_requested_time"] = knowledge_complete
    result["confirmed_releases_as_of_time_view"] = selected
    result["confirmed_release_count_as_of_time_view"] = len(selected)
    result["latest_confirmed_version_as_of_time_view"] = (
        selected[-1].get("version") if selected else None
    )
    return result


def release_artifact_path(kb: dict[str, Any]) -> Path:
    artifacts = kb.get("release_history", {}).get("artifacts", [])
    paths = [
        str(row.get("path", "")).strip()
        for row in artifacts
        if isinstance(row, dict) and str(row.get("path", "")).strip()
    ]
    if len(paths) != 1:
        raise ValueError(
            f"Expected exactly one release-history artifact for {kb.get('distribution')}, got {paths}"
        )
    path = ROOT / paths[0]
    if not path.exists():
        raise FileNotFoundError(path)
    return path


def build_api_history_adapter(kb: dict[str, Any]) -> dict[str, Any]:
    distribution = str(kb.get("distribution", ""))
    source_history = kb.get("api_surface_history")
    if not isinstance(source_history, dict):
        source_history = {}
    source_status = str(
        source_history.get("status") or "not_provided"
    )
    source_scope_policy = str(
        source_history.get("scope_policy") or ""
    )

    proof_index: dict[str, dict[str, Any]] = {}
    for artifact in source_history.get("artifacts", []):
        if not isinstance(artifact, dict):
            continue
        artifact_path_text = str(artifact.get("path", "")).strip()
        if not artifact_path_text:
            continue
        artifact_path = ROOT / artifact_path_text
        if not artifact_path.exists():
            continue
        evidence = read_json(artifact_path)
        for entry in evidence.get("entries", []):
            if not isinstance(entry, dict):
                continue
            for rule in entry.get("version_rules", []):
                if not isinstance(rule, dict):
                    continue
                rule_id = str(rule.get("rule_id", "")).strip()
                if rule_id:
                    proof_index[rule_id] = rule

    entries = []
    for row in source_history.get("entries", []):
        if not isinstance(row, dict):
            continue
        item = copy.deepcopy(row)
        item["distribution"] = distribution
        item["normalized_distribution"] = pep503_normalize(distribution)

        enriched_rules = []
        for rule in item.get("version_rules", []):
            if not isinstance(rule, dict):
                continue
            enriched = copy.deepcopy(rule)
            rule_id = str(enriched.get("rule_id", "")).strip()
            proof = proof_index.get(rule_id, {})
            derivation = proof.get("derivation", {})
            if not isinstance(derivation, dict):
                derivation = {}
            coverage = derivation.get("coverage", {})
            if not isinstance(coverage, dict):
                coverage = {}
            state_summary = derivation.get("release_state_summary", {})
            if not isinstance(state_summary, dict):
                state_summary = {}

            unknown_count = state_summary.get("unknown_count")
            specifier_exclusion_safe = (
                str(derivation.get("status", "")) == "resolved"
                and coverage.get("coverage_complete") is True
                and unknown_count == 0
            )

            exclusion_semantics: dict[str, Any]
            if specifier_exclusion_safe:
                exclusion_semantics = {
                    "status": "proven_false_outside_specifier",
                    "coverage_complete": True,
                    "coverage_scope": coverage.get("coverage_scope"),
                    "include_prereleases": coverage.get(
                        "include_prereleases"
                    ),
                    "unknown_count": unknown_count,
                    "proof_source": str(
                        proof.get("evidence_ref")
                        or enriched.get("evidence_ref")
                        or ""
                    ),
                    "false_versions": [],
                    "unknown_versions": [],
                }
            else:
                evidence_ref = str(
                    enriched.get("evidence_ref", "")
                ).strip()
                evidence_path = ROOT / evidence_ref if evidence_ref else None
                exact_state_evidence: dict[str, Any] | None = None
                if evidence_path is not None and evidence_path.exists():
                    candidate = read_json(evidence_path)
                    if (
                        str(candidate.get("schema_version", "")).startswith(
                            "avcs_python_api_symbol_release_history_refined_"
                        )
                        and str(candidate.get("api_symbol", "")).strip()
                        == str(item.get("api_symbol", "")).strip()
                        and isinstance(candidate.get("records"), list)
                    ):
                        exact_state_evidence = candidate

                if exact_state_evidence is not None:
                    false_versions = sorted(
                        {
                            str(record.get("version", "")).strip()
                            for record in exact_state_evidence.get(
                                "records", []
                            )
                            if isinstance(record, dict)
                            and record.get("support_status") == "unsupported"
                            and str(record.get("version", "")).strip()
                        },
                        key=Version,
                    )
                    unknown_versions = sorted(
                        {
                            str(record.get("version", "")).strip()
                            for record in exact_state_evidence.get(
                                "records", []
                            )
                            if isinstance(record, dict)
                            and record.get("support_status") == "unknown"
                            and str(record.get("version", "")).strip()
                        },
                        key=Version,
                    )
                    exclusion_semantics = {
                        "status": "explicit_release_states",
                        "coverage_complete": (
                            int(
                                exact_state_evidence.get(
                                    "unknown_count", -1
                                )
                            )
                            == 0
                        ),
                        "coverage_scope": "recorded_release_states_only",
                        "include_prereleases": None,
                        "unknown_count": exact_state_evidence.get(
                            "unknown_count"
                        ),
                        "proof_source": evidence_ref,
                        "false_versions": false_versions,
                        "unknown_versions": unknown_versions,
                        "recorded_release_count": exact_state_evidence.get(
                            "release_count"
                        ),
                        "supported_count": exact_state_evidence.get(
                            "supported_count"
                        ),
                        "unsupported_count": exact_state_evidence.get(
                            "unsupported_count"
                        ),
                    }
                else:
                    exclusion_semantics = {
                        "status": "unknown_outside_specifier",
                        "coverage_complete": False,
                        "coverage_scope": coverage.get("coverage_scope"),
                        "include_prereleases": coverage.get(
                            "include_prereleases"
                        ),
                        "unknown_count": unknown_count,
                        "proof_source": str(
                            proof.get("evidence_ref")
                            or enriched.get("evidence_ref")
                            or ""
                        ),
                        "false_versions": [],
                        "unknown_versions": [],
                    }

            enriched["exclusion_semantics"] = exclusion_semantics
            enriched_rules.append(enriched)

        item["version_rules"] = enriched_rules
        entries.append(item)

    return {
        "schema_version": "step8_package_kb_api_history_adapter_v0.4",
        "ecosystem": kb.get("ecosystem", "pypi"),
        "source_kb_id": kb.get("kb_id"),
        # F-15 step 1: preserve the Package-KB scope contract at the adapter
        # boundary.  "resolved" applies only to the declared scope_policy;
        # it must never be read as package-wide API completeness.
        "status": source_status,
        "scope_policy": source_scope_policy,
        "entry_count": len(entries),
        "scope_semantics": {
            "status_scope": "declared_scope_policy",
            "resolved_does_not_imply_package_wide_coverage": True,
        },
        "entries": entries,
        "scientific_boundary": {
            "source_scope_metadata_preserved": True,
            "resolved_status_is_scope_local": True,
            "specifier_excludes_only_with_complete_zero_unknown_proof": True,
            "explicit_release_state_false_can_exclude_that_release": True,
            "missing_or_unknown_release_state_does_not_exclude": True,
            "coverage_outside_rule_scope_remains_unknown": True,
        },
    }


def filter_api_call_evidence(
    evidence: dict[str, Any],
    normalized_distribution: str,
) -> dict[str, Any]:
    result = copy.deepcopy(evidence)
    calls = [
        row
        for row in evidence.get("api_calls", [])
        if isinstance(row, dict)
        and pep503_normalize(str(row.get("distribution", "")))
        == normalized_distribution
    ]
    result["api_calls"] = calls
    result["api_call_count"] = len(calls)
    result["binding_unresolved"] = [
        copy.deepcopy(row) for row in evidence.get("binding_unresolved", [])
        if isinstance(row, dict) and (row.get("unresolved_scope") == "sample" or normalized_distribution in {
            pep503_normalize(str(value)) for value in row.get("candidate_distributions", [])
        })
    ]
    return result


def find_distribution_constraint(
    api_constraints: dict[str, Any],
    normalized_distribution: str,
) -> dict[str, Any] | None:
    matches = [
        row
        for row in api_constraints.get("distribution_constraints", [])
        if isinstance(row, dict)
        and pep503_normalize(str(row.get("normalized_distribution", "")))
        == normalized_distribution
    ]
    if len(matches) > 1:
        raise ValueError(
            f"Multiple API distribution constraints for {normalized_distribution}"
        )
    return matches[0] if matches else None


def constraint_specifier(
    distribution_constraint: dict[str, Any] | None,
) -> str:
    if distribution_constraint is None:
        return ""
    s_api = distribution_constraint.get("s_api", {})
    if not isinstance(s_api, dict):
        return ""
    return str(
        s_api.get("simplified_specifier")
        or s_api.get("raw_specifier")
        or ""
    ).strip()


def filter_releases_by_specifier(
    releases: list[dict[str, Any]],
    specifier_text: str,
) -> list[dict[str, Any]]:
    if not specifier_text:
        return [copy.deepcopy(row) for row in releases]

    try:
        specifier = SpecifierSet(specifier_text)
    except InvalidSpecifier as exc:
        raise ValueError(f"Invalid version specifier {specifier_text!r}: {exc}") from exc

    result = []
    for row in releases:
        version_text = str(row.get("version", "")).strip()
        try:
            version = Version(version_text)
        except InvalidVersion:
            continue
        if specifier.contains(version, prereleases=True):
            result.append(copy.deepcopy(row))
    return result


def specifier_explicitly_allows_prerelease(specifier_text: str) -> bool:
    text = str(specifier_text or "").strip()
    if not text:
        return False

    for raw_part in text.split(","):
        part = raw_part.strip()
        match = re.search(
            r"(?:===|==|~=|!=|<=|>=|<|>)\s*([^,;\s]+)",
            part,
        )
        if match is None:
            continue
        version_text = match.group(1).strip()
        if version_text.endswith(".*"):
            version_text = version_text[:-2]
        try:
            if Version(version_text).is_prerelease:
                return True
        except InvalidVersion:
            continue

    return False


def manifest_requests_prereleases(manifest: dict[str, Any]) -> bool:
    status = str(manifest.get("status", ""))
    if status != "resolved":
        return False

    kind = str(manifest.get("constraint_kind", ""))
    specifier = str(manifest.get("specifier", "")).strip()

    if kind not in {"version_specifier", "lockfile_exact_pin"}:
        return False

    return specifier_explicitly_allows_prerelease(specifier)


def apply_default_prerelease_policy(
    releases: list[dict[str, Any]],
    manifest: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if manifest_requests_prereleases(manifest):
        return [copy.deepcopy(row) for row in releases], {
            "mode": "explicit_prerelease_constraint_preserved",
            "prereleases_included": True,
            "excluded_prerelease_count": 0,
        }

    kept: list[dict[str, Any]] = []
    excluded_count = 0

    for row in releases:
        version_text = str(row.get("version", "")).strip()
        try:
            is_prerelease = Version(version_text).is_prerelease
        except InvalidVersion:
            # Invalid/unknown versions remain conservative rather than being
            # silently excluded by resolver policy.
            kept.append(copy.deepcopy(row))
            continue

        if is_prerelease:
            excluded_count += 1
            continue

        kept.append(copy.deepcopy(row))

    return kept, {
        "mode": "default_stable_release_policy",
        "prereleases_included": False,
        "excluded_prerelease_count": excluded_count,
    }


def solve_manifest_before_api(
    releases: list[dict[str, Any]],
    manifest: dict[str, Any],
) -> tuple[list[dict[str, Any]], str]:
    status = str(manifest.get("status", "not_provided"))
    kind = str(manifest.get("constraint_kind", "not_provided"))
    specifier = str(manifest.get("specifier", "")).strip()

    if (
        status == "resolved"
        and kind in {"version_specifier", "lockfile_exact_pin"}
        and specifier
    ):
        return filter_releases_by_specifier(
            releases,
            specifier,
        ), (
            "lockfile_exact_pin_applied"
            if kind == "lockfile_exact_pin"
            else "manifest_specifier_applied"
        )

    if status in {"resolved", "not_declared", "not_provided"}:
        return [copy.deepcopy(row) for row in releases], "no_restrictive_constraint"

    return [copy.deepcopy(row) for row in releases], "unknown_not_excluding"


def _release_is_explicitly_yanked(release: dict[str, Any]) -> bool:
    """Return True only when the release evidence explicitly says yanked."""
    if release.get("yanked") is True:
        return True
    if release.get("all_files_yanked") is True:
        return True

    status = str(
        release.get("release_status")
        or release.get("status")
        or ""
    ).strip().lower()
    if status in {"yanked", "all_files_yanked"}:
        return True

    files = [
        row
        for row in release.get("files", [])
        if isinstance(row, dict)
    ]
    if files and all(row.get("yanked") is True for row in files):
        return True

    file_count = release.get("file_count")
    yanked_file_count = release.get("yanked_file_count")
    if (
        isinstance(file_count, int)
        and file_count > 0
        and isinstance(yanked_file_count, int)
        and yanked_file_count == file_count
    ):
        return True

    return False


def assess_constraint_satisfiability(
    *,
    snapshot_releases: list[dict[str, Any]],
    time_releases: list[dict[str, Any]],
    policy_releases: list[dict[str, Any]],
    manifest: dict[str, Any],
    manifest_candidates: list[dict[str, Any]],
    feasible_releases: list[dict[str, Any]],
) -> dict[str, Any]:
    """Assess whether a formal negative has a non-empty release universe.

    This is deliberately a finite-universe assessment. It does not claim that
    a PEP 440 expression is mathematically satisfiable over every imaginable
    version; it records whether the frozen release snapshot and requested time
    view contain usable candidates. That is the universe required by the
    mentor design's V_feasible definition.
    """
    manifest_status = str(manifest.get("status") or "not_provided")
    constraint_kind = str(
        manifest.get("constraint_kind") or "not_provided"
    )
    specifier = str(manifest.get("specifier") or "").strip()
    declares_effective_constraint = (
        manifest_status == "resolved"
        and constraint_kind
        in {"version_specifier", "lockfile_exact_pin"}
    )
    has_effective_constraint = (
        declares_effective_constraint and bool(specifier)
    )

    if has_effective_constraint:
        snapshot_matches = filter_releases_by_specifier(
            snapshot_releases,
            specifier,
        )
        time_matches = filter_releases_by_specifier(
            time_releases,
            specifier,
        )
        policy_matches = [
            copy.deepcopy(row) for row in manifest_candidates
        ]
    else:
        snapshot_matches = [
            copy.deepcopy(row) for row in snapshot_releases
        ]
        time_matches = [
            copy.deepcopy(row) for row in time_releases
        ]
        policy_matches = [
            copy.deepcopy(row) for row in policy_releases
        ]

    yanked_candidate_count = sum(
        _release_is_explicitly_yanked(row)
        for row in policy_matches
    )
    all_candidates_yanked = (
        bool(policy_matches)
        and yanked_candidate_count == len(policy_matches)
    )
    matched_requirement_count = len(
        [
            row
            for row in manifest.get("matched_requirements", [])
            if isinstance(row, dict)
        ]
    )

    if declares_effective_constraint and not specifier:
        status = "manifest_constraint_missing_specifier"
    elif not snapshot_releases:
        status = "no_release_candidates_in_snapshot"
    elif has_effective_constraint and not snapshot_matches:
        if constraint_kind == "lockfile_exact_pin":
            status = "exact_lock_target_absent_from_snapshot"
        elif matched_requirement_count > 1:
            status = (
                "multiple_manifest_constraints_no_snapshot_match"
            )
        else:
            status = "manifest_constraint_no_snapshot_match"
    elif not time_releases:
        status = "no_release_candidates_as_of_time_view"
    elif has_effective_constraint and not time_matches:
        status = "manifest_constraint_no_match_as_of_time_view"
    elif has_effective_constraint and not policy_matches:
        status = "prerelease_only_match_excluded_by_policy"
    elif not policy_releases:
        status = "no_release_candidates_after_prerelease_policy"
    elif all_candidates_yanked:
        status = "yanked_only_release_match"
    elif not feasible_releases:
        status = (
            "api_constraints_eliminate_all_manifest_candidates"
            if has_effective_constraint
            else "api_constraints_eliminate_all_versions"
        )
    elif has_effective_constraint:
        status = "satisfiable_in_time_view"
    else:
        status = "not_applicable_unconstrained"

    formal_negative_eligible = (
        bool(feasible_releases)
        and status
        in {
            "satisfiable_in_time_view",
            "not_applicable_unconstrained",
        }
    )

    return {
        "schema_version": (
            "avcs_constraint_satisfiability_v1"
        ),
        "assessment_scope": (
            "frozen_snapshot_and_requested_time_view"
        ),
        "status": status,
        "formal_negative_eligible": formal_negative_eligible,
        "manifest_status": manifest_status,
        "constraint_kind": constraint_kind,
        "specifier": specifier,
        "has_effective_constraint": has_effective_constraint,
        "snapshot_release_count": len(snapshot_releases),
        "snapshot_match_count": len(snapshot_matches),
        "time_release_count": len(time_releases),
        "time_match_count": len(time_matches),
        "policy_release_count": len(policy_releases),
        "manifest_candidate_count": len(policy_matches),
        "yanked_manifest_candidate_count": yanked_candidate_count,
        "feasible_release_count": len(feasible_releases),
        "matched_requirement_count": matched_requirement_count,
        "scientific_boundary": {
            "finite_release_universe_only": True,
            "empty_feasible_is_formal_negative": False,
            "yanked_only_is_formal_negative": False,
            "unknown_is_false": False,
        },
    }


def release_is_covered_by_api_rule(
    release: dict[str, Any],
    exclusion_rule: dict[str, Any],
) -> bool:
    coverage = exclusion_rule.get("coverage", {})
    if not isinstance(coverage, dict):
        coverage = {}

    include_prereleases = coverage.get("include_prereleases")
    if include_prereleases is False:
        version_text = str(release.get("version", "")).strip()
        try:
            if Version(version_text).is_prerelease:
                return False
        except InvalidVersion:
            return False

    return True


def filter_releases_by_exclusion_rules(
    releases: list[dict[str, Any]],
    exclusion_rules: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    kept: list[dict[str, Any]] = []
    excluded: list[dict[str, Any]] = []

    for row in releases:
        version_text = str(row.get("version", "")).strip()
        false_rule_ids: list[str] = []
        false_evidence: list[dict[str, Any]] = []

        for rule in exclusion_rules:
            if not isinstance(rule, dict):
                continue

            semantics_status = str(
                rule.get("exclusion_semantics_status", "")
            )
            rule_id = str(rule.get("rule_id", "")).strip()

            if semantics_status == "explicit_release_states":
                false_versions = {
                    str(value).strip()
                    for value in rule.get("false_versions", [])
                    if str(value).strip()
                }
                if version_text in false_versions:
                    if rule_id:
                        false_rule_ids.append(rule_id)
                    false_evidence.append(
                        {
                            "rule_id": rule_id,
                            "mode": "explicit_release_state",
                            "proof_source": rule.get("proof_source"),
                        }
                    )
                continue

            if semantics_status != "proven_false_outside_specifier":
                continue
            if not release_is_covered_by_api_rule(row, rule):
                continue

            specifier_text = str(rule.get("version_specifier", "")).strip()
            if not specifier_text:
                continue
            try:
                version = Version(version_text)
                specifier = SpecifierSet(specifier_text)
            except (InvalidVersion, InvalidSpecifier):
                continue

            if not specifier.contains(version, prereleases=True):
                if rule_id:
                    false_rule_ids.append(rule_id)
                false_evidence.append(
                    {
                        "rule_id": rule_id,
                        "mode": "complete_specifier_proof",
                        "proof_source": rule.get("proof_source"),
                        "version_specifier": specifier_text,
                    }
                )

        if false_rule_ids:
            excluded.append(
                {
                    "version": version_text,
                    "false_rule_ids": sorted(set(false_rule_ids)),
                    "false_evidence": false_evidence,
                }
            )
        else:
            kept.append(copy.deepcopy(row))

    return kept, excluded


def solve_api_constraints(
    releases: list[dict[str, Any]],
    distribution_constraint: dict[str, Any] | None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if distribution_constraint is None:
        return [copy.deepcopy(row) for row in releases], {
            "status": "not_found",
            "specifier": "",
            "mode": "unknown_not_excluding",
            "api_call_count": 0,
            "resolved_api_call_count": 0,
            "unresolved_api_call_count": 0,
            "exclusion_rule_count": 0,
            "excluded_release_evidence": [],
            "contributing_calls": [],
        }

    status = str(distribution_constraint.get("status", "unresolved"))
    specifier = constraint_specifier(distribution_constraint)
    s_api = distribution_constraint.get("s_api", {})
    if not isinstance(s_api, dict):
        s_api = {}
    exclusion_rules = [
        row
        for row in s_api.get("exclusion_rules", [])
        if isinstance(row, dict)
        and row.get("exclusion_semantics_status")
        in {
            "proven_false_outside_specifier",
            "explicit_release_states",
        }
    ]

    if exclusion_rules:
        filtered, excluded = filter_releases_by_exclusion_rules(
            releases,
            exclusion_rules,
        )
        mode = "explicit_false_constraints_applied"
    else:
        filtered = [copy.deepcopy(row) for row in releases]
        excluded = []
        mode = "unknown_not_excluding"

    meta = {
        "status": status,
        "specifier": specifier,
        "mode": mode,
        "api_call_count": int(distribution_constraint.get("api_call_count", 0)),
        "resolved_api_call_count": int(
            distribution_constraint.get("resolved_api_call_count", 0)
        ),
        "unresolved_api_call_count": int(
            distribution_constraint.get("unresolved_api_call_count", 0)
        ),
        "exclusion_rule_count": len(exclusion_rules),
        "exclusion_rules": exclusion_rules,
        "excluded_release_evidence": excluded,
        "contributing_calls": copy.deepcopy(
            distribution_constraint.get("contributing_calls", [])
        ),
    }
    return filtered, meta


def vulnerability_specifiers(vulnerability: dict[str, Any]) -> list[str]:
    result = []
    for row in vulnerability.get("affected_ranges", []):
        if not isinstance(row, dict):
            continue
        value = str(row.get("version_specifier", "")).strip()
        if value and value not in result:
            result.append(value)
    return result


def version_matches_any(version_text: str, specifiers: list[str]) -> bool:
    try:
        version = Version(version_text)
    except InvalidVersion:
        return False

    for text in specifiers:
        try:
            spec = SpecifierSet(text)
        except InvalidSpecifier:
            continue
        if spec.contains(version, prereleases=True):
            return True
    return False


def exposed_releases_for_vulnerability(
    feasible: list[dict[str, Any]],
    vulnerability: dict[str, Any],
) -> tuple[list[dict[str, Any]], str]:
    specifiers = vulnerability_specifiers(vulnerability)
    if not specifiers:
        return [], "affected_range_unresolved"

    result = [
        copy.deepcopy(row)
        for row in feasible
        if version_matches_any(str(row.get("version", "")), specifiers)
    ]
    return result, "resolved"


def trigger_entry_from_kb(
    kb: dict[str, Any],
    vulnerability: dict[str, Any],
) -> dict[str, Any] | None:
    assessment = vulnerability.get("trigger_assessment", {})
    if assessment.get("status") != "eligible":
        return None

    rule_ids = assessment.get("rule_refs", [])
    rule_index = {
        str(row.get("trigger_id", "")): row
        for row in kb.get("trigger_rules", [])
        if isinstance(row, dict)
    }

    rules = []
    for rule_id in rule_ids:
        if rule_id not in rule_index:
            raise ValueError(
                f"Eligible vulnerability {vulnerability.get('vulnerability_id')} "
                f"references missing Trigger rule {rule_id!r}"
            )
        rules.append(copy.deepcopy(rule_index[rule_id]))

    direct = [row for row in rules if row.get("kind") == "direct_api"]
    conditional = [row for row in rules if row.get("kind") != "direct_api"]

    return {
        "distribution": kb.get("distribution"),
        "normalized_distribution": kb.get("normalized_distribution"),
        "vulnerability_ids": [
            vulnerability.get("vulnerability_id"),
            *(vulnerability.get("aliases") or []),
        ],
        "trigger_conditions": {
            "direct_api_rules": direct,
            "conditional_api_rules": conditional,
        },
        "safe_api_rules": [],
        "safe_api_symbols": [],
    }


def compute_fixed_excluded(
    *,
    vulnerability: dict[str, Any],
    time_releases: list[dict[str, Any]],
    api_meta: dict[str, Any],
) -> bool | None:
    fixed_versions = [
        str(value).strip()
        for value in vulnerability.get("fixed_versions", [])
        if str(value).strip()
    ]
    if not fixed_versions:
        return None

    available = {
        str(row.get("version", "")).strip()
        for row in time_releases
    }
    fixed_available = [value for value in fixed_versions if value in available]
    if not fixed_available:
        return None

    excluded_rows = api_meta.get("excluded_release_evidence", [])
    explicitly_false = {
        str(row.get("version", "")).strip()
        for row in excluded_rows
        if isinstance(row, dict)
        and str(row.get("version", "")).strip()
        and row.get("false_rule_ids")
    }
    if not explicitly_false:
        return None

    return all(value in explicitly_false for value in fixed_available)


def choose_repair(
    *,
    distribution: str,
    feasible: list[dict[str, Any]],
    exposed: list[dict[str, Any]],
    vulnerability: dict[str, Any],
    vulnerability_catalog: list[dict[str, Any]],
    knowledge_time: datetime,
    api_meta: dict[str, Any],
) -> dict[str, Any]:
    resolved_vulnerabilities: list[dict[str, Any]] = []
    unresolved_range_ids: list[str] = []
    publication_time_unknown_ids: list[str] = []
    future_vulnerability_ids: list[str] = []

    for item in vulnerability_catalog:
        if not isinstance(item, dict):
            continue
        vulnerability_id = str(
            item.get("vulnerability_id", "")
        ).strip()
        knowledge_status = vulnerability_knowledge_status(
            item,
            knowledge_time,
        )
        if knowledge_status == "not_yet_published":
            if vulnerability_id:
                future_vulnerability_ids.append(vulnerability_id)
            continue
        if knowledge_status == "publication_time_unknown":
            if vulnerability_id:
                publication_time_unknown_ids.append(vulnerability_id)
            continue
        if vulnerability_specifiers(item):
            resolved_vulnerabilities.append(item)
        elif vulnerability_id:
            unresolved_range_ids.append(vulnerability_id)

    known_affected_versions: set[str] = set()
    for row in feasible:
        version_text = str(row.get("version", "")).strip()
        if not version_text:
            continue
        if any(
            version_matches_any(
                version_text,
                vulnerability_specifiers(item),
            )
            for item in resolved_vulnerabilities
        ):
            known_affected_versions.add(version_text)

    known_safe = [
        row
        for row in feasible
        if str(row.get("version", "")).strip()
        not in known_affected_versions
    ]

    fixed_versions = []
    for value in vulnerability.get("fixed_versions", []):
        try:
            fixed_versions.append(Version(str(value)))
        except InvalidVersion:
            continue
    fixed_floor = min(fixed_versions) if fixed_versions else None

    candidates: list[tuple[Version, dict[str, Any]]] = []
    fallback: list[tuple[Version, dict[str, Any]]] = []
    for row in known_safe:
        try:
            version = Version(str(row.get("version", "")))
        except InvalidVersion:
            continue
        fallback.append((version, row))
        if fixed_floor is None or version >= fixed_floor:
            candidates.append((version, row))

    pool = candidates or fallback
    stable = [item for item in pool if not item[0].is_prerelease]
    chosen_pool = stable or pool

    safety_scope = {
        "basis": "all_resolved_affected_ranges_in_frozen_package_kb",
        "resolved_vulnerability_count": len(resolved_vulnerabilities),
        "unresolved_affected_range_vulnerability_ids": sorted(
            unresolved_range_ids
        ),
        "publication_time_unknown_vulnerability_ids": sorted(
            publication_time_unknown_ids
        ),
        "future_vulnerability_ids_excluded_by_knowledge_cutoff": sorted(
            future_vulnerability_ids
        ),
        "knowledge_time": time_text(knowledge_time),
        "complete_for_known_catalog": (
            not unresolved_range_ids
            and not publication_time_unknown_ids
        ),
    }

    if chosen_pool:
        chosen = min(chosen_pool, key=lambda item: item[0])[0]
        return {
            "action": "upgrade_dependency",
            "minimum_compatible_known_safe_version": str(chosen),
            "candidate_command": (
                f'python -m pip install "{distribution}=={chosen}"'
            ),
            "auto_apply": False,
            "package_safety_scope": safety_scope,
            "notes": (
                "Candidate release is compatible with the currently resolved "
                "manifest/API constraints and is not affected by any resolved "
                "affected range in the frozen Package KB. Vulnerabilities with "
                "unresolved affected ranges remain unknown; this is a "
                "reviewable repair candidate, not an automatic patch."
            ),
        }

    if exposed and int(api_meta.get("exclusion_rule_count", 0)) > 0:
        return {
            "action": "migrate_api",
            "minimum_compatible_known_safe_version": None,
            "candidate_command": None,
            "auto_apply": False,
            "package_safety_scope": safety_scope,
            "notes": (
                "No release outside all resolved affected ranges remains "
                "inside the current feasible version set; review API migration "
                "before upgrading."
            ),
        }

    return {
        "action": "review_dependency_constraints",
        "minimum_compatible_known_safe_version": None,
        "candidate_command": None,
        "auto_apply": False,
        "package_safety_scope": safety_scope,
        "notes": (
            "A compatible release outside all resolved affected ranges cannot "
            "be derived from current static version evidence."
        ),
    }


def resolve_knowledge_time(
    *,
    explicit_knowledge_time: str | None,
    requested_time: datetime,
) -> tuple[datetime, str]:
    if explicit_knowledge_time:
        parsed = parse_time(explicit_knowledge_time)
        if parsed is None:
            raise ValueError(
                "--knowledge-time must be a timezone-aware ISO-8601 "
                f"timestamp: {explicit_knowledge_time!r}"
            )
        validate_generation_knowledge(
            generation_time=requested_time,
            knowledge_time=parsed,
            label="AVCS",
        )
        return parsed, "explicit"

    validate_generation_knowledge(
        generation_time=requested_time,
        knowledge_time=requested_time,
        label="AVCS",
    )
    return requested_time, "requested_time_default"


def vulnerability_knowledge_status(
    vulnerability: dict[str, Any],
    knowledge_time: datetime,
) -> str:
    return vulnerability_knowledge_status_at_cutoff(
        published_at=vulnerability.get("published_at"),
        knowledge_time=knowledge_time,
    )


def temporal_classification(
    vulnerability: dict[str, Any],
    requested_time: datetime,
) -> str:
    published = parse_time(vulnerability.get("published_at"))
    if published is None:
        return "publication_time_unknown"
    if published > requested_time:
        return "temporal_drift"
    return "published_by_time_view"


def risk_type_for_actionable_finding(
    *,
    actionability: str,
    temporal: str,
    manifest_kind: str,
) -> str | None:
    if actionability not in {
        "probable_manifest_exposure",
        "api_induced_vulnerable_dependency",
    }:
        return None

    # Temporal drift is a first-class v2.1 risk: the vulnerable condition
    # is evaluated at generation time, while vulnerability knowledge may
    # come from a later audit-time view.
    if temporal == "temporal_drift":
        return "temporal_drift"

    if actionability == "api_induced_vulnerable_dependency":
        return "api_induced_vulnerable_dependency"

    return (
        "lockfile_vulnerable_dependency"
        if manifest_kind == "lockfile_exact_pin"
        else "manifest_vulnerable_dependency"
    )


def make_risk_id(
    sample_id: str,
    distribution: str,
    vulnerability_id: str,
    actionability: str,
) -> str:
    payload = "|".join(
        [sample_id, distribution, vulnerability_id, actionability, "step8"]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def _attribution_sort_key(row: dict[str, Any]) -> tuple[Any, ...]:
    file_value = str(row.get("file") or "")
    line_value = row.get("line")
    column_value = row.get("column")
    return (
        1 if not file_value else 0,
        file_value,
        int(line_value) if isinstance(line_value, int) else 10**12,
        int(column_value) if isinstance(column_value, int) else 10**12,
        str(row.get("entity") or ""),
        str(row.get("source_type") or ""),
    )


def _api_attribution_candidates(
    api_meta: dict[str, Any],
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for row in api_meta.get("contributing_calls", []):
        if not isinstance(row, dict):
            continue
        location = row.get("location")
        if not isinstance(location, dict):
            location = {}
        candidate = {
            "source_type": "api_call",
            "file": location.get("file"),
            "line": location.get("line"),
            "column": location.get("column"),
            "entity": row.get("api_symbol"),
            "call_text": row.get("call_text"),
            "matched_rule_ids": sorted(
                {
                    str(value)
                    for value in row.get("matched_rule_ids", [])
                    if str(value).strip()
                }
            ),
            "version_specifiers": list(
                row.get("version_specifiers", [])
            ),
        }
        candidates.append(candidate)

    candidates.sort(key=_attribution_sort_key)
    return candidates


def _dependency_attribution_candidates(
    manifest: dict[str, Any],
    distribution: str,
) -> list[dict[str, Any]]:
    kind = str(manifest.get("constraint_kind") or "")
    source = str(manifest.get("constraint_source") or "")

    if kind == "lockfile_exact_pin" or source == "lockfile":
        detail = manifest.get("lockfile")
        if not isinstance(detail, dict):
            detail = {}
        rows = [
            row
            for row in detail.get("matched_entries", [])
            if isinstance(row, dict)
        ]
        source_type = "lockfile"
        fallback_file = detail.get("source_path")
    else:
        rows = [
            row
            for row in manifest.get("matched_requirements", [])
            if isinstance(row, dict)
        ]
        source_type = "manifest"
        nested_manifest = manifest.get("manifest")
        fallback_file = None
        if isinstance(nested_manifest, dict):
            selected_files = [
                str(value)
                for value in nested_manifest.get(
                    "selected_manifest_files", []
                )
                if str(value).strip()
            ]
            if len(selected_files) == 1:
                fallback_file = selected_files[0]

    candidates: list[dict[str, Any]] = []
    for row in rows:
        file_value = (
            row.get("file")
            or row.get("source_path")
            or fallback_file
        )
        entity = (
            row.get("raw_name")
            or row.get("name")
            or row.get("normalized_name")
            or distribution
        )
        candidates.append(
            {
                "source_type": source_type,
                "file": file_value,
                "line": row.get("line"),
                "column": row.get("column"),
                "entity": entity,
                "specifier": (
                    row.get("specifier")
                    or (
                        f"=={row.get('exact_version')}"
                        if row.get("exact_version")
                        else ""
                    )
                ),
                "source_kind": row.get("source_kind"),
            }
        )

    if not candidates:
        fallback_file = (
            (manifest.get("lockfile") or {}).get("source_path")
            if source_type == "lockfile"
            and isinstance(manifest.get("lockfile"), dict)
            else fallback_file
        )
        candidates.append(
            {
                "source_type": source_type,
                "file": fallback_file,
                "line": None,
                "column": None,
                "entity": distribution,
                "specifier": manifest.get("specifier"),
                "source_kind": "constraint_summary_fallback",
            }
        )

    candidates.sort(key=_attribution_sort_key)
    return candidates


def select_causal_introduced_by(
    *,
    actionability: str,
    distribution: str,
    api_meta: dict[str, Any],
    manifest: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    if actionability == "api_induced_vulnerable_dependency":
        candidates = _api_attribution_candidates(api_meta)
        if not candidates:
            raise ValueError(
                "Formal API-induced Risk Card has no contributing API call; "
                f"distribution={distribution}"
            )
        primary = candidates[0]
        basis = "api_constraint_contributing_call"
        evidence_key = "causal_api_calls"
    elif actionability == "probable_manifest_exposure":
        candidates = _dependency_attribution_candidates(
            manifest,
            distribution,
        )
        primary = candidates[0]
        basis = (
            "lockfile_constraint_declaration"
            if primary.get("source_type") == "lockfile"
            else "manifest_constraint_declaration"
        )
        evidence_key = "causal_dependency_declarations"
    else:
        raise ValueError(
            "Formal AVCS Risk Card has unsupported attribution actionability: "
            f"{actionability}"
        )

    introduced_by = {
        "source_type": primary.get("source_type"),
        "file": primary.get("file"),
        "line": primary.get("line"),
        "column": primary.get("column"),
        "entity": primary.get("entity"),
    }
    return introduced_by, {
        "attribution_basis": basis,
        "primary_causal_location": copy.deepcopy(introduced_by),
        evidence_key: copy.deepcopy(candidates),
    }


def build_package_coverage(
    *,
    kb: dict[str, Any],
    api_history_adapter: dict[str, Any],
    release_view: dict[str, Any],
    filtered_calls: dict[str, Any],
    api_meta: dict[str, Any],
    manifest: dict[str, Any],
    constraint_satisfiability: dict[str, Any],
    findings: list[dict[str, Any]],
    risk_cards: list[dict[str, Any]],
    trigger_matches: dict[str, Any],
    evaluation_time_view: dict[str, Any] | None = None,
) -> dict[str, Any]:
    validated_time_view = validate_time_view_contract(
        evaluation_time_view,
        allow_legacy=True,
    )
    generation_metric_view = formal_generation_metric_eligible(
        validated_time_view
    )
    vulnerability_rows = [
        row
        for row in kb.get("vulnerability_catalog", [])
        if isinstance(row, dict)
        and str(row.get("vulnerability_id") or "").strip()
    ]
    published_count = sum(
        parse_time(row.get("published_at")) is not None
        for row in vulnerability_rows
    )

    if not isinstance(api_history_adapter, dict):
        raise ValueError("api_history_adapter must be a dict")
    missing_scope_keys = [
        key
        for key in ("status", "scope_policy")
        if key not in api_history_adapter
    ]
    if missing_scope_keys:
        raise ValueError(
            "API-History adapter lost required scope metadata: "
            + ",".join(missing_scope_keys)
        )
    api_history_status = str(
        api_history_adapter.get("status") or "not_provided"
    )
    api_history_scope_policy = str(
        api_history_adapter.get("scope_policy") or ""
    )
    api_history_entries = [
        row
        for row in api_history_adapter.get("entries", [])
        if isinstance(row, dict)
    ]
    adapter_entry_count = api_history_adapter.get("entry_count")
    if (
        not isinstance(adapter_entry_count, int)
        or adapter_entry_count != len(api_history_entries)
    ):
        raise ValueError(
            "API-History adapter entry_count does not match entries: "
            f"{adapter_entry_count!r}!={len(api_history_entries)}"
        )
    scope_semantics = api_history_adapter.get("scope_semantics")
    if not isinstance(scope_semantics, dict):
        raise ValueError("API-History adapter scope_semantics missing")
    if (
        scope_semantics.get(
            "resolved_does_not_imply_package_wide_coverage"
        )
        is not True
    ):
        raise ValueError(
            "API-History adapter lost scoped-resolution semantics"
        )

    trigger_eligibility_counts: dict[str, int] = {}
    for vulnerability in vulnerability_rows:
        assessment = vulnerability.get("trigger_assessment")
        if not isinstance(assessment, dict):
            eligibility = "not_assessed"
        else:
            eligibility = str(
                assessment.get("status") or "not_assessed"
            )
        trigger_eligibility_counts[eligibility] = (
            trigger_eligibility_counts.get(eligibility, 0) + 1
        )

    trigger_status_counts: dict[str, int] = {}
    for result in trigger_matches.values():
        if not isinstance(result, dict):
            continue
        summary = result.get("summary")
        if isinstance(summary, dict):
            status = str(
                summary.get("overall_trigger_status")
                or result.get("status")
                or "unknown"
            )
        else:
            status = str(result.get("status") or "unknown")
        trigger_status_counts[status] = (
            trigger_status_counts.get(status, 0) + 1
        )

    actionability_counts: dict[str, int] = {}
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        value = str(
            finding.get("actionability") or "unknown"
        )
        actionability_counts[value] = (
            actionability_counts.get(value, 0) + 1
        )

    def _formal_card_for_authorized_view(card: dict[str, Any]) -> bool:
        card_view = (
            card.get("evaluation_time_view")
            if isinstance(card.get("evaluation_time_view"), dict)
            else validated_time_view
        )
        return (
            card.get("channel") == "formal"
            and card.get("formal_eligible") is True
            and avcs_formal_risk_view_eligible(
                str(card.get("type") or ""),
                card_view,
            )
        )

    formal_cards = [
        card
        for card in risk_cards
        if isinstance(card, dict)
        and _formal_card_for_authorized_view(card)
    ]
    generation_formal_card_count = sum(
        str(card.get("type") or "")
        == "api_induced_vulnerable_dependency"
        for card in formal_cards
    )
    audit_drift_formal_card_count = sum(
        str(card.get("type") or "") == "temporal_drift"
        for card in formal_cards
    )
    audit_drift_auxiliary_card_count = sum(
        str(card.get("type") or "") == "temporal_drift"
        and card not in formal_cards
        for card in risk_cards
        if isinstance(card, dict)
    )
    formal_card_count = len(formal_cards)
    auxiliary_card_count = len(risk_cards) - formal_card_count

    blocking_unknown_reasons: set[str] = set()
    if filtered_calls.get("binding_unresolved"):
        # Losing uncertain calls must not silently manufacture a formal
        # negative, even when a manifest independently supplies versions.
        blocking_unknown_reasons.add("api_binding_unresolved")
    time_complete = (
        release_view.get("knowledge_complete_to_requested_time")
        is True
    )
    if not time_complete:
        blocking_unknown_reasons.add("time_evidence_incomplete")

    triage_actions = sorted(
        value
        for value in actionability_counts
        if value.startswith("triage_")
    )
    for value in triage_actions:
        blocking_unknown_reasons.add(
            f"actionability:{value}"
        )

    if not vulnerability_rows:
        blocking_unknown_reasons.add(
            "vulnerability_catalog_empty"
        )
    elif published_count < len(vulnerability_rows):
        blocking_unknown_reasons.add(
            "vulnerability_publication_time_incomplete"
        )

    manifest_status = str(
        manifest.get("status") or "not_provided"
    )
    if manifest_status not in {
        "resolved",
        "not_declared",
        "not_provided",
    }:
        blocking_unknown_reasons.add(
            f"manifest_status:{manifest_status}"
        )

    satisfiability_status = str(
        constraint_satisfiability.get("status")
        or "assessment_missing"
    )
    if (
        constraint_satisfiability.get(
            "formal_negative_eligible"
        )
        is not True
    ):
        blocking_unknown_reasons.add(
            "constraint_satisfiability:"
            + satisfiability_status
        )

    observed_api_call_count = int(
        filtered_calls.get("api_call_count", 0) or 0
    )
    api_constraint_status = str(
        api_meta.get("status") or "not_found"
    )
    manifest_has_effective_constraint = (
        manifest_status == "resolved"
        and str(manifest.get("constraint_kind") or "")
        in {"version_specifier", "lockfile_exact_pin"}
    )
    raw_api_parse_status = str(
        filtered_calls.get("syntax_parse_status")
        or filtered_calls.get("parse_status")
        or "unknown"
    ).strip()
    syntax_unavailable = raw_api_parse_status in {
        "syntax_invalid",
        "syntax_error",
        "decode_error",
    }
    if (
        observed_api_call_count > 0
        and api_constraint_status != "resolved"
        and not manifest_has_effective_constraint
    ):
        blocking_unknown_reasons.add(
            f"api_constraint_status:{api_constraint_status}"
        )

    coverage_annotations: list[str] = []
    if api_history_status not in {"resolved", "complete"}:
        coverage_annotations.append(
            f"api_history_scope:{api_history_status}"
        )
    if int(api_meta.get("unresolved_api_call_count", 0) or 0) > 0:
        coverage_annotations.append("unresolved_observed_api_calls")
    for status in sorted(trigger_status_counts):
        if status not in {"matched", "resolved", "not_matched"}:
            coverage_annotations.append(
                f"trigger_status:{status}"
            )

    # Preserve what the detector observed inside this named view while
    # keeping the generation-time denominator strictly limited to as_of_tg.
    # Audit/oracle/legacy outputs remain reviewable evidence, never silent
    # positives or negatives in the main experiment.
    if formal_card_count > 0:
        view_specific_outcome = "formal_positive"
    elif syntax_unavailable and not manifest_has_effective_constraint:
        view_specific_outcome = "syntax_unavailable"
    elif blocking_unknown_reasons:
        view_specific_outcome = "unknown_review"
    elif auxiliary_card_count > 0:
        view_specific_outcome = "auxiliary_only"
    else:
        view_specific_outcome = "formal_negative"

    base_blocking_unknown_reasons = set(blocking_unknown_reasons)

    if not generation_metric_view:
        view_id = str(validated_time_view.get("view_id") or "unknown")
        blocking_unknown_reasons.add(
            "time_view_not_formal_generation_metric:" + view_id
        )
        coverage_annotations.append(
            "view_specific_result_excluded_from_generation_denominator"
        )

    if generation_formal_card_count > 0:
        main_metric_outcome = "formal_positive"
        main_metric_eligible = True
    elif syntax_unavailable and not manifest_has_effective_constraint:
        # R5-r7: syntax failure is generation/support evidence, not a negative.
        # Manifest/lock-backed analyses remain allowed because they do not
        # require API recovery. API-dependent analyses without recoverable AST
        # evidence are explicitly excluded from the formal denominator.
        blocking_unknown_reasons.add("syntax_unavailable")
        main_metric_outcome = "syntax_unavailable"
        main_metric_eligible = False
    elif blocking_unknown_reasons:
        # Unknown/review takes precedence over auxiliary-only. Otherwise a
        # time-incomplete or semantically unresolved analysis that also emits
        # an auxiliary finding is mislabeled as merely auxiliary, hiding the
        # reason it cannot enter the formal denominator.
        main_metric_outcome = "unknown_review"
        main_metric_eligible = False
    elif auxiliary_card_count > 0:
        main_metric_outcome = "auxiliary_only"
        main_metric_eligible = False
    else:
        main_metric_outcome = "formal_negative"
        main_metric_eligible = True

    audit_drift_metric_eligible = avcs_formal_risk_view_eligible(
        "temporal_drift",
        validated_time_view,
    )
    if not audit_drift_metric_eligible:
        audit_drift_metric_outcome = "not_applicable"
        audit_drift_metric_formal_positive = False
    elif audit_drift_formal_card_count > 0:
        audit_drift_metric_outcome = "formal_positive"
        audit_drift_metric_formal_positive = True
    elif syntax_unavailable and not manifest_has_effective_constraint:
        audit_drift_metric_outcome = "syntax_unavailable"
        audit_drift_metric_eligible = False
        audit_drift_metric_formal_positive = False
    elif base_blocking_unknown_reasons:
        audit_drift_metric_outcome = "unknown_review"
        audit_drift_metric_eligible = False
        audit_drift_metric_formal_positive = False
    elif audit_drift_auxiliary_card_count > 0:
        audit_drift_metric_outcome = "auxiliary_only"
        audit_drift_metric_eligible = False
        audit_drift_metric_formal_positive = False
    else:
        audit_drift_metric_outcome = "formal_negative"
        audit_drift_metric_formal_positive = False

    return {
        "schema_version": "avcs_package_coverage_v1",
        "main_metric_outcome": main_metric_outcome,
        "main_metric_eligible": main_metric_eligible,
        "formal_positive": generation_formal_card_count > 0,
        "generation_metric": {
            "channel": "generation_time",
            "outcome": main_metric_outcome,
            "eligible": main_metric_eligible,
            "formal_positive": generation_formal_card_count > 0,
        },
        "audit_drift_metric": {
            "channel": "audit_time",
            "outcome": audit_drift_metric_outcome,
            "eligible": audit_drift_metric_eligible,
            "formal_positive": audit_drift_metric_formal_positive,
        },
        "evaluation_time_view": copy.deepcopy(validated_time_view),
        "view_specific_metric_outcome": {
            "channel": validated_time_view.get(
                "view_specific_metric_channel",
                "legacy_diagnostic",
            ),
            "outcome": view_specific_outcome,
            "formal_generation_metric_eligible": generation_metric_view,
        },
        "syntax_parse_status": raw_api_parse_status,
        "analysis_support": {
            "api_evidence": (
                "syntax_unavailable"
                if syntax_unavailable
                else "available"
            ),
            "manifest_or_lock_effective_constraint": (
                manifest_has_effective_constraint
            ),
            "syntax_unavailable_is_negative": False,
            "syntax_unavailable_metric_eligible": False,
            "constraint_satisfiability": copy.deepcopy(
                constraint_satisfiability
            ),
        },
        "formal_risk_card_count": formal_card_count,
        "generation_formal_risk_card_count": (
            generation_formal_card_count
        ),
        "audit_drift_formal_risk_card_count": (
            audit_drift_formal_card_count
        ),
        "auxiliary_risk_card_count": auxiliary_card_count,
        "blocking_unknown_reasons": sorted(
            blocking_unknown_reasons
        ),
        "coverage_annotations": sorted(
            set(coverage_annotations)
        ),
        "time_analysis": {
            "knowledge_complete_to_requested_time": time_complete,
            "release_evidence_complete": (
                release_view.get("release_evidence_complete")
            ),
            "snapshot_covers_requested_time": (
                release_view.get("snapshot_covers_requested_time")
            ),
        },
        "package_kb_scope": {
            "kb_id": kb.get("kb_id"),
            "api_history_status": api_history_status,
            "api_history_scope_policy": api_history_scope_policy,
            "api_history_entry_count": adapter_entry_count,
            "api_history_scope_semantics": copy.deepcopy(
                scope_semantics
            ),
            "api_history_scope_source": "api_history_adapter",
            "vulnerability_catalog_count": len(vulnerability_rows),
            "vulnerability_published_at_count": published_count,
            "trigger_rule_count": len(
                [
                    row
                    for row in kb.get("trigger_rules", [])
                    if isinstance(row, dict)
                ]
            ),
        },
        "observed_call_coverage": {
            "observed_api_call_count": observed_api_call_count,
            "resolved_api_call_count": int(
                api_meta.get("resolved_api_call_count", 0) or 0
            ),
            "unresolved_api_call_count": int(
                api_meta.get("unresolved_api_call_count", 0) or 0
            ),
            "api_constraint_status": api_constraint_status,
        },
        "manifest_coverage": {
            "status": manifest_status,
            "constraint_kind": manifest.get("constraint_kind"),
            "constraint_source": manifest.get("constraint_source"),
            "constraint_satisfiability": copy.deepcopy(
                constraint_satisfiability
            ),
        },
        "vulnerability_coverage": {
            "catalog_count": len(vulnerability_rows),
            "published_at_count": published_count,
            "publication_time_complete": (
                bool(vulnerability_rows)
                and published_count == len(vulnerability_rows)
            ),
            "actionability_counts": actionability_counts,
        },
        "trigger_coverage": {
            "catalog_vulnerability_count": len(vulnerability_rows),
            "eligibility_status_counts": trigger_eligibility_counts,
            "matcher_assessment_count": len(trigger_matches),
            "matcher_status_counts": trigger_status_counts,
            "secondary_only": True,
            "required_for_formal_negative": False,
            "matched_is_exploit_proof": False,
        },
        "scientific_boundary": {
            "absence_of_risk_card_is_not_negative_by_itself": True,
            "unknown_or_partial_coverage_is_not_negative": True,
            "auxiliary_finding_is_excluded_from_main_metrics": True,
            "trigger_unsupported_is_not_negative_evidence": True,
            "empty_feasible_is_not_formal_negative": True,
            "yanked_only_is_not_formal_negative": True,
            "legacy_view_is_not_metric_eligible": True,
            "audit_view_is_separate_from_generation_metric": True,
            "oracle_view_is_retrospective_only": True,
        },
    }


def build_final_output_coverage(
    *,
    coverage: dict[str, Any],
    support_status: str,
) -> dict[str, Any]:
    """Project package coverage into the stable consumer-facing output shape."""
    return {
        "schema_version": "avcs_final_output_coverage_v1",
        "support_status": support_status,
        "avcs_package_scope": copy.deepcopy(
            coverage.get("avcs_package_scope")
        ),
        "coverage_outcome": coverage.get("main_metric_outcome"),
        "main_metric_eligible": coverage.get("main_metric_eligible"),
        "formal_positive": coverage.get("formal_positive"),
        "generation_metric": copy.deepcopy(
            coverage.get("generation_metric")
        ),
        "audit_drift_metric": copy.deepcopy(
            coverage.get("audit_drift_metric")
        ),
        "evaluation_time_view": copy.deepcopy(
            coverage.get("evaluation_time_view")
        ),
        "view_specific_metric_outcome": copy.deepcopy(
            coverage.get("view_specific_metric_outcome")
        ),
        "syntax_parse_status": coverage.get("syntax_parse_status"),
        "analysis_support": copy.deepcopy(
            coverage.get("analysis_support")
        ),
        "blocking_unknown_reasons": copy.deepcopy(
            coverage.get("blocking_unknown_reasons") or []
        ),
        "coverage_annotations": copy.deepcopy(
            coverage.get("coverage_annotations") or []
        ),
        "package_kb_scope": copy.deepcopy(
            coverage.get("package_kb_scope")
        ),
        "observed_call_coverage": copy.deepcopy(
            coverage.get("observed_call_coverage")
        ),
        "manifest_coverage": copy.deepcopy(
            coverage.get("manifest_coverage")
        ),
        "vulnerability_coverage": copy.deepcopy(
            coverage.get("vulnerability_coverage")
        ),
        "trigger_coverage": copy.deepcopy(
            coverage.get("trigger_coverage")
        ),
        "time_analysis": copy.deepcopy(
            coverage.get("time_analysis")
        ),
        "scientific_boundary": {
            "coverage_is_explanatory_not_additional_risk_evidence": True,
            "unknown_is_not_false": True,
            "syntax_unavailable_is_not_negative": True,
            "syntax_unavailable_is_not_metric_eligible": True,
            "selected_scope_is_not_package_wide": True,
            "trigger_match_is_not_exploit_proof": True,
            "non_generation_view_is_not_main_metric_eligible": True,
            "audit_drift_metric_is_separate_from_generation_metric": True,
        },
    }


def analyze_package(
    *,
    sample_id: str,
    sample: dict[str, Any] | None,
    explicit_time: str | None,
    explicit_knowledge_time: str | None,
    package_dir: Path,
    kb_path: Path,
    kb: dict[str, Any],
    api_call_evidence: dict[str, Any],
    theta_reduce: float | None,
    theta_expose: float | None,
    threshold_policy: dict[str, Any],
    threshold_policy_path: Path,
    project_root: Path | None = None,
    project_dependency_facts: dict[str, Any] | None = None,
    identity_policy_path: Path = DEFAULT_IDENTITY_POLICY,
    release_snapshot_entry: dict[str, Any] | None = None,
    authoritative_time: str | None = None,
    authoritative_time_source: str | None = None,
    curated_scope_id: str | None = None,
    evaluation_time_view: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    distribution = str(kb.get("distribution", ""))
    normalized = pep503_normalize(distribution)
    validated_time_view = validate_time_view_contract(
        evaluation_time_view,
        allow_legacy=True,
    )
    generation_metric_view = formal_generation_metric_eligible(
        validated_time_view
    )

    filtered_calls = filter_api_call_evidence(api_call_evidence, normalized)
    api_calls_path = package_dir / "api_calls.json"
    write_json(api_calls_path, filtered_calls)

    api_history = build_api_history_adapter(kb)
    api_history_path = package_dir / "api_history_adapter.json"
    write_json(api_history_path, api_history)

    api_constraints = resolve_api_version_constraints(
        api_calls_path=api_calls_path,
        history_path=api_history_path,
    )
    api_constraints_path = package_dir / "api_constraints.json"
    write_json(api_constraints_path, api_constraints)

    if release_snapshot_entry is not None:
        release_path = ROOT / str(release_snapshot_entry["path"])
    else:
        release_path = release_artifact_path(kb)
    raw_release_history = read_json(release_path)
    release_source_sha256 = sha256_file(release_path)
    if release_snapshot_entry is not None:
        expected_release_sha = str(
            release_snapshot_entry.get("sha256", "")
        ).strip()
        if release_source_sha256 != expected_release_sha:
            raise ValueError(
                f"Verified release snapshot changed before analysis: "
                f"{normalized}"
            )
    requested_time, requested_time_source = resolve_requested_time(
        explicit_time=explicit_time,
        sample=sample,
        release_history=raw_release_history,
        authoritative_time=authoritative_time,
        authoritative_time_source=authoritative_time_source,
    )
    release_view = derive_release_history_view(
        release_history=raw_release_history,
        requested_time=requested_time,
        requested_time_source=requested_time_source,
    )
    knowledge_time, knowledge_time_source = resolve_knowledge_time(
        explicit_knowledge_time=explicit_knowledge_time,
        requested_time=requested_time,
    )
    release_view["source_release_history_file"] = rel(release_path)
    release_view["source_release_history_sha256"] = release_source_sha256
    release_view["source_release_snapshot_manifest_bound"] = (
        release_snapshot_entry is not None
    )
    release_view_path = package_dir / "release_history_view.json"
    write_json(release_view_path, release_view)

    if sample is not None:
        manifest = resolve_manifest_constraints(
            sample=sample,
            distribution=distribution,
            project_root=project_root,
            project_facts_override=project_dependency_facts,
            identity_policy_path=identity_policy_path,
        )
    else:
        manifest = {
            "schema_version": "avcs_manifest_constraints_v0.1",
            "sample_id": sample_id,
            "distribution": distribution,
            "normalized_distribution": normalized,
            "requirements_text": "",
            "status": "not_provided",
            "constraint_kind": "not_provided",
            "specifier": "",
            "matched_requirements": [],
            "invalid_lines": [],
        }

    manifest_path = package_dir / "manifest_constraints.json"
    write_json(manifest_path, manifest)

    snapshot_releases_all = [
        row
        for row in raw_release_history.get(
            "confirmed_releases_as_of_time_view", []
        )
        if isinstance(row, dict)
    ]
    time_releases_all = [
        row
        for row in release_view.get("confirmed_releases_as_of_time_view", [])
        if isinstance(row, dict)
    ]
    time_releases, prerelease_policy = apply_default_prerelease_policy(
        time_releases_all,
        manifest,
    )
    before_api, manifest_solver_mode = solve_manifest_before_api(
        time_releases,
        manifest,
    )

    distribution_constraint = find_distribution_constraint(
        api_constraints,
        normalized,
    )
    feasible, api_meta = solve_api_constraints(
        before_api,
        distribution_constraint,
    )

    constraint_satisfiability = assess_constraint_satisfiability(
        snapshot_releases=snapshot_releases_all,
        time_releases=time_releases_all,
        policy_releases=time_releases,
        manifest=manifest,
        manifest_candidates=before_api,
        feasible_releases=feasible,
    )

    before_count = len(before_api)
    feasible_count = len(feasible)
    reduction = (
        1.0 - (feasible_count / before_count)
        if before_count > 0
        else None
    )

    trigger_matches: dict[str, Any] = {}
    findings = []
    risk_cards: list[dict[str, Any]] = []

    threshold_policy_status = str(
        threshold_policy.get("status", "not_frozen")
    )
    threshold_policy_frozen = threshold_policy_status == "frozen"

    policy_theta_reduce = threshold_policy.get("theta_reduce")
    policy_theta_expose = threshold_policy.get("theta_expose")

    if threshold_policy_frozen:
        effective_theta_reduce = float(policy_theta_reduce)
        effective_theta_expose = float(policy_theta_expose)

        if (
            theta_reduce is not None
            and float(theta_reduce) != effective_theta_reduce
        ):
            raise ValueError(
                "Ad-hoc --theta-reduce cannot override a frozen threshold policy"
            )
        if (
            theta_expose is not None
            and float(theta_expose) != effective_theta_expose
        ):
            raise ValueError(
                "Ad-hoc --theta-expose cannot override a frozen threshold policy"
            )
    else:
        effective_theta_reduce = theta_reduce
        effective_theta_expose = theta_expose

    diagnostic_thresholds_supplied = (
        effective_theta_reduce is not None
        and effective_theta_expose is not None
    )
    interval_quality = api_interval_quality_gate(threshold_policy)

    for vulnerability in kb.get("vulnerability_catalog", []):
        if not isinstance(vulnerability, dict):
            continue

        vulnerability_id = str(
            vulnerability.get("vulnerability_id", "")
        ).strip()
        if not vulnerability_id:
            continue

        exposed, affected_status = exposed_releases_for_vulnerability(
            feasible,
            vulnerability,
        )

        exposure_ratio = (
            len(exposed) / feasible_count
            if feasible_count > 0
            else None
        )

        trigger_entry = trigger_entry_from_kb(kb, vulnerability)
        if trigger_entry is None:
            trigger_result = {
                "status": "not_available",
                "reason": vulnerability.get(
                    "trigger_assessment", {}
                ).get("status", "not_assessed"),
                "semantic_boundary": {
                    "negative_evidence": False,
                    "matched_trigger_is_full_exploit_proof": False,
                },
            }
        else:
            trigger_result = match_trigger_entry(
                api_call_evidence=filtered_calls,
                trigger_entry=trigger_entry,
                confirmed_exposed_releases=[
                    {"version": str(row.get("version", ""))}
                    for row in exposed
                ],
            )

        trigger_matches[vulnerability_id] = trigger_result

        fixed_excluded = compute_fixed_excluded(
            vulnerability=vulnerability,
            time_releases=time_releases,
            api_meta=api_meta,
        )

        temporal = temporal_classification(
            vulnerability,
            requested_time,
        )
        knowledge_status = vulnerability_knowledge_status(
            vulnerability,
            knowledge_time,
        )

        manifest_status = str(manifest.get("status", "not_provided"))
        manifest_kind = str(
            manifest.get("constraint_kind", "not_provided")
        )
        manifest_has_version_constraint = (
            manifest_status == "resolved"
            and manifest_kind in {
                "version_specifier",
                "lockfile_exact_pin",
            }
            and bool(str(manifest.get("specifier", "")).strip())
        )

        time_complete = bool(
            release_view.get("knowledge_complete_to_requested_time")
        )

        threshold_pair_passed = (
            api_meta.get("status") == "resolved"
            and threshold_policy_frozen
            and diagnostic_thresholds_supplied
            and reduction is not None
            and exposure_ratio is not None
            and reduction >= float(effective_theta_reduce)
            and exposure_ratio >= float(effective_theta_expose)
        )
        api_induced_gate = api_induced_gate_decision(
            api_status=str(api_meta.get("status", "")),
            interval_quality_passed=(
                interval_quality.get("passed") is True
            ),
            fixed_excluded=fixed_excluded,
            threshold_pair_passed=threshold_pair_passed,
            vulnerable_exposure_present=bool(exposed),
        )

        if affected_status != "resolved":
            actionability = "triage_affected_range_unresolved"
        elif knowledge_status == "not_yet_published":
            actionability = "not_observable_at_knowledge_time"
        elif knowledge_status == "publication_time_unknown":
            actionability = "triage_vulnerability_publication_time_unknown"
        elif not exposed:
            actionability = "no_version_exposure"
        elif manifest_has_version_constraint:
            # Manifest/lockfile-backed exposure is anchored by an explicit
            # dependency constraint. Partial package-wide release evidence
            # remains visible in provenance, but does not erase this probable
            # exposure finding.
            actionability = "probable_manifest_exposure"
        elif manifest_status not in {
            "resolved",
            "not_declared",
            "not_provided",
        }:
            actionability = "triage_manifest_constraint_unresolved"
        elif not time_complete:
            # API-induced/no-manifest claims depend on the shape of the
            # feasible release set, so incomplete release evidence must stay
            # triage-only.
            actionability = "triage_time_view_incomplete"
        elif api_induced_gate.get("passed") is True:
            actionability = "api_induced_vulnerable_dependency"
        else:
            actionability = "triage_version_exposure"

        repair = choose_repair(
            distribution=distribution,
            feasible=feasible,
            exposed=exposed,
            vulnerability=vulnerability,
            vulnerability_catalog=[
                item
                for item in kb.get("vulnerability_catalog", [])
                if isinstance(item, dict)
            ],
            knowledge_time=knowledge_time,
            api_meta=api_meta,
        )

        trigger_overall = (
            trigger_result.get("summary", {}).get("overall_trigger_status")
            if isinstance(trigger_result.get("summary"), dict)
            else trigger_result.get("status")
        )

        if manifest_has_version_constraint and exposed:
            sufficient_condition = (
                "lockfile_exact_pin"
                if manifest_kind == "lockfile_exact_pin"
                else "manifest_version_constraint"
            )
        elif api_induced_gate.get("passed") is True:
            sufficient_condition = api_induced_gate.get(
                "sufficient_condition"
            )
        else:
            sufficient_condition = None

        finding = {
            "vulnerability_id": vulnerability_id,
            "aliases": vulnerability.get("aliases", []),
            "trigger_assessment_status": vulnerability.get(
                "trigger_assessment", {}
            ).get("status"),
            "affected_range_status": affected_status,
            "affected_version_specifiers": vulnerability_specifiers(
                vulnerability
            ),
            "V_exposed": [
                str(row.get("version", ""))
                for row in exposed
            ],
            "V_exposed_count": len(exposed),
            "exposure_ratio": exposure_ratio,
            "fixed_excluded_by_known_api_constraint": fixed_excluded,
            "decision_evidence": {
                "sufficient_condition": sufficient_condition,
                "threshold_pair_passed": threshold_pair_passed,
                "api_interval_manual_validation": copy.deepcopy(
                    interval_quality
                ),
                "api_induced_gate": copy.deepcopy(api_induced_gate),
                "manifest_version_constraint": (
                    manifest_has_version_constraint
                ),
            },
            "trigger_evidence_status": trigger_overall,
            "trigger_evidence_secondary_only": True,
            "temporal_classification": temporal,
            "generation_time": time_text(requested_time),
            "vulnerability_published_at": vulnerability.get("published_at"),
            "vulnerability_knowledge_status": knowledge_status,
            "knowledge_time": time_text(knowledge_time),
            "evaluation_time_view": copy.deepcopy(validated_time_view),
            "actionability": actionability,
            "repair": repair,
        }
        findings.append(finding)

        risk_type = risk_type_for_actionable_finding(
            actionability=actionability,
            temporal=temporal,
            manifest_kind=manifest_kind,
        )
        if risk_type is not None:
            observed_calls = [
                row
                for row in filtered_calls.get("api_calls", [])
                if isinstance(row, dict)
            ]
            introduced_by, attribution_evidence = (
                select_causal_introduced_by(
                    actionability=actionability,
                    distribution=distribution,
                    api_meta=api_meta,
                    manifest=manifest,
                )
            )
            api_rule_ids = sorted(
                {
                    str(rule.get("rule_id", "")).strip()
                    for rule in api_meta.get("exclusion_rules", [])
                    if isinstance(rule, dict)
                    and str(rule.get("rule_id", "")).strip()
                }
            )
            api_proof_sources = sorted(
                {
                    str(rule.get("proof_source", "")).strip()
                    for rule in api_meta.get("exclusion_rules", [])
                    if isinstance(rule, dict)
                    and str(rule.get("proof_source", "")).strip()
                }
            )

            card_repair = copy.deepcopy(repair)
            card_repair["verify"] = (
                "Re-run dependency resolution and project tests; verify the "
                "selected candidate remains inside known manifest/API "
                "constraints and outside every resolved affected range in the "
                "current knowledge view. Unresolved vulnerability ranges "
                "remain review items."
            )
            formal_risk_view = avcs_formal_risk_view_eligible(
                risk_type,
                validated_time_view,
            )

            risk_cards.append(
                {
                    "schema_version": "step8_avcs_risk_card_v0.2",
                    "risk_id": make_risk_id(
                        sample_id,
                        distribution,
                        vulnerability_id,
                        actionability,
                    ),
                    "sample_id": sample_id,
                    "distribution": distribution,
                    "vulnerability_id": vulnerability_id,
                    "type": risk_type,
                    "status": "probable",
                    "severity": vulnerability.get(
                        "severity", []
                    ) or "not_calibrated",
                    "confidence": {
                        "level": "probable",
                        "basis": sufficient_condition,
                    },
                    "actionability": actionability,
                    "temporal_classification": temporal,
                    "generation_time": time_text(requested_time),
                    "vulnerability_published_at": vulnerability.get(
                        "published_at"
                    ),
                    "knowledge_time": time_text(knowledge_time),
                    "evaluation_time_view": copy.deepcopy(
                        validated_time_view
                    ),
                    "channel": (
                        "formal"
                        if formal_risk_view
                        else "auxiliary"
                    ),
                    "formal_eligible": formal_risk_view,
                    "introduced_by": introduced_by,
                    "decision": copy.deepcopy(
                        finding["decision_evidence"]
                    ),
                    "version_evidence": {
                        "V_before_api_count": before_count,
                        "V_feasible_count": feasible_count,
                        "V_exposed_count": len(exposed),
                        "reduction": reduction,
                        "exposure_ratio": exposure_ratio,
                        "V_exposed": finding["V_exposed"],
                        "api_excluded_release_evidence": copy.deepcopy(
                            api_meta.get(
                                "excluded_release_evidence", []
                            )
                        ),
                    },
                    "evidence": {
                        "package_kb": rel(kb_path),
                        "package_kb_id": kb.get("kb_id"),
                        "release_history_view": rel(
                            release_view_path
                        ),
                        "api_history_adapter": rel(
                            api_history_path
                        ),
                        "api_constraints": rel(
                            api_constraints_path
                        ),
                        "manifest_constraints": rel(
                            manifest_path
                        ),
                        "vulnerability_source_refs": vulnerability.get(
                            "source_refs", []
                        ),
                        "api_rule_ids": api_rule_ids,
                        "api_proof_sources": api_proof_sources,
                        "observed_api_symbols": [
                            row.get("api_symbol")
                            for row in observed_calls
                        ],
                        "causal_attribution": attribution_evidence,
                    },
                    "unknowns": {
                        "release_evidence_complete": release_view.get(
                            "release_evidence_complete"
                        ),
                        "unresolved_api_call_count": api_meta.get(
                            "unresolved_api_call_count"
                        ),
                        "vulnerability_publication_time_unknown": (
                            knowledge_status
                            == "publication_time_unknown"
                        ),
                        "affected_range_resolved": (
                            affected_status == "resolved"
                        ),
                    },
                    "trigger_evidence": {
                        "status": trigger_overall,
                        "secondary_only": True,
                        "matched_is_exploit_proof": False,
                    },
                    "repair": card_repair,
                    "scientific_boundary": {
                        "trigger_required_for_version_exposure": False,
                        "unsupported_trigger_is_negative_evidence": False,
                        "insufficient_trigger_is_negative_evidence": False,
                        "unknown_constraint_is_false": False,
                    },
                }
            )

    trigger_path = package_dir / "trigger_matches.json"
    write_json(
        trigger_path,
        {
            "schema_version": "step8_trigger_match_bundle_v0.1",
            "sample_id": sample_id,
            "distribution": distribution,
            "matches": trigger_matches,
        },
    )

    vulnerability_rows = [
        row
        for row in kb.get("vulnerability_catalog", [])
        if isinstance(row, dict)
    ]
    vulnerability_with_published_at = [
        row
        for row in vulnerability_rows
        if parse_time(row.get("published_at")) is not None
    ]
    vulnerability_without_published_at_ids = sorted(
        str(row.get("vulnerability_id", "")).strip()
        for row in vulnerability_rows
        if parse_time(row.get("published_at")) is None
        and str(row.get("vulnerability_id", "")).strip()
    )

    coverage = build_package_coverage(
        kb=kb,
        api_history_adapter=api_history,
        release_view=release_view,
        filtered_calls=filtered_calls,
        api_meta=api_meta,
        manifest=manifest,
        constraint_satisfiability=constraint_satisfiability,
        findings=findings,
        risk_cards=risk_cards,
        trigger_matches=trigger_matches,
        evaluation_time_view=validated_time_view,
    )
    coverage["avcs_package_scope"] = {
        "scope_id": curated_scope_id,
        "scope_status": "in_curated_scope",
        "membership_basis": "explicit_curated_scope_membership",
    }
    final_output_coverage = build_final_output_coverage(
        coverage=coverage,
        support_status="supported",
    )
    for card in risk_cards:
        card["coverage"] = copy.deepcopy(final_output_coverage)

    analysis = {
        "schema_version": "step8_unified_avcs_package_analysis_v0.2",
        "sample_id": sample_id,
        "distribution": distribution,
        "normalized_distribution": normalized,
        "package_kb": rel(kb_path),
        "package_kb_id": kb.get("kb_id"),
        "evaluation_time_view": copy.deepcopy(validated_time_view),
        "time_view": release_view.get("time_view"),
        "requested_time_source": requested_time_source,
        "knowledge_time": time_text(knowledge_time),
        "knowledge_time_source": knowledge_time_source,
        "release_time_view_status": release_view.get(
            "online_time_view_status"
        ),
        "snapshot_covers_requested_time": release_view.get(
            "snapshot_covers_requested_time"
        ),
        "release_evidence_complete": release_view.get(
            "release_evidence_complete"
        ),
        "source_release_history_status": release_view.get(
            "source_release_history_status"
        ),
        "source_release_history_file": rel(release_path),
        "source_release_history_sha256": release_source_sha256,
        "source_release_snapshot_manifest_bound": (
            release_snapshot_entry is not None
        ),
        "knowledge_complete_to_requested_time": release_view.get(
            "knowledge_complete_to_requested_time"
        ),
        "vulnerability_catalog_count": len(vulnerability_rows),
        "vulnerability_published_at_count": len(
            vulnerability_with_published_at
        ),
        "vulnerability_publication_time_coverage": (
            len(vulnerability_with_published_at) / len(vulnerability_rows)
            if vulnerability_rows
            else None
        ),
        "vulnerability_without_published_at_ids": (
            vulnerability_without_published_at_ids
        ),
        "api_history_scope": {
            "status": api_history.get("status"),
            "scope_policy": api_history.get("scope_policy"),
            "entry_count": api_history.get("entry_count"),
            "scope_semantics": copy.deepcopy(
                api_history.get("scope_semantics", {})
            ),
            "source": "api_history_adapter",
        },
        "api_call_count": len(filtered_calls.get("api_calls", [])),
        "api_constraint_status": api_meta.get("status"),
        "api_constraint_specifier": api_meta.get("specifier"),
        "resolved_api_call_count": api_meta.get(
            "resolved_api_call_count"
        ),
        "unresolved_api_call_count": api_meta.get(
            "unresolved_api_call_count"
        ),
        "api_exclusion_rule_count": api_meta.get("exclusion_rule_count"),
        "api_exclusion_rules": api_meta.get("exclusion_rules", []),
        "api_excluded_release_evidence": api_meta.get(
            "excluded_release_evidence"
        ),
        "manifest_status": manifest.get("status"),
        "manifest_constraint_kind": manifest.get("constraint_kind"),
        "manifest_specifier": manifest.get("specifier"),
        "manifest_constraint_source": manifest.get("constraint_source"),
        "lockfile_status": (
            manifest.get("lockfile", {}).get("status")
            if isinstance(manifest.get("lockfile"), dict)
            else None
        ),
        "lockfile_format": (
            manifest.get("lockfile", {}).get("format")
            if isinstance(manifest.get("lockfile"), dict)
            else None
        ),
        "lockfile_source_path": (
            manifest.get("lockfile", {}).get("source_path")
            if isinstance(manifest.get("lockfile"), dict)
            else None
        ),
        "manifest_solver_mode": manifest_solver_mode,
        "constraint_satisfiability": constraint_satisfiability,
        "resolver_prerelease_policy": prerelease_policy,
        "release_count_before_prerelease_policy": len(time_releases_all),
        "release_count_after_prerelease_policy": len(time_releases),
        "V_before_api": [
            str(row.get("version", ""))
            for row in before_api
        ],
        "V_before_api_count": before_count,
        "V_feasible": [
            str(row.get("version", ""))
            for row in feasible
        ],
        "V_feasible_count": feasible_count,
        "reduction": reduction,
        "thresholds": {
            "policy_file": rel(threshold_policy_path),
            "policy_status": threshold_policy_status,
            "policy_frozen": threshold_policy_frozen,
            "theta_reduce": effective_theta_reduce,
            "theta_expose": effective_theta_expose,
            "diagnostic_thresholds_supplied": diagnostic_thresholds_supplied,
            "formal_threshold_decision_enabled": threshold_policy_frozen,
            "ad_hoc_thresholds_can_create_formal_risk_card": False,
            "api_interval_manual_validation": copy.deepcopy(
                interval_quality
            ),
        },
        "finding_count": len(findings),
        "risk_card_count": len(risk_cards),
        "coverage": coverage,
        "findings": findings,
        "artifacts": {
            "api_calls": rel(api_calls_path),
            "api_history_adapter": rel(api_history_path),
            "api_constraints": rel(api_constraints_path),
            "release_history_view": rel(release_view_path),
            "manifest_constraints": rel(manifest_path),
            "trigger_matches": rel(trigger_path),
        },
        "scientific_boundary": {
            "api_unknown_does_not_exclude_release": True,
            "every_api_excluded_release_has_explicit_false_rule_evidence": True,
            "trigger_evidence_is_secondary": True,
            "trigger_match_is_not_exploit_proof": True,
            "unsupported_or_insufficient_trigger_is_not_negative_evidence": True,
            "no_manifest_api_induced_policy": "C_AND_(A_OR_B)",
            "api_induced_vulnerable_exposure_prerequisite": "V_exposed_count > 0",
            "api_induced_formal_reporting_rule": "V_EXPOSED_NONEMPTY_AND_C_AND_(A_OR_B)",
            "api_interval_manual_validation_is_global_prerequisite": True,
            "api_interval_manual_validation_is_independent_sufficient_condition": False,
            "fixed_excluded_requires_api_interval_quality_gate": True,
            "threshold_pair_requires_api_interval_quality_gate": True,
            "ad_hoc_cli_thresholds_are_diagnostic_only": True,
            "lockfile_path_implemented": True,
            "lockfile_scope": "requirements_style_exact_pin_and_pipfile_lock",
            "transitive_dependency_path_implemented": False,
            "api_history_adapter_preserves_scope_status": True,
            "api_history_resolved_is_declared_scope_only": True,
            "formal_risk_cards_carry_final_output_coverage": True,
            "empty_feasible_is_not_formal_negative": True,
            "constraint_satisfiability_is_finite_universe_assessment": True,
        },
    }
    write_json(package_dir / "analysis.json", analysis)
    return analysis, risk_cards



def filter_observed_by_identity_context(
    *,
    observed: list[str],
    unresolved_observed: set[str],
    manifest_declared: list[str],
    lockfile_declared: list[str],
    installability: set[str],
) -> tuple[list[str], list[str]]:
    """
    Keep an API-observed distribution when external dependency intent is
    independently evidenced. Otherwise an import whose local-module exclusion
    is unresolved remains diagnostic-only rather than a formal AVCS candidate.
    """
    external_dependency_evidence = (
        set(manifest_declared)
        | set(lockfile_declared)
        | set(installability)
    )
    suppressed = sorted(
        set(unresolved_observed) - external_dependency_evidence
    )
    kept = sorted(set(observed) - set(suppressed))
    return kept, suppressed


def run_unified_avcs(
    *,
    code_path: Path | None,
    sample_id: str,
    out_dir: Path,
    sample_records_path: Path | None = None,
    time_view: str | None = None,
    knowledge_time: str | None = None,
    time_view_id: str | None = None,
    time_view_snapshot_sha256: str | None = None,
    time_view_output_namespace: str | None = None,
    package_kb_dir: Path = DEFAULT_KB_DIR,
    mapping_path: Path = DEFAULT_MAPPING,
    identity_policy_path: Path = DEFAULT_IDENTITY_POLICY,
    project_root: Path | None = None,
    distributions: list[str] | None = None,
    theta_reduce: float | None = None,
    theta_expose: float | None = None,
    threshold_policy_path: Path = DEFAULT_THRESHOLD_POLICY,
    freeze_report_path: Path = DEFAULT_FREEZE_REPORT,
    curated_scope_path: Path = DEFAULT_CURATED_SCOPE,
    release_snapshot_manifest_path: Path | None = None,
    sceg_ir_path: Path | None = None,
) -> dict[str, Any]:
    if out_dir.exists():
        raise FileExistsError(f"Refusing overwrite: {out_dir}")

    freeze_report = verify_step7_freeze(freeze_report_path)
    threshold_policy = load_threshold_policy(threshold_policy_path)
    curated_scope = load_curated_scope(curated_scope_path)
    release_snapshot_index = load_release_snapshot_manifest(
        release_snapshot_manifest_path
    )
    external_sample = select_sample(sample_records_path, sample_id)
    sample = external_sample
    authoritative_generation_time: str | None = None
    authoritative_time_source: str | None = None
    external_sample_time_validation = (
        "not_applicable" if sample_records_path is None else "pending"
    )
    explicit_time_validation = (
        "not_applicable" if time_view is None else "pending"
    )
    code_consistency_validation = (
        "not_applicable" if code_path is None else "pending"
    )

    identity_service = PackageIdentityService(
        policy_path=identity_policy_path,
        project_root=project_root,
    )
    identity_contract = identity_service.contract()

    sceg_ir: dict[str, Any] | None = None
    if sceg_ir_path is not None:
        sceg_ir = read_sceg_json(sceg_ir_path)
        verify_sceg_ir(sceg_ir)
        if sceg_ir.get("schema_version") != "2.1":
            raise ValueError("AVCS requires SCEG schema_version 2.1")
        sceg_identity = sceg_ir.get("package_identity_contract")
        if not isinstance(sceg_identity, dict):
            raise ValueError(
                "AVCS requires SCEG package_identity_contract"
            )
        for key in (
            "policy_version",
            "policy_sha256",
            "mapping_sha256",
        ):
            if sceg_identity.get(key) != identity_contract.get(key):
                raise ValueError(
                    "AVCS/SCEG package identity contract mismatch: "
                    f"{key} expected={identity_contract.get(key)} "
                    f"actual={sceg_identity.get(key)}"
                )
        sample_context = sample_context_for_sample(
            sceg_ir,
            sample_id,
        )
        sample = copy.deepcopy(sample_context["sample"])
        authoritative_generation_time = str(
            sample_context["generation_time"]
        )
        authoritative_time_source = "sceg.sample.generation_time"
        authoritative_dt = parse_time(authoritative_generation_time)
        if authoritative_dt is None:
            raise ValueError(
                "Canonical SCEG generation_time is not a valid time view: "
                f"{authoritative_generation_time!r}"
            )

        if external_sample is not None:
            external_time_value = None
            for key in ("generation_time", "gen_time"):
                if str(external_sample.get(key) or "").strip():
                    external_time_value = external_sample.get(key)
                    break
            if external_time_value is not None:
                external_dt = parse_time(external_time_value)
                if external_dt is None:
                    raise ValueError(
                        "External sample generation time is invalid and "
                        "cannot be consistency-validated against SCEG"
                    )
                if external_dt != authoritative_dt:
                    raise ValueError(
                        "External sample generation_time disagrees with "
                        "canonical SCEG time; external sample records are "
                        "validation-only in SCEG mode: "
                        f"sample={sample_id} "
                        f"sceg={time_text(authoritative_dt)} "
                        f"external={time_text(external_dt)}"
                    )
            external_sample_time_validation = "PASS"

        if time_view is not None:
            explicit_dt = parse_time(time_view)
            if explicit_dt is None:
                raise ValueError(f"Invalid --time-view: {time_view!r}")
            if explicit_dt != authoritative_dt:
                raise ValueError(
                    "--time-view disagrees with canonical SCEG generation "
                    "time; --time-view is validation-only in SCEG mode: "
                    f"sceg={time_text(authoritative_dt)} "
                    f"explicit={time_text(explicit_dt)}"
                )
            explicit_time_validation = "PASS"

        source_code = sample_context.get("source_code")
        if not isinstance(source_code, dict):
            raise ValueError(
                "Canonical SCEG does not bind a source code hash for "
                f"sample {sample_id!r}"
            )
        expected_code_sha = str(
            source_code.get("sha256") or ""
        ).strip()
        if not expected_code_sha:
            raise ValueError(
                "Canonical SCEG source code record has no sha256 for "
                f"sample {sample_id!r}"
            )
        if code_path is not None:
            if not code_path.is_file():
                raise FileNotFoundError(
                    "External validation code file not found: "
                    f"{code_path}"
                )
            actual_code_sha = hashlib.sha256(
                code_path.read_bytes()
            ).hexdigest()
            if actual_code_sha != expected_code_sha:
                raise ValueError(
                    "External --code disagrees with the code snapshot bound into "
                    "canonical SCEG; --code is validation-only in SCEG mode: "
                    f"sample={sample_id} "
                    f"expected={expected_code_sha} actual={actual_code_sha}"
                )
            code_consistency_validation = "PASS"

        api_calls = api_call_evidence_for_sample(
            sceg_ir,
            sample_id,
        )
        if api_calls.get("identity_policy_version") != (
            identity_service.policy_version
        ):
            raise ValueError(
                "AVCS API evidence identity policy version mismatch"
            )
    else:
        if code_path is None:
            raise ValueError(
                "--code is required when --sceg-ir is not supplied"
            )
        api_calls = extract_api_calls(
            code_path=code_path,
            mapping_path=mapping_path,
            sample_id=sample_id,
            identity_policy_path=identity_policy_path,
            project_root=project_root,
        )

    explicit_view_fields = (
        time_view_snapshot_sha256,
        time_view_output_namespace,
    )
    if time_view_id is None:
        if any(value is not None for value in explicit_view_fields):
            raise ValueError(
                "time-view snapshot/namespace require --time-view-id"
            )
        evaluation_time_view = build_legacy_time_view_marker()
    else:
        if any(value is None for value in explicit_view_fields):
            raise ValueError(
                "explicit named time view requires snapshot SHA-256 and "
                "output namespace"
            )
        generation_value = authoritative_generation_time
        if generation_value is None and isinstance(sample, dict):
            for key in ("generation_time", "gen_time"):
                candidate = str(sample.get(key) or "").strip()
                if candidate:
                    generation_value = candidate
                    break
        if generation_value is None:
            raise ValueError(
                "explicit named time view requires sample generation_time"
            )
        generation_dt = parse_time(generation_value)
        if generation_dt is None:
            raise ValueError("sample generation_time is invalid")
        if time_view is not None and parse_time(time_view) != generation_dt:
            raise ValueError(
                "explicit named views keep release-state cutoff at generation_time"
            )
        if time_view_id in {"as_of_audit", "oracle_now"}:
            if knowledge_time is None:
                raise ValueError(
                    f"{time_view_id} requires explicit --knowledge-time"
                )
            evidence_cutoff = knowledge_time
        else:
            # The generation-time view is defined by what was knowable at
            # t_g. A later audit cutoff must never be smuggled into as_of_tg.
            evidence_cutoff = generation_value
        snapshot_sha = time_view_snapshot_sha256
        if release_snapshot_manifest_path is not None:
            actual_snapshot_sha = sha256_file(
                release_snapshot_manifest_path
            )
            if snapshot_sha != actual_snapshot_sha:
                raise ValueError(
                    "time-view snapshot SHA-256 disagrees with the bound "
                    "release snapshot manifest"
                )
        evaluation_time_view = build_time_view_contract(
            view_id=time_view_id,
            generation_time=generation_value,
            evidence_cutoff=evidence_cutoff,
            evidence_snapshot_sha256=str(snapshot_sha or ""),
            output_namespace=str(time_view_output_namespace or ""),
        )

    evaluation_time_view = validate_time_view_contract(
        evaluation_time_view,
        allow_legacy=True,
    )
    if evaluation_time_view.get("view_id") == "as_of_tg":
        effective_knowledge_time = str(
            evaluation_time_view["target_generation_time"]
        )
    else:
        effective_knowledge_time = knowledge_time

    out_dir.mkdir(parents=True, exist_ok=False)
    root_api_path = out_dir / "api_calls_all.json"
    write_json(root_api_path, api_calls)

    kb_index = load_package_kbs(package_kb_dir)
    wanted = {
        pep503_normalize(value)
        for value in (distributions or [])
        if str(value).strip()
    }

    project_facts: dict[str, Any] | None = None
    unresolved_observed: set[str] = set()

    if sceg_ir is not None:
        observed = distributions_for_sample(
            sceg_ir,
            sample_id,
            node_types={"APICall"},
            avcs_candidates_only=True,
        )
        for node in sceg_ir.get("nodes", []):
            if (
                not isinstance(node, dict)
                or node.get("type") != "APICall"
                or str(node.get("sample_id") or "") != sample_id
            ):
                continue
            payload = node.get("payload") or {}
            identity = payload.get("package_identity")
            if identity_has_unresolved_local_context(identity):
                distribution = pep503_normalize(
                    str(payload.get("distribution") or "")
                )
                if distribution:
                    unresolved_observed.add(distribution)

        project_facts = project_dependency_facts_for_sample(
            sceg_ir,
            sample_id,
        )
        if project_facts.get("schema_version") != FACTS_SCHEMA_VERSION:
            raise ValueError(
                "Unexpected canonical project dependency facts schema in AVCS"
            )
        manifest_declared = sorted(
            project_facts.get("manifests", {})
        )
        lockfile_declared = sorted(
            project_facts.get("locks", {})
        )
    else:
        observed_rows = [
            row
            for row in api_calls.get("api_calls", [])
            if isinstance(row, dict)
            and str(row.get("distribution", "")).strip()
            and is_avcs_candidate_identity(
                row.get("package_identity")
            )
        ]
        observed = sorted(
            {
                pep503_normalize(str(row.get("distribution", "")))
                for row in observed_rows
            }
        )
        unresolved_observed = {
            pep503_normalize(str(row.get("distribution", "")))
            for row in observed_rows
            if identity_has_unresolved_local_context(
                row.get("package_identity")
            )
        }
        manifest_declared = sorted(
            {
                identity_service.resolve(
                    raw_name=name,
                    source_type="manifest",
                ).normalized_distribution
                for name in manifest_declared_distributions(sample)
                if identity_service.resolve(
                    raw_name=name,
                    source_type="manifest",
                ).avcs_candidate
            }
        )
        if project_root is not None:
            project_facts = collect_project_dependency_facts(
                project_root,
                identity_policy_path=identity_policy_path,
            )
            if project_facts.get("schema_version") != FACTS_SCHEMA_VERSION:
                raise ValueError(
                    "Unexpected project dependency facts schema in AVCS"
                )
            manifest_declared = sorted(
                project_facts.get("manifests", {})
            )
            lockfile_declared = sorted(
                project_facts.get("locks", {})
            )
        else:
            lockfile_declared = lockfile_declared_distributions(sample)

    observed, identity_context_suppressed_observed = (
        filter_observed_by_identity_context(
            observed=observed,
            unresolved_observed=unresolved_observed,
            manifest_declared=manifest_declared,
            lockfile_declared=lockfile_declared,
            installability=(
                set(project_facts.get("installability", {}))
                if project_facts is not None
                else set()
            ),
        )
    )

    declared = sorted(
        set(manifest_declared) | set(lockfile_declared)
    )
    dependency_candidates = sorted(set(observed) | set(declared))
    filtered_dependency_candidates = [
        name
        for name in dependency_candidates
        if not wanted or name in wanted
    ]
    in_scope_candidates, out_of_scope_candidates = classify_candidates(
        filtered_dependency_candidates,
        curated_scope,
    )

    supported = [
        name for name in in_scope_candidates if name in kb_index
    ]
    unsupported_in_scope = [
        name for name in in_scope_candidates if name not in kb_index
    ]
    supported_observed = [
        name for name in observed
        if name in supported and (not wanted or name in wanted)
    ]
    supported_declared = [
        name for name in declared
        if name in supported and (not wanted or name in wanted)
    ]
    supported_manifest_declared = [
        name for name in manifest_declared
        if name in supported and (not wanted or name in wanted)
    ]
    supported_lockfile_declared = [
        name for name in lockfile_declared
        if name in supported and (not wanted or name in wanted)
    ]
    unsupported_observed = [
        name for name in observed
        if name in unsupported_in_scope and (not wanted or name in wanted)
    ]
    unsupported_declared = [
        name for name in declared
        if name in unsupported_in_scope and (not wanted or name in wanted)
    ]
    unsupported_manifest_declared = [
        name for name in manifest_declared
        if name in unsupported_in_scope and (not wanted or name in wanted)
    ]
    unsupported_lockfile_declared = [
        name for name in lockfile_declared
        if name in unsupported_in_scope and (not wanted or name in wanted)
    ]
    out_of_scope_observed = [
        name for name in observed
        if name in out_of_scope_candidates and (not wanted or name in wanted)
    ]
    out_of_scope_declared = [
        name for name in declared
        if name in out_of_scope_candidates and (not wanted or name in wanted)
    ]

    package_analyses = []
    all_risk_cards: list[dict[str, Any]] = []

    if release_snapshot_index:
        missing_release_snapshots = sorted(
            name for name in supported if name not in release_snapshot_index
        )
        if missing_release_snapshots:
            raise ValueError(
                "Release snapshot manifest does not cover supported packages: "
                + ", ".join(missing_release_snapshots)
            )

    for normalized in supported:
        kb_path, kb = kb_index[normalized]
        package_dir = out_dir / "packages" / normalized
        package_dir.mkdir(parents=True, exist_ok=True)

        analysis, cards = analyze_package(
            sample_id=sample_id,
            sample=sample,
            explicit_time=time_view,
            explicit_knowledge_time=effective_knowledge_time,
            package_dir=package_dir,
            kb_path=kb_path,
            kb=kb,
            api_call_evidence=api_calls,
            theta_reduce=theta_reduce,
            theta_expose=theta_expose,
            threshold_policy=threshold_policy,
            threshold_policy_path=threshold_policy_path,
            project_root=(
                None if sceg_ir is not None else project_root
            ),
            project_dependency_facts=(
                project_facts if sceg_ir is not None else None
            ),
            identity_policy_path=identity_policy_path,
            release_snapshot_entry=(
                release_snapshot_index.get(normalized)
                if release_snapshot_index
                else None
            ),
            authoritative_time=authoritative_generation_time,
            authoritative_time_source=authoritative_time_source,
            curated_scope_id=str(curated_scope.get("scope_id") or ""),
            evaluation_time_view=evaluation_time_view,
        )
        package_analyses.append(analysis)
        all_risk_cards.extend(cards)

        print(
            f"[STEP8 PACKAGE PASS] {normalized} | "
            f"calls={analysis['api_call_count']} | "
            f"V_feasible={analysis['V_feasible_count']} | "
            f"risk_cards={analysis['risk_card_count']}"
        )

    risk_cards_path = out_dir / "risk_cards.jsonl"
    write_jsonl(risk_cards_path, all_risk_cards)

    coverage_outcomes: list[dict[str, Any]] = []
    for row in package_analyses:
        coverage_outcomes.append(
            {
                "schema_version": "avcs_coverage_outcome_v1",
                "sample_id": sample_id,
                "distribution": row["normalized_distribution"],
                "support_status": "supported",
                **copy.deepcopy(row["coverage"]),
            }
        )
    for normalized in unsupported_in_scope:
        coverage_outcomes.append(
            {
                "schema_version": "avcs_coverage_outcome_v1",
                "sample_id": sample_id,
                "distribution": normalized,
                "support_status": "unsupported_in_scope",
                "main_metric_outcome": "unsupported_in_scope",
                "main_metric_eligible": False,
                "formal_positive": False,
                "blocking_unknown_reasons": [
                    "curated_scope_package_kb_missing"
                ],
                "coverage_annotations": [],
                "avcs_package_scope": {
                    "scope_id": curated_scope.get("scope_id"),
                    "scope_status": "in_curated_scope",
                    "membership_basis": "explicit_curated_scope_membership",
                },
                "scientific_boundary": {
                    "absence_of_risk_card_is_not_negative_by_itself": True,
                    "unsupported_is_not_negative": True,
                    "in_scope_missing_method_support_is_contract_failure": True,
                },
            }
        )
    for normalized in out_of_scope_candidates:
        coverage_outcomes.append(
            {
                "schema_version": "avcs_coverage_outcome_v1",
                "sample_id": sample_id,
                "distribution": normalized,
                "support_status": "out_of_curated_scope",
                "main_metric_outcome": "out_of_curated_scope",
                "main_metric_eligible": False,
                "formal_positive": False,
                "blocking_unknown_reasons": [],
                "coverage_annotations": [
                    "outside_frozen_curated_avcs_package_scope"
                ],
                "avcs_package_scope": {
                    "scope_id": curated_scope.get("scope_id"),
                    "scope_status": "out_of_curated_scope",
                    "membership_basis": "explicit_curated_scope_non_membership",
                },
                "scientific_boundary": {
                    "absence_of_risk_card_is_not_negative_by_itself": True,
                    "out_of_curated_scope_is_not_negative": True,
                    "out_of_curated_scope_is_not_metric_eligible": True,
                },
            }
        )
    for normalized in identity_context_suppressed_observed:
        coverage_outcomes.append(
            {
                "schema_version": "avcs_coverage_outcome_v1",
                "sample_id": sample_id,
                "distribution": normalized,
                "support_status": "identity_context_unresolved",
                "main_metric_outcome": "unknown_review",
                "main_metric_eligible": False,
                "formal_positive": False,
                "blocking_unknown_reasons": [
                    "external_dependency_identity_unresolved"
                ],
                "coverage_annotations": [],
                "scientific_boundary": {
                    "absence_of_risk_card_is_not_negative_by_itself": True,
                    "unresolved_identity_is_not_negative": True,
                },
            }
        )
    if not coverage_outcomes:
        coverage_outcomes.append(
            {
                "schema_version": "avcs_coverage_outcome_v1",
                "sample_id": sample_id,
                "distribution": None,
                "support_status": "not_applicable",
                "main_metric_outcome": "no_avcs_candidate",
                "main_metric_eligible": False,
                "formal_positive": False,
                "blocking_unknown_reasons": [],
                "coverage_annotations": [],
                "scientific_boundary": {
                    "absence_of_risk_card_is_not_negative_by_itself": True,
                    "no_candidate_is_not_formal_negative": True,
                },
            }
        )

    for coverage_row in coverage_outcomes:
        coverage_row.setdefault(
            "evaluation_time_view",
            copy.deepcopy(evaluation_time_view),
        )
        coverage_row.setdefault(
            "view_specific_metric_outcome",
            {
                "channel": evaluation_time_view.get(
                    "view_specific_metric_channel",
                    "legacy_diagnostic",
                ),
                "outcome": coverage_row.get("main_metric_outcome"),
                "formal_generation_metric_eligible": (
                    formal_generation_metric_eligible(
                        evaluation_time_view
                    )
                ),
            },
        )

    coverage_outcomes.sort(
        key=lambda row: (
            str(row.get("distribution") or ""),
            str(row.get("support_status") or ""),
        )
    )
    coverage_outcomes_path = out_dir / "coverage_outcomes.jsonl"
    write_jsonl(coverage_outcomes_path, coverage_outcomes)

    resume_input = build_avcs_resume_input(
        sample_id=sample_id,
        code_path=code_path,
        sample_records_path=sample_records_path,
        sceg_ir_path=sceg_ir_path,
        release_snapshot_manifest_path=release_snapshot_manifest_path,
        kb_dir=package_kb_dir,
        threshold_policy_path=threshold_policy_path,
        freeze_report_path=freeze_report_path,
        mapping_path=mapping_path,
        time_view=time_view,
        knowledge_time=effective_knowledge_time,
        identity_policy_path=identity_policy_path,
        curated_scope_path=curated_scope_path,
        project_snapshot_manifest_path=(
            project_root / "snapshot_manifest.json"
            if project_root is not None
            and (project_root / "snapshot_manifest.json").exists()
            else None
        ),
        evaluation_time_view=evaluation_time_view,
    )
    resume_outputs = build_avcs_output_contract(
        sample_out=out_dir,
        package_names=[
            str(row["normalized_distribution"])
            for row in package_analyses
        ],
        coverage_outcomes_path=coverage_outcomes_path,
    )

    summary = {
        "schema_version": "step8_unified_avcs_run_v0.3",
        "runner_version": "step8_unified_avcs_runner_v0.6_f04_canonical_sceg",
        "canonical_sceg_input": sceg_ir is not None,
        "evaluation_time_view": evaluation_time_view,
        "project_source_reread_after_sceg": (
            False if sceg_ir is not None else None
        ),
        "generation_time_authority": (
            authoritative_time_source
            if sceg_ir is not None
            else "legacy_non_sceg_resolution"
        ),
        "canonical_generation_time": (
            authoritative_generation_time
            if sceg_ir is not None
            else None
        ),
        "external_sample_records_role": (
            "consistency_validation_only"
            if sceg_ir is not None and sample_records_path is not None
            else (
                "not_supplied"
                if sample_records_path is None
                else "legacy_analysis_input"
            )
        ),
        "external_sample_time_validation": (
            external_sample_time_validation
        ),
        "external_code_role": (
            (
                "consistency_validation_only"
                if code_path is not None
                else "not_supplied"
            )
            if sceg_ir is not None
            else "legacy_analysis_input"
        ),
        "external_code_consistency_validation": (
            code_consistency_validation
        ),
        "explicit_time_view_role": (
            "consistency_validation_only"
            if sceg_ir is not None and time_view is not None
            else (
                "not_supplied"
                if time_view is None
                else "legacy_analysis_input"
            )
        ),
        "explicit_time_view_validation": explicit_time_validation,
        "sample_id": sample_id,
        "code_file": (
            rel(code_path)
            if code_path is not None
            else (
                str(
                    (sample_context.get("source_code") or {}).get("path")
                    or ""
                )
                if sceg_ir is not None
                else None
            )
        ),
        "external_code_file": (
            rel(code_path) if code_path is not None else None
        ),
        "sample_records_file": (
            rel(sample_records_path)
            if sample_records_path is not None
            else None
        ),
        "sceg_ir_file": (
            rel(sceg_ir_path)
            if sceg_ir_path is not None
            else None
        ),
        "sceg_ir_sha256": (
            sha256_file(sceg_ir_path)
            if sceg_ir_path is not None
            else None
        ),
        "sceg_source_snapshot_id": (
            sceg_ir.get("source_snapshot_id")
            if sceg_ir is not None
            else None
        ),
        "api_calls_source": (
            "sceg_v2_1"
            if sceg_ir is not None
            else "direct_code_extraction"
        ),
        "api_parse_status": api_calls.get("parse_status"),
        "identity_policy_file": rel(identity_policy_path),
        "identity_policy_sha256": identity_service.policy_sha256,
        "identity_mapping_file": rel(identity_service.mapping_path),
        "identity_mapping_sha256": identity_service.mapping_sha256,
        "identity_policy_version": identity_service.policy_version,
        "identity_contract": identity_contract,
        "project_root": (
            rel(project_root)
            if project_root is not None
            else None
        ),
        "project_snapshot_manifest": (
            rel(project_root / "snapshot_manifest.json")
            if project_root is not None
            and (project_root / "snapshot_manifest.json").exists()
            else None
        ),
        "project_snapshot_manifest_sha256": (
            sha256_file(project_root / "snapshot_manifest.json")
            if project_root is not None
            and (project_root / "snapshot_manifest.json").exists()
            else None
        ),
        "candidate_identity_filter": (
            "identity_status=distribution_candidate && avcs_candidate=true"
        ),
        "curated_scope_file": rel(curated_scope_path),
        "curated_scope_sha256": sha256_file(curated_scope_path),
        "curated_scope_id": curated_scope.get("scope_id"),
        "curated_scope_package_count": len(curated_scope.get("packages", [])),
        "scope_resolution_semantics": (
            "package identity candidacy precedes and does not imply curated "
            "AVCS package-scope membership"
        ),
        "unsupported_candidate_semantics": (
            "in-scope dependency candidate lacks required curated AVCS "
            "Package KB; this is method-contract failure, not negative identity "
            "or vulnerability evidence"
        ),
        "out_of_curated_scope_semantics": (
            "valid dependency candidate outside the frozen curated AVCS "
            "library scope; explicitly reported, non-negative, and excluded "
            "from formal AVCS effectiveness metrics"
        ),
        "step7_freeze_report": rel(freeze_report_path),
        "step7_freeze_status": freeze_report.get("freeze_status"),
        "threshold_policy_file": rel(threshold_policy_path),
        "threshold_policy_status": threshold_policy.get("status"),
        "release_snapshot_manifest_file": (
            rel(release_snapshot_manifest_path)
            if release_snapshot_manifest_path is not None
            else None
        ),
        "release_snapshot_manifest_sha256": (
            sha256_file(release_snapshot_manifest_path)
            if release_snapshot_manifest_path is not None
            else None
        ),
        "observed_distributions": observed,
        "identity_context_suppressed_observed_distributions": (
            identity_context_suppressed_observed
        ),
        "manifest_declared_distributions": manifest_declared,
        "lockfile_declared_distributions": lockfile_declared,
        "declared_distributions": declared,
        "candidate_distributions": filtered_dependency_candidates,
        "dependency_candidate_distributions": filtered_dependency_candidates,
        "in_curated_scope_candidate_distributions": in_scope_candidates,
        "out_of_curated_scope_candidate_distributions": out_of_scope_candidates,
        "supported_observed_distributions": supported_observed,
        "supported_declared_distributions": supported_declared,
        "supported_manifest_declared_distributions": (
            supported_manifest_declared
        ),
        "supported_lockfile_declared_distributions": (
            supported_lockfile_declared
        ),
        "supported_analyzed_distributions": supported,
        "unsupported_observed_distributions": unsupported_observed,
        "unsupported_declared_distributions": unsupported_declared,
        "unsupported_manifest_declared_distributions": (
            unsupported_manifest_declared
        ),
        "unsupported_lockfile_declared_distributions": (
            unsupported_lockfile_declared
        ),
        "unsupported_candidate_distributions": unsupported_in_scope,
        "unsupported_in_scope_distributions": unsupported_in_scope,
        "out_of_scope_observed_distributions": out_of_scope_observed,
        "out_of_scope_declared_distributions": out_of_scope_declared,
        "package_analysis_count": len(package_analyses),
        "risk_card_count": len(all_risk_cards),
        "risk_cards_file": rel(risk_cards_path),
        "coverage_outcomes_file": rel(coverage_outcomes_path),
        "coverage_outcome_counts": {
            outcome: sum(
                row.get("main_metric_outcome") == outcome
                for row in coverage_outcomes
            )
            for outcome in sorted(
                {
                    str(row.get("main_metric_outcome") or "")
                    for row in coverage_outcomes
                    if str(row.get("main_metric_outcome") or "")
                }
            )
        },
        "audit_drift_metric_outcome_counts": {
            outcome: sum(
                isinstance(row.get("audit_drift_metric"), dict)
                and row["audit_drift_metric"].get("outcome") == outcome
                for row in coverage_outcomes
            )
            for outcome in sorted(
                {
                    str(row["audit_drift_metric"].get("outcome") or "")
                    for row in coverage_outcomes
                    if isinstance(row.get("audit_drift_metric"), dict)
                    and str(
                        row["audit_drift_metric"].get("outcome") or ""
                    )
                }
            )
        },
        "resume_contract": {
            "schema_version": "avcs_sample_resume_contract_v1",
            "input": resume_input,
            "outputs": resume_outputs,
        },
        "packages": [
            {
                "distribution": row["distribution"],
                "normalized_distribution": row[
                    "normalized_distribution"
                ],
                "analysis_file": rel(
                    out_dir
                    / "packages"
                    / row["normalized_distribution"]
                    / "analysis.json"
                ),
                "V_before_api_count": row["V_before_api_count"],
                "V_feasible_count": row["V_feasible_count"],
                "reduction": row["reduction"],
                "risk_card_count": row["risk_card_count"],
                "coverage": copy.deepcopy(row["coverage"]),
                "knowledge_complete_to_requested_time": row[
                    "knowledge_complete_to_requested_time"
                ],
                "source_release_history_file": row[
                    "source_release_history_file"
                ],
                "source_release_history_sha256": row[
                    "source_release_history_sha256"
                ],
                "source_release_snapshot_manifest_bound": row[
                    "source_release_snapshot_manifest_bound"
                ],
                "vulnerability_catalog_count": row[
                    "vulnerability_catalog_count"
                ],
                "vulnerability_published_at_count": row[
                    "vulnerability_published_at_count"
                ],
            }
            for row in package_analyses
        ],
        "scientific_boundary": {
            "step7_frozen_input_required": True,
            "step7_freeze_report_verified": True,
            "analysis_scope_is_api_observed_union_manifest_or_lockfile_declared": True,
            "minimal_python_lockfile_path_implemented": True,
            "default_resolver_excludes_prereleases_unless_explicitly_requested": True,
            "step8_online_runner_started": True,
            "step9_benchmark_started": False,
            "trigger_evidence_is_secondary": True,
            "trigger_match_is_not_exploit_proof": True,
            "unknown_constraints_are_not_negative_evidence": True,
            "absence_of_risk_card_is_not_formal_negative": True,
            "coverage_outcomes_are_explicit": True,
            "syntax_unavailable_is_explicit_nonnegative_support_state": True,
            "syntax_unavailable_is_not_metric_eligible": True,
            "manifest_lock_evidence_can_remain_usable_when_api_ast_unavailable": True,
            "formal_negative_requires_complete_nontriage_evidence": True,
            "vulnerability_knowledge_cutoff_is_explicit": True,
            "shared_sceg_ir_consumed": (sceg_ir is not None),
            "api_calls_reextracted_when_sceg_supplied": False,
            "package_identity_service_shared_with_tho_and_sceg": True,
            "import_only_unresolved_local_context_not_formal_avcs": True,
            "project_dependency_facts_schema": (
                project_facts.get("schema_version")
                if project_facts is not None
                else None
            ),
            "project_dependency_facts_shared_with_reachability": (
                project_facts is not None
            ),
            "project_dependency_facts_source": (
                "canonical_sceg_projection"
                if sceg_ir is not None and project_facts is not None
                else (
                    "project_source_extraction"
                    if project_root is not None and project_facts is not None
                    else "not_available"
                )
            ),
            "sceg_identity_contract_hashes_verified": (
                sceg_ir is not None
            ),
            "unsupported_candidate_is_not_identity_negative": True,
            "package_identity_candidate_is_not_avcs_scope_membership": True,
            "curated_scope_membership_is_pre_generation_method_input": True,
            "out_of_curated_scope_is_not_negative": True,
            "out_of_curated_scope_is_not_metric_eligible": True,
            "in_scope_missing_method_support_is_contract_failure": True,
            "stdlib_local_false_positive_excluded_before_avcs_coverage": True,
            "resume_requires_input_runtime_digest_match": True,
            "resume_requires_required_output_hash_match": True,
            "post_sceg_external_code_not_required": (
                sceg_ir is not None
            ),
            "post_sceg_external_sample_records_not_required": (
                sceg_ir is not None
            ),
            "validation_only_raw_inputs_excluded_from_resume_identity": (
                sceg_ir is not None
            ),
            "api_induced_actionability_policy": "C_AND_(A_OR_B)",
            "f10_advisor_confirmation_pending": False,
            "f10_advisor_confirmed": True,
            "f10_policy_status": "final_advisor_confirmed",
            "explicit_three_view_contract_supported": True,
            "oracle_now_formal_metrics_forbidden": True,
            "cross_view_output_overwrite_forbidden": True,
        },
    }
    write_json(out_dir / "manifest.json", summary)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Run the Step8 unified online AVCS flow over one generated "
            "Python code sample using the frozen Package KBs."
        )
    )
    parser.add_argument(
        "--code",
        type=Path,
        default=None,
        help=(
            "Generated code file. Required only without --sceg-ir. In SCEG "
            "mode this is optional validation-only input; if supplied, its "
            "hash must match the code snapshot bound into canonical SCEG."
        ),
    )
    parser.add_argument("--sample-id", required=True)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--sample-records", type=Path, default=None)
    parser.add_argument("--time-view", default=None)
    parser.add_argument(
        "--time-view-id",
        choices=sorted(FORMAL_TIME_VIEW_IDS),
        default=None,
        help="Explicit evaluation channel; required for future main experiments.",
    )
    parser.add_argument(
        "--time-view-snapshot-sha256",
        default=None,
        help="SHA-256 of the exact evidence snapshot bound to the named view.",
    )
    parser.add_argument(
        "--time-view-output-namespace",
        default=None,
        help="Relative namespace beginning with the named view ID.",
    )
    parser.add_argument(
        "--knowledge-time",
        default=None,
        help=(
            "Optional vulnerability/advisory knowledge cutoff. Defaults to "
            "--time-view (or the sample generation time) to avoid temporal "
            "leakage. Use an audit-time cutoff for retrospective analysis."
        ),
    )
    parser.add_argument(
        "--package-kb-dir",
        type=Path,
        default=DEFAULT_KB_DIR,
    )
    parser.add_argument(
        "--mapping",
        type=Path,
        default=DEFAULT_MAPPING,
        help="Compatibility provenance only; identity uses --identity-policy.",
    )
    parser.add_argument(
        "--identity-policy",
        type=Path,
        default=DEFAULT_IDENTITY_POLICY,
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        default=None,
    )
    parser.add_argument(
        "--curated-scope",
        type=Path,
        default=DEFAULT_CURATED_SCOPE,
        help=(
            "Frozen/candidate AVCS curated package-scope contract. Package "
            "identity candidacy does not imply membership in this scope."
        ),
    )
    parser.add_argument(
        "--sceg-ir",
        type=Path,
        default=None,
        help=(
            "Optional SCEG 2.1 shared IR. When supplied, AVCS consumes "
            "APICall and ManifestDep identities from the IR instead of "
            "re-extracting API calls from source code."
        ),
    )
    parser.add_argument(
        "--release-snapshot-manifest",
        type=Path,
        default=None,
        help=(
            "Optional frozen, hash-verified release snapshot manifest. "
            "When supplied, every supported analyzed package must be bound "
            "to an entry in this manifest."
        ),
    )
    parser.add_argument(
        "--distribution",
        action="append",
        default=[],
        help="Optional normalized/distribution filter; may be repeated.",
    )
    parser.add_argument("--theta-reduce", type=float, default=None)
    parser.add_argument("--theta-expose", type=float, default=None)
    parser.add_argument(
        "--threshold-policy",
        type=Path,
        default=DEFAULT_THRESHOLD_POLICY,
        help=(
            "Threshold policy artifact. Only status=frozen may turn "
            "threshold crossings into formal API-induced Risk Cards."
        ),
    )
    parser.add_argument(
        "--freeze-report",
        type=Path,
        default=DEFAULT_FREEZE_REPORT,
    )
    args = parser.parse_args()

    if (args.theta_reduce is None) != (args.theta_expose is None):
        raise SystemExit(
            "--theta-reduce and --theta-expose must be supplied together"
        )
    for name, value in [
        ("theta_reduce", args.theta_reduce),
        ("theta_expose", args.theta_expose),
    ]:
        if value is not None and not (0.0 <= value <= 1.0):
            raise SystemExit(f"{name} must be in [0,1]")

    result = run_unified_avcs(
        code_path=args.code,
        sample_id=args.sample_id,
        out_dir=args.out_dir,
        sample_records_path=args.sample_records,
        time_view=args.time_view,
        knowledge_time=args.knowledge_time,
        time_view_id=args.time_view_id,
        time_view_snapshot_sha256=args.time_view_snapshot_sha256,
        time_view_output_namespace=args.time_view_output_namespace,
        package_kb_dir=args.package_kb_dir,
        mapping_path=args.mapping,
        identity_policy_path=args.identity_policy,
        project_root=args.project_root,
        distributions=args.distribution,
        theta_reduce=args.theta_reduce,
        theta_expose=args.theta_expose,
        threshold_policy_path=args.threshold_policy,
        freeze_report_path=args.freeze_report,
        curated_scope_path=args.curated_scope,
        release_snapshot_manifest_path=args.release_snapshot_manifest,
        sceg_ir_path=args.sceg_ir,
    )

    print("\nSTEP8 UNIFIED ONLINE AVCS RUN PASS")
    print("sample_id =", result["sample_id"])
    print(
        "supported_analyzed_distributions =",
        result["supported_analyzed_distributions"],
    )
    print("package_analysis_count =", result["package_analysis_count"])
    print("risk_card_count =", result["risk_card_count"])
    print("step8_online_runner_started = True")
    print("step9_benchmark_started = False")
    print("saved =", rel(args.out_dir))


if __name__ == "__main__":
    main()
