from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from normalizer import pep503_normalize


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CURATED_SCOPE = ROOT / "config" / "avcs_curated_scope_v1.json"

SCOPE_SCHEMA_VERSION = "codesentry_gen_avcs_curated_scope_v1"
ALLOWED_SCOPE_STATUSES = {
    "candidate_for_r5_method_freeze",
    "frozen_for_r5_method",
}


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return value


def load_curated_scope(
    path: Path = DEFAULT_CURATED_SCOPE,
) -> dict[str, Any]:
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(path)

    scope = read_json(path)
    if scope.get("schema_version") != SCOPE_SCHEMA_VERSION:
        raise ValueError("Unexpected AVCS curated-scope schema")
    if scope.get("status") not in ALLOWED_SCOPE_STATUSES:
        raise ValueError("AVCS curated-scope status is not usable")
    if scope.get("ecosystem") != "pypi":
        raise ValueError("AVCS curated-scope ecosystem must be pypi")
    if scope.get("claim_scope") != "avcs_curated_library_effectiveness":
        raise ValueError("Unexpected AVCS curated-scope claim_scope")
    if scope.get("membership_policy") != (
        "exact_pre_r4_pilot_step7_formal_package_inventory"
    ):
        raise ValueError("Unexpected AVCS curated-scope membership policy")

    raw_packages = scope.get("packages")
    if not isinstance(raw_packages, list) or not raw_packages:
        raise ValueError("AVCS curated-scope packages must be non-empty")

    packages = [
        pep503_normalize(str(value).strip())
        for value in raw_packages
        if str(value).strip()
    ]
    if len(packages) != len(raw_packages):
        raise ValueError("AVCS curated-scope contains an empty package")
    if packages != sorted(packages):
        raise ValueError("AVCS curated-scope packages must be sorted")
    if len(packages) != len(set(packages)):
        raise ValueError("AVCS curated-scope packages must be unique")

    expected_count = scope.get("expected_package_count")
    if expected_count != len(packages):
        raise ValueError(
            "AVCS curated-scope expected_package_count mismatch"
        )

    boundary = scope.get("scientific_boundary")
    if not isinstance(boundary, dict):
        raise ValueError("AVCS curated-scope scientific_boundary missing")
    required_true = (
        "package_identity_candidate_is_not_avcs_scope_membership",
        "registry_candidate_is_not_avcs_scope_membership",
        "scope_membership_is_independent_of_metric_eligibility",
        "out_of_curated_scope_is_not_negative",
        "out_of_curated_scope_is_not_unknown_vulnerability_evidence",
        "out_of_curated_scope_is_not_metric_eligible",
        "in_scope_missing_method_support_is_contract_failure",
        "unknown_review_is_not_false",
        "unsupported_is_not_negative",
        "formal_risk_taxonomy_unchanged",
        "f10_policy_unchanged",
    )
    missing = [
        key
        for key in required_true
        if boundary.get(key) is not True
    ]
    if missing:
        raise ValueError(
            "AVCS curated-scope scientific boundary mismatch: "
            + ",".join(missing)
        )

    result = json.loads(json.dumps(scope))
    result["packages"] = packages
    return result


def curated_scope_packages(scope: dict[str, Any]) -> set[str]:
    raw = scope.get("packages")
    if not isinstance(raw, list):
        raise ValueError("AVCS curated-scope packages missing")
    return {
        pep503_normalize(str(value).strip())
        for value in raw
        if str(value).strip()
    }


def classify_candidates(
    candidates: Iterable[str],
    scope: dict[str, Any],
) -> tuple[list[str], list[str]]:
    scope_packages = curated_scope_packages(scope)
    normalized = sorted(
        {
            pep503_normalize(str(value).strip())
            for value in candidates
            if str(value).strip()
        }
    )
    in_scope = [
        value for value in normalized if value in scope_packages
    ]
    out_of_scope = [
        value for value in normalized if value not in scope_packages
    ]
    return in_scope, out_of_scope
