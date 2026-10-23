from __future__ import annotations

import csv
from copy import deepcopy
from pathlib import Path
from typing import Any

from resolve_avcs_exposed_releases import build_exposed_release_view
from resolve_avcs_manifest_compatible_releases import (
    build_manifest_compatible_release_view,
)


ROOT = Path(__file__).resolve().parents[1]
OUTPUT_PATH = ROOT / "output" / "avcs_manifest_exposure_integration_validation.csv"


def check(
    name: str,
    actual: Any,
    expected: Any,
) -> bool:
    passed = actual == expected
    status = "PASS" if passed else "FAIL"

    print(
        f"[{status}] {name} | "
        f"expected={expected!r} | actual={actual!r}"
    )

    return passed


def build_api_compatible_fixture() -> dict[str, Any]:
    versions = [
        "5.1",
        "5.1.1",
        "5.1.2",
        "5.2b1",
        "5.2",
        "5.3b1",
        "5.3",
        "5.3.1",
        "5.4b1",
        "5.4b2",
        "5.4",
        "5.4.1",
        "6.0b1",
        "6.0",
        "6.0.1",
        "6.0.2rc1",
        "6.0.2",
        "6.0.3",
    ]

    releases = [
        {
            "version": version,
            "first_upload_time": "2024-01-01T00:00:00+00:00",
        }
        for version in versions
    ]

    return {
        "sample_id": "manifest_exposure_test",
        "distribution": "PyYAML",
        "normalized_distribution": "pyyaml",
        "time_view": "2026-06-17T08:15:25+00:00",
        "status": "resolved_with_partial_release_history",
        "release_history_status": "partial",
        "s_api": ">=5.1",
        "confirmed_api_compatible_release_count": 18,
        "confirmed_api_compatible_releases": releases,
        "time_unknown_api_compatible_release_labels": [],
    }


def build_manifest_constraint(
    specifier: str,
    constraint_kind: str,
) -> dict[str, Any]:
    return {
        "sample_id": "manifest_exposure_test",
        "distribution": "PyYAML",
        "normalized_distribution": "pyyaml",
        "status": "resolved",
        "constraint_kind": constraint_kind,
        "specifier": specifier,
        "matched_requirements": [],
    }


def build_vulnerability_constraints() -> dict[str, Any]:
    return {
        "vulnerabilities": [
            {
                "vulnerability_id": "CVE-2020-14343",
                "severity": "high",
                "affected_version_specifier": ">=5.1,<5.4",
                "fixed_version_specifier": ">=5.4",
                "trigger_conditions": {
                    "api_symbols": [
                        "yaml.full_load",
                        "yaml.load",
                    ]
                },
                "safe_api_symbols": [
                    "yaml.safe_load",
                ],
                "evidence_type": "controlled_fixture",
                "evidence_ref": "manifest-exposure-integration",
            }
        ]
    }


def main() -> None:
    results: list[bool] = []

    api_compatible = build_api_compatible_fixture()
    vulnerability_constraints = build_vulnerability_constraints()

    unconstrained_manifest = build_manifest_constraint(
        specifier="",
        constraint_kind="unconstrained",
    )

    unconstrained_releases = build_manifest_compatible_release_view(
        api_compatible=api_compatible,
        manifest_constraints=unconstrained_manifest,
    )

    unconstrained_exposure = build_exposed_release_view(
        api_compatible=api_compatible,
        vulnerability_constraints=vulnerability_constraints,
        manifest_compatible=unconstrained_releases,
    )

    unconstrained_evaluation = (
        unconstrained_exposure["evaluations"][0]
    )

    results.append(
        check(
            "unconstrained_manifest_candidate_count",
            unconstrained_evaluation["release_candidate_count"],
            18,
        )
    )

    results.append(
        check(
            "unconstrained_exposed_count",
            unconstrained_evaluation[
                "confirmed_exposed_release_count"
            ],
            8,
        )
    )

    versioned_manifest = build_manifest_constraint(
        specifier=">=5.4",
        constraint_kind="version_specifier",
    )

    versioned_releases = build_manifest_compatible_release_view(
        api_compatible=api_compatible,
        manifest_constraints=versioned_manifest,
    )

    versioned_exposure = build_exposed_release_view(
        api_compatible=api_compatible,
        vulnerability_constraints=vulnerability_constraints,
        manifest_compatible=versioned_releases,
    )

    versioned_evaluation = versioned_exposure["evaluations"][0]

    results.append(
        check(
            "versioned_manifest_candidate_count",
            versioned_evaluation["release_candidate_count"],
            8,
        )
    )

    results.append(
        check(
            "versioned_manifest_exposed_count",
            versioned_evaluation[
                "confirmed_exposed_release_count"
            ],
            0,
        )
    )

    results.append(
        check(
            "versioned_manifest_not_affected_count",
            versioned_evaluation[
                "confirmed_not_affected_release_count"
            ],
            8,
        )
    )

    results.append(
        check(
            "release_evidence_mode",
            versioned_exposure["release_evidence_mode"],
            "manifest_compatible",
        )
    )

    results.append(
        check(
            "manifest_context_status",
            versioned_exposure["manifest_context_status"],
            "matched",
        )
    )

    mismatched_manifest = deepcopy(versioned_releases)
    mismatched_manifest["sample_id"] = "wrong_sample"

    mismatched_exposure = build_exposed_release_view(
        api_compatible=api_compatible,
        vulnerability_constraints=vulnerability_constraints,
        manifest_compatible=mismatched_manifest,
    )

    mismatched_evaluation = mismatched_exposure["evaluations"][0]

    results.append(
        check(
            "mismatched_manifest_context",
            mismatched_exposure["manifest_context_status"],
            "sample_id_mismatch",
        )
    )

    results.append(
        check(
            "mismatched_exposure_unknown",
            mismatched_evaluation[
                "confirmed_exposed_release_count"
            ],
            None,
        )
    )

    total = len(results)
    passed = sum(results)
    failed = total - passed

    validation_rows = [
        {
            "case_id": "unconstrained",
            "manifest_constraint": "PyYAML",
            "release_candidate_count": unconstrained_evaluation[
                "release_candidate_count"
            ],
            "exposed_release_count": unconstrained_evaluation[
                "confirmed_exposed_release_count"
            ],
            "not_affected_release_count": unconstrained_evaluation[
                "confirmed_not_affected_release_count"
            ],
            "release_evidence_mode": unconstrained_exposure[
                "release_evidence_mode"
            ],
            "manifest_context_status": unconstrained_exposure[
                "manifest_context_status"
            ],
            "validation_status": (
                "PASS"
                if (
                        unconstrained_evaluation["release_candidate_count"] == 18
                        and unconstrained_evaluation[
                            "confirmed_exposed_release_count"
                        ] == 8
                )
                else "FAIL"
            ),
        },
        {
            "case_id": "versioned",
            "manifest_constraint": "PyYAML>=5.4",
            "release_candidate_count": versioned_evaluation[
                "release_candidate_count"
            ],
            "exposed_release_count": versioned_evaluation[
                "confirmed_exposed_release_count"
            ],
            "not_affected_release_count": versioned_evaluation[
                "confirmed_not_affected_release_count"
            ],
            "release_evidence_mode": versioned_exposure[
                "release_evidence_mode"
            ],
            "manifest_context_status": versioned_exposure[
                "manifest_context_status"
            ],
            "validation_status": (
                "PASS"
                if (
                        versioned_evaluation["release_candidate_count"] == 8
                        and versioned_evaluation[
                            "confirmed_exposed_release_count"
                        ] == 0
                        and versioned_evaluation[
                            "confirmed_not_affected_release_count"
                        ] == 8
                )
                else "FAIL"
            ),
        },
        {
            "case_id": "sample_mismatch",
            "manifest_constraint": "PyYAML>=5.4 / wrong sample",
            "release_candidate_count": "",
            "exposed_release_count": mismatched_evaluation[
                "confirmed_exposed_release_count"
            ],
            "not_affected_release_count": "",
            "release_evidence_mode": "",
            "manifest_context_status": mismatched_exposure[
                "manifest_context_status"
            ],
            "validation_status": (
                "PASS"
                if (
                        mismatched_exposure["manifest_context_status"]
                        == "sample_id_mismatch"
                        and mismatched_evaluation[
                            "confirmed_exposed_release_count"
                        ] is None
                )
                else "FAIL"
            ),
        },
    ]

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_PATH.open(
            "w",
            encoding="utf-8-sig",
            newline="",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "case_id",
                "manifest_constraint",
                "release_candidate_count",
                "exposed_release_count",
                "not_affected_release_count",
                "release_evidence_mode",
                "manifest_context_status",
                "validation_status",
            ],
        )
        writer.writeheader()
        writer.writerows(validation_rows)

    print()
    print(f"[OK] total tests: {total}")
    print(f"[OK] passed: {passed}")
    print(f"[OK] failed: {failed}")
    print(f"[OK] result saved to: {OUTPUT_PATH}")

    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()