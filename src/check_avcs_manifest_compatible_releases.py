from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from resolve_avcs_manifest_compatible_releases import (
    build_manifest_compatible_release_view,
)


ROOT = Path(__file__).resolve().parents[1]
OUTPUT_PATH = ROOT / "output" / "avcs_manifest_compatible_releases_validation.csv"


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

def format_versions(result: dict[str, Any]) -> str:
    return "; ".join(
        str(release["version"])
        for release in result.get("confirmed_manifest_compatible_releases", [])
    )

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

    return {
        "sample_id": "sample_manifest_test",
        "distribution": "PyYAML",
        "normalized_distribution": "pyyaml",
        "time_view": "2026-06-17T08:15:25+00:00",
        "status": "resolved_with_partial_release_history",
        "release_history_status": "partial",
        "s_api": ">=5.1",
        "confirmed_api_compatible_release_count": len(versions),
        "confirmed_api_compatible_releases": [
            {"version": version}
            for version in versions
        ],
        "time_unknown_api_compatible_release_labels": [],
    }


def build_manifest_constraint(
    specifier: str,
    constraint_kind: str = "version_specifier",
) -> dict[str, Any]:
    return {
        "sample_id": "sample_manifest_test",
        "distribution": "PyYAML",
        "normalized_distribution": "pyyaml",
        "status": "resolved",
        "constraint_kind": constraint_kind,
        "specifier": specifier,
        "matched_requirements": [],
    }


def main() -> None:
    results: list[bool] = []

    api_compatible = build_api_compatible_fixture()

    unconstrained = build_manifest_compatible_release_view(
        api_compatible=api_compatible,
        manifest_constraints=build_manifest_constraint(
            specifier="",
            constraint_kind="unconstrained",
        ),
    )

    results.append(
        check(
            "unconstrained_count",
            unconstrained[
                "confirmed_manifest_compatible_release_count"
            ],
            18,
        )
    )

    results.append(
        check(
            "unconstrained_status",
            unconstrained["status"],
            "resolved_with_partial_release_history",
        )
    )

    versioned = build_manifest_compatible_release_view(
        api_compatible=api_compatible,
        manifest_constraints=build_manifest_constraint(
            specifier=">=5.4",
        ),
    )

    results.append(
        check(
            "versioned_count",
            versioned[
                "confirmed_manifest_compatible_release_count"
            ],
            8,
        )
    )

    results.append(
        check(
            "versioned_incompatible_count",
            versioned[
                "confirmed_manifest_incompatible_release_count"
            ],
            10,
        )
    )

    results.append(
        check(
            "versioned_versions",
            [
                release["version"]
                for release in versioned[
                    "confirmed_manifest_compatible_releases"
                ]
            ],
            [
                "5.4",
                "5.4.1",
                "6.0b1",
                "6.0",
                "6.0.1",
                "6.0.2rc1",
                "6.0.2",
                "6.0.3",
            ],
        )
    )

    sample_mismatch_manifest = build_manifest_constraint(
        specifier=">=5.4",
    )
    sample_mismatch_manifest["sample_id"] = "wrong_sample"

    sample_mismatch = build_manifest_compatible_release_view(
        api_compatible=api_compatible,
        manifest_constraints=sample_mismatch_manifest,
    )

    results.append(
        check(
            "sample_mismatch_status",
            sample_mismatch["status"],
            "sample_id_mismatch",
        )
    )

    distribution_mismatch_manifest = build_manifest_constraint(
        specifier=">=5.4",
    )
    distribution_mismatch_manifest[
        "normalized_distribution"
    ] = "requests"

    distribution_mismatch = build_manifest_compatible_release_view(
        api_compatible=api_compatible,
        manifest_constraints=distribution_mismatch_manifest,
    )

    results.append(
        check(
            "distribution_mismatch_status",
            distribution_mismatch["status"],
            "distribution_mismatch",
        )
    )

    conditional_manifest = build_manifest_constraint(
        specifier=">=5.4",
    )
    conditional_manifest["status"] = "conditional"

    conditional = build_manifest_compatible_release_view(
        api_compatible=api_compatible,
        manifest_constraints=conditional_manifest,
    )

    results.append(
        check(
            "conditional_count_unknown",
            conditional[
                "confirmed_manifest_compatible_release_count"
            ],
            None,
        )
    )

    results.append(
        check(
            "conditional_status",
            conditional["status"],
            "manifest_constraint_conditional",
        )
    )

    total = len(results)
    passed = sum(results)
    failed = total - passed

    validation_rows = [
        {
            "case_id": "unconstrained",
            "manifest_constraint": "PyYAML",
            "api_compatible_before": unconstrained[
                "confirmed_api_compatible_release_count_before_manifest"
            ],
            "manifest_compatible": unconstrained[
                "confirmed_manifest_compatible_release_count"
            ],
            "manifest_incompatible": unconstrained[
                "confirmed_manifest_incompatible_release_count"
            ],
            "result_status": unconstrained["status"],
            "compatible_versions": format_versions(unconstrained),
            "validation_status": (
                "PASS"
                if (
                        unconstrained[
                            "confirmed_manifest_compatible_release_count"
                        ] == 18
                        and unconstrained["status"]
                        == "resolved_with_partial_release_history"
                )
                else "FAIL"
            ),
        },
        {
            "case_id": "versioned",
            "manifest_constraint": "PyYAML>=5.4",
            "api_compatible_before": versioned[
                "confirmed_api_compatible_release_count_before_manifest"
            ],
            "manifest_compatible": versioned[
                "confirmed_manifest_compatible_release_count"
            ],
            "manifest_incompatible": versioned[
                "confirmed_manifest_incompatible_release_count"
            ],
            "result_status": versioned["status"],
            "compatible_versions": format_versions(versioned),
            "validation_status": (
                "PASS"
                if (
                        versioned[
                            "confirmed_manifest_compatible_release_count"
                        ] == 8
                        and versioned[
                            "confirmed_manifest_incompatible_release_count"
                        ] == 10
                )
                else "FAIL"
            ),
        },
        {
            "case_id": "sample_mismatch",
            "manifest_constraint": "PyYAML>=5.4 / wrong sample",
            "api_compatible_before": sample_mismatch[
                "confirmed_api_compatible_release_count_before_manifest"
            ],
            "manifest_compatible": sample_mismatch[
                "confirmed_manifest_compatible_release_count"
            ],
            "manifest_incompatible": sample_mismatch[
                "confirmed_manifest_incompatible_release_count"
            ],
            "result_status": sample_mismatch["status"],
            "compatible_versions": "",
            "validation_status": (
                "PASS"
                if sample_mismatch["status"] == "sample_id_mismatch"
                else "FAIL"
            ),
        },
        {
            "case_id": "distribution_mismatch",
            "manifest_constraint": "PyYAML>=5.4 / wrong package",
            "api_compatible_before": distribution_mismatch[
                "confirmed_api_compatible_release_count_before_manifest"
            ],
            "manifest_compatible": distribution_mismatch[
                "confirmed_manifest_compatible_release_count"
            ],
            "manifest_incompatible": distribution_mismatch[
                "confirmed_manifest_incompatible_release_count"
            ],
            "result_status": distribution_mismatch["status"],
            "compatible_versions": "",
            "validation_status": (
                "PASS"
                if distribution_mismatch["status"] == "distribution_mismatch"
                else "FAIL"
            ),
        },
        {
            "case_id": "conditional",
            "manifest_constraint": 'PyYAML>=5.4; python_version >= "3.10"',
            "api_compatible_before": conditional[
                "confirmed_api_compatible_release_count_before_manifest"
            ],
            "manifest_compatible": conditional[
                "confirmed_manifest_compatible_release_count"
            ],
            "manifest_incompatible": conditional[
                "confirmed_manifest_incompatible_release_count"
            ],
            "result_status": conditional["status"],
            "compatible_versions": "",
            "validation_status": (
                "PASS"
                if (
                        conditional[
                            "confirmed_manifest_compatible_release_count"
                        ] is None
                        and conditional["status"]
                        == "manifest_constraint_conditional"
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
                "api_compatible_before",
                "manifest_compatible",
                "manifest_incompatible",
                "result_status",
                "compatible_versions",
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