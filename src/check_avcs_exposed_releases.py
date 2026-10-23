from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from resolve_avcs_exposed_releases import (
    build_exposed_release_view,
)


ROOT = Path(__file__).resolve().parents[1]

OUTPUT_PATH = (
    ROOT
    / "output"
    / "avcs_exposed_releases_validation.csv"
)


def add_check(
    rows: list[dict[str, str]],
    check_id: str,
    expected: Any,
    actual: Any,
) -> None:
    rows.append(
        {
            "check_id": check_id,
            "expected": json.dumps(
                expected,
                ensure_ascii=False,
                sort_keys=True,
            ),
            "actual": json.dumps(
                actual,
                ensure_ascii=False,
                sort_keys=True,
            ),
            "status": (
                "PASS"
                if actual == expected
                else "FAIL"
            ),
        }
    )


def make_release(
    version: str,
) -> dict[str, Any]:
    return {
        "version": version,
        "first_upload_time": (
            "2024-01-01T00:00:00+00:00"
        ),
        "file_count": 1,
        "currently_yanked_file_count": 0,
        "all_files_currently_yanked": False,
        "is_prerelease": False,
        "is_devrelease": False,
    }


def main() -> None:
    api_compatible = {
        "sample_id": "fixture_sample",
        "distribution": "DemoPkg",
        "normalized_distribution": "demopkg",
        "time_view": (
            "2024-07-01T00:00:00+00:00"
        ),
        "status": "resolved",
        "s_api": ">=1,<4",
        "release_history_status": "partial",
        "confirmed_api_compatible_releases": [
            make_release("1.0"),
            make_release("1.5"),
            make_release("2.0"),
            make_release("3.0"),
        ],
        "time_unknown_api_compatible_release_labels": [
            "2.5",
            "4.0",
        ],
    }

    vulnerability_constraints = {
        "vulnerabilities": [
            {
                "vulnerability_id": "CVE-TEST-0001",
                "severity": "high",
                "affected_version_specifier": (
                    ">=1.5,<3"
                ),
                "fixed_version_specifier": ">=3",
                "trigger_conditions": {
                    "api_symbols": [
                        "demo.danger"
                    ]
                },
                "safe_api_symbols": [
                    "demo.safe"
                ],
                "evidence_type": "fixture",
                "evidence_ref": "fixture-ref",
            }
        ]
    }

    result = build_exposed_release_view(
        api_compatible=api_compatible,
        vulnerability_constraints=(
            vulnerability_constraints
        ),
    )

    evaluation = result["evaluations"][0]

    exposed_versions = [
        row["version"]
        for row in evaluation[
            "confirmed_exposed_releases"
        ]
    ]

    not_affected_versions = [
        row["version"]
        for row in evaluation[
            "confirmed_not_affected_releases"
        ]
    ]

    unresolved_vulnerability_constraints = {
        "vulnerabilities": [
            {
                "vulnerability_id":
                    "CVE-TEST-UNRESOLVED",
                "severity": "high",

                "constraint_status":
                    "unsupported_range_shape",

                "affected_version_specifier":
                    "",

                "fixed_version_specifier":
                    "",

                "trigger_conditions": {
                    "api_symbols": [
                        "demo.danger"
                    ]
                },

                "safe_api_symbols": [],
                "evidence_type": "fixture",
                "evidence_ref":
                    "fixture-unresolved",
            }
        ]
    }

    unresolved_result = (
        build_exposed_release_view(
            api_compatible=api_compatible,
            vulnerability_constraints=(
                unresolved_vulnerability_constraints
            ),
        )
    )

    unresolved_evaluation = (
        unresolved_result[
            "evaluations"
        ][0]
    )

    rows: list[dict[str, str]] = []

    add_check(
        rows,
        "evaluation_count",
        1,
        result["evaluation_count"],
    )

    add_check(
        rows,
        "vulnerability_id",
        "CVE-TEST-0001",
        evaluation["vulnerability_id"],
    )

    add_check(
        rows,
        "s_vuln",
        ">=1.5,<3",
        evaluation["s_vuln"],
    )

    add_check(
        rows,
        "api_compatible_count",
        4,
        evaluation[
            "confirmed_api_compatible_release_count"
        ],
    )

    add_check(
        rows,
        "exposed_count",
        2,
        evaluation[
            "confirmed_exposed_release_count"
        ],
    )

    add_check(
        rows,
        "not_affected_count",
        2,
        evaluation[
            "confirmed_not_affected_release_count"
        ],
    )

    add_check(
        rows,
        "exposed_versions",
        ["1.5", "2.0"],
        exposed_versions,
    )

    add_check(
        rows,
        "not_affected_versions",
        ["1.0", "3.0"],
        not_affected_versions,
    )

    add_check(
        rows,
        "time_unknown_exposed",
        ["2.5"],
        evaluation[
            "time_unknown_exposed_release_labels"
        ],
    )

    add_check(
        rows,
        "unresolved_constraint_status",
        "unsupported_range_shape",
        unresolved_evaluation[
            "vulnerability_constraint_status"
        ],
    )

    add_check(
        rows,
        "unresolved_exposure_status",
        (
            "vulnerability_constraint_"
            "unsupported_range_shape"
        ),
        unresolved_evaluation[
            "status"
        ],
    )

    add_check(
        rows,
        "unresolved_exposed_count",
        None,
        unresolved_evaluation[
            "confirmed_exposed_release_count"
        ],
    )

    add_check(
        rows,
        "unresolved_not_affected_count",
        None,
        unresolved_evaluation[
            "confirmed_not_affected_release_count"
        ],
    )

    add_check(
        rows,
        "unresolved_exposed_versions",
        [],
        unresolved_evaluation[
            "confirmed_exposed_releases"
        ],
    )

    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with OUTPUT_PATH.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "check_id",
                "expected",
                "actual",
                "status",
            ],
        )

        writer.writeheader()
        writer.writerows(rows)

    passed = sum(
        row["status"] == "PASS"
        for row in rows
    )

    failed = len(rows) - passed

    print(
        f"[OK] total tests: {len(rows)}"
    )
    print(
        f"[OK] passed: {passed}"
    )
    print(
        f"[OK] failed: {failed}"
    )
    print(
        f"[OK] result saved to: "
        f"{OUTPUT_PATH}"
    )

    for row in rows:
        print(
            f"[{row['status']}] "
            f"{row['check_id']}"
        )

    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()