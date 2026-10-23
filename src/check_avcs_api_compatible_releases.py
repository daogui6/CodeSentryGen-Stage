from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from resolve_avcs_api_compatible_releases import (
    build_api_compatible_release_view,
)


ROOT = Path(__file__).resolve().parents[1]

OUTPUT_PATH = (
    ROOT
    / "output"
    / "avcs_api_compatible_releases_validation.csv"
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
        "is_prerelease": (
            "rc" in version
            or "b" in version
        ),
        "is_devrelease": False,
    }


def main() -> None:
    release_history = {
        "distribution": "DemoPkg",
        "normalized_distribution": "demopkg",
        "time_view": (
            "2024-07-01T00:00:00+00:00"
        ),
        "release_history_status": "partial",
        "release_history_evidence_scope": (
            "test_fixture"
        ),
        "confirmed_releases_as_of_time_view": [
            make_release("1.0"),
            make_release("1.5"),
            make_release("2.0b1"),
            make_release("2.0"),
            make_release("3.0"),
        ],
        "release_labels_without_file_evidence": [
            "0.9",
            "2.5",
        ],
        "invalid_version_labels": [],
    }

    api_constraints = {
        "sample_id": "fixture_sample",
        "distribution_constraints": [
            {
                "distribution": "DemoPkg",
                "normalized_distribution": (
                    "demopkg"
                ),
                "status": "resolved",
                "s_api": {
                    "raw_specifier": ">=1.5,<3",
                    "simplified_specifier": (
                        ">=1.5,<3"
                    ),
                },
            }
        ],
    }

    result = (
        build_api_compatible_release_view(
            release_history=release_history,
            api_constraints=api_constraints,
        )
    )

    compatible_versions = [
        row["version"]
        for row in result[
            "confirmed_api_compatible_releases"
        ]
    ]

    incompatible_versions = [
        row["version"]
        for row in result[
            "confirmed_api_incompatible_releases"
        ]
    ]

    rows: list[dict[str, str]] = []

    add_check(
        rows,
        "status",
        "resolved_with_partial_release_history",
        result["status"],
    )

    add_check(
        rows,
        "s_api",
        ">=1.5,<3",
        result["s_api"],
    )

    add_check(
        rows,
        "before_api_count",
        5,
        result[
            "confirmed_release_count_before_api"
        ],
    )

    add_check(
        rows,
        "compatible_count",
        3,
        result[
            "confirmed_api_compatible_release_count"
        ],
    )

    add_check(
        rows,
        "incompatible_count",
        2,
        result[
            "confirmed_api_incompatible_release_count"
        ],
    )

    add_check(
        rows,
        "compatible_versions",
        ["1.5", "2.0b1", "2.0"],
        compatible_versions,
    )

    add_check(
        rows,
        "incompatible_versions",
        ["1.0", "3.0"],
        incompatible_versions,
    )

    add_check(
        rows,
        "time_unknown_api_compatible",
        ["2.5"],
        result[
            "time_unknown_api_compatible_release_labels"
        ],
    )

    add_check(
        rows,
        "time_unknown_api_incompatible",
        ["0.9"],
        result[
            "time_unknown_api_incompatible_release_labels"
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