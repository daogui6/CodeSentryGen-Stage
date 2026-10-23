from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from resolve_avcs_release_history import (
    build_release_view,
    parse_datetime,
)


ROOT = Path(__file__).resolve().parents[1]

FIXTURE_PATH = (
    ROOT
    / "data"
    / "avcs_validation"
    / "pypi_release_history_fixture.json"
)

OUTPUT_PATH = (
    ROOT
    / "output"
    / "avcs_release_history_validation.csv"
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


def main() -> None:
    data = json.loads(
        FIXTURE_PATH.read_text(
            encoding="utf-8"
        )
    )

    time_view = parse_datetime(
        "2024-07-01T00:00:00Z"
    )

    if time_view is None:
        raise RuntimeError(
            "fixture time view parse failed"
        )

    result = build_release_view(
        data=data,
        time_view=time_view,
    )

    confirmed = result[
        "confirmed_releases_as_of_time_view"
    ]

    confirmed_versions = [
        row["version"]
        for row in confirmed
    ]

    version_1_0 = next(
        row
        for row in confirmed
        if row["version"] == "1.0"
    )

    rows: list[dict[str, str]] = []

    add_check(
        rows,
        "registry_release_count",
        5,
        result["registry_release_count"],
    )

    add_check(
        rows,
        "release_count_with_files",
        3,
        result["release_count_with_files"],
    )

    add_check(
        rows,
        "release_without_file_evidence",
        ["0.9"],
        result[
            "release_labels_without_file_evidence"
        ],
    )

    add_check(
        rows,
        "invalid_version_label",
        ["not-a-version"],
        result["invalid_version_labels"],
    )

    add_check(
        rows,
        "confirmed_count_as_of_time_view",
        2,
        result[
            "confirmed_release_count_as_of_time_view"
        ],
    )

    add_check(
        rows,
        "confirmed_count_after_time_view",
        1,
        result[
            "confirmed_release_count_after_time_view"
        ],
    )

    add_check(
        rows,
        "confirmed_versions",
        ["1.0", "1.1rc1"],
        confirmed_versions,
    )

    add_check(
        rows,
        "latest_confirmed_version",
        "1.1rc1",
        result[
            "latest_confirmed_version_as_of_time_view"
        ],
    )

    add_check(
        rows,
        "earliest_file_upload_time",
        "2024-01-01T00:00:00+00:00",
        version_1_0["first_upload_time"],
    )

    add_check(
        rows,
        "prerelease_count",
        1,
        result[
            "confirmed_prerelease_count_as_of_time_view"
        ],
    )

    add_check(
        rows,
        "currently_yanked_count",
        1,
        result[
            "currently_yanked_confirmed_release_count"
        ],
    )

    add_check(
        rows,
        "history_status",
        "partial",
        result["release_history_status"],
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