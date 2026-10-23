from __future__ import annotations

import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

TARGET_VULNERABILITY_ID = (
    "GHSA-pq67-6m6q-mj2v"
)

TARGET_PYSEC_ID = (
    "PYSEC-2026-1999"
)

TARGET_CVE_ID = (
    "CVE-2025-50181"
)


def read_json(
    path: Path,
) -> dict[str, Any]:
    return json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )


def check(
    name: str,
    expected: Any,
    actual: Any,
) -> bool:
    passed = (
        expected == actual
    )

    status = (
        "PASS"
        if passed
        else "FAIL"
    )

    print(
        f"[{status}] {name} | "
        f"expected={expected!r} | "
        f"actual={actual!r}"
    )

    return passed


def check_true(
    name: str,
    actual: Any,
) -> bool:
    return check(
        name=name,
        expected=True,
        actual=bool(actual),
    )


def find_group(
    catalog: dict[str, Any],
    identifier: str,
) -> dict[str, Any]:
    groups = catalog.get(
        "vulnerability_groups",
        [],
    )

    if not isinstance(
        groups,
        list,
    ):
        return {}

    for group in groups:
        if not isinstance(
            group,
            dict,
        ):
            continue

        identifiers = group.get(
            "identifiers",
            [],
        )

        if (
            isinstance(
                identifiers,
                list,
            )
            and identifier
            in identifiers
        ):
            return group

    return {}


def find_constraint(
    constraints: dict[str, Any],
    identifier: str,
) -> dict[str, Any]:
    rows = constraints.get(
        "vulnerabilities",
        [],
    )

    if not isinstance(
        rows,
        list,
    ):
        return {}

    for row in rows:
        if not isinstance(
            row,
            dict,
        ):
            continue

        identifiers = row.get(
            "identity_group_identifiers",
            [],
        )

        if (
            isinstance(
                identifiers,
                list,
            )
            and identifier
            in identifiers
        ):
            return row

    return {}


def find_exposure(
    exposed: dict[str, Any],
    vulnerability_id: str,
) -> dict[str, Any]:
    rows = exposed.get(
        "evaluations",
        [],
    )

    if not isinstance(
        rows,
        list,
    ):
        return {}

    for row in rows:
        if not isinstance(
            row,
            dict,
        ):
            continue

        if (
            row.get(
                "vulnerability_id"
            )
            == vulnerability_id
        ):
            return row

    return {}


def main() -> None:
    snapshot = read_json(
        ROOT
        / "output"
        / (
            "avcs_urllib3_"
            "osv_package_snapshot_v0.json"
        )
    )

    catalog = read_json(
        ROOT
        / "output"
        / (
            "avcs_urllib3_"
            "osv_package_catalog_v0.json"
        )
    )

    constraints = read_json(
        ROOT
        / "output"
        / (
            "avcs_urllib3_"
            "osv_package_constraints_v0.json"
        )
    )

    exposed = read_json(
        ROOT
        / "output"
        / (
            "avcs_urllib3_"
            "osv_catalog_exposed_"
            "releases_v0.json"
        )
    )

    results: list[bool] = []

    snapshot_count = int(
        snapshot.get(
            "vulnerability_count",
            0,
        )
    )

    catalog_source_count = int(
        catalog.get(
            "source_record_count",
            0,
        )
    )

    catalog_group_count = int(
        catalog.get(
            "vulnerability_group_count",
            0,
        )
    )

    constraint_count = int(
        constraints.get(
            "vulnerability_count",
            0,
        )
    )

    resolved_count = int(
        constraints.get(
            "resolved_vulnerability_count",
            0,
        )
    )

    unresolved_count = int(
        constraints.get(
            "unresolved_vulnerability_count",
            0,
        )
    )

    evaluation_count = int(
        exposed.get(
            "evaluation_count",
            0,
        )
    )

    results.extend(
        [
            check(
                "snapshot distribution",
                "urllib3",
                snapshot.get(
                    "distribution"
                ),
            ),

            check(
                "snapshot ecosystem",
                "PyPI",
                snapshot.get(
                    "ecosystem"
                ),
            ),

            check_true(
                "snapshot has vulnerabilities",
                snapshot_count > 0,
            ),

            check(
                "snapshot/catalog source count",
                snapshot_count,
                catalog_source_count,
            ),

            check_true(
                "catalog has identity groups",
                catalog_group_count > 0,
            ),

            check_true(
                "alias grouping reduces source records",
                (
                    catalog_group_count
                    < catalog_source_count
                ),
            ),

            check(
                "catalog/constraint group count",
                catalog_group_count,
                constraint_count,
            ),

            check(
                "resolved + unresolved count",
                constraint_count,
                (
                    resolved_count
                    + unresolved_count
                ),
            ),

            check_true(
                "catalog preserves unresolved evidence",
                unresolved_count > 0,
            ),

            check(
                "constraint/exposure evaluation count",
                constraint_count,
                evaluation_count,
            ),

            check(
                "exposed sample id",
                (
                    "avcs_urllib3_"
                    "poolmanager_retries_true"
                ),
                exposed.get(
                    "sample_id"
                ),
            ),

            check(
                "exposed distribution",
                "urllib3",
                exposed.get(
                    "distribution"
                ),
            ),

            check(
                "S_api preserved",
                ">=1.9",
                exposed.get(
                    "s_api"
                ),
            ),
        ]
    )

    snapshot_ids = snapshot.get(
        "vulnerability_ids",
        [],
    )

    if not isinstance(
        snapshot_ids,
        list,
    ):
        snapshot_ids = []

    results.append(
        check_true(
            "target GHSA auto-discovered",
            (
                TARGET_VULNERABILITY_ID
                in snapshot_ids
            ),
        )
    )

    target_group = find_group(
        catalog,
        TARGET_VULNERABILITY_ID,
    )

    target_group_identifiers = (
        target_group.get(
            "identifiers",
            [],
        )
    )

    if not isinstance(
        target_group_identifiers,
        list,
    ):
        target_group_identifiers = []

    target_source_record_ids = (
        target_group.get(
            "source_record_ids",
            [],
        )
    )

    if not isinstance(
        target_source_record_ids,
        list,
    ):
        target_source_record_ids = []

    results.extend(
        [
            check(
                "target display id",
                TARGET_VULNERABILITY_ID,
                target_group.get(
                    "display_id"
                ),
            ),

            check_true(
                "target group contains GHSA",
                (
                    TARGET_VULNERABILITY_ID
                    in target_group_identifiers
                ),
            ),

            check_true(
                "target group contains PYSEC alias",
                (
                    TARGET_PYSEC_ID
                    in target_group_identifiers
                ),
            ),

            check_true(
                "target group contains CVE alias",
                (
                    TARGET_CVE_ID
                    in target_group_identifiers
                ),
            ),

            check_true(
                "target preserves GHSA source record",
                (
                    TARGET_VULNERABILITY_ID
                    in target_source_record_ids
                ),
            ),

            check_true(
                "target preserves PYSEC source record",
                (
                    TARGET_PYSEC_ID
                    in target_source_record_ids
                ),
            ),

            check(
                "target range disagreement",
                False,
                target_group.get(
                    "range_disagreement"
                ),
            ),

            check(
                (
                    "target affected-version-list "
                    "disagreement"
                ),
                False,
                target_group.get(
                    "affected_version_list_disagreement"
                ),
            ),
        ]
    )

    target_constraint = find_constraint(
        constraints,
        TARGET_VULNERABILITY_ID,
    )

    results.extend(
        [
            check(
                "target constraint status",
                "resolved",
                target_constraint.get(
                    "constraint_status"
                ),
            ),

            check(
                "target S_vuln",
                "<2.5.0",
                target_constraint.get(
                    "affected_version_specifier"
                ),
            ),

            check(
                "target fixed specifier",
                ">=2.5.0",
                target_constraint.get(
                    "fixed_version_specifier"
                ),
            ),

            check(
                "target constraint range disagreement",
                False,
                target_constraint.get(
                    "range_disagreement"
                ),
            ),
        ]
    )

    target_exposure = find_exposure(
        exposed,
        TARGET_VULNERABILITY_ID,
    )

    results.extend(
        [
            check(
                "target exposure status",
                "resolved",
                target_exposure.get(
                    "status"
                ),
            ),

            check(
                "target exposure constraint status",
                "resolved",
                target_exposure.get(
                    "vulnerability_constraint_status"
                ),
            ),

            check(
                "target exposure S_vuln",
                "<2.5.0",
                target_exposure.get(
                    "s_vuln"
                ),
            ),

            check(
                "target API-compatible releases",
                87,
                target_exposure.get(
                    (
                        "confirmed_api_compatible_"
                        "release_count"
                    )
                ),
            ),

            check(
                "target manifest-compatible releases",
                87,
                target_exposure.get(
                    (
                        "confirmed_manifest_compatible_"
                        "release_count"
                    )
                ),
            ),

            check(
                "target release candidates",
                87,
                target_exposure.get(
                    "release_candidate_count"
                ),
            ),

            check(
                "target exposed releases",
                81,
                target_exposure.get(
                    (
                        "confirmed_exposed_"
                        "release_count"
                    )
                ),
            ),

            check(
                "target not-affected releases",
                6,
                target_exposure.get(
                    (
                        "confirmed_not_affected_"
                        "release_count"
                    )
                ),
            ),
        ]
    )

    unresolved_evaluations = [
        row
        for row in exposed.get(
            "evaluations",
            [],
        )
        if (
            isinstance(
                row,
                dict,
            )
            and row.get(
                "status"
            )
            != "resolved"
        )
    ]

    unresolved_constraint_rows = [
        row
        for row in constraints.get(
            "vulnerabilities",
            [],
        )
        if (
            isinstance(
                row,
                dict,
            )
            and row.get(
                "constraint_status"
            )
            != "resolved"
        )
    ]

    results.extend(
        [
            check(
                "unresolved constraint propagation",
                len(
                    unresolved_constraint_rows
                ),
                len(
                    unresolved_evaluations
                ),
            ),

            check_true(
                "all unresolved exposures have no count",
                all(
                    row.get(
                        (
                            "confirmed_exposed_"
                            "release_count"
                        )
                    )
                    is None
                    for row
                    in unresolved_evaluations
                ),
            ),
        ]
    )

    passed = sum(
        1
        for result
        in results
        if result
    )

    total = len(
        results
    )

    print("")
    print(
        f"[SUMMARY] "
        f"{passed}/{total} PASS"
    )

    if passed != total:
        raise SystemExit(1)


if __name__ == "__main__":
    main()