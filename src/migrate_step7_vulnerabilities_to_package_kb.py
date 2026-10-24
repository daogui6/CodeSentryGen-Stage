from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


def read_json(path: Path) -> dict[str, Any]:
    data = json.loads(
        path.read_text(
            encoding="utf-8-sig"
        )
    )

    if not isinstance(data, dict):
        raise ValueError(
            f"Expected JSON object: {path}"
        )

    return data


def write_json(
    path: Path,
    data: dict[str, Any],
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        json.dumps(
            data,
            ensure_ascii=False,
            indent=2,
        ) + "\n",
        encoding="utf-8",
    )


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()

    with path.open("rb") as handle:
        for chunk in iter(
            lambda: handle.read(
                1024 * 1024
            ),
            b"",
        ):
            h.update(chunk)

    return h.hexdigest()


def normalize_package(value: str) -> str:
    return re.sub(
        r"[-_.]+",
        "-",
        str(value).strip().lower(),
    )


def slug(value: str) -> str:
    return re.sub(
        r"[^a-zA-Z0-9]+",
        "_",
        str(value),
    ).strip("_").lower()


def unique_strings(
    values: Any,
) -> list[str]:

    if not isinstance(values, list):
        return []

    result = []

    for value in values:
        text = str(value).strip()

        if (
            text
            and text not in result
        ):
            result.append(text)

    return result


def identifier_set(
    vulnerability: dict[str, Any],
) -> set[str]:

    values = {
        str(
            vulnerability.get(
                "vulnerability_id",
                "",
            )
        ).strip().lower()
    }

    values.update(
        value.lower()
        for value in unique_strings(
            vulnerability.get(
                "aliases",
                [],
            )
        )
    )

    return {
        value
        for value in values
        if value
    }


def find_constraint(
    *,
    constraint_doc: dict[str, Any],
    identifiers: list[str],
) -> dict[str, Any]:

    wanted = {
        value.lower()
        for value in identifiers
        if value
    }

    matches = []

    for row in constraint_doc.get(
        "vulnerabilities",
        [],
    ):
        if not isinstance(row, dict):
            continue

        ids = identifier_set(row)

        if ids & wanted:
            matches.append(row)

    if len(matches) != 1:
        raise ValueError(
            "Expected exactly one constraint "
            f"match for {sorted(wanted)!r}, "
            f"got {len(matches)}"
        )

    return matches[0]


def find_catalog_group(
    *,
    catalog: dict[str, Any],
    group_id: str,
) -> dict[str, Any]:

    matches = [
        row
        for row in catalog.get(
            "vulnerability_groups",
            [],
        )
        if (
            isinstance(row, dict)
            and str(
                row.get(
                    "group_id",
                    "",
                )
            ).strip()
            == group_id
        )
    ]

    if len(matches) != 1:
        raise ValueError(
            "Expected exactly one catalog group "
            f"{group_id!r}; got {len(matches)}"
        )

    return matches[0]


def artifact_ref(
    *,
    role: str,
    path: Path,
    status: str,
) -> dict[str, Any]:

    doc = read_json(path)

    return {
        "role":
            role,

        "path":
            path.as_posix(),

        "schema_version":
            doc.get(
                "schema_version"
            ),

        "status":
            status,

        "sha256":
            sha256_file(path),

        "generated_at":
            None,

        "notes":
            (
                "Step7 vulnerability/version "
                "catalog input. No Trigger "
                "semantic judgment is implied."
            ),
    }


def build_source_id(
    *,
    package: str,
    display_id: str,
    group_id: str,
) -> str:

    digest = hashlib.sha256(
        group_id.encode(
            "utf-8"
        )
    ).hexdigest()[:8]

    return (
        "step7_osv_"
        + slug(package)
        + "_"
        + slug(display_id)
        + "_"
        + digest
    )


def build_vulnerability_record(
    *,
    package: str,
    case: dict[str, Any],
    constraint: dict[str, Any],
    source_id: str,
    constraint_source_id: str,
) -> dict[str, Any]:

    vulnerability_id = str(
        constraint.get(
            "vulnerability_id",
            case[
                "display_id"
            ],
        )
    ).strip()

    aliases = unique_strings(
        constraint.get(
            "aliases",
            [],
        )
    )

    affected_specifier = str(
        constraint.get(
            "affected_version_specifier",
            "",
        )
    ).strip()

    if not affected_specifier:
        raise ValueError(
            "Resolved semantic-ready case has "
            "empty affected_version_specifier: "
            + vulnerability_id
        )

    if (
        constraint.get(
            "constraint_status"
        )
        != "resolved"
    ):
        raise ValueError(
            "Cannot migrate unresolved constraint: "
            + vulnerability_id
            + " status="
            + repr(
                constraint.get(
                    "constraint_status"
                )
            )
        )

    fixed_versions = unique_strings(
        constraint.get(
            "fixed_versions",
            [],
        )
    )

    fixed = (
        fixed_versions[0]
        if len(
            fixed_versions
        ) == 1
        else None
    )

    return {
        "vulnerability_id":
            vulnerability_id,

        "aliases":
            aliases,

        "summary":
            None,

        "published_at":
            None,

        "modified_at":
            None,

        "withdrawn_at":
            None,

        "severity":
            [],

        "affected_ranges": [
            {
                "range_type":
                    "OSV_ECOSYSTEM_DERIVED",

                "introduced":
                    None,

                "fixed":
                    fixed,

                "last_affected":
                    None,

                "version_specifier":
                    affected_specifier,

                "source_ref":
                    constraint_source_id,
            }
        ],

        "fixed_versions":
            fixed_versions,

        "source_refs": [
            source_id,
            constraint_source_id,
        ],

        "trigger_assessment": {
            "status":
                "not_assessed",

            "review_required":
                True,

            "coverage_status":
                "not_assessed",

            "affected_version_scope":
                affected_specifier,

            "assessed_trigger_version_scope":
                None,

            "uncovered_scope_note":
                (
                    "Trigger semantics have not "
                    "yet been reviewed."
                ),

            "rule_refs":
                [],

            "evidence_refs": [
                source_id,
                constraint_source_id,
            ],

            "unsupported_reasons":
                [],

            "positive_regression_refs":
                [],

            "negative_regression_refs":
                [],

            "notes":
                (
                    "Version evidence was "
                    "mechanically migrated from "
                    "the Step7 OSV catalog and "
                    "constraint resolver. "
                    "No Trigger eligibility "
                    "judgment has been created."
                ),
        },

        "review": {
            "status":
                "not_reviewed",

            "review_required":
                True,

            "reviewer":
                None,

            "reviewed_at":
                None,

            "protocol_version":
                "avcs_trigger_eligibility_protocol_v0.2",

            "notes":
                (
                    "Awaiting HITL Trigger "
                    "semantic review."
                ),
        },

        "notes":
            (
                "Step7 semantic-ready "
                "vulnerability/version record. "
                "Package/API History, affected "
                "version range, and Trigger "
                "semantics remain separate "
                "evidence layers."
            ),
    }


def assert_append_only_existing_kb(
    *,
    before: dict[str, Any],
    after: dict[str, Any],
    added: int,
    package: str,
) -> None:
    """
    Fail closed unless an existing curated Package KB
    changed only by appending new vulnerability/version
    records and their provenance.

    Existing vulnerability semantics, Trigger rules,
    package-level review, API History, release history,
    metadata, and provenance notes must remain identical.
    """

    before_vulnerabilities = before.get(
        "vulnerability_catalog",
        [],
    )
    after_vulnerabilities = after.get(
        "vulnerability_catalog",
        [],
    )

    if (
        not isinstance(
            before_vulnerabilities,
            list,
        )
        or not isinstance(
            after_vulnerabilities,
            list,
        )
    ):
        raise ValueError(
            "vulnerability_catalog must be a list "
            f"for append-only migration: {package}"
        )

    if (
        after_vulnerabilities[
            :len(before_vulnerabilities)
        ]
        != before_vulnerabilities
    ):
        raise ValueError(
            "Append-only violation: existing "
            "vulnerability_catalog entries changed "
            f"for {package}"
        )

    if (
        len(after_vulnerabilities)
        != len(before_vulnerabilities) + added
    ):
        raise ValueError(
            "Append-only violation: vulnerability count "
            f"mismatch for {package}"
        )

    before_provenance = before.get(
        "provenance",
        {},
    )
    after_provenance = after.get(
        "provenance",
        {},
    )

    if (
        not isinstance(
            before_provenance,
            dict,
        )
        or not isinstance(
            after_provenance,
            dict,
        )
    ):
        raise ValueError(
            "provenance must be an object "
            f"for append-only migration: {package}"
        )

    before_sources = before_provenance.get(
        "sources",
        [],
    )
    after_sources = after_provenance.get(
        "sources",
        [],
    )

    if (
        after_sources[
            :len(before_sources)
        ]
        != before_sources
    ):
        raise ValueError(
            "Append-only violation: existing "
            f"provenance.sources changed for {package}"
        )

    if (
        len(after_sources)
        != len(before_sources) + 2 * added
    ):
        raise ValueError(
            "Append-only violation: expected exactly "
            "two new provenance sources per vulnerability "
            f"for {package}"
        )

    before_generated = before_provenance.get(
        "generated_from",
        [],
    )
    after_generated = after_provenance.get(
        "generated_from",
        [],
    )

    if (
        after_generated[
            :len(before_generated)
        ]
        != before_generated
    ):
        raise ValueError(
            "Append-only violation: existing "
            f"provenance.generated_from changed for {package}"
        )

    def stable_projection(
        doc: dict[str, Any],
    ) -> dict[str, Any]:
        stable = copy.deepcopy(
            doc
        )

        stable[
            "vulnerability_catalog"
        ] = []

        provenance = stable.get(
            "provenance"
        )

        if isinstance(
            provenance,
            dict,
        ):
            provenance[
                "sources"
            ] = []

            provenance[
                "generated_from"
            ] = []

        return stable

    if (
        stable_projection(before)
        != stable_projection(after)
    ):
        raise ValueError(
            "Append-only violation: a protected "
            "Package KB semantic field changed "
            f"for {package}"
        )


def main() -> None:

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--case-plan",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--base-kb-dir",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--out-dir",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--lane",
        action="append",
        default=[],
        help=(
            "Restrict migration to explicit Case Plan "
            "lane(s). May be repeated."
        ),
    )

    parser.add_argument(
        "--package",
        action="append",
        default=[],
        help=(
            "Restrict migration to explicit normalized "
            "package(s). May be repeated."
        ),
    )

    parser.add_argument(
        "--expected-count",
        type=int,
        default=None,
        help=(
            "Fail closed unless the selected case count "
            "matches this value."
        ),
    )

    parser.add_argument(
        "--append-only-existing-kb",
        action="store_true",
        help=(
            "Use strict append-only semantics for existing "
            "curated Package KBs. Only vulnerability_catalog, "
            "provenance.sources, and provenance.generated_from "
            "may grow."
        ),
    )

    args = parser.parse_args()

    plan = read_json(
        args.case_plan
    )

    pending_cases = [
        row
        for row in plan.get(
            "pending_cases",
            [],
        )
        if isinstance(
            row,
            dict,
        )
    ]

    wanted_lanes = {
        str(value).strip()
        for value in args.lane
        if str(value).strip()
    }

    requested_packages = {
        normalize_package(value)
        for value in args.package
        if str(value).strip()
    }

    if args.append_only_existing_kb:
        if wanted_lanes != {
            "requires_vulnerability_migration"
        }:
            raise ValueError(
                "--append-only-existing-kb requires exactly "
                "--lane requires_vulnerability_migration"
            )

        if not requested_packages:
            raise ValueError(
                "--append-only-existing-kb requires an "
                "explicit --package allowlist."
            )

    if wanted_lanes:
        pending_cases = [
            row
            for row in pending_cases
            if str(
                row.get(
                    "lane",
                    "",
                )
            ).strip()
            in wanted_lanes
        ]

    #
    # Select cases by the Package KB bases that
    # this invocation can actually build from,
    # rather than by a transient Case Plan lane.
    #
    # After formal promotion the same cases move
    # from requires_base_kb_initialization to
    # formal_kb_ready. Reproduction must therefore
    # remain stable across that state transition.
    #
    suffix = "_package_kb_v0.json"

    base_packages = {
        path.name[
            :-len(suffix)
        ]
        for path
        in args.base_kb_dir.glob(
            f"*{suffix}"
        )
        if path.name.endswith(
            suffix
        )
    }

    cases = [
        row
        for row in pending_cases
        if (
            normalize_package(
                row.get(
                    "normalized_package",
                    "",
                )
            )
            in base_packages
            and (
                not requested_packages
                or normalize_package(
                    row.get(
                        "normalized_package",
                        "",
                    )
                )
                in requested_packages
            )
        )
    ]

    if not cases:
        raise ValueError(
            "No pending cases match the Package KB "
            "bases and explicit selection."
        )

    actual_packages = {
        normalize_package(
            row.get(
                "normalized_package",
                "",
            )
        )
        for row in cases
    }

    if requested_packages:
        missing_packages = (
            requested_packages
            - actual_packages
        )

        if missing_packages:
            raise ValueError(
                "Requested packages have no selected cases: "
                + repr(
                    sorted(
                        missing_packages
                    )
                )
            )

    if (
        args.expected_count is not None
        and len(cases) != args.expected_count
    ):
        raise ValueError(
            "Selected case count mismatch: "
            f"{len(cases)} != {args.expected_count}"
        )

    grouped: dict[
        str,
        list[dict[str, Any]],
    ] = defaultdict(list)

    for case in cases:
        grouped[
            normalize_package(
                case[
                    "normalized_package"
                ]
            )
        ].append(case)

    args.out_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    total_added = 0

    summary = {}

    for package, package_cases in sorted(
        grouped.items()
    ):

        base_path = (
            args.base_kb_dir
            / (
                package
                + "_package_kb_v0.json"
            )
        )

        if not base_path.exists():
            raise ValueError(
                "Missing base KB: "
                + str(base_path)
            )

        kb = copy.deepcopy(
            read_json(
                base_path
            )
        )

        before_kb = (
            copy.deepcopy(
                kb
            )
            if args.append_only_existing_kb
            else None
        )

        existing_ids = set()

        for vuln in kb.get(
            "vulnerability_catalog",
            [],
        ):
            existing_ids.update(
                identifier_set(
                    vuln
                )
            )

        source_ids = {
            str(
                row.get(
                    "source_id",
                    "",
                )
            )
            for row in kb.get(
                "provenance",
                {},
            ).get(
                "sources",
                [],
            )
            if isinstance(
                row,
                dict,
            )
        }

        constraints_cache = {}
        catalog_cache = {}

        added = 0

        for case in sorted(
            package_cases,
            key=lambda row:
                str(
                    row[
                        "display_id"
                    ]
                ).lower(),
        ):

            identifiers = unique_strings(
                case.get(
                    "identifiers",
                    [],
                )
            )

            display_id = str(
                case[
                    "display_id"
                ]
            ).strip()

            if display_id not in identifiers:
                identifiers = [
                    display_id,
                    *identifiers,
                ]

            wanted = {
                value.lower()
                for value
                in identifiers
            }

            overlap = (
                existing_ids
                & wanted
            )

            if overlap:
                raise ValueError(
                    "Vulnerability already exists "
                    f"in base KB {package}: "
                    f"{sorted(overlap)}"
                )

            constraint_path = Path(
                case[
                    "constraint_file"
                ]
            )

            catalog_path = Path(
                case[
                    "catalog_file"
                ]
            )

            if (
                not constraint_path.exists()
            ):
                raise ValueError(
                    "Missing constraint file: "
                    + str(
                        constraint_path
                    )
                )

            if not catalog_path.exists():
                raise ValueError(
                    "Missing catalog file: "
                    + str(
                        catalog_path
                    )
                )

            constraint_doc = (
                constraints_cache.setdefault(
                    constraint_path,
                    read_json(
                        constraint_path
                    ),
                )
            )

            catalog_doc = (
                catalog_cache.setdefault(
                    catalog_path,
                    read_json(
                        catalog_path
                    ),
                )
            )

            constraint = find_constraint(
                constraint_doc=
                    constraint_doc,

                identifiers=
                    identifiers,
            )

            group_id = str(
                case.get(
                    "group_id",
                    "",
                )
            ).strip()

            if not group_id:
                raise ValueError(
                    "Case has empty group_id: "
                    + display_id
                )

            catalog_group = (
                find_catalog_group(
                    catalog=
                        catalog_doc,

                    group_id=
                        group_id,
                )
            )

            group_identifiers = {
                str(value).strip().lower()
                for value
                in catalog_group.get(
                    "identifiers",
                    [],
                )
                if str(value).strip()
            }

            if not (
                group_identifiers
                & wanted
            ):
                raise ValueError(
                    "Catalog-group identifiers "
                    "do not match case identifiers: "
                    + display_id
                )

            source_id = build_source_id(
                package=
                    package,

                display_id=
                    display_id,

                group_id=
                    group_id,
            )

            constraint_source_id = (
                source_id
                + "_constraint"
            )

            for candidate_source_id in [
                source_id,
                constraint_source_id,
            ]:
                if candidate_source_id in source_ids:
                    raise ValueError(
                        "Duplicate provenance source_id: "
                        + candidate_source_id
                    )

            source_record_ids = (
                unique_strings(
                    case.get(
                        "source_record_ids",
                        [],
                    )
                )
            )

            kb[
                "provenance"
            ][
                "sources"
            ].append(
                {
                    "source_id":
                        source_id,

                    "source_type":
                        "osv_package_catalog_group",

                    "url":
                        None,

                    "path":
                        catalog_path.as_posix(),

                    "locator":
                        group_id,

                    "sha256":
                        sha256_file(
                            catalog_path
                        ),

                    "acquired_at":
                        None,

                    "claim":
                        (
                            "OSV package catalog "
                            "identity group for "
                            f"{display_id}; "
                            "used for vulnerability "
                            "identity and alias grouping. "
                            "The resolved affected-version "
                            "specifier is bound separately "
                            "to the constraint-resolver "
                            "source. "
                            "source_record_ids="
                            + repr(
                                source_record_ids
                            )
                        ),
                }
            )

            kb[
                "provenance"
            ][
                "sources"
            ].append(
                {
                    "source_id":
                        constraint_source_id,

                    "source_type":
                        "osv_resolved_version_constraint",

                    "url":
                        None,

                    "path":
                        constraint_path.as_posix(),

                    "locator":
                        display_id,

                    "sha256":
                        sha256_file(
                            constraint_path
                        ),

                    "acquired_at":
                        None,

                    "claim":
                        (
                            "Resolved affected-version "
                            "constraint for "
                            f"{display_id}: "
                            f"{constraint.get('affected_version_specifier')!r}; "
                            "constraint_status="
                            f"{constraint.get('constraint_status')!r}; "
                            "fixed_versions="
                            f"{constraint.get('fixed_versions', [])!r}."
                        ),
                }
            )

            source_ids.add(
                source_id
            )

            source_ids.add(
                constraint_source_id
            )

            vuln = build_vulnerability_record(
                package=
                    package,

                case=
                    case,

                constraint=
                    constraint,

                source_id=
                    source_id,

                constraint_source_id=
                    constraint_source_id,
            )

            kb[
                "vulnerability_catalog"
            ].append(
                vuln
            )

            existing_ids.update(
                identifier_set(
                    vuln
                )
            )

            added += 1

        #
        # One catalog + one constraint artifact
        # per package in generated_from.
        #
        unique_catalogs = sorted(
            {
                Path(
                    case[
                        "catalog_file"
                    ]
                )
                for case
                in package_cases
            },
            key=lambda p:
                p.as_posix(),
        )

        unique_constraints = sorted(
            {
                Path(
                    case[
                        "constraint_file"
                    ]
                )
                for case
                in package_cases
            },
            key=lambda p:
                p.as_posix(),
        )

        generated_from = kb[
            "provenance"
        ][
            "generated_from"
        ]

        existing_generated_paths = {
            str(
                row.get(
                    "path",
                    "",
                )
            ).replace(
                "\\",
                "/",
            )
            for row
            in generated_from
            if isinstance(
                row,
                dict,
            )
        }

        for path in unique_catalogs:

            if (
                path.as_posix()
                not in existing_generated_paths
            ):
                generated_from.append(
                    artifact_ref(
                        role=
                            "osv_package_catalog",

                        path=
                            path,

                        status=
                            "resolved",
                    )
                )

        for path in unique_constraints:

            if (
                path.as_posix()
                not in existing_generated_paths
            ):
                generated_from.append(
                    artifact_ref(
                        role=
                            "vulnerability_constraints",

                        path=
                            path,

                        status=
                            "resolved",
                    )
                )

        kb[
            "provenance"
        ][
            "notes"
        ] = (
            "Base API History KB plus Step7 "
            "OSV vulnerability/version records. "
            "All newly migrated vulnerabilities "
            "remain Trigger not_assessed until "
            "HITL semantic review."
        )

        #
        # Package-level review is still open.
        #
        kb[
            "review"
        ][
            "status"
        ] = "not_reviewed"

        kb[
            "review"
        ][
            "review_required"
        ] = True

        kb[
            "review"
        ][
            "notes"
        ] = (
            "Package/API History structure and "
            "vulnerability/version records are "
            "assembled. Trigger semantics remain "
            "unreviewed and are not formal truth."
        )

        if args.append_only_existing_kb:
            assert before_kb is not None

            if "review" in before_kb:
                kb[
                    "review"
                ] = copy.deepcopy(
                    before_kb[
                        "review"
                    ]
                )
            else:
                kb.pop(
                    "review",
                    None,
                )

            before_provenance = (
                before_kb.get(
                    "provenance",
                    {},
                )
            )

            if (
                isinstance(
                    before_provenance,
                    dict,
                )
                and "notes"
                in before_provenance
            ):
                kb[
                    "provenance"
                ][
                    "notes"
                ] = copy.deepcopy(
                    before_provenance[
                        "notes"
                    ]
                )
            else:
                kb[
                    "provenance"
                ].pop(
                    "notes",
                    None,
                )

            assert_append_only_existing_kb(
                before=before_kb,
                after=kb,
                added=added,
                package=package,
            )

        out_path = (
            args.out_dir
            / (
                package
                + "_package_kb_v0.json"
            )
        )

        write_json(
            out_path,
            kb,
        )

        summary[package] = {
            "added":
                added,

            "final_vulnerability_count":
                len(
                    kb[
                        "vulnerability_catalog"
                    ]
                ),

            "trigger_rule_count":
                len(
                    kb[
                        "trigger_rules"
                    ]
                ),
        }

        total_added += added

        print()
        print(
            "PACKAGE:",
            package
        )

        print(
            "added vulnerabilities:",
            added
        )

        print(
            "final vulnerabilities:",
            len(
                kb[
                    "vulnerability_catalog"
                ]
            )
        )

        print(
            "trigger rules:",
            len(
                kb[
                    "trigger_rules"
                ]
            )
        )

        print(
            "saved:",
            out_path
        )

    print()
    print("=" * 72)

    print(
        "STEP7 VULNERABILITY KB MIGRATION COMPLETE"
    )

    print(
        "package_count:",
        len(
            summary
        )
    )

    print(
        "total_added:",
        total_added
    )

    print(
        "per_package:",
        {
            key:
                value[
                    "added"
                ]
            for key, value
            in summary.items()
        }
    )

    if total_added != len(cases):
        raise ValueError(
            "Migration count mismatch: "
            f"{total_added} != {len(cases)}"
        )


if __name__ == "__main__":
    main()
