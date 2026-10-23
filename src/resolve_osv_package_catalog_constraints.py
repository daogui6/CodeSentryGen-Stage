from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from normalizer import pep503_normalize
from osv_pypi_release_ranges import analyze_sources


SCHEMA_VERSION = "vulnerability_constraint_v0.5"
SOURCE_MODE = "osv_package_catalog"


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )


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
        ),
        encoding="utf-8",
    )


def unique_sorted_strings(
    values: list[Any],
) -> list[str]:
    return sorted(
        {
            str(value).strip()
            for value in values
            if str(value).strip()
        }
    )


def get_single_range_variant(
    group: dict[str, Any],
) -> dict[str, Any] | None:
    variants = group.get(
        "range_evidence_variants",
        [],
    )

    if not isinstance(
        variants,
        list,
    ):
        return None

    if len(variants) != 1:
        return None

    variant = variants[0]

    if not isinstance(
        variant,
        dict,
    ):
        return None

    return variant


def get_single_affected_version_variant(
    group: dict[str, Any],
) -> list[str] | None:
    variants = group.get(
        "affected_version_list_variants",
        [],
    )

    if not isinstance(
        variants,
        list,
    ):
        return None

    if len(variants) != 1:
        return None

    variant = variants[0]

    if not isinstance(
        variant,
        dict,
    ):
        return None

    versions = variant.get(
        "affected_versions",
        [],
    )

    if not isinstance(
        versions,
        list,
    ):
        return None

    return unique_sorted_strings(
        versions
    )


def build_group_constraint(
    group: dict[str, Any],
    ecosystem: str = "PyPI",
) -> dict[str, Any]:
    group_id = str(
        group.get(
            "group_id",
            "",
        )
    ).strip()

    display_id = str(
        group.get(
            "display_id",
            "",
        )
    ).strip()

    identifiers = group.get(
        "identifiers",
        [],
    )

    if not isinstance(
        identifiers,
        list,
    ):
        identifiers = []

    identifiers = unique_sorted_strings(
        identifiers
    )

    source_record_ids = group.get(
        "source_record_ids",
        [],
    )

    if not isinstance(
        source_record_ids,
        list,
    ):
        source_record_ids = []

    source_record_ids = unique_sorted_strings(
        source_record_ids
    )

    aliases = [
        identifier
        for identifier in identifiers
        if identifier != display_id
    ]

    range_disagreement = bool(
        group.get(
            "range_disagreement",
            False,
        )
    )

    affected_version_list_disagreement = bool(
        group.get(
            "affected_version_list_disagreement",
            False,
        )
    )

    records = group.get("source_records", [])
    malformed_records = (not isinstance(records, list) or
                         any(not isinstance(record, dict) for record in records))
    if not isinstance(records, list):
        records = []
    records = [record for record in records if isinstance(record, dict)]
    # Never trust a persisted derived analysis or join independently stored
    # range/list variants. Re-evaluate each original source claim together.
    analysis = analyze_sources(records, ecosystem)
    actual_ids = [str(record.get("source_record_id", "")) for record in records]
    if (malformed_records or not source_record_ids or sorted(actual_ids) != source_record_ids
            or len(set(actual_ids)) != len(actual_ids)
            or group.get("source_record_count", len(records)) != len(records)):
        analysis.update(constraint_status="source_record_provenance_mismatch",
                        classification="insufficient_or_unsupported_release_evidence",
                        affected_version_specifier="", fixed_version_specifier="",
                        fixed_versions=[], affected_versions=[])
    constraint_status = analysis["constraint_status"]
    constraint_notes = [
        "Legacy range/list disagreement flags describe JSON structure only.",
        "Release consensus is evaluated source by source, including explicit versions.",
        "GIT ranges are retained without a commit-to-PyPI-release mapping.",
        "Single-interval constraints use public PEP 440 versions; disjoint unions remain unsupported.",
    ]
    affected_specifier = analysis["affected_version_specifier"]
    fixed_specifier = analysis["fixed_version_specifier"]
    fixed_versions = analysis["fixed_versions"]
    affected_versions = analysis["affected_versions"]

    return {
        "vulnerability_id":
            display_id,

        "aliases":
            aliases,

        "identity_group_id":
            group_id,

        "identity_group_identifiers":
            identifiers,

        "source_record_ids":
            source_record_ids,

        "source_record_count":
            group.get(
                "source_record_count",
                len(source_record_ids),
            ),

        "severity":
            "not_calibrated",

        "constraint_status":
            constraint_status,

        "constraint_notes":
            constraint_notes,

        "affected_version_specifier":
            affected_specifier,

        "fixed_version_specifier":
            fixed_specifier,

        "affected_versions":
            affected_versions,

        "fixed_versions":
            fixed_versions,

        "range_disagreement":
            range_disagreement,
        "range_disagreement_basis": "legacy_structure_only",
        "release_range_disagreement": analysis["range_disagreement"],
        "release_range_analysis": analysis,

        "affected_version_list_disagreement":
            affected_version_list_disagreement,

        "range_evidence_variants":
            group.get(
                "range_evidence_variants",
                [],
            ),

        "affected_version_list_variants":
            group.get(
                "affected_version_list_variants",
                [],
            ),

        # OSV package discovery only gives us
        # vulnerability/version evidence.
        # Trigger semantics remain a separate layer.
        "trigger_conditions": {},

        "safe_api_symbols": [],

        "evidence_type":
            "osv_package_catalog_group",

        "evidence_ref":
            group_id,

        "evidence_source": {
            "provider":
                "OSV",

            "source_mode":
                SOURCE_MODE,

            "source_record_ids":
                source_record_ids,
        },
    }


def resolve_catalog_constraints(
    catalog: dict[str, Any],
    distribution: str,
) -> dict[str, Any]:
    normalized_distribution = pep503_normalize(
        distribution
    )

    catalog_distribution = pep503_normalize(
        str(
            catalog.get(
                "normalized_distribution",
                catalog.get(
                    "distribution",
                    "",
                ),
            )
        )
    )

    if (
        catalog_distribution
        != normalized_distribution
    ):
        return {
            "schema_version":
                SCHEMA_VERSION,

            "source_schema_version":
                catalog.get(
                    "schema_version",
                    "",
                ),

            "source_mode":
                SOURCE_MODE,

            "distribution":
                distribution,

            "normalized_distribution":
                normalized_distribution,

            "status":
                "distribution_mismatch",

            "vulnerability_count":
                0,

            "resolved_vulnerability_count":
                0,

            "unresolved_vulnerability_count":
                0,

            "vulnerabilities":
                [],
        }

    groups = catalog.get(
        "vulnerability_groups",
        [],
    )

    if not isinstance(
        groups,
        list,
    ):
        groups = []

    vulnerabilities: list[
        dict[str, Any]
    ] = []

    for group in groups:
        if not isinstance(
            group,
            dict,
        ):
            continue

        vulnerabilities.append(
            build_group_constraint(
                group,
                ecosystem=str(catalog.get("ecosystem", "PyPI")),
            )
        )

    resolved_count = sum(
        1
        for vulnerability
        in vulnerabilities
        if vulnerability.get(
            "constraint_status"
        ) == "resolved"
    )

    unresolved_count = (
        len(vulnerabilities)
        - resolved_count
    )

    overall_status = (
        "resolved"
        if (
            vulnerabilities
            and unresolved_count == 0
        )
        else (
            "partial"
            if vulnerabilities
            else "no_vulnerabilities"
        )
    )

    return {
        "schema_version":
            SCHEMA_VERSION,

        "source_schema_version":
            catalog.get(
                "schema_version",
                "",
            ),

        "source_mode":
            SOURCE_MODE,

        "distribution":
            distribution,

        "normalized_distribution":
            normalized_distribution,

        "ecosystem":
            catalog.get(
                "ecosystem"
            ),

        "status":
            overall_status,

        "source_record_count":
            catalog.get(
                "source_record_count"
            ),

        "vulnerability_group_count":
            catalog.get(
                "vulnerability_group_count"
            ),

        "groups_with_range_disagreement":
            catalog.get(
                "groups_with_range_disagreement"
            ),

        "groups_with_affected_version_list_disagreement":
            catalog.get(
                "groups_with_affected_version_list_disagreement"
            ),

        "vulnerability_count":
            len(vulnerabilities),

        "groups_with_release_range_disagreement": sum(
            bool(row["release_range_disagreement"]) for row in vulnerabilities
        ),
        "groups_with_affected_release_set_disagreement": sum(
            bool(row["release_range_analysis"]["affected_release_set_disagreement"])
            for row in vulnerabilities
        ),

        "resolved_vulnerability_count":
            resolved_count,

        "unresolved_vulnerability_count":
            unresolved_count,

        "vulnerabilities":
            vulnerabilities,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Adapt one package-level OSV vulnerability "
            "catalog into the existing AVCS vulnerability "
            "constraint list format."
        )
    )

    parser.add_argument(
        "--catalog",
        type=Path,
        required=True,
    )

    parser.add_argument(
        "--distribution",
        required=True,
    )

    parser.add_argument(
        "--out",
        type=Path,
        required=True,
    )

    args = parser.parse_args()

    catalog = load_json(
        args.catalog
    )

    result = resolve_catalog_constraints(
        catalog=catalog,
        distribution=args.distribution,
    )

    write_json(
        args.out,
        result,
    )

    print(
        f"[OK] distribution: "
        f"{result['distribution']}"
    )

    print(
        f"[OK] source mode: "
        f"{result['source_mode']}"
    )

    print(
        f"[OK] status: "
        f"{result['status']}"
    )

    print(
        f"[OK] vulnerability groups: "
        f"{result['vulnerability_count']}"
    )

    print(
        f"[OK] resolved groups: "
        f"{result['resolved_vulnerability_count']}"
    )

    print(
        f"[OK] unresolved groups: "
        f"{result['unresolved_vulnerability_count']}"
    )

    print(
        f"[OK] result saved to: "
        f"{args.out}"
    )


if __name__ == "__main__":
    main()
