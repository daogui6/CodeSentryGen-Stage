from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from normalizer import pep503_normalize
from normalize_osv_vulnerability import (
    normalize_osv_vulnerability,
)
from osv_pypi_release_ranges import analyze_sources


ROOT = Path(__file__).resolve().parents[1]

SCHEMA_VERSION = (
    "avcs_osv_package_catalog_v0.2"
)


def load_json(
    path: Path,
) -> dict[str, Any]:
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


def safe_component(
    value: str,
) -> str:
    cleaned = re.sub(
        r"[^A-Za-z0-9._-]+",
        "_",
        value.strip(),
    )

    return (
        cleaned
        or "unknown"
    )


def resolve_project_path(
    value: str,
) -> Path:
    path = Path(value)

    if path.is_absolute():
        return path

    return ROOT / path


def unique_sorted_strings(
    values: list[Any],
) -> list[str]:
    result = {
        str(value).strip()
        for value in values
        if str(value).strip()
    }

    return sorted(
        result
    )


def stable_json(
    value: Any,
) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def short_hash(
    value: str,
) -> str:
    digest = hashlib.sha256(
        value.encode(
            "utf-8"
        )
    ).hexdigest()

    return digest[:12]


class UnionFind:
    def __init__(self) -> None:
        self.parent: dict[
            str,
            str,
        ] = {}

    def add(
        self,
        value: str,
    ) -> None:
        if value not in self.parent:
            self.parent[
                value
            ] = value

    def find(
        self,
        value: str,
    ) -> str:
        self.add(
            value
        )

        parent = self.parent[
            value
        ]

        if parent != value:
            self.parent[
                value
            ] = self.find(
                parent
            )

        return self.parent[
            value
        ]

    def union(
        self,
        left: str,
        right: str,
    ) -> None:
        left_root = self.find(
            left
        )

        right_root = self.find(
            right
        )

        if (
            left_root
            == right_root
        ):
            return

        if left_root < right_root:
            self.parent[
                right_root
            ] = left_root
        else:
            self.parent[
                left_root
            ] = right_root


def normalize_identifier(
    value: Any,
) -> str:
    return str(
        value
    ).strip()


def collect_identifiers(
    evidence: dict[str, Any],
) -> list[str]:
    values: list[Any] = [
        evidence.get(
            "vulnerability_id",
            "",
        ),
    ]

    aliases = evidence.get(
        "aliases",
        [],
    )

    if isinstance(
        aliases,
        list,
    ):
        values.extend(
            aliases
        )

    return unique_sorted_strings(
        values
    )


def choose_display_id(
    identifiers: list[str],
) -> str:
    priority_prefixes = [
        "GHSA-",
        "CVE-",
        "PYSEC-",
    ]

    for prefix in (
        priority_prefixes
    ):
        matches = sorted(
            identifier
            for identifier
            in identifiers
            if identifier.upper().startswith(
                prefix
            )
        )

        if matches:
            return matches[0]

    return (
        identifiers[0]
        if identifiers
        else ""
    )


def canonical_ranges(
    evidence: dict[str, Any],
) -> list[Any]:
    ranges = evidence.get(
        "affected_ranges",
        [],
    )

    if not isinstance(
        ranges,
        list,
    ):
        return []

    encoded = sorted(
        stable_json(
            range_entry
        )
        for range_entry
        in ranges
        if isinstance(
            range_entry,
            dict,
        )
    )

    return [
        json.loads(
            item
        )
        for item
        in encoded
    ]


def build_range_variant(
    evidence: dict[str, Any],
) -> dict[str, Any]:
    return {
        "affected_ranges":
            canonical_ranges(
                evidence
            ),

        "fixed_versions":
            unique_sorted_strings(
                evidence.get(
                    "fixed_versions",
                    [],
                )
                if isinstance(
                    evidence.get(
                        "fixed_versions",
                        [],
                    ),
                    list,
                )
                else []
            ),
    }


def build_affected_version_variant(
    evidence: dict[str, Any],
) -> list[str]:
    versions = evidence.get(
        "affected_versions",
        [],
    )

    if not isinstance(
        versions,
        list,
    ):
        return []

    return unique_sorted_strings(
        versions
    )


def build_normalized_record(
    snapshot_record:
        dict[str, Any],
    distribution:
        str,
    ecosystem:
        str,
    queried_at:
        str | None,
    normalized_record_dir:
        Path,
) -> dict[str, Any]:
    raw_file_text = str(
        snapshot_record.get(
            "raw_osv_file",
            "",
        )
    ).strip()

    if not raw_file_text:
        raise RuntimeError(
            "Snapshot record is "
            "missing raw_osv_file."
        )

    raw_file = resolve_project_path(
        raw_file_text
    )

    if not raw_file.exists():
        raise FileNotFoundError(
            f"Raw OSV file "
            f"not found: "
            f"{raw_file}"
        )

    raw_record = load_json(
        raw_file
    )

    source_record_id = str(
        raw_record.get(
            "id",
            "",
        )
    ).strip()

    if not source_record_id:
        raise RuntimeError(
            f"Raw OSV file has "
            f"no id: {raw_file}"
        )

    normalized_distribution = (
        pep503_normalize(
            distribution
        )
    )

    synthetic_sample_id = (
        f"osv_catalog::"
        f"{ecosystem}::"
        f"{normalized_distribution}"
    )

    evidence = (
        normalize_osv_vulnerability(
            raw_record=
                raw_record,
            raw_file=
                raw_file,
            sample_id=
                synthetic_sample_id,
            distribution=
                distribution,
            ecosystem=
                ecosystem,
            queried_at=
                queried_at,
        )
    )

    package_dir = (
        normalized_record_dir
        / (
            f"{safe_component(ecosystem).lower()}"
            f"__"
            f"{normalized_distribution}"
        )
    )

    normalized_file = (
        package_dir
        / (
            f"{safe_component(source_record_id)}"
            ".json"
        )
    )

    write_json(
        normalized_file,
        evidence,
    )

    identifiers = (
        collect_identifiers(
            evidence
        )
    )

    source = evidence.get(
        "source",
        {},
    )

    if not isinstance(
        source,
        dict,
    ):
        source = {}

    return {
        "source_record_id":
            source_record_id,

        "aliases":
            unique_sorted_strings(
                evidence.get(
                    "aliases",
                    [],
                )
                if isinstance(
                    evidence.get(
                        "aliases",
                        [],
                    ),
                    list,
                )
                else []
            ),

        "identifiers":
            identifiers,

        "evidence_status":
            evidence.get(
                "evidence_status"
            ),

        "published_at":
            evidence.get(
                "published_at"
            ),

        "modified_at":
            evidence.get(
                "modified_at"
            ),

        "withdrawn_at":
            evidence.get(
                "withdrawn_at"
            ),

        "affected_ranges":
            evidence.get(
                "affected_ranges",
                [],
            ),

        "affected_versions":
            evidence.get(
                "affected_versions",
                [],
            ),

        "normalization_issues": evidence.get("normalization_issues", []),

        "fixed_versions":
            evidence.get(
                "fixed_versions",
                [],
            ),

        "fixed_commits":
            evidence.get(
                "fixed_commits",
                [],
            ),

        "matched_purls":
            evidence.get(
                "matched_purls",
                [],
            ),

        "raw_osv_file":
            raw_file_text.replace(
                "\\",
                "/",
            ),

        "normalized_evidence_file":
            str(
                normalized_file
            ).replace(
                "\\",
                "/",
            ),

        "source_url":
            source.get(
                "source_url"
            ),

        "evidence_hash":
            source.get(
                "evidence_hash"
            ),
    }


def build_identity_groups(
    records:
        list[dict[str, Any]],
    ecosystem: str = "PyPI",
) -> list[dict[str, Any]]:
    union_find = UnionFind()

    for record in records:
        identifiers = record.get(
            "identifiers",
            [],
        )

        if not isinstance(
            identifiers,
            list,
        ):
            continue

        normalized_identifiers = [
            normalize_identifier(
                identifier
            )
            for identifier
            in identifiers
            if normalize_identifier(
                identifier
            )
        ]

        if not normalized_identifiers:
            continue

        first = (
            normalized_identifiers[0]
        )

        union_find.add(
            first
        )

        for identifier in (
            normalized_identifiers[1:]
        ):
            union_find.union(
                first,
                identifier,
            )

    grouped_records: dict[
        str,
        list[dict[str, Any]],
    ] = {}

    for record in records:
        identifiers = record.get(
            "identifiers",
            [],
        )

        if not isinstance(
            identifiers,
            list,
        ):
            identifiers = []

        identifiers = [
            normalize_identifier(
                identifier
            )
            for identifier
            in identifiers
            if normalize_identifier(
                identifier
            )
        ]

        source_record_id = str(
            record.get(
                "source_record_id",
                "",
            )
        ).strip()

        if identifiers:
            root = union_find.find(
                identifiers[0]
            )
        else:
            root = (
                source_record_id
            )

        grouped_records.setdefault(
            root,
            [],
        ).append(
            record
        )

    groups: list[
        dict[str, Any]
    ] = []

    for group_records in (
        grouped_records.values()
    ):
        identifier_set: set[
            str
        ] = set()

        for record in group_records:
            for identifier in (
                record.get(
                    "identifiers",
                    [],
                )
            ):
                identifier_text = (
                    normalize_identifier(
                        identifier
                    )
                )

                if identifier_text:
                    identifier_set.add(
                        identifier_text
                    )

        identifiers = sorted(
            identifier_set
        )

        source_record_ids = sorted(
            str(
                record.get(
                    "source_record_id",
                    "",
                )
            )
            for record
            in group_records
            if str(
                record.get(
                    "source_record_id",
                    "",
                )
            ).strip()
        )

        range_variants_by_key: dict[
            str,
            dict[str, Any],
        ] = {}

        affected_versions_by_key: dict[
            str,
            dict[str, Any],
        ] = {}

        for record in group_records:
            source_record_id = str(
                record.get(
                    "source_record_id",
                    "",
                )
            )

            range_variant = (
                build_range_variant(
                    record
                )
            )

            range_key = stable_json(
                range_variant
            )

            if (
                range_key
                not in
                range_variants_by_key
            ):
                range_variants_by_key[
                    range_key
                ] = {
                    "variant_id":
                        (
                            "range_"
                            f"{short_hash(range_key)}"
                        ),

                    **range_variant,

                    "source_record_ids":
                        [],
                }

            range_variants_by_key[
                range_key
            ][
                "source_record_ids"
            ].append(
                source_record_id
            )

            affected_versions = (
                build_affected_version_variant(
                    record
                )
            )

            versions_key = stable_json(
                affected_versions
            )

            if (
                versions_key
                not in
                affected_versions_by_key
            ):
                affected_versions_by_key[
                    versions_key
                ] = {
                    "variant_id":
                        (
                            "versions_"
                            f"{short_hash(versions_key)}"
                        ),

                    "affected_versions":
                        affected_versions,

                    "source_record_ids":
                        [],
                }

            affected_versions_by_key[
                versions_key
            ][
                "source_record_ids"
            ].append(
                source_record_id
            )

        range_variants = list(
            range_variants_by_key.values()
        )

        affected_version_variants = (
            list(
                affected_versions_by_key.values()
            )
        )

        for variant in range_variants:
            variant[
                "source_record_ids"
            ] = sorted(
                set(
                    variant[
                        "source_record_ids"
                    ]
                )
            )

        for variant in (
            affected_version_variants
        ):
            variant[
                "source_record_ids"
            ] = sorted(
                set(
                    variant[
                        "source_record_ids"
                    ]
                )
            )

        evidence_status_counts: dict[
            str,
            int,
        ] = {}

        for record in group_records:
            status = str(
                record.get(
                    "evidence_status",
                    "unknown",
                )
            )

            evidence_status_counts[
                status
            ] = (
                evidence_status_counts.get(
                    status,
                    0,
                )
                + 1
            )

        group_identity_key = (
            "|".join(
                identifiers
            )
        )

        group_records = sorted(group_records, key=lambda row: str(row.get("source_record_id", "")))
        range_variants.sort(key=lambda row: row["variant_id"])
        affected_version_variants.sort(key=lambda row: row["variant_id"])
        groups.append(
            {
                "group_id":
                    (
                        "osvgrp_"
                        f"{short_hash(group_identity_key)}"
                    ),

                "display_id":
                    choose_display_id(
                        identifiers
                    ),

                "identifiers":
                    identifiers,

                "source_record_ids":
                    source_record_ids,

                "source_record_count":
                    len(
                        group_records
                    ),

                "evidence_status_counts":
                    evidence_status_counts,

                "range_variant_count":
                    len(
                        range_variants
                    ),

                "range_disagreement":
                    (
                        len(
                            range_variants
                        )
                        > 1
                    ),

                "range_evidence_variants":
                    range_variants,

                # Legacy flags above describe JSON structure only. This
                # additive analysis compares independent release claims.
                "range_disagreement_basis": "legacy_structure_only",
                "release_range_analysis": analyze_sources(group_records, ecosystem),

                "affected_version_list_variant_count":
                    len(
                        affected_version_variants
                    ),

                "affected_version_list_disagreement":
                    (
                        len(
                            affected_version_variants
                        )
                        > 1
                    ),

                "affected_version_list_variants":
                    affected_version_variants,

                "source_records":
                    sorted(
                        group_records,
                        key=lambda row: str(
                            row.get(
                                "source_record_id",
                                "",
                            )
                        ),
                    ),
            }
        )

    groups.sort(
        key=lambda group: (
            str(
                group.get(
                    "display_id",
                    "",
                )
            ),
            str(
                group.get(
                    "group_id",
                    "",
                )
            ),
        )
    )

    return groups


def build_catalog(
    snapshot_file:
        Path,
    normalized_record_dir:
        Path,
) -> dict[str, Any]:
    snapshot = load_json(
        snapshot_file
    )

    distribution = str(
        snapshot.get(
            "distribution",
            "",
        )
    ).strip()

    ecosystem = str(
        snapshot.get(
            "ecosystem",
            "",
        )
    ).strip()

    if not distribution:
        raise RuntimeError(
            "Snapshot is missing "
            "distribution."
        )

    if not ecosystem:
        raise RuntimeError(
            "Snapshot is missing "
            "ecosystem."
        )

    snapshot_records = (
        snapshot.get(
            "records",
            [],
        )
    )

    if not isinstance(
        snapshot_records,
        list,
    ):
        raise RuntimeError(
            "Snapshot records "
            "is not a list."
        )

    normalized_records: list[
        dict[str, Any]
    ] = []

    for snapshot_record in (
        snapshot_records
    ):
        if not isinstance(
            snapshot_record,
            dict,
        ):
            continue

        normalized_record = (
            build_normalized_record(
                snapshot_record=
                    snapshot_record,
                distribution=
                    distribution,
                ecosystem=
                    ecosystem,
                queried_at=
                    snapshot.get(
                        "query_queried_at"
                    ),
                normalized_record_dir=
                    normalized_record_dir,
            )
        )

        normalized_records.append(
            normalized_record
        )

    groups = build_identity_groups(
        normalized_records,
        ecosystem=ecosystem,
    )

    resolved_source_record_count = sum(
        1
        for record
        in normalized_records
        if record.get(
            "evidence_status"
        ) == "resolved"
    )

    partial_source_record_count = sum(
        1
        for record
        in normalized_records
        if record.get(
            "evidence_status"
        ) == "partial"
    )

    unresolved_source_record_count = (
        len(
            normalized_records
        )
        - resolved_source_record_count
        - partial_source_record_count
    )

    withdrawn_source_record_count = sum(
        1
        for record
        in normalized_records
        if record.get(
            "withdrawn_at"
        )
    )

    groups_with_range_disagreement = sum(
        1
        for group
        in groups
        if group.get(
            "range_disagreement"
        )
    )

    groups_with_version_list_disagreement = sum(
        1
        for group
        in groups
        if group.get(
            "affected_version_list_disagreement"
        )
    )

    return {
        "schema_version":
            SCHEMA_VERSION,

        "provider":
            "OSV",

        "distribution":
            distribution,

        "normalized_distribution":
            pep503_normalize(
                distribution
            ),

        "ecosystem":
            ecosystem,

        "source_snapshot_file":
            str(
                snapshot_file
            ).replace(
                "\\",
                "/",
            ),

        "source_snapshot_schema_version":
            snapshot.get(
                "schema_version"
            ),

        "source_query_data_source":
            snapshot.get(
                "query_data_source"
            ),

        "source_query_queried_at":
            snapshot.get(
                "query_queried_at"
            ),

        "normalizer_sample_id":
            (
                f"osv_catalog::"
                f"{ecosystem}::"
                f"{pep503_normalize(distribution)}"
            ),

        "source_record_count":
            len(
                normalized_records
            ),

        "resolved_source_record_count":
            resolved_source_record_count,

        "partial_source_record_count":
            partial_source_record_count,

        "unresolved_source_record_count":
            unresolved_source_record_count,

        "withdrawn_source_record_count":
            withdrawn_source_record_count,

        "vulnerability_group_count":
            len(
                groups
            ),

        "groups_with_range_disagreement":
            groups_with_range_disagreement,

        "groups_with_affected_version_list_disagreement":
            (
                groups_with_version_list_disagreement
            ),

        "normalized_records":
            normalized_records,

        "vulnerability_groups":
            groups,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Normalize all raw OSV "
            "records from one package "
            "snapshot and group related "
            "source records by aliases."
        )
    )

    parser.add_argument(
        "--snapshot",
        type=Path,
        required=True,
    )

    parser.add_argument(
        "--normalized-record-dir",
        type=Path,
        default=Path(
            "output/"
            "avcs_osv_normalized_cache"
        ),
    )

    parser.add_argument(
        "--out",
        type=Path,
        required=True,
    )

    args = parser.parse_args()

    result = build_catalog(
        snapshot_file=
            args.snapshot,
        normalized_record_dir=
            args.normalized_record_dir,
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
        f"[OK] ecosystem: "
        f"{result['ecosystem']}"
    )

    print(
        f"[OK] source records: "
        f"{result['source_record_count']}"
    )

    print(
        f"[OK] resolved source records: "
        f"{result['resolved_source_record_count']}"
    )

    print(
        f"[OK] partial source records: "
        f"{result['partial_source_record_count']}"
    )

    print(
        f"[OK] unresolved source records: "
        f"{result['unresolved_source_record_count']}"
    )

    print(
        f"[OK] vulnerability groups: "
        f"{result['vulnerability_group_count']}"
    )

    print(
        f"[OK] groups with range disagreement: "
        f"{result['groups_with_range_disagreement']}"
    )

    print(
        "[OK] groups with affected-version-list "
        f"disagreement: "
        f"{result['groups_with_affected_version_list_disagreement']}"
    )

    print(
        f"[OK] catalog saved to: "
        f"{args.out}"
    )


if __name__ == "__main__":
    main()
