from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

SCHEMA_VERSION = (
    "avcs_trigger_local_structured_acquisition_v0.1"
)

DEFAULT_PLAN = (
    ROOT
    / "output"
    / "avcs_trigger_source_acquisition_plan_v0.json"
)

DEFAULT_OSV_RAW_DIR = (
    ROOT
    / "data"
    / "avcs_validation"
    / "osv_raw"
)

DEFAULT_OUTPUT = (
    ROOT
    / "output"
    / "avcs_trigger_local_structured_acquisition_v0.json"
)

SUPPORTED_BACKENDS = {
    "local_evidence_file",
    "osv_api_record",
}


def load_json(
    path: Path,
) -> dict[str, Any]:
    data = json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )

    if not isinstance(
        data,
        dict,
    ):
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
        )
        + "\n",
        encoding="utf-8",
    )


def clean_text(
    value: Any,
) -> str:
    return str(
        value
        if value is not None
        else ""
    ).strip()


def sha256_file(
    path: Path,
) -> str:
    digest = hashlib.sha256()

    with path.open(
        "rb"
    ) as file_obj:
        for chunk in iter(
            lambda: file_obj.read(
                1024 * 1024
            ),
            b"",
        ):
            digest.update(
                chunk
            )

    return (
        "sha256:"
        f"{digest.hexdigest()}"
    )


def normalized_identifier(
    value: Any,
) -> str:
    return clean_text(
        value
    ).upper()


def osv_identifiers(
    record: dict[str, Any],
) -> list[str]:
    result: set[str] = set()

    primary_id = normalized_identifier(
        record.get(
            "id"
        )
    )

    if primary_id:
        result.add(
            primary_id
        )

    aliases = record.get(
        "aliases",
        [],
    )

    if isinstance(
        aliases,
        list,
    ):
        for alias in aliases:
            normalized = (
                normalized_identifier(
                    alias
                )
            )

            if normalized:
                result.add(
                    normalized
                )

    return sorted(
        result
    )


def path_under_root(
    path_text: str,
) -> tuple[
    Path | None,
    str,
]:
    """
    将 raw evidence 中的相对路径解析到项目根目录。

    同时阻止：
        ../../outside.json

    这样的路径逃逸。
    """
    path_text = clean_text(
        path_text
    )

    if not path_text:
        return (
            None,
            "missing_path",
        )

    candidate = (
        ROOT
        / Path(
            path_text
        )
    ).resolve()

    root_resolved = (
        ROOT.resolve()
    )

    try:
        candidate.relative_to(
            root_resolved
        )
    except ValueError:
        return (
            None,
            "path_outside_project_root",
        )

    if not candidate.exists():
        return (
            candidate,
            "file_not_found",
        )

    if not candidate.is_file():
        return (
            candidate,
            "path_not_file",
        )

    return (
        candidate,
        "resolved",
    )


def load_osv_records(
    raw_dir: Path,
) -> list[
    dict[str, Any]
]:
    records: list[
        dict[str, Any]
    ] = []

    for path in sorted(
        raw_dir.glob(
            "*.json"
        )
    ):
        try:
            record = load_json(
                path
            )
        except (
            OSError,
            ValueError,
            json.JSONDecodeError,
        ):
            continue

        identifiers = (
            osv_identifiers(
                record
            )
        )

        if not identifiers:
            continue

        records.append(
            {
                "path":
                    path,

                "record":
                    record,

                "primary_id":
                    normalized_identifier(
                        record.get(
                            "id"
                        )
                    ),

                "identifiers":
                    identifiers,
            }
        )

    return records


def resolve_osv_record(
    vulnerability_id: str,
    records: list[
        dict[str, Any]
    ],
) -> dict[str, Any]:
    requested_id = (
        normalized_identifier(
            vulnerability_id
        )
    )

    if not requested_id:
        return {
            "status":
                "unresolved",

            "reason":
                "missing_vulnerability_id",
        }

    exact_matches = [
        item
        for item in records
        if (
            item.get(
                "primary_id"
            )
            == requested_id
        )
    ]

    if len(
        exact_matches
    ) == 1:
        item = exact_matches[0]

        return {
            "status":
                "resolved",

            "matched_via":
                "primary_id",

            "item":
                item,
        }

    if len(
        exact_matches
    ) > 1:
        return {
            "status":
                "ambiguous",

            "reason":
                "multiple_primary_id_matches",

            "match_count":
                len(
                    exact_matches
                ),
        }

    alias_matches = [
        item
        for item in records
        if (
            requested_id
            in item.get(
                "identifiers",
                [],
            )
        )
    ]

    if len(
        alias_matches
    ) == 1:
        item = alias_matches[0]

        return {
            "status":
                "resolved",

            "matched_via":
                "alias",

            "item":
                item,
        }

    if len(
        alias_matches
    ) > 1:
        return {
            "status":
                "ambiguous",

            "reason":
                "multiple_alias_matches",

            "match_count":
                len(
                    alias_matches
                ),
        }

    return {
        "status":
            "unresolved",

        "reason":
            "no_local_osv_match",
    }


def relative_project_path(
    path: Path,
) -> str:
    try:
        return str(
            path.resolve().relative_to(
                ROOT.resolve()
            )
        ).replace(
            "\\",
            "/",
        )

    except ValueError:
        return str(
            path
        )


def acquire_local_evidence_file(
    source: dict[str, Any],
) -> dict[str, Any]:
    target = source.get(
        "target",
        {},
    )

    if not isinstance(
        target,
        dict,
    ):
        target = {}

    requested_path = clean_text(
        target.get(
            "path"
        )
    )

    (
        resolved_path,
        path_status,
    ) = path_under_root(
        requested_path
    )

    result: dict[
        str,
        Any,
    ] = {
        "source_key":
            clean_text(
                source.get(
                    "source_key"
                )
            ),

        "distribution":
            clean_text(
                source.get(
                    "distribution"
                )
            ),

        "source_id":
            clean_text(
                source.get(
                    "source_id"
                )
            ),

        "source_type":
            clean_text(
                source.get(
                    "source_type"
                )
            ),

        "acquisition_backend":
            "local_evidence_file",

        "acquisition_mode":
            "local_frozen_file",

        "requested_path":
            requested_path,

        "status":
            path_status,
    }

    if (
        path_status
        != "resolved"
        or resolved_path is None
    ):
        return result

    try:
        data = load_json(
            resolved_path
        )

    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        result[
            "status"
        ] = "invalid_json"

        result[
            "error"
        ] = str(
            exc
        )

        return result

    result.update(
        {
            "status":
                "resolved",

            "local_path":
                relative_project_path(
                    resolved_path
                ),

            "sha256":
                sha256_file(
                    resolved_path
                ),

            "size_bytes":
                resolved_path.stat().st_size,

            "content_kind":
                "json",

            "record_id":
                clean_text(
                    data.get(
                        "id"
                    )
                ),

            "record_identifiers":
                osv_identifiers(
                    data
                ),
        }
    )

    return result


def acquire_osv_api_record(
    source: dict[str, Any],
    osv_records: list[
        dict[str, Any]
    ],
) -> dict[str, Any]:
    target = source.get(
        "target",
        {},
    )

    if not isinstance(
        target,
        dict,
    ):
        target = {}

    requested_id = clean_text(
        target.get(
            "vulnerability_id"
        )
    )

    resolution = resolve_osv_record(
        requested_id,
        osv_records,
    )

    result: dict[
        str,
        Any,
    ] = {
        "source_key":
            clean_text(
                source.get(
                    "source_key"
                )
            ),

        "distribution":
            clean_text(
                source.get(
                    "distribution"
                )
            ),

        "source_id":
            clean_text(
                source.get(
                    "source_id"
                )
            ),

        "source_type":
            clean_text(
                source.get(
                    "source_type"
                )
            ),

        "acquisition_backend":
            "osv_api_record",

        "acquisition_mode":
            "local_osv_mirror",

        "requested_vulnerability_id":
            requested_id,

        "status":
            clean_text(
                resolution.get(
                    "status"
                )
            ),
    }

    if (
        resolution.get(
            "status"
        )
        != "resolved"
    ):
        result[
            "reason"
        ] = clean_text(
            resolution.get(
                "reason"
            )
        )

        result[
            "match_count"
        ] = resolution.get(
            "match_count",
            0,
        )

        return result

    item = resolution.get(
        "item"
    )

    if not isinstance(
        item,
        dict,
    ):
        result[
            "status"
        ] = "unresolved"

        result[
            "reason"
        ] = "resolved_item_missing"

        return result

    path = item.get(
        "path"
    )

    record = item.get(
        "record"
    )

    if (
        not isinstance(
            path,
            Path,
        )
        or not isinstance(
            record,
            dict,
        )
    ):
        result[
            "status"
        ] = "unresolved"

        result[
            "reason"
        ] = "resolved_item_invalid"

        return result

    result.update(
        {
            "status":
                "resolved",

            "matched_via":
                clean_text(
                    resolution.get(
                        "matched_via"
                    )
                ),

            "matched_record_id":
                clean_text(
                    record.get(
                        "id"
                    )
                ),

            "matched_identifiers":
                osv_identifiers(
                    record
                ),

            "local_path":
                relative_project_path(
                    path
                ),

            "sha256":
                sha256_file(
                    path
                ),

            "size_bytes":
                path.stat().st_size,

            "content_kind":
                "osv_json",
        }
    )

    return result


def acquire(
    plan: dict[str, Any],
    osv_raw_dir: Path,
) -> dict[str, Any]:
    plan_sources = plan.get(
        "sources",
        [],
    )

    if not isinstance(
        plan_sources,
        list,
    ):
        raise ValueError(
            "Plan field 'sources' must be a list."
        )

    selected_sources = [
        source
        for source in plan_sources
        if (
            isinstance(
                source,
                dict,
            )
            and clean_text(
                source.get(
                    "acquisition_backend"
                )
            )
            in SUPPORTED_BACKENDS
        )
    ]

    osv_records = (
        load_osv_records(
            osv_raw_dir
        )
    )

    results: list[
        dict[str, Any]
    ] = []

    for source in selected_sources:
        backend = clean_text(
            source.get(
                "acquisition_backend"
            )
        )

        if (
            backend
            == "local_evidence_file"
        ):
            result = (
                acquire_local_evidence_file(
                    source
                )
            )

        elif (
            backend
            == "osv_api_record"
        ):
            result = (
                acquire_osv_api_record(
                    source,
                    osv_records,
                )
            )

        else:
            continue

        results.append(
            result
        )

    status_counter = Counter(
        clean_text(
            result.get(
                "status"
            )
        )
        for result in results
    )

    backend_counter = Counter(
        clean_text(
            result.get(
                "acquisition_backend"
            )
        )
        for result in results
    )

    matched_via_counter = Counter(
        clean_text(
            result.get(
                "matched_via"
            )
        )
        for result in results
        if result.get(
            "matched_via"
        )
    )

    resolved_count = sum(
        1
        for result in results
        if (
            result.get(
                "status"
            )
            == "resolved"
        )
    )

    unresolved = [
        clean_text(
            result.get(
                "source_key"
            )
        )
        for result in results
        if (
            result.get(
                "status"
            )
            != "resolved"
        )
    ]

    overall_status = (
        "resolved"
        if (
            results
            and resolved_count
            == len(
                results
            )
        )
        else "partial"
    )

    return {
        "schema_version":
            SCHEMA_VERSION,

        "status":
            overall_status,

        "source_plan_schema_version":
            clean_text(
                plan.get(
                    "schema_version"
                )
            ),

        "supported_backends":
            sorted(
                SUPPORTED_BACKENDS
            ),

        "selected_source_count":
            len(
                results
            ),

        "resolved_source_count":
            resolved_count,

        "unresolved_source_count":
            len(
                unresolved
            ),

        "backend_counts":
            dict(
                sorted(
                    backend_counter.items()
                )
            ),

        "status_counts":
            dict(
                sorted(
                    status_counter.items()
                )
            ),

        "osv_match_mode_counts":
            dict(
                sorted(
                    matched_via_counter.items()
                )
            ),

        "local_osv_record_count":
            len(
                osv_records
            ),

        "unresolved_sources":
            unresolved,

        "results":
            results,

        "limitations": [
            (
                "This v0 resolves only local frozen "
                "evidence and locally mirrored OSV "
                "records."
            ),
            (
                "No network acquisition is performed."
            ),
            (
                "Successful source resolution does not "
                "validate trigger semantics or claims."
            ),
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Resolve the local structured subset "
            "of the AVCS Trigger Source "
            "Acquisition Plan."
        )
    )

    parser.add_argument(
        "--plan",
        type=Path,
        default=DEFAULT_PLAN,
    )

    parser.add_argument(
        "--osv-raw-dir",
        type=Path,
        default=DEFAULT_OSV_RAW_DIR,
    )

    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUTPUT,
    )

    args = parser.parse_args()

    plan = load_json(
        args.plan
    )

    result = acquire(
        plan=plan,
        osv_raw_dir=args.osv_raw_dir,
    )

    write_json(
        args.out,
        result,
    )

    print(
        "============================================================"
    )
    print(
        "TRIGGER LOCAL STRUCTURED ACQUISITION SUMMARY"
    )
    print(
        "============================================================"
    )

    print(
        "[OK] schema:",
        result.get(
            "schema_version"
        ),
    )

    print(
        "[OK] status:",
        result.get(
            "status"
        ),
    )

    print(
        "[OK] selected sources:",
        result.get(
            "selected_source_count"
        ),
    )

    print(
        "[OK] resolved sources:",
        result.get(
            "resolved_source_count"
        ),
    )

    print(
        "[OK] unresolved sources:",
        result.get(
            "unresolved_source_count"
        ),
    )

    print(
        "[OK] local OSV records:",
        result.get(
            "local_osv_record_count"
        ),
    )

    print(
        "[OK] backends:",
        json.dumps(
            result.get(
                "backend_counts",
                {},
            ),
            ensure_ascii=False,
            sort_keys=True,
        ),
    )

    print(
        "[OK] OSV match modes:",
        json.dumps(
            result.get(
                "osv_match_mode_counts",
                {},
            ),
            ensure_ascii=False,
            sort_keys=True,
        ),
    )

    print(
        "[OK] saved:",
        args.out,
    )


if __name__ == "__main__":
    main()