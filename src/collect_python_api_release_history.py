from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from packaging.version import (
    InvalidVersion,
    Version,
)

from collect_pypi_release_source_index import (
    collect_release_source_index,
)
from resolve_python_public_api_symbol import (
    resolve_public_api_symbol,
)


SCHEMA_VERSION = (
    "avcs_python_api_release_history_v0.1"
)


def read_json(
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
    """
    将 distribution / API symbol / version
    转换成适合作为输出目录名称的形式。

    原始值仍然保存在 JSON 中，
    这里只影响缓存/输出路径。
    """

    cleaned = re.sub(
        r"[^A-Za-z0-9._+-]+",
        "_",
        value.strip(),
    )

    cleaned = cleaned.strip(
        "._"
    )

    return (
        cleaned
        if cleaned
        else "unknown"
    )


def parse_optional_version(
    value: str | None,
    argument_name: str,
) -> Version | None:
    if value is None:
        return None

    cleaned = value.strip()

    if not cleaned:
        return None

    try:
        return Version(
            cleaned
        )
    except InvalidVersion as exc:
        raise ValueError(
            f"{argument_name} is not "
            f"a valid PEP 440 version: "
            f"{value}"
        ) from exc


def select_releases(
    release_history: dict[str, Any],
    start_version: Version | None,
    end_version: Version | None,
    include_prereleases: bool,
    limit: int | None,
) -> list[dict[str, Any]]:
    rows = release_history.get(
        "confirmed_releases_as_of_time_view",
        [],
    )

    if not isinstance(
        rows,
        list,
    ):
        raise RuntimeError(
            "release history has no valid "
            "confirmed_releases_as_of_time_view"
        )

    selected: list[
        tuple[
            Version,
            dict[str, Any],
        ]
    ] = []

    for row in rows:
        if not isinstance(
            row,
            dict,
        ):
            continue

        version_text = str(
            row.get(
                "version",
                "",
            )
        ).strip()

        if not version_text:
            continue

        try:
            parsed = Version(
                version_text
            )
        except InvalidVersion:
            continue

        if (
            not include_prereleases
            and parsed.is_prerelease
        ):
            continue

        if (
            start_version is not None
            and parsed < start_version
        ):
            continue

        if (
            end_version is not None
            and parsed > end_version
        ):
            continue

        selected.append(
            (
                parsed,
                row,
            )
        )

    selected.sort(
        key=lambda item: item[0]
    )

    result = [
        row
        for _, row in selected
    ]

    if limit is not None:
        result = result[:limit]

    return result


def build_release_output_paths(
    batch_dir: Path,
    distribution: str,
    api_symbol: str,
    version: str,
) -> tuple[Path, Path]:
    base = (
        batch_dir
        / safe_component(
            distribution
        )
        / safe_component(
            api_symbol
        )
        / safe_component(
            version
        )
    )

    return (
        base / "source_index.json",
        base / "public_symbol.json",
    )


def collect_one_release(
    distribution: str,
    api_symbol: str,
    release_row: dict[str, Any],
    registry_cache_dir: Path,
    artifact_cache_dir: Path,
    batch_dir: Path,
    refresh: bool,
    timeout: int,
) -> dict[str, Any]:
    version = str(
        release_row.get(
            "version",
            "",
        )
    ).strip()

    if not version:
        raise RuntimeError(
            "release row has no version"
        )

    (
        source_index_path,
        public_symbol_path,
    ) = build_release_output_paths(
        batch_dir=batch_dir,
        distribution=distribution,
        api_symbol=api_symbol,
        version=version,
    )

    record: dict[str, Any] = {
        "version":
            version,

        "first_upload_time":
            release_row.get(
                "first_upload_time"
            ),

        "file_count":
            release_row.get(
                "file_count"
            ),

        "all_files_currently_yanked":
            release_row.get(
                "all_files_currently_yanked"
            ),

        "is_prerelease":
            release_row.get(
                "is_prerelease"
            ),

        "is_devrelease":
            release_row.get(
                "is_devrelease"
            ),

        "source_index_status":
            "not_attempted",

        "public_symbol_status":
            "not_attempted",

        "source_index_file":
            str(
                source_index_path
            ).replace(
                "\\",
                "/",
            ),

        "public_symbol_file":
            str(
                public_symbol_path
            ).replace(
                "\\",
                "/",
            ),

        "artifact":
            None,

        "implementation":
            None,

        "public_signature":
            None,

        "resolution_chain":
            [],

        "error_stage":
            None,

        "error_type":
            None,

        "error_message":
            None,
    }

    try:
        source_index = (
            collect_release_source_index(
                distribution=
                    distribution,

                version=
                    version,

                registry_cache_dir=
                    registry_cache_dir,

                artifact_cache_dir=
                    artifact_cache_dir,

                refresh=
                    refresh,

                timeout=
                    timeout,
            )
        )

        write_json(
            source_index_path,
            source_index,
        )

        record[
            "source_index_status"
        ] = "resolved"

        record[
            "artifact"
        ] = source_index.get(
            "artifact"
        )

    except Exception as exc:
        record[
            "source_index_status"
        ] = "error"

        record[
            "public_symbol_status"
        ] = "blocked"

        record[
            "error_stage"
        ] = "source_index"

        record[
            "error_type"
        ] = type(
            exc
        ).__name__

        record[
            "error_message"
        ] = str(exc)

        return record

    try:
        public_symbol = (
            resolve_public_api_symbol(
                source_index_path=
                    source_index_path,

                api_symbol=
                    api_symbol,
            )
        )

        write_json(
            public_symbol_path,
            public_symbol,
        )

        public_status = str(
            public_symbol.get(
                "status",
                "unresolved",
            )
        )

        record[
            "public_symbol_status"
        ] = public_status

        record[
            "implementation"
        ] = public_symbol.get(
            "implementation"
        )

        record[
            "public_signature"
        ] = public_symbol.get(
            "public_signature"
        )

        record[
            "resolution_chain"
        ] = public_symbol.get(
            "resolution_chain",
            [],
        )

        if public_symbol.get(
            "error"
        ):
            record[
                "error_stage"
            ] = "public_symbol"

            record[
                "error_type"
            ] = (
                "resolver_reported_error"
            )

            record[
                "error_message"
            ] = str(
                public_symbol.get(
                    "error"
                )
            )

    except Exception as exc:
        record[
            "public_symbol_status"
        ] = "error"

        record[
            "error_stage"
        ] = "public_symbol"

        record[
            "error_type"
        ] = type(
            exc
        ).__name__

        record[
            "error_message"
        ] = str(exc)

    return record


def summarize_records(
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    source_resolved = sum(
        record.get(
            "source_index_status"
        )
        == "resolved"
        for record in records
    )

    source_errors = sum(
        record.get(
            "source_index_status"
        )
        == "error"
        for record in records
    )

    public_resolved = sum(
        record.get(
            "public_symbol_status"
        )
        == "resolved"
        for record in records
    )

    public_errors = sum(
        record.get(
            "public_symbol_status"
        )
        == "error"
        for record in records
    )

    public_blocked = sum(
        record.get(
            "public_symbol_status"
        )
        == "blocked"
        for record in records
    )

    unresolved_status_counts: dict[
        str,
        int,
    ] = {}

    for record in records:
        status = str(
            record.get(
                "public_symbol_status",
                "",
            )
        )

        if status in {
            "resolved",
            "error",
            "blocked",
        }:
            continue

        unresolved_status_counts[
            status
        ] = (
            unresolved_status_counts.get(
                status,
                0,
            )
            + 1
        )

    return {
        "selected_release_count":
            len(records),

        "source_index_resolved_count":
            source_resolved,

        "source_index_error_count":
            source_errors,

        "public_symbol_resolved_count":
            public_resolved,

        "public_symbol_error_count":
            public_errors,

        "public_symbol_blocked_count":
            public_blocked,

        "public_symbol_unresolved_count":
            (
                len(records)
                - public_resolved
                - public_errors
                - public_blocked
            ),

        "public_symbol_unresolved_status_counts":
            unresolved_status_counts,
    }


def collect_api_release_history(
    release_history_path: Path,
    distribution: str,
    api_symbol: str,
    registry_cache_dir: Path,
    artifact_cache_dir: Path,
    batch_dir: Path,
    start_version_text: str | None,
    end_version_text: str | None,
    include_prereleases: bool,
    limit: int | None,
    refresh: bool,
    timeout: int,
) -> dict[str, Any]:
    release_history = read_json(
        release_history_path
    )

    history_distribution = str(
        release_history.get(
            "normalized_distribution",
            "",
        )
    ).strip()

    if not history_distribution:
        raise RuntimeError(
            "release history has no "
            "normalized_distribution"
        )

    start_version = (
        parse_optional_version(
            start_version_text,
            "--start-version",
        )
    )

    end_version = (
        parse_optional_version(
            end_version_text,
            "--end-version",
        )
    )

    if (
        start_version is not None
        and end_version is not None
        and start_version
        > end_version
    ):
        raise ValueError(
            "--start-version cannot be "
            "greater than --end-version"
        )

    if (
        limit is not None
        and limit <= 0
    ):
        raise ValueError(
            "--limit must be positive"
        )

    selected = select_releases(
        release_history=
            release_history,

        start_version=
            start_version,

        end_version=
            end_version,

        include_prereleases=
            include_prereleases,

        limit=
            limit,
    )

    records: list[
        dict[str, Any]
    ] = []

    for index, release_row in enumerate(
        selected,
        start=1,
    ):
        version = str(
            release_row.get(
                "version",
                "",
            )
        )

        print(
            f"[RUN] "
            f"{index}/{len(selected)} "
            f"{distribution} "
            f"{version} "
            f"{api_symbol}"
        )

        record = collect_one_release(
            distribution=
                distribution,

            api_symbol=
                api_symbol,

            release_row=
                release_row,

            registry_cache_dir=
                registry_cache_dir,

            artifact_cache_dir=
                artifact_cache_dir,

            batch_dir=
                batch_dir,

            refresh=
                refresh,

            timeout=
                timeout,
        )

        records.append(
            record
        )

        print(
            f"[{'OK' if record.get('public_symbol_status') == 'resolved' else 'WARN'}] "
            f"{version} | "
            f"source={record.get('source_index_status')} | "
            f"public={record.get('public_symbol_status')}"
        )

        if record.get(
            "error_message"
        ):
            print(
                f"       "
                f"{record.get('error_stage')}: "
                f"{record.get('error_type')}: "
                f"{record.get('error_message')}"
            )

    summary = summarize_records(
        records
    )

    return {
        "schema_version":
            SCHEMA_VERSION,

        "ecosystem":
            "pypi",

        "distribution":
            distribution,

        "normalized_distribution":
            history_distribution,

        "api_symbol":
            api_symbol,

        "release_history_source":
            str(
                release_history_path
            ).replace(
                "\\",
                "/",
            ),

        "time_view":
            release_history.get(
                "time_view"
            ),

        "registry_release_count":
            release_history.get(
                "registry_release_count"
            ),

        "release_history_status":
            release_history.get(
                "release_history_status"
            ),

        "selection": {
            "start_version":
                start_version_text,

            "end_version":
                end_version_text,

            "include_prereleases":
                include_prereleases,

            "limit":
                limit,
        },

        **summary,

        "records":
            records,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Collect one public Python API "
            "symbol across multiple historical "
            "PyPI releases."
        )
    )

    parser.add_argument(
        "--release-history",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--distribution",
        required=True,
    )

    parser.add_argument(
        "--api-symbol",
        required=True,
    )

    parser.add_argument(
        "--registry-cache-dir",
        type=Path,
        default=Path(
            "output/"
            "avcs_pypi_release_cache"
        ),
    )

    parser.add_argument(
        "--artifact-cache-dir",
        type=Path,
        default=Path(
            "output/"
            "avcs_api_artifact_cache"
        ),
    )

    parser.add_argument(
        "--batch-dir",
        type=Path,
        default=Path(
            "output/"
            "avcs_api_history_batch"
        ),
    )

    parser.add_argument(
        "--start-version",
    )

    parser.add_argument(
        "--end-version",
    )

    parser.add_argument(
        "--include-prereleases",
        action="store_true",
    )

    parser.add_argument(
        "--limit",
        type=int,
    )

    parser.add_argument(
        "--refresh",
        action="store_true",
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
    )

    parser.add_argument(
        "--out",
        required=True,
        type=Path,
    )

    args = parser.parse_args()

    if args.timeout <= 0:
        raise ValueError(
            "--timeout must be positive"
        )

    result = (
        collect_api_release_history(
            release_history_path=
                args.release_history,

            distribution=
                args.distribution,

            api_symbol=
                args.api_symbol.strip(),

            registry_cache_dir=
                args.registry_cache_dir,

            artifact_cache_dir=
                args.artifact_cache_dir,

            batch_dir=
                args.batch_dir,

            start_version_text=
                args.start_version,

            end_version_text=
                args.end_version,

            include_prereleases=
                args.include_prereleases,

            limit=
                args.limit,

            refresh=
                args.refresh,

            timeout=
                args.timeout,
        )
    )

    write_json(
        args.out,
        result,
    )

    print("")
    print("=" * 60)
    print("API RELEASE HISTORY SUMMARY")
    print("=" * 60)

    print(
        f"[OK] distribution: "
        f"{result['distribution']}"
    )

    print(
        f"[OK] API symbol: "
        f"{result['api_symbol']}"
    )

    print(
        f"[OK] selected releases: "
        f"{result['selected_release_count']}"
    )

    print(
        f"[OK] source indexes resolved: "
        f"{result['source_index_resolved_count']}"
    )

    print(
        f"[OK] source index errors: "
        f"{result['source_index_error_count']}"
    )

    print(
        f"[OK] public symbols resolved: "
        f"{result['public_symbol_resolved_count']}"
    )

    print(
        f"[OK] public symbol unresolved: "
        f"{result['public_symbol_unresolved_count']}"
    )

    print(
        f"[OK] public symbol errors: "
        f"{result['public_symbol_error_count']}"
    )

    print(
        f"[OK] public symbol blocked: "
        f"{result['public_symbol_blocked_count']}"
    )

    print(
        f"[OK] result saved to: "
        f"{args.out}"
    )


if __name__ == "__main__":
    main()