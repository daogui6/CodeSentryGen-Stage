from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

from normalizer import pep503_normalize


QUERY_ENDPOINT = "https://api.osv.dev/v1/query"

QUERY_CACHE_SCHEMA_VERSION = (
    "avcs_osv_package_query_cache_v0.1"
)

SNAPSHOT_SCHEMA_VERSION = (
    "avcs_osv_package_snapshot_v0.1"
)


def now_iso() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


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
        f"sha256:"
        f"{digest.hexdigest()}"
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


def query_cache_path(
    cache_dir: Path,
    distribution: str,
    ecosystem: str,
) -> Path:
    normalized_distribution = (
        pep503_normalize(
            distribution
        )
    )

    ecosystem_part = (
        safe_component(
            ecosystem
        ).lower()
    )

    return (
        cache_dir
        / (
            f"{ecosystem_part}__"
            f"{normalized_distribution}"
            ".json"
        )
    )


def query_osv_package(
    distribution: str,
    ecosystem: str,
    timeout: int,
) -> dict[str, Any]:
    records_by_id: dict[
        str,
        dict[str, Any],
    ] = {}

    page_count = 0

    page_token: (
        str
        | None
    ) = None

    seen_tokens: set[
        str
    ] = set()

    while True:
        payload: dict[
            str,
            Any,
        ] = {
            "package": {
                "name":
                    distribution,
                "ecosystem":
                    ecosystem,
            }
        }

        if page_token:
            payload[
                "page_token"
            ] = page_token

        response = requests.post(
            QUERY_ENDPOINT,
            json=payload,
            timeout=timeout,
        )

        response.raise_for_status()

        data = response.json()

        if not isinstance(
            data,
            dict,
        ):
            raise RuntimeError(
                "OSV query returned "
                "a non-object response."
            )

        page_count += 1

        rows = data.get(
            "vulns",
            [],
        )

        if not isinstance(
            rows,
            list,
        ):
            raise RuntimeError(
                "OSV query field "
                "'vulns' is not a list."
            )

        for row in rows:
            if not isinstance(
                row,
                dict,
            ):
                continue

            vulnerability_id = str(
                row.get(
                    "id",
                    "",
                )
            ).strip()

            if vulnerability_id:
                records_by_id[
                    vulnerability_id
                ] = row

        next_token = str(
            data.get(
                "next_page_token",
                "",
            )
            or ""
        ).strip()

        if not next_token:
            break

        if (
            next_token
            in seen_tokens
        ):
            raise RuntimeError(
                "OSV query returned "
                "a repeated page token."
            )

        seen_tokens.add(
            next_token
        )

        page_token = (
            next_token
        )

    vulnerability_ids = (
        sorted(
            records_by_id
        )
    )

    return {
        "schema_version":
            QUERY_CACHE_SCHEMA_VERSION,
        "provider":
            "OSV",
        "query_endpoint":
            QUERY_ENDPOINT,
        "query_scope":
            (
                "all_known_package_"
                "vulnerabilities"
            ),
        "distribution":
            distribution,
        "normalized_distribution":
            pep503_normalize(
                distribution
            ),
        "ecosystem":
            ecosystem,
        "queried_at":
            now_iso(),
        "query_payload": {
            "package": {
                "name":
                    distribution,
                "ecosystem":
                    ecosystem,
            }
        },
        "page_count":
            page_count,
        "vulnerability_count":
            len(
                vulnerability_ids
            ),
        "vulnerabilities": [
            records_by_id[
                vulnerability_id
            ]
            for vulnerability_id
            in vulnerability_ids
        ],
    }


def load_or_query_package(
    distribution: str,
    ecosystem: str,
    cache_dir: Path,
    refresh: bool,
    timeout: int,
) -> tuple[
    dict[str, Any],
    str,
    Path,
]:
    cache_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    cache_path = (
        query_cache_path(
            cache_dir=
                cache_dir,
            distribution=
                distribution,
            ecosystem=
                ecosystem,
        )
    )

    if (
        cache_path.exists()
        and not refresh
    ):
        return (
            load_json(
                cache_path
            ),
            "cache",
            cache_path,
        )

    data = query_osv_package(
        distribution=
            distribution,
        ecosystem=
            ecosystem,
        timeout=
            timeout,
    )

    write_json(
        cache_path,
        data,
    )

    return (
        data,
        "network",
        cache_path,
    )


def materialize_records(
    query_data:
        dict[str, Any],
    record_cache_dir:
        Path,
    refresh:
        bool,
    query_source:
        str,
) -> list[
    dict[str, Any]
]:
    record_cache_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_rows: list[
        dict[str, Any]
    ] = []

    rows = query_data.get(
        "vulnerabilities",
        [],
    )

    if not isinstance(
        rows,
        list,
    ):
        raise RuntimeError(
            "Cached OSV field "
            "'vulnerabilities' "
            "is not a list."
        )

    for record in rows:
        if not isinstance(
            record,
            dict,
        ):
            continue

        vulnerability_id = str(
            record.get(
                "id",
                "",
            )
        ).strip()

        if not vulnerability_id:
            continue

        raw_file = (
            record_cache_dir
            / (
                f"{safe_component(vulnerability_id)}"
                ".json"
            )
        )

        if (
            raw_file.exists()
            and not refresh
        ):
            raw_source = (
                "record_cache"
            )

            raw_record = (
                load_json(
                    raw_file
                )
            )

        else:
            if (
                query_source
                == "network"
            ):
                raw_source = (
                    "network_query"
                )
            else:
                raw_source = (
                    "query_cache"
                )

            raw_record = (
                record
            )

            write_json(
                raw_file,
                raw_record,
            )

        output_rows.append(
            {
                "vulnerability_id":
                    vulnerability_id,

                "aliases":
                    raw_record.get(
                        "aliases",
                        [],
                    ),

                "published_at":
                    raw_record.get(
                        "published"
                    ),

                "modified_at":
                    raw_record.get(
                        "modified"
                    ),

                "withdrawn_at":
                    raw_record.get(
                        "withdrawn"
                    ),

                "raw_data_source":
                    raw_source,

                "raw_osv_file":
                    str(
                        raw_file
                    ).replace(
                        "\\",
                        "/",
                    ),

                "canonical_source_url":
                    (
                        "https://api.osv.dev/"
                        "v1/vulns/"
                        f"{vulnerability_id}"
                    ),

                "evidence_hash":
                    sha256_file(
                        raw_file
                    ),
            }
        )

    return output_rows


def build_snapshot(
    distribution: str,
    ecosystem: str,
    query_cache_dir: Path,
    record_cache_dir: Path,
    refresh: bool,
    timeout: int,
) -> dict[str, Any]:
    (
        query_data,
        query_source,
        query_cache_file,
    ) = load_or_query_package(
        distribution=
            distribution,
        ecosystem=
            ecosystem,
        cache_dir=
            query_cache_dir,
        refresh=
            refresh,
        timeout=
            timeout,
    )

    records = materialize_records(
        query_data=
            query_data,
        record_cache_dir=
            record_cache_dir,
        refresh=
            refresh,
        query_source=
            query_source,
    )

    return {
        "schema_version":
            SNAPSHOT_SCHEMA_VERSION,

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

        "snapshot_created_at":
            now_iso(),

        "query_scope":
            (
                "all_known_package_"
                "vulnerabilities"
            ),

        "query_data_source":
            query_source,

        "query_queried_at":
            query_data.get(
                "queried_at"
            ),

        "query_page_count":
            query_data.get(
                "page_count"
            ),

        "query_cache_file":
            str(
                query_cache_file
            ).replace(
                "\\",
                "/",
            ),

        "record_cache_dir":
            str(
                record_cache_dir
            ).replace(
                "\\",
                "/",
            ),

        "vulnerability_count":
            len(
                records
            ),

        "vulnerability_ids": [
            row[
                "vulnerability_id"
            ]
            for row in records
        ],

        "records":
            records,
    }


def main() -> None:
    parser = (
        argparse.ArgumentParser(
            description=(
                "Discover OSV "
                "vulnerabilities for "
                "one package and cache "
                "raw vulnerability "
                "records."
            )
        )
    )

    parser.add_argument(
        "--distribution",
        required=True,
    )

    parser.add_argument(
        "--ecosystem",
        default="PyPI",
    )

    parser.add_argument(
        "--query-cache-dir",
        type=Path,
        default=Path(
            "output/"
            "avcs_osv_query_cache"
        ),
    )

    parser.add_argument(
        "--record-cache-dir",
        type=Path,
        default=Path(
            "output/"
            "avcs_osv_record_cache"
        ),
    )

    parser.add_argument(
        "--refresh",
        action="store_true",
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=20,
    )

    parser.add_argument(
        "--out",
        type=Path,
        required=True,
    )

    args = parser.parse_args()

    if args.timeout <= 0:
        raise ValueError(
            "--timeout must be positive."
        )

    result = build_snapshot(
        distribution=
            args.distribution,
        ecosystem=
            args.ecosystem,
        query_cache_dir=
            args.query_cache_dir,
        record_cache_dir=
            args.record_cache_dir,
        refresh=
            args.refresh,
        timeout=
            args.timeout,
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
        f"[OK] query data: "
        f"{result['query_data_source']}"
    )

    print(
        f"[OK] vulnerabilities: "
        f"{result['vulnerability_count']}"
    )

    for record in result[
        "records"
    ]:
        print(
            f"[OK] "
            f"{record['vulnerability_id']} "
            f"| raw: "
            f"{record['raw_data_source']} "
            f"| file: "
            f"{record['raw_osv_file']}"
        )

    print(
        f"[OK] snapshot saved to: "
        f"{args.out}"
    )


if __name__ == "__main__":
    main()