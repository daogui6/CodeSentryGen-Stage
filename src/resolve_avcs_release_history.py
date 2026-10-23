from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from packaging.version import InvalidVersion, Version

from normalizer import pep503_normalize


def parse_datetime(value: str) -> datetime | None:
    if not value:
        return None

    value = str(value).strip()

    if value.endswith("Z"):
        value = value[:-1] + "+00:00"

    try:
        result = datetime.fromisoformat(value)
    except ValueError:
        return None

    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)

    return result.astimezone(timezone.utc)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_pypi_json(
    distribution: str,
    cache_dir: Path,
    refresh: bool = False,
    timeout: int = 15,
) -> tuple[dict[str, Any], str, Path]:
    normalized_distribution = pep503_normalize(
        distribution
    )

    cache_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    cache_path = (
        cache_dir
        / f"{normalized_distribution}.json"
    )

    if cache_path.exists() and not refresh:
        data = json.loads(
            cache_path.read_text(
                encoding="utf-8"
            )
        )
        return data, "cache", cache_path

    query_url = (
        f"https://pypi.org/pypi/"
        f"{distribution}/json"
    )

    response = requests.get(
        query_url,
        timeout=timeout,
    )

    if response.status_code == 404:
        raise RuntimeError(
            f"PyPI distribution not found: "
            f"{distribution}"
        )

    response.raise_for_status()

    data = response.json()

    cache_path.write_text(
        json.dumps(
            data,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    return data, "network", cache_path


def build_release_view(
    data: dict[str, Any],
    time_view: datetime,
) -> dict[str, Any]:
    releases_with_files: list[
        dict[str, Any]
    ] = []

    release_labels_without_file_evidence: list[str] = []

    invalid_version_labels: list[str] = []

    for version_text, files in (
        data.get("releases", {}).items()
    ):
        try:
            parsed_version = Version(
                version_text
            )
        except InvalidVersion:
            invalid_version_labels.append(
                version_text
            )
            continue

        upload_times: list[datetime] = []

        currently_yanked_file_count = 0

        for file_info in files:
            upload_time_text = (
                file_info.get(
                    "upload_time_iso_8601"
                )
                or file_info.get(
                    "upload_time"
                )
            )

            upload_time = parse_datetime(
                upload_time_text
            )

            if upload_time is not None:
                upload_times.append(
                    upload_time
                )

            if file_info.get("yanked"):
                currently_yanked_file_count += 1

        # 没有任何可用上传时间的 release，
        # 当前不能可靠放入时间视图。
        if not upload_times:
            release_labels_without_file_evidence.append(
                version_text
            )
            continue

        first_upload_time = min(
            upload_times
        )

        releases_with_files.append(
            {
                "version": version_text,
                "first_upload_time": (
                    first_upload_time.isoformat()
                ),
                "file_count": len(files),
                "currently_yanked_file_count": (
                    currently_yanked_file_count
                ),
                "all_files_currently_yanked": (
                    bool(files)
                    and currently_yanked_file_count
                    == len(files)
                ),
                "is_prerelease": (
                    parsed_version.is_prerelease
                ),
                "is_devrelease": (
                    parsed_version.is_devrelease
                ),
            }
        )

    releases_with_files.sort(
        key=lambda row: Version(
            row["version"]
        )
    )

    confirmed_releases_as_of_time_view = [
        row
        for row in releases_with_files
        if (
            parse_datetime(
                row["first_upload_time"]
            )
            <= time_view
        )
    ]

    confirmed_prerelease_count_as_of_time_view = sum(
        row["is_prerelease"]
        for row in confirmed_releases_as_of_time_view
    )

    currently_yanked_confirmed_release_count = sum(
        row["all_files_currently_yanked"]
        for row in confirmed_releases_as_of_time_view
    )

    confirmed_releases_after_time_view = [
        row
        for row in releases_with_files
        if (
            parse_datetime(
                row["first_upload_time"]
            )
            > time_view
        )
    ]

    return {
        "registry_release_count": len(
            data.get("releases", {})
        ),
        "release_count_with_files": len(
            releases_with_files
        ),
        "release_count_without_file_evidence": len(
            release_labels_without_file_evidence
        ),
        "release_history_evidence_scope": (
            "current_pypi_project_json_file_metadata"
        ),
        "release_history_status": (
            "partial"
            if (
                release_labels_without_file_evidence
                or invalid_version_labels
            )
            else "current_registry_file_evidence_complete"
        ),
        "confirmed_release_count_as_of_time_view": len(
            confirmed_releases_as_of_time_view
        ),
        "confirmed_release_count_after_time_view": len(
            confirmed_releases_after_time_view
        ),
        "latest_confirmed_version_as_of_time_view": (
            confirmed_releases_as_of_time_view[-1]["version"]
            if confirmed_releases_as_of_time_view
            else None
        ),
        "confirmed_releases_as_of_time_view": (
            confirmed_releases_as_of_time_view
        ),
        "invalid_version_labels": sorted(
            invalid_version_labels
        ),
        "release_labels_without_file_evidence": sorted(
            release_labels_without_file_evidence
        ),
        "confirmed_prerelease_count_as_of_time_view": (
            confirmed_prerelease_count_as_of_time_view
        ),
        "currently_yanked_confirmed_release_count": (
            currently_yanked_confirmed_release_count
        ),
    }


def resolve_release_history(
    distribution: str,
    time_view_text: str,
    cache_dir: Path,
    refresh: bool = False,
) -> dict[str, Any]:
    time_view = parse_datetime(
        time_view_text
    )

    if time_view is None:
        raise ValueError(
            f"Invalid time view: "
            f"{time_view_text}"
        )

    data, source, cache_path = (
        load_pypi_json(
            distribution=distribution,
            cache_dir=cache_dir,
            refresh=refresh,
        )
    )

    release_view = build_release_view(
        data=data,
        time_view=time_view,
    )

    return {
        "schema_version": (
            "avcs_release_history_v0.1"
        ),
        "distribution": distribution,
        "normalized_distribution": (
            pep503_normalize(distribution)
        ),
        "time_view": time_view.isoformat(),
        "audit_time": now_iso(),
        "registry_source": "PyPI JSON API",
        "registry_data_source": source,
        "cache_file": str(
            cache_path
        ).replace("\\", "/"),
        **release_view,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Resolve historical PyPI releases "
            "for an AVCS time view."
        )
    )

    parser.add_argument(
        "--distribution",
        required=True,
    )

    parser.add_argument(
        "--time-view",
        required=True,
    )

    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=Path(
            "output/"
            "avcs_pypi_release_cache"
        ),
    )

    parser.add_argument(
        "--refresh",
        action="store_true",
    )

    parser.add_argument(
        "--out",
        type=Path,
        required=True,
    )

    args = parser.parse_args()

    result = resolve_release_history(
        distribution=args.distribution,
        time_view_text=args.time_view,
        cache_dir=args.cache_dir,
        refresh=args.refresh,
    )

    args.out.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    args.out.write_text(
        json.dumps(
            result,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    print(
        f"[OK] distribution: "
        f"{result['distribution']}"
    )
    print(
        f"[OK] time view: "
        f"{result['time_view']}"
    )
    print(
        f"[OK] registry data: "
        f"{result['registry_data_source']}"
    )
    print(
        f"[OK] registry releases: "
        f"{result['registry_release_count']}"
    )
    print(
        f"[OK] releases with files: "
        f"{result['release_count_with_files']}"
    )
    print(
        f"[OK] releases without file evidence: "
        f"{result['release_count_without_file_evidence']}"
    )
    print(
        f"[OK] confirmed prereleases "
        f"as of time view: "
        f"{result['confirmed_prerelease_count_as_of_time_view']}"
    )

    print(
        f"[OK] currently yanked "
        f"confirmed releases: "
        f"{result['currently_yanked_confirmed_release_count']}"
    )
    print(
        f"[OK] confirmed releases as of time view: "
        f"{result['confirmed_release_count_as_of_time_view']}"
    )

    print(
        f"[OK] confirmed releases after time view: "
        f"{result['confirmed_release_count_after_time_view']}"
    )

    print(
        f"[OK] latest confirmed version as of time view: "
        f"{result['latest_confirmed_version_as_of_time_view']}"
    )
    print(
        f"[OK] release history status: "
        f"{result['release_history_status']}"
    )
    print(
        f"[OK] invalid version labels: "
        f"{len(result['invalid_version_labels'])}"
    )
    print(
        f"[OK] result saved to: "
        f"{args.out}"
    )


if __name__ == "__main__":
    main()