from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import quote

import requests


ROOT = Path(__file__).resolve().parents[1]

SCHEMA_VERSION = (
    "avcs_trigger_github_file_acquisition_v0.1"
)

DEFAULT_PLAN = (
    ROOT
    / "output"
    / "avcs_trigger_source_acquisition_plan_v0.json"
)

DEFAULT_CACHE_DIR = (
    ROOT
    / "output"
    / "avcs_trigger_github_file_cache"
)

DEFAULT_OUTPUT = (
    ROOT
    / "output"
    / "avcs_trigger_github_file_acquisition_v0.json"
)

SUPPORTED_BACKENDS = {
    "github_blob_url",
    "github_repository_file",
}

GITHUB_API_BASE = (
    "https://api.github.com"
)


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


def safe_component(
    value: str,
) -> str:
    cleaned = re.sub(
        r"[^A-Za-z0-9._-]+",
        "_",
        clean_text(
            value
        ),
    )

    return (
        cleaned
        or "unknown"
    )


def sha256_bytes(
    data: bytes,
) -> str:
    digest = hashlib.sha256(
        data
    )

    return (
        "sha256:"
        f"{digest.hexdigest()}"
    )


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


def github_token() -> str:
    """
    优先读取 GITHUB_TOKEN，
    其次读取 GH_TOKEN。

    未配置 token 时仍然可以使用
    GitHub public API，只是 rate limit 更低。
    """
    return (
        clean_text(
            os.environ.get(
                "GITHUB_TOKEN"
            )
        )
        or clean_text(
            os.environ.get(
                "GH_TOKEN"
            )
        )
    )


def build_session() -> requests.Session:
    session = requests.Session()

    headers = {
        "Accept":
            "application/vnd.github+json",

        "X-GitHub-Api-Version":
            "2022-11-28",

        "User-Agent":
            "CodeSentryGen-AVCS-Trigger-Evidence",
    }

    token = github_token()

    if token:
        headers[
            "Authorization"
        ] = (
            f"Bearer {token}"
        )

    session.headers.update(
        headers
    )

    return session


def cache_paths(
    cache_dir: Path,
    source_key: str,
) -> tuple[
    Path,
    Path,
]:
    component = safe_component(
        source_key
    )

    source_dir = (
        cache_dir
        / component
    )

    return (
        source_dir
        / "metadata.json",
        source_dir
        / "content.bin",
    )


def validate_target(
    target: Any,
) -> tuple[
    str,
    str,
    str,
]:
    if not isinstance(
        target,
        dict,
    ):
        return (
            "",
            "",
            "",
        )

    repository = clean_text(
        target.get(
            "repository"
        )
    )

    ref = clean_text(
        target.get(
            "ref"
        )
    )

    path = clean_text(
        target.get(
            "path"
        )
    )

    return (
        repository,
        ref,
        path,
    )


def github_contents_api_url(
    repository: str,
    source_path: str,
) -> str:
    encoded_path = quote(
        source_path,
        safe="/",
    )

    return (
        f"{GITHUB_API_BASE}"
        f"/repos/{repository}"
        f"/contents/{encoded_path}"
    )


def decode_contents_response(
    data: dict[str, Any],
) -> bytes | None:
    encoding = clean_text(
        data.get(
            "encoding"
        )
    ).lower()

    content = data.get(
        "content"
    )

    if (
        encoding == "base64"
        and isinstance(
            content,
            str,
        )
    ):
        try:
            return base64.b64decode(
                content,
                validate=False,
            )

        except (
            ValueError,
            TypeError,
        ):
            return None

    return None


def fetch_download_url(
    session: requests.Session,
    download_url: str,
    timeout: int,
) -> bytes:
    response = session.get(
        download_url,
        timeout=timeout,
    )

    response.raise_for_status()

    return response.content


def fetch_github_file(
    session: requests.Session,
    repository: str,
    ref: str,
    source_path: str,
    timeout: int,
) -> tuple[
    dict[str, Any],
    bytes,
]:
    api_url = (
        github_contents_api_url(
            repository,
            source_path,
        )
    )

    response = session.get(
        api_url,
        params={
            "ref":
                ref,
        },
        timeout=timeout,
    )

    response.raise_for_status()

    data = response.json()

    if not isinstance(
        data,
        dict,
    ):
        raise RuntimeError(
            "GitHub contents API returned "
            "a non-object response."
        )

    if (
        data.get(
            "type"
        )
        != "file"
    ):
        raise RuntimeError(
            "GitHub contents API target "
            "is not a file."
        )

    content_bytes = (
        decode_contents_response(
            data
        )
    )

    content_mode = (
        "contents_api_base64"
    )

    if content_bytes is None:
        download_url = clean_text(
            data.get(
                "download_url"
            )
        )

        if not download_url:
            raise RuntimeError(
                "GitHub file response contains "
                "neither decodable content nor "
                "download_url."
            )

        content_bytes = (
            fetch_download_url(
                session=session,
                download_url=download_url,
                timeout=timeout,
            )
        )

        content_mode = (
            "download_url"
        )

    metadata = {
        "api_url":
            api_url,

        "repository":
            repository,

        "requested_ref":
            ref,

        "requested_path":
            source_path,

        "github_name":
            clean_text(
                data.get(
                    "name"
                )
            ),

        "github_path":
            clean_text(
                data.get(
                    "path"
                )
            ),

        "github_blob_sha":
            clean_text(
                data.get(
                    "sha"
                )
            ),

        "github_size":
            data.get(
                "size"
            ),

        "html_url":
            clean_text(
                data.get(
                    "html_url"
                )
            ),

        "download_url":
            clean_text(
                data.get(
                    "download_url"
                )
            ),

        "content_mode":
            content_mode,
    }

    return (
        metadata,
        content_bytes,
    )


def load_cache(
    metadata_path: Path,
    content_path: Path,
) -> dict[str, Any] | None:
    if (
        not metadata_path.exists()
        or not content_path.exists()
    ):
        return None

    if (
        not metadata_path.is_file()
        or not content_path.is_file()
    ):
        return None

    try:
        metadata = load_json(
            metadata_path
        )

        content_bytes = (
            content_path.read_bytes()
        )

    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
    ):
        return None

    expected_sha256 = clean_text(
        metadata.get(
            "content_sha256"
        )
    )

    actual_sha256 = (
        sha256_bytes(
            content_bytes
        )
    )

    if (
        expected_sha256
        and expected_sha256
        != actual_sha256
    ):
        return None

    result = dict(
        metadata
    )

    result[
        "content_sha256"
    ] = actual_sha256

    result[
        "content_size_bytes"
    ] = len(
        content_bytes
    )

    return result


def save_cache(
    metadata_path: Path,
    content_path: Path,
    metadata: dict[str, Any],
    content_bytes: bytes,
) -> None:
    metadata_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    content_path.write_bytes(
        content_bytes
    )

    write_json(
        metadata_path,
        metadata,
    )


def acquire_source(
    session: requests.Session,
    source: dict[str, Any],
    cache_dir: Path,
    timeout: int,
    refresh: bool,
) -> dict[str, Any]:
    source_key = clean_text(
        source.get(
            "source_key"
        )
    )

    distribution = clean_text(
        source.get(
            "distribution"
        )
    )

    source_id = clean_text(
        source.get(
            "source_id"
        )
    )

    source_type = clean_text(
        source.get(
            "source_type"
        )
    )

    backend = clean_text(
        source.get(
            "acquisition_backend"
        )
    )

    (
        repository,
        ref,
        source_path,
    ) = validate_target(
        source.get(
            "target"
        )
    )

    result: dict[
        str,
        Any,
    ] = {
        "source_key":
            source_key,

        "distribution":
            distribution,

        "source_id":
            source_id,

        "source_type":
            source_type,

        "acquisition_backend":
            backend,

        "repository":
            repository,

        "ref":
            ref,

        "path":
            source_path,

        "status":
            "unresolved",

        "cache_hit":
            False,
    }

    if not repository:
        result[
            "reason"
        ] = "missing_repository"

        return result

    if not ref:
        result[
            "reason"
        ] = "missing_ref"

        return result

    if not source_path:
        result[
            "reason"
        ] = "missing_path"

        return result

    (
        metadata_path,
        content_path,
    ) = cache_paths(
        cache_dir,
        source_key,
    )

    if not refresh:
        cached = load_cache(
            metadata_path,
            content_path,
        )

        cache_target_matches = (
                cached is not None
                and clean_text(
            cached.get(
                "repository"
            )
        )
                == repository
                and clean_text(
            cached.get(
                "ref"
            )
        )
                == ref
                and clean_text(
            cached.get(
                "path"
            )
        )
                == source_path
        )

        if (
                cached is not None
                and cache_target_matches
        ):
            result.update(
                {
                    "status":
                        "resolved",

                    "cache_hit":
                        True,

                    "github_blob_sha":
                        clean_text(
                            cached.get(
                                "github_blob_sha"
                            )
                        ),

                    "content_sha256":
                        clean_text(
                            cached.get(
                                "content_sha256"
                            )
                        ),

                    "content_size_bytes":
                        cached.get(
                            "content_size_bytes",
                            0,
                        ),

                    "content_mode":
                        clean_text(
                            cached.get(
                                "content_mode"
                            )
                        ),

                    "cache_metadata_path":
                        relative_project_path(
                            metadata_path
                        ),

                    "cache_content_path":
                        relative_project_path(
                            content_path
                        ),
                }
            )

            return result

    try:
        (
            github_metadata,
            content_bytes,
        ) = fetch_github_file(
            session=session,
            repository=repository,
            ref=ref,
            source_path=source_path,
            timeout=timeout,
        )

    except requests.RequestException as exc:
        response = getattr(
            exc,
            "response",
            None,
        )

        status_code = (
            response.status_code
            if response is not None
            else None
        )

        result[
            "status"
        ] = "network_error"

        result[
            "http_status"
        ] = status_code

        result[
            "error"
        ] = str(
            exc
        )

        return result

    except (
        RuntimeError,
        ValueError,
        TypeError,
    ) as exc:
        result[
            "status"
        ] = "acquisition_error"

        result[
            "error"
        ] = str(
            exc
        )

        return result

    content_sha256 = (
        sha256_bytes(
            content_bytes
        )
    )

    cache_metadata = {
        "schema_version":
            SCHEMA_VERSION,

        "source_key":
            source_key,

        "distribution":
            distribution,

        "source_id":
            source_id,

        "source_type":
            source_type,

        "acquisition_backend":
            backend,

        "repository":
            repository,

        "ref":
            ref,

        "path":
            source_path,

        "github_blob_sha":
            clean_text(
                github_metadata.get(
                    "github_blob_sha"
                )
            ),

        "github_size":
            github_metadata.get(
                "github_size"
            ),

        "html_url":
            clean_text(
                github_metadata.get(
                    "html_url"
                )
            ),

        "download_url":
            clean_text(
                github_metadata.get(
                    "download_url"
                )
            ),

        "content_mode":
            clean_text(
                github_metadata.get(
                    "content_mode"
                )
            ),

        "content_sha256":
            content_sha256,

        "content_size_bytes":
            len(
                content_bytes
            ),
    }

    save_cache(
        metadata_path=metadata_path,
        content_path=content_path,
        metadata=cache_metadata,
        content_bytes=content_bytes,
    )

    result.update(
        {
            "status":
                "resolved",

            "cache_hit":
                False,

            "github_blob_sha":
                clean_text(
                    github_metadata.get(
                        "github_blob_sha"
                    )
                ),

            "content_sha256":
                content_sha256,

            "content_size_bytes":
                len(
                    content_bytes
                ),

            "content_mode":
                clean_text(
                    github_metadata.get(
                        "content_mode"
                    )
                ),

            "cache_metadata_path":
                relative_project_path(
                    metadata_path
                ),

            "cache_content_path":
                relative_project_path(
                    content_path
                ),
        }
    )

    return result


def acquire(
    plan: dict[str, Any],
    cache_dir: Path,
    timeout: int,
    refresh: bool,
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

    session = build_session()

    results: list[
        dict[str, Any]
    ] = []

    for source in selected_sources:
        result = acquire_source(
            session=session,
            source=source,
            cache_dir=cache_dir,
            timeout=timeout,
            refresh=refresh,
        )

        results.append(
            result
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

    cache_hit_count = sum(
        1
        for result in results
        if (
            result.get(
                "cache_hit"
            )
            is True
        )
    )

    backend_counts = {}

    for backend in sorted(
        SUPPORTED_BACKENDS
    ):
        backend_counts[
            backend
        ] = sum(
            1
            for result in results
            if (
                result.get(
                    "acquisition_backend"
                )
                == backend
            )
        )

    status_counts: dict[
        str,
        int,
    ] = {}

    for result in results:
        status = clean_text(
            result.get(
                "status"
            )
        )

        status_counts[
            status
        ] = (
            status_counts.get(
                status,
                0,
            )
            + 1
        )

    unresolved_sources = [
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
                unresolved_sources
            ),

        "cache_hit_count":
            cache_hit_count,

        "network_fetch_count":
            (
                len(
                    results
                )
                - cache_hit_count
            ),

        "backend_counts":
            backend_counts,

        "status_counts":
            dict(
                sorted(
                    status_counts.items()
                )
            ),

        "github_token_available":
            bool(
                github_token()
            ),

        "unresolved_sources":
            unresolved_sources,

        "results":
            results,

        "limitations": [
            (
                "This v0 acquires only GitHub "
                "repository file evidence."
            ),
            (
                "GitHub commit, pull request, issue, "
                "security advisory, and release "
                "metadata are handled separately."
            ),
            (
                "Successful acquisition proves only "
                "source availability and provenance; "
                "it does not validate trigger claims."
            ),
            (
                "Complex Git branch refs containing "
                "slashes are not inferred from blob "
                "URLs in the current acquisition plan."
            ),
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Acquire Phase-1 GitHub file evidence "
            "for AVCS Trigger Evidence automation."
        )
    )

    parser.add_argument(
        "--plan",
        type=Path,
        default=DEFAULT_PLAN,
    )

    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=DEFAULT_CACHE_DIR,
    )

    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUTPUT,
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
    )

    parser.add_argument(
        "--refresh",
        action="store_true",
    )

    args = parser.parse_args()

    plan = load_json(
        args.plan
    )

    result = acquire(
        plan=plan,
        cache_dir=args.cache_dir,
        timeout=args.timeout,
        refresh=args.refresh,
    )

    write_json(
        args.out,
        result,
    )

    print(
        "============================================================"
    )
    print(
        "TRIGGER GITHUB FILE ACQUISITION SUMMARY"
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
        "[OK] cache hits:",
        result.get(
            "cache_hit_count"
        ),
    )

    print(
        "[OK] network fetches:",
        result.get(
            "network_fetch_count"
        ),
    )

    print(
        "[OK] GitHub token available:",
        result.get(
            "github_token_available"
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
        "[OK] statuses:",
        json.dumps(
            result.get(
                "status_counts",
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