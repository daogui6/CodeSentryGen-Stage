from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

import requests


ROOT = Path(__file__).resolve().parents[1]

SCHEMA_VERSION = (
    "avcs_trigger_github_commit_acquisition_v0.1"
)

DEFAULT_PLAN = (
    ROOT
    / "output"
    / "avcs_trigger_source_acquisition_plan_v0.json"
)

DEFAULT_CACHE_DIR = (
    ROOT
    / "output"
    / "avcs_trigger_github_commit_cache"
)

DEFAULT_OUTPUT = (
    ROOT
    / "output"
    / "avcs_trigger_github_commit_acquisition_v0.json"
)

SUPPORTED_BACKENDS = {
    "github_commit_url",
    "github_repository_commit",
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
    source_dir = (
        cache_dir
        / safe_component(
            source_key
        )
    )

    return (
        source_dir
        / "metadata.json",

        source_dir
        / "response.json",
    )


def validate_target(
    target: Any,
) -> tuple[
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
        )

    repository = clean_text(
        target.get(
            "repository"
        )
    )

    commit = clean_text(
        target.get(
            "commit"
        )
    )

    return (
        repository,
        commit,
    )


def github_commit_api_url(
    repository: str,
    commit: str,
) -> str:
    return (
        f"{GITHUB_API_BASE}"
        f"/repos/{repository}"
        f"/commits/{commit}"
    )


def parse_response_bytes(
    response_bytes: bytes,
) -> dict[str, Any]:
    try:
        data = json.loads(
            response_bytes.decode(
                "utf-8"
            )
        )

    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as exc:
        raise ValueError(
            "Cached/fetched GitHub commit "
            "response is not valid UTF-8 JSON."
        ) from exc

    if not isinstance(
        data,
        dict,
    ):
        raise ValueError(
            "GitHub commit response "
            "must be a JSON object."
        )

    return data


def summarize_files(
    data: dict[str, Any],
) -> list[
    dict[str, Any]
]:
    raw_files = data.get(
        "files",
        [],
    )

    if not isinstance(
        raw_files,
        list,
    ):
        return []

    result: list[
        dict[str, Any]
    ] = []

    for raw_file in raw_files:
        if not isinstance(
            raw_file,
            dict,
        ):
            continue

        patch = raw_file.get(
            "patch"
        )

        patch_text = (
            patch
            if isinstance(
                patch,
                str,
            )
            else ""
        )

        result.append(
            {
                "filename":
                    clean_text(
                        raw_file.get(
                            "filename"
                        )
                    ),

                "status":
                    clean_text(
                        raw_file.get(
                            "status"
                        )
                    ),

                "additions":
                    raw_file.get(
                        "additions"
                    ),

                "deletions":
                    raw_file.get(
                        "deletions"
                    ),

                "changes":
                    raw_file.get(
                        "changes"
                    ),

                "blob_url":
                    clean_text(
                        raw_file.get(
                            "blob_url"
                        )
                    ),

                "raw_url":
                    clean_text(
                        raw_file.get(
                            "raw_url"
                        )
                    ),

                "patch_present":
                    bool(
                        patch_text
                    ),

                "patch_size_chars":
                    len(
                        patch_text
                    ),

                "patch_sha256":
                    (
                        sha256_bytes(
                            patch_text.encode(
                                "utf-8"
                            )
                        )
                        if patch_text
                        else ""
                    ),
            }
        )

    return result


def extract_commit_message(
    data: dict[str, Any],
) -> str:
    commit_data = data.get(
        "commit",
        {},
    )

    if not isinstance(
        commit_data,
        dict,
    ):
        return ""

    return clean_text(
        commit_data.get(
            "message"
        )
    )


def extract_commit_created_at(
    data: dict[str, Any],
) -> str:
    commit_data = data.get(
        "commit",
        {},
    )

    if not isinstance(
        commit_data,
        dict,
    ):
        return ""

    committer = commit_data.get(
        "committer",
        {},
    )

    if isinstance(
        committer,
        dict,
    ):
        date = clean_text(
            committer.get(
                "date"
            )
        )

        if date:
            return date

    author = commit_data.get(
        "author",
        {},
    )

    if isinstance(
        author,
        dict,
    ):
        return clean_text(
            author.get(
                "date"
            )
        )

    return ""


def build_commit_evidence(
    data: dict[str, Any],
    response_sha256: str,
    response_size_bytes: int,
) -> dict[str, Any]:
    canonical_sha = clean_text(
        data.get(
            "sha"
        )
    )

    files = summarize_files(
        data
    )

    patch_present_count = sum(
        1
        for item in files
        if (
            item.get(
                "patch_present"
            )
            is True
        )
    )

    patch_missing_count = (
        len(
            files
        )
        - patch_present_count
    )

    stats = data.get(
        "stats",
        {},
    )

    if not isinstance(
        stats,
        dict,
    ):
        stats = {}

    parents = data.get(
        "parents",
        [],
    )

    parent_shas: list[str] = []

    if isinstance(
        parents,
        list,
    ):
        for parent in parents:
            if not isinstance(
                parent,
                dict,
            ):
                continue

            parent_sha = clean_text(
                parent.get(
                    "sha"
                )
            )

            if parent_sha:
                parent_shas.append(
                    parent_sha
                )

    return {
        "canonical_commit_sha":
            canonical_sha,

        "message":
            extract_commit_message(
                data
            ),

        "created_at":
            extract_commit_created_at(
                data
            ),

        "html_url":
            clean_text(
                data.get(
                    "html_url"
                )
            ),

        "parent_shas":
            parent_shas,

        "parent_count":
            len(
                parent_shas
            ),

        "changed_file_count":
            len(
                files
            ),

        "patch_present_count":
            patch_present_count,

        "patch_missing_count":
            patch_missing_count,

        "stats": {
            "additions":
                stats.get(
                    "additions"
                ),

            "deletions":
                stats.get(
                    "deletions"
                ),

            "total":
                stats.get(
                    "total"
                ),
        },

        "files":
            files,

        "response_sha256":
            response_sha256,

        "response_size_bytes":
            response_size_bytes,
    }


def save_cache(
    metadata_path: Path,
    response_path: Path,
    metadata: dict[str, Any],
    response_bytes: bytes,
) -> None:
    metadata_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    response_path.write_bytes(
        response_bytes
    )

    write_json(
        metadata_path,
        metadata,
    )


def load_cache(
    metadata_path: Path,
    response_path: Path,
    repository: str,
    requested_commit: str,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
] | None:
    if (
        not metadata_path.exists()
        or not response_path.exists()
    ):
        return None

    if (
        not metadata_path.is_file()
        or not response_path.is_file()
    ):
        return None

    try:
        metadata = load_json(
            metadata_path
        )

        response_bytes = (
            response_path.read_bytes()
        )

        data = parse_response_bytes(
            response_bytes
        )

    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
    ):
        return None

    if (
        clean_text(
            metadata.get(
                "repository"
            )
        )
        != repository
    ):
        return None

    if (
        clean_text(
            metadata.get(
                "requested_commit"
            )
        ).lower()
        != requested_commit.lower()
    ):
        return None

    actual_response_sha256 = (
        sha256_bytes(
            response_bytes
        )
    )

    if (
        clean_text(
            metadata.get(
                "response_sha256"
            )
        )
        != actual_response_sha256
    ):
        return None

    canonical_sha = clean_text(
        data.get(
            "sha"
        )
    )

    if (
        not canonical_sha
        or canonical_sha.lower()
        != requested_commit.lower()
    ):
        return None

    evidence = build_commit_evidence(
        data=data,
        response_sha256=actual_response_sha256,
        response_size_bytes=len(
            response_bytes
        ),
    )

    return (
        metadata,
        evidence,
    )


def fetch_commit(
    session: requests.Session,
    repository: str,
    commit: str,
    timeout: int,
) -> tuple[
    dict[str, Any],
    bytes,
]:
    api_url = github_commit_api_url(
        repository,
        commit,
    )

    response = session.get(
        api_url,
        timeout=timeout,
    )

    response.raise_for_status()

    response_bytes = (
        response.content
    )

    data = parse_response_bytes(
        response_bytes
    )

    canonical_sha = clean_text(
        data.get(
            "sha"
        )
    )

    if not canonical_sha:
        raise RuntimeError(
            "GitHub commit response "
            "does not contain SHA."
        )

    if (
        canonical_sha.lower()
        != commit.lower()
    ):
        raise RuntimeError(
            "GitHub returned a different "
            "canonical commit SHA."
        )

    return (
        data,
        response_bytes,
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
        requested_commit,
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

        "requested_commit":
            requested_commit,

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

    if not requested_commit:
        result[
            "reason"
        ] = "missing_commit"

        return result

    (
        metadata_path,
        response_path,
    ) = cache_paths(
        cache_dir,
        source_key,
    )

    if not refresh:
        cached = load_cache(
            metadata_path=metadata_path,
            response_path=response_path,
            repository=repository,
            requested_commit=requested_commit,
        )

        if cached is not None:
            (
                _,
                evidence,
            ) = cached

            result.update(
                {
                    "status":
                        "resolved",

                    "cache_hit":
                        True,

                    **evidence,

                    "cache_metadata_path":
                        relative_project_path(
                            metadata_path
                        ),

                    "cache_response_path":
                        relative_project_path(
                            response_path
                        ),
                }
            )

            return result

    try:
        (
            data,
            response_bytes,
        ) = fetch_commit(
            session=session,
            repository=repository,
            commit=requested_commit,
            timeout=timeout,
        )

    except requests.RequestException as exc:
        response = getattr(
            exc,
            "response",
            None,
        )

        result[
            "status"
        ] = "network_error"

        result[
            "http_status"
        ] = (
            response.status_code
            if response is not None
            else None
        )

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

    response_sha256 = (
        sha256_bytes(
            response_bytes
        )
    )

    evidence = build_commit_evidence(
        data=data,
        response_sha256=response_sha256,
        response_size_bytes=len(
            response_bytes
        ),
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

        "requested_commit":
            requested_commit,

        "canonical_commit_sha":
            evidence.get(
                "canonical_commit_sha"
            ),

        "response_sha256":
            response_sha256,

        "response_size_bytes":
            len(
                response_bytes
            ),
    }

    save_cache(
        metadata_path=metadata_path,
        response_path=response_path,
        metadata=cache_metadata,
        response_bytes=response_bytes,
    )

    result.update(
        {
            "status":
                "resolved",

            "cache_hit":
                False,

            **evidence,

            "cache_metadata_path":
                relative_project_path(
                    metadata_path
                ),

            "cache_response_path":
                relative_project_path(
                    response_path
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

    backend_counts: dict[
        str,
        int,
    ] = {}

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

    patch_missing_total = sum(
        int(
            result.get(
                "patch_missing_count",
                0,
            )
            or 0
        )
        for result in results
        if (
            result.get(
                "status"
            )
            == "resolved"
        )
    )

    changed_file_total = sum(
        int(
            result.get(
                "changed_file_count",
                0,
            )
            or 0
        )
        for result in results
        if (
            result.get(
                "status"
            )
            == "resolved"
        )
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

        "changed_file_total":
            changed_file_total,

        "patch_missing_total":
            patch_missing_total,

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
                "This v0 acquires GitHub fix-commit "
                "metadata and diff/patch evidence only."
            ),
            (
                "A successful commit acquisition does "
                "not prove the security meaning of "
                "the patch."
            ),
            (
                "GitHub may omit patch text for binary "
                "or very large file changes; such "
                "absence is recorded rather than "
                "silently interpreted."
            ),
            (
                "Trigger candidate semantics are "
                "derived in a later evidence-analysis "
                "layer."
            ),
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Acquire Phase-1 GitHub fix-commit "
            "evidence for AVCS Trigger Evidence "
            "automation."
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
        "TRIGGER GITHUB COMMIT ACQUISITION SUMMARY"
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
        "[OK] changed files:",
        result.get(
            "changed_file_total"
        ),
    )

    print(
        "[OK] missing patches:",
        result.get(
            "patch_missing_total"
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