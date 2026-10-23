from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import quote

import requests


ROOT = Path(__file__).resolve().parents[1]

SCHEMA_VERSION = (
    "avcs_trigger_github_metadata_acquisition_v0.1"
)

CACHE_SCHEMA_VERSION = (
    "avcs_trigger_github_metadata_cache_v0.1"
)

DEFAULT_PLAN = (
    ROOT
    / "output"
    / "avcs_trigger_source_acquisition_plan_v0.json"
)

DEFAULT_CACHE_DIR = (
    ROOT
    / "output"
    / "avcs_trigger_github_metadata_cache"
)

DEFAULT_OUTPUT = (
    ROOT
    / "output"
    / "avcs_trigger_github_metadata_acquisition_v0.json"
)

PHASE_STRUCTURED_METADATA = (
    "phase_2_structured_metadata"
)

SUPPORTED_BACKENDS = {
    "github_security_advisory_url",
    "github_pull_request_url",
    "github_issue_url",
    "github_release_url",
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
        + digest.hexdigest()
    )


def sha256_text(
    value: Any,
) -> str:
    text = (
        value
        if isinstance(
            value,
            str,
        )
        else ""
    )

    if not text:
        return ""

    return sha256_bytes(
        text.encode(
            "utf-8"
        )
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
            "Bearer "
            + token
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
            "Cached/fetched GitHub metadata "
            "response is not valid UTF-8 JSON."
        ) from exc

    if not isinstance(
        data,
        dict,
    ):
        raise ValueError(
            "GitHub metadata response "
            "must be a JSON object."
        )

    return data


def normalize_repository(
    value: Any,
) -> str:
    return clean_text(
        value
    ).strip(
        "/"
    ).lower()


def normalize_ghsa_id(
    value: Any,
) -> str:
    return clean_text(
        value
    ).upper()


def normalized_target(
    backend: str,
    target: Any,
) -> dict[str, Any]:
    if not isinstance(
        target,
        dict,
    ):
        target = {}

    if (
        backend
        == "github_security_advisory_url"
    ):
        return {
            "advisory_scope":
                clean_text(
                    target.get(
                        "advisory_scope"
                    )
                ),

            "advisory_id":
                normalize_ghsa_id(
                    target.get(
                        "advisory_id"
                    )
                ),

            "repository":
                normalize_repository(
                    target.get(
                        "repository"
                    )
                ),
        }

    if (
        backend
        == "github_pull_request_url"
    ):
        return {
            "repository":
                normalize_repository(
                    target.get(
                        "repository"
                    )
                ),

            "pull_number":
                target.get(
                    "pull_number"
                ),
        }

    if (
        backend
        == "github_issue_url"
    ):
        return {
            "repository":
                normalize_repository(
                    target.get(
                        "repository"
                    )
                ),

            "issue_number":
                target.get(
                    "issue_number"
                ),
        }

    if (
        backend
        == "github_release_url"
    ):
        return {
            "repository":
                normalize_repository(
                    target.get(
                        "repository"
                    )
                ),

            "tag":
                clean_text(
                    target.get(
                        "tag"
                    )
                ),
        }

    return {}


def validate_target(
    backend: str,
    target: dict[str, Any],
) -> tuple[
    bool,
    str,
]:
    if (
        backend
        == "github_security_advisory_url"
    ):
        scope = clean_text(
            target.get(
                "advisory_scope"
            )
        )

        advisory_id = (
            normalize_ghsa_id(
                target.get(
                    "advisory_id"
                )
            )
        )

        repository = (
            normalize_repository(
                target.get(
                    "repository"
                )
            )
        )

        if scope not in {
            "global",
            "repository",
        }:
            return (
                False,
                "invalid_advisory_scope",
            )

        if not advisory_id:
            return (
                False,
                "missing_advisory_id",
            )

        if (
            scope
            == "repository"
            and not repository
        ):
            return (
                False,
                "missing_repository",
            )

        return (
            True,
            "resolved",
        )

    if (
        backend
        == "github_pull_request_url"
    ):
        repository = (
            normalize_repository(
                target.get(
                    "repository"
                )
            )
        )

        pull_number = target.get(
            "pull_number"
        )

        if not repository:
            return (
                False,
                "missing_repository",
            )

        if (
            not isinstance(
                pull_number,
                int,
            )
            or pull_number <= 0
        ):
            return (
                False,
                "invalid_pull_number",
            )

        return (
            True,
            "resolved",
        )

    if (
        backend
        == "github_issue_url"
    ):
        repository = (
            normalize_repository(
                target.get(
                    "repository"
                )
            )
        )

        issue_number = target.get(
            "issue_number"
        )

        if not repository:
            return (
                False,
                "missing_repository",
            )

        if (
            not isinstance(
                issue_number,
                int,
            )
            or issue_number <= 0
        ):
            return (
                False,
                "invalid_issue_number",
            )

        return (
            True,
            "resolved",
        )

    if (
        backend
        == "github_release_url"
    ):
        repository = (
            normalize_repository(
                target.get(
                    "repository"
                )
            )
        )

        tag = clean_text(
            target.get(
                "tag"
            )
        )

        if not repository:
            return (
                False,
                "missing_repository",
            )

        if not tag:
            return (
                False,
                "missing_tag",
            )

        return (
            True,
            "resolved",
        )

    return (
        False,
        "unsupported_backend",
    )


def github_api_url(
    backend: str,
    target: dict[str, Any],
) -> str:
    if (
        backend
        == "github_security_advisory_url"
    ):
        advisory_id = quote(
            normalize_ghsa_id(
                target.get(
                    "advisory_id"
                )
            ),
            safe="",
        )

        scope = clean_text(
            target.get(
                "advisory_scope"
            )
        )

        if (
            scope
            == "repository"
        ):
            repository = (
                normalize_repository(
                    target.get(
                        "repository"
                    )
                )
            )

            return (
                GITHUB_API_BASE
                + "/repos/"
                + repository
                + "/security-advisories/"
                + advisory_id
            )

        return (
            GITHUB_API_BASE
            + "/advisories/"
            + advisory_id
        )

    repository = (
        normalize_repository(
            target.get(
                "repository"
            )
        )
    )

    if (
        backend
        == "github_pull_request_url"
    ):
        return (
            GITHUB_API_BASE
            + "/repos/"
            + repository
            + "/pulls/"
            + str(
                target.get(
                    "pull_number"
                )
            )
        )

    if (
        backend
        == "github_issue_url"
    ):
        return (
            GITHUB_API_BASE
            + "/repos/"
            + repository
            + "/issues/"
            + str(
                target.get(
                    "issue_number"
                )
            )
        )

    if (
        backend
        == "github_release_url"
    ):
        tag = quote(
            clean_text(
                target.get(
                    "tag"
                )
            ),
            safe="",
        )

        return (
            GITHUB_API_BASE
            + "/repos/"
            + repository
            + "/releases/tags/"
            + tag
        )

    return ""


def repository_from_api_url(
    value: Any,
) -> str:
    url = clean_text(
        value
    )

    prefix = (
        GITHUB_API_BASE
        + "/repos/"
    )

    if not url.startswith(
        prefix
    ):
        return ""

    remaining = url[
        len(
            prefix
        ):
    ]

    segments = [
        segment
        for segment
        in remaining.split(
            "/"
        )
        if segment
    ]

    if len(
        segments
    ) < 2:
        return ""

    return normalize_repository(
        segments[0]
        + "/"
        + segments[1]
    )


def repository_from_pr(
    data: dict[str, Any],
) -> str:
    base = data.get(
        "base",
        {},
    )

    if isinstance(
        base,
        dict,
    ):
        repo = base.get(
            "repo",
            {},
        )

        if isinstance(
            repo,
            dict,
        ):
            full_name = (
                normalize_repository(
                    repo.get(
                        "full_name"
                    )
                )
            )

            if full_name:
                return full_name

    return repository_from_api_url(
        data.get(
            "url"
        )
    )


def validate_canonical_identity(
    backend: str,
    target: dict[str, Any],
    data: dict[str, Any],
) -> tuple[
    bool,
    str,
    dict[str, Any],
]:
    if (
        backend
        == "github_security_advisory_url"
    ):
        requested_id = (
            normalize_ghsa_id(
                target.get(
                    "advisory_id"
                )
            )
        )

        canonical_id = (
            normalize_ghsa_id(
                data.get(
                    "ghsa_id"
                )
            )
        )

        canonical = {
            "advisory_id":
                canonical_id,
        }

        if (
            not canonical_id
            or canonical_id
            != requested_id
        ):
            return (
                False,
                "advisory_id_mismatch",
                canonical,
            )

        return (
            True,
            "resolved",
            canonical,
        )

    if (
        backend
        == "github_pull_request_url"
    ):
        requested_repository = (
            normalize_repository(
                target.get(
                    "repository"
                )
            )
        )

        requested_number = (
            target.get(
                "pull_number"
            )
        )

        canonical_repository = (
            repository_from_pr(
                data
            )
        )

        canonical_number = (
            data.get(
                "number"
            )
        )

        canonical = {
            "repository":
                canonical_repository,

            "pull_number":
                canonical_number,
        }

        if (
            canonical_repository
            != requested_repository
        ):
            return (
                False,
                "pull_repository_mismatch",
                canonical,
            )

        if (
            canonical_number
            != requested_number
        ):
            return (
                False,
                "pull_number_mismatch",
                canonical,
            )

        return (
            True,
            "resolved",
            canonical,
        )

    if (
        backend
        == "github_issue_url"
    ):
        requested_repository = (
            normalize_repository(
                target.get(
                    "repository"
                )
            )
        )

        requested_number = (
            target.get(
                "issue_number"
            )
        )

        canonical_repository = (
            repository_from_api_url(
                data.get(
                    "repository_url"
                )
            )
        )

        canonical_number = (
            data.get(
                "number"
            )
        )

        canonical = {
            "repository":
                canonical_repository,

            "issue_number":
                canonical_number,
        }

        if (
            canonical_repository
            != requested_repository
        ):
            return (
                False,
                "issue_repository_mismatch",
                canonical,
            )

        if (
            canonical_number
            != requested_number
        ):
            return (
                False,
                "issue_number_mismatch",
                canonical,
            )

        if isinstance(
            data.get(
                "pull_request"
            ),
            dict,
        ):
            return (
                False,
                "issue_target_resolved_to_pull_request",
                canonical,
            )

        return (
            True,
            "resolved",
            canonical,
        )

    if (
        backend
        == "github_release_url"
    ):
        requested_repository = (
            normalize_repository(
                target.get(
                    "repository"
                )
            )
        )

        requested_tag = (
            clean_text(
                target.get(
                    "tag"
                )
            )
        )

        canonical_repository = (
            repository_from_api_url(
                data.get(
                    "url"
                )
            )
        )

        canonical_tag = (
            clean_text(
                data.get(
                    "tag_name"
                )
            )
        )

        canonical = {
            "repository":
                canonical_repository,

            "tag":
                canonical_tag,
        }

        if (
            canonical_repository
            != requested_repository
        ):
            return (
                False,
                "release_repository_mismatch",
                canonical,
            )

        if (
            canonical_tag
            != requested_tag
        ):
            return (
                False,
                "release_tag_mismatch",
                canonical,
            )

        return (
            True,
            "resolved",
            canonical,
        )

    return (
        False,
        "unsupported_backend",
        {},
    )


def summarize_user(
    value: Any,
) -> str:
    if not isinstance(
        value,
        dict,
    ):
        return ""

    return clean_text(
        value.get(
            "login"
        )
    )


def summarize_labels(
    value: Any,
) -> list[str]:
    if not isinstance(
        value,
        list,
    ):
        return []

    labels: list[str] = []

    for item in value:
        if isinstance(
            item,
            dict,
        ):
            name = clean_text(
                item.get(
                    "name"
                )
            )

            if name:
                labels.append(
                    name
                )

    return sorted(
        set(
            labels
        )
    )


def build_metadata_summary(
    backend: str,
    data: dict[str, Any],
) -> dict[str, Any]:
    if (
        backend
        == "github_security_advisory_url"
    ):
        description = (
            data.get(
                "description"
            )
            if isinstance(
                data.get(
                    "description"
                ),
                str,
            )
            else ""
        )

        references = data.get(
            "references",
            [],
        )

        vulnerabilities = data.get(
            "vulnerabilities",
            [],
        )

        cwes = data.get(
            "cwes",
            [],
        )

        return {
            "kind":
                "security_advisory",

            "ghsa_id":
                normalize_ghsa_id(
                    data.get(
                        "ghsa_id"
                    )
                ),

            "cve_id":
                clean_text(
                    data.get(
                        "cve_id"
                    )
                ),

            "advisory_type":
                clean_text(
                    data.get(
                        "type"
                    )
                ),

            "severity":
                clean_text(
                    data.get(
                        "severity"
                    )
                ),

            "summary":
                clean_text(
                    data.get(
                        "summary"
                    )
                ),

            "published_at":
                clean_text(
                    data.get(
                        "published_at"
                    )
                ),

            "updated_at":
                clean_text(
                    data.get(
                        "updated_at"
                    )
                ),

            "withdrawn_at":
                clean_text(
                    data.get(
                        "withdrawn_at"
                    )
                ),

            "description_size_chars":
                len(
                    description
                ),

            "description_sha256":
                sha256_text(
                    description
                ),

            "reference_count":
                (
                    len(
                        references
                    )
                    if isinstance(
                        references,
                        list,
                    )
                    else 0
                ),

            "vulnerability_count":
                (
                    len(
                        vulnerabilities
                    )
                    if isinstance(
                        vulnerabilities,
                        list,
                    )
                    else 0
                ),

            "cwe_count":
                (
                    len(
                        cwes
                    )
                    if isinstance(
                        cwes,
                        list,
                    )
                    else 0
                ),
        }

    if (
        backend
        == "github_pull_request_url"
    ):
        body = (
            data.get(
                "body"
            )
            if isinstance(
                data.get(
                    "body"
                ),
                str,
            )
            else ""
        )

        return {
            "kind":
                "pull_request",

            "number":
                data.get(
                    "number"
                ),

            "title":
                clean_text(
                    data.get(
                        "title"
                    )
                ),

            "state":
                clean_text(
                    data.get(
                        "state"
                    )
                ),

            "draft":
                data.get(
                    "draft"
                ),

            "merged":
                data.get(
                    "merged"
                ),

            "merge_commit_sha":
                clean_text(
                    data.get(
                        "merge_commit_sha"
                    )
                ),

            "created_at":
                clean_text(
                    data.get(
                        "created_at"
                    )
                ),

            "updated_at":
                clean_text(
                    data.get(
                        "updated_at"
                    )
                ),

            "closed_at":
                clean_text(
                    data.get(
                        "closed_at"
                    )
                ),

            "merged_at":
                clean_text(
                    data.get(
                        "merged_at"
                    )
                ),

            "author":
                summarize_user(
                    data.get(
                        "user"
                    )
                ),

            "changed_files":
                data.get(
                    "changed_files"
                ),

            "commits":
                data.get(
                    "commits"
                ),

            "additions":
                data.get(
                    "additions"
                ),

            "deletions":
                data.get(
                    "deletions"
                ),

            "body_size_chars":
                len(
                    body
                ),

            "body_sha256":
                sha256_text(
                    body
                ),

            "html_url":
                clean_text(
                    data.get(
                        "html_url"
                    )
                ),
        }

    if (
        backend
        == "github_issue_url"
    ):
        body = (
            data.get(
                "body"
            )
            if isinstance(
                data.get(
                    "body"
                ),
                str,
            )
            else ""
        )

        return {
            "kind":
                "issue",

            "number":
                data.get(
                    "number"
                ),

            "title":
                clean_text(
                    data.get(
                        "title"
                    )
                ),

            "state":
                clean_text(
                    data.get(
                        "state"
                    )
                ),

            "state_reason":
                clean_text(
                    data.get(
                        "state_reason"
                    )
                ),

            "created_at":
                clean_text(
                    data.get(
                        "created_at"
                    )
                ),

            "updated_at":
                clean_text(
                    data.get(
                        "updated_at"
                    )
                ),

            "closed_at":
                clean_text(
                    data.get(
                        "closed_at"
                    )
                ),

            "author":
                summarize_user(
                    data.get(
                        "user"
                    )
                ),

            "comment_count":
                data.get(
                    "comments"
                ),

            "labels":
                summarize_labels(
                    data.get(
                        "labels"
                    )
                ),

            "body_size_chars":
                len(
                    body
                ),

            "body_sha256":
                sha256_text(
                    body
                ),

            "html_url":
                clean_text(
                    data.get(
                        "html_url"
                    )
                ),
        }

    if (
        backend
        == "github_release_url"
    ):
        body = (
            data.get(
                "body"
            )
            if isinstance(
                data.get(
                    "body"
                ),
                str,
            )
            else ""
        )

        assets = data.get(
            "assets",
            [],
        )

        return {
            "kind":
                "release",

            "release_id":
                data.get(
                    "id"
                ),

            "tag_name":
                clean_text(
                    data.get(
                        "tag_name"
                    )
                ),

            "name":
                clean_text(
                    data.get(
                        "name"
                    )
                ),

            "target_commitish":
                clean_text(
                    data.get(
                        "target_commitish"
                    )
                ),

            "draft":
                data.get(
                    "draft"
                ),

            "prerelease":
                data.get(
                    "prerelease"
                ),

            "created_at":
                clean_text(
                    data.get(
                        "created_at"
                    )
                ),

            "published_at":
                clean_text(
                    data.get(
                        "published_at"
                    )
                ),

            "author":
                summarize_user(
                    data.get(
                        "author"
                    )
                ),

            "asset_count":
                (
                    len(
                        assets
                    )
                    if isinstance(
                        assets,
                        list,
                    )
                    else 0
                ),

            "body_size_chars":
                len(
                    body
                ),

            "body_sha256":
                sha256_text(
                    body
                ),

            "html_url":
                clean_text(
                    data.get(
                        "html_url"
                    )
                ),
        }

    return {
        "kind":
            "unknown",
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
    source_key: str,
    backend: str,
    target: dict[str, Any],
) -> tuple[
    dict[str, Any],
    dict[str, Any],
] | None:
    if (
        not metadata_path.exists()
        or not response_path.exists()
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
                "schema_version"
            )
        )
        != CACHE_SCHEMA_VERSION
    ):
        return None

    if (
        clean_text(
            metadata.get(
                "source_key"
            )
        )
        != source_key
    ):
        return None

    if (
        clean_text(
            metadata.get(
                "acquisition_backend"
            )
        )
        != backend
    ):
        return None

    cached_target = metadata.get(
        "requested_target",
        {},
    )

    if (
        not isinstance(
            cached_target,
            dict,
        )
        or cached_target
        != normalized_target(
            backend,
            target,
        )
    ):
        return None

    expected_sha256 = clean_text(
        metadata.get(
            "response_sha256"
        )
    )

    actual_sha256 = (
        sha256_bytes(
            response_bytes
        )
    )

    if (
        not expected_sha256
        or expected_sha256
        != actual_sha256
    ):
        return None

    (
        identity_ok,
        _,
        canonical_identity,
    ) = validate_canonical_identity(
        backend=backend,
        target=target,
        data=data,
    )

    if not identity_ok:
        return None

    return (
        metadata,
        {
            "data":
                data,

            "response_bytes":
                response_bytes,

            "canonical_identity":
                canonical_identity,
        },
    )


def base_result(
    source: dict[str, Any],
    backend: str,
    target: dict[str, Any],
    api_url: str,
    metadata_path: Path,
    response_path: Path,
) -> dict[str, Any]:
    return {
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

        "acquisition_phase":
            clean_text(
                source.get(
                    "acquisition_phase"
                )
            ),

        "acquisition_backend":
            backend,

        "requested_target":
            normalized_target(
                backend,
                target,
            ),

        "api_url":
            api_url,

        "cache_metadata_path":
            relative_project_path(
                metadata_path
            ),

        "cache_response_path":
            relative_project_path(
                response_path
            ),

        "cache_hit":
            False,

        "network_fetch":
            False,

        "status":
            "unresolved",
    }


def acquire_source(
    source: dict[str, Any],
    session: requests.Session,
    cache_dir: Path,
    refresh: bool,
    timeout_seconds: float,
) -> dict[str, Any]:
    source_key = clean_text(
        source.get(
            "source_key"
        )
    )

    backend = clean_text(
        source.get(
            "acquisition_backend"
        )
    )

    raw_target = source.get(
        "target",
        {},
    )

    target = (
        raw_target
        if isinstance(
            raw_target,
            dict,
        )
        else {}
    )

    (
        metadata_path,
        response_path,
    ) = cache_paths(
        cache_dir,
        source_key,
    )

    (
        target_ok,
        target_reason,
    ) = validate_target(
        backend,
        target,
    )

    api_url = (
        github_api_url(
            backend,
            target,
        )
        if target_ok
        else ""
    )

    result = base_result(
        source=source,
        backend=backend,
        target=target,
        api_url=api_url,
        metadata_path=metadata_path,
        response_path=response_path,
    )

    if not target_ok:
        result[
            "status"
        ] = (
            "invalid_target"
        )

        result[
            "reason"
        ] = (
            target_reason
        )

        return result

    if not refresh:
        cached = load_cache(
            metadata_path=metadata_path,
            response_path=response_path,
            source_key=source_key,
            backend=backend,
            target=target,
        )

        if cached is not None:
            (
                metadata,
                cache_payload,
            ) = cached

            data = cache_payload[
                "data"
            ]

            response_bytes = (
                cache_payload[
                    "response_bytes"
                ]
            )

            canonical_identity = (
                cache_payload[
                    "canonical_identity"
                ]
            )

            result.update(
                {
                    "status":
                        "resolved",

                    "acquisition_mode":
                        "cache",

                    "cache_hit":
                        True,

                    "network_fetch":
                        False,

                    "canonical_identity":
                        canonical_identity,

                    "response_sha256":
                        sha256_bytes(
                            response_bytes
                        ),

                    "response_size_bytes":
                        len(
                            response_bytes
                        ),

                    "metadata":
                        build_metadata_summary(
                            backend,
                            data,
                        ),

                    "cached_at_source":
                        clean_text(
                            metadata.get(
                                "api_url"
                            )
                        ),
                }
            )

            return result

    result[
        "network_fetch"
    ] = True

    try:
        response = session.get(
            api_url,
            timeout=timeout_seconds,
        )

    except requests.RequestException as exc:
        result[
            "status"
        ] = (
            "network_error"
        )

        result[
            "reason"
        ] = str(
            exc
        )

        return result

    result[
        "http_status"
    ] = response.status_code

    if (
        response.status_code
        != 200
    ):
        result[
            "status"
        ] = (
            "http_error"
        )

        result[
            "reason"
        ] = (
            "unexpected_http_status"
        )

        return result

    response_bytes = (
        response.content
    )

    try:
        data = parse_response_bytes(
            response_bytes
        )

    except ValueError as exc:
        result[
            "status"
        ] = (
            "invalid_response_json"
        )

        result[
            "reason"
        ] = str(
            exc
        )

        return result

    (
        identity_ok,
        identity_reason,
        canonical_identity,
    ) = validate_canonical_identity(
        backend=backend,
        target=target,
        data=data,
    )

    if not identity_ok:
        result[
            "status"
        ] = (
            "identity_mismatch"
        )

        result[
            "reason"
        ] = (
            identity_reason
        )

        result[
            "canonical_identity"
        ] = (
            canonical_identity
        )

        return result

    response_sha256 = (
        sha256_bytes(
            response_bytes
        )
    )

    response_size_bytes = len(
        response_bytes
    )

    cache_metadata = {
        "schema_version":
            CACHE_SCHEMA_VERSION,

        "source_key":
            source_key,

        "acquisition_backend":
            backend,

        "requested_target":
            normalized_target(
                backend,
                target,
            ),

        "canonical_identity":
            canonical_identity,

        "api_url":
            api_url,

        "response_sha256":
            response_sha256,

        "response_size_bytes":
            response_size_bytes,
    }

    try:
        save_cache(
            metadata_path=metadata_path,
            response_path=response_path,
            metadata=cache_metadata,
            response_bytes=response_bytes,
        )

    except OSError as exc:
        result[
            "status"
        ] = (
            "cache_write_error"
        )

        result[
            "reason"
        ] = str(
            exc
        )

        return result

    result.update(
        {
            "status":
                "resolved",

            "acquisition_mode":
                "github_rest_api",

            "cache_hit":
                False,

            "network_fetch":
                True,

            "canonical_identity":
                canonical_identity,

            "response_sha256":
                response_sha256,

            "response_size_bytes":
                response_size_bytes,

            "metadata":
                build_metadata_summary(
                    backend,
                    data,
                ),
        }
    )

    return result


def acquire(
    plan: dict[str, Any],
    cache_dir: Path,
    refresh: bool,
    timeout_seconds: float,
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
            "Plan field 'sources' "
            "must be a list."
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
                    "acquisition_phase"
                )
            )
            == PHASE_STRUCTURED_METADATA
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
            source=source,
            session=session,
            cache_dir=cache_dir,
            refresh=refresh,
            timeout_seconds=timeout_seconds,
        )

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

    network_fetch_count = sum(
        1
        for result in results
        if (
            result.get(
                "network_fetch"
            )
            is True
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

        "acquisition_phase":
            PHASE_STRUCTURED_METADATA,

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
            network_fetch_count,

        "github_token_present":
            bool(
                github_token()
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

        "unresolved_sources":
            unresolved_sources,

        "results":
            results,

        "limitations": [
            (
                "This v0 acquires GitHub structured "
                "metadata only; it does not infer or "
                "validate Trigger Rules."
            ),
            (
                "Advisory, pull-request, issue, and "
                "release text is preserved in cached "
                "raw API responses; the acquisition "
                "summary records identity and content "
                "hashes rather than treating text as "
                "ground-truth trigger semantics."
            ),
            (
                "Successful source acquisition proves "
                "source identity and provenance only, "
                "not the correctness of a source claim."
            ),
            (
                "GitHub API availability and rate "
                "limits may require GITHUB_TOKEN or "
                "GH_TOKEN for larger future runs."
            ),
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Acquire Phase-2 GitHub structured "
            "metadata for AVCS Trigger Evidence."
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
        "--refresh",
        action="store_true",
        help=(
            "Ignore valid cache entries and "
            "fetch the GitHub API again."
        ),
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help=(
            "Per-request timeout in seconds."
        ),
    )

    args = parser.parse_args()

    if (
        args.timeout
        <= 0
    ):
        raise ValueError(
            "--timeout must be positive."
        )

    plan = load_json(
        args.plan
    )

    result = acquire(
        plan=plan,
        cache_dir=args.cache_dir,
        refresh=args.refresh,
        timeout_seconds=args.timeout,
    )

    write_json(
        args.out,
        result,
    )

    print(
        "============================================================"
    )

    print(
        "TRIGGER GITHUB METADATA ACQUISITION SUMMARY"
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
        "[OK] GitHub token present:",
        result.get(
            "github_token_present"
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