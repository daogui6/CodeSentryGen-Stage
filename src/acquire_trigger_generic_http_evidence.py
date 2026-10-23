from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import (
    urldefrag,
    urljoin,
    urlparse,
)

import requests


ROOT = Path(__file__).resolve().parents[1]

SCHEMA_VERSION = (
    "avcs_trigger_generic_http_acquisition_v0.3"
)

CACHE_SCHEMA_VERSION = (
    "avcs_trigger_generic_http_cache_v0.3"
)

ACQUISITION_VERSION = (
    "trigger_generic_http_acquisition_v0.3"
)

DEFAULT_PLAN = (
    ROOT
    / "output"
    / "avcs_trigger_source_acquisition_plan_v0.json"
)

DEFAULT_CACHE_DIR = (
    ROOT
    / "output"
    / "avcs_trigger_generic_http_cache"
)

DEFAULT_OUTPUT = (
    ROOT
    / "output"
    / "avcs_trigger_generic_http_acquisition_v0.json"
)

PHASE_GENERIC_WEB = (
    "phase_3_generic_web"
)

SUPPORTED_BACKENDS = {
    "generic_http_url",
}

DEFAULT_TIMEOUT_SECONDS = 20

DEFAULT_MAX_BYTES = (
    2
    * 1024
    * 1024
)

ALLOWED_CONTENT_TYPES = {
    "text/html",
    "text/plain",
    "application/xhtml+xml",
}


def clean_text(
    value: Any,
) -> str:
    return str(
        value
        if value is not None
        else ""
    ).strip()


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
    value: bytes,
) -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            value
        ).hexdigest()
    )


def sha256_text(
    value: str,
) -> str:
    return sha256_bytes(
        value.encode(
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


def content_type_base(
    value: Any,
) -> str:
    return (
        clean_text(
            value
        )
        .split(
            ";",
            1,
        )[0]
        .strip()
        .lower()
    )


def is_json_content_type(
    content_type: str,
) -> bool:
    normalized = clean_text(
        content_type
    ).lower()

    return (
        normalized
        == "application/json"
        or normalized.endswith(
            "+json"
        )
    )


def is_supported_content_type(
    content_type: str,
) -> bool:
    normalized = clean_text(
        content_type
    ).lower()

    if not normalized:
        return True

    if (
        normalized
        in ALLOWED_CONTENT_TYPES
    ):
        return True

    return is_json_content_type(
        normalized
    )


def normalized_http_url(
    value: Any,
) -> str:
    text = clean_text(
        value
    )

    if not text:
        return ""

    try:
        parsed = urlparse(
            text
        )

    except ValueError:
        return ""

    if (
        parsed.scheme.lower()
        not in {
            "http",
            "https",
        }
    ):
        return ""

    if not parsed.netloc:
        return ""

    return text


class VisibleTextHTMLParser(
    HTMLParser
):
    def __init__(
        self,
        *,
        base_url: str,
    ) -> None:
        super().__init__(
            convert_charrefs=True
        )

        self.base_url = (
            base_url
        )

        self.hidden_depth = 0

        self.text_parts: list[
            str
        ] = []

        self.links: list[
            dict[str, str]
        ] = []

        self.current_link: (
            dict[str, str]
            | None
        ) = None

    def handle_starttag(
        self,
        tag: str,
        attrs: list[
            tuple[
                str,
                str | None,
            ]
        ],
    ) -> None:
        tag_lower = (
            tag.lower()
        )

        if tag_lower in {
            "script",
            "style",
            "noscript",
            "svg",
        }:
            self.hidden_depth += 1
            return

        if (
            self.hidden_depth > 0
        ):
            return

        if tag_lower != "a":
            return

        attrs_dict = {
            clean_text(
                key
            ).lower():
                clean_text(
                    value
                )
            for key, value
            in attrs
        }

        href = clean_text(
            attrs_dict.get(
                "href"
            )
        )

        if not href:
            return

        absolute = urljoin(
            self.base_url,
            href,
        )

        absolute, _ = urldefrag(
            absolute
        )

        absolute = (
            normalized_http_url(
                absolute
            )
        )

        if not absolute:
            return

        self.current_link = {
            "url":
                absolute,

            "anchor_text":
                "",
        }

    def handle_endtag(
        self,
        tag: str,
    ) -> None:
        tag_lower = (
            tag.lower()
        )

        if tag_lower in {
            "script",
            "style",
            "noscript",
            "svg",
        }:
            if (
                self.hidden_depth
                > 0
            ):
                self.hidden_depth -= 1

            return

        if (
            self.hidden_depth
            > 0
        ):
            return

        if (
            tag_lower == "a"
            and self.current_link
            is not None
        ):
            self.current_link[
                "anchor_text"
            ] = " ".join(
                self.current_link[
                    "anchor_text"
                ].split()
            )

            self.links.append(
                self.current_link
            )

            self.current_link = None

    def handle_data(
        self,
        data: str,
    ) -> None:
        if (
            self.hidden_depth
            > 0
        ):
            return

        text = " ".join(
            data.split()
        )

        if not text:
            return

        self.text_parts.append(
            text
        )

        if (
            self.current_link
            is not None
        ):
            existing = (
                self.current_link[
                    "anchor_text"
                ]
            )

            self.current_link[
                "anchor_text"
            ] = (
                existing
                + " "
                + text
            ).strip()


def deduplicate_links(
    links: list[
        dict[str, str]
    ],
) -> list[
    dict[str, str]
]:
    result: list[
        dict[str, str]
    ] = []

    index: dict[
        str,
        int,
    ] = {}

    for row in links:
        url = clean_text(
            row.get(
                "url"
            )
        )

        if not url:
            continue

        anchor_text = clean_text(
            row.get(
                "anchor_text"
            )
        )

        if url in index:
            existing = (
                result[
                    index[url]
                ]
            )

            if (
                anchor_text
                and anchor_text
                not in clean_text(
                    existing.get(
                        "anchor_text"
                    )
                )
            ):
                combined = (
                    clean_text(
                        existing.get(
                            "anchor_text"
                        )
                    )
                    + " | "
                    + anchor_text
                ).strip(
                    " |"
                )

                existing[
                    "anchor_text"
                ] = combined

            continue

        index[url] = len(
            result
        )

        result.append(
            {
                "url":
                    url,

                "anchor_text":
                    anchor_text,
            }
        )

    return result


def extract_html(
    body: bytes,
    *,
    base_url: str,
    encoding: str,
) -> tuple[
    str,
    list[
        dict[str, str]
    ],
]:
    try:
        html = body.decode(
            encoding,
            errors="replace",
        )

    except LookupError:
        html = body.decode(
            "utf-8",
            errors="replace",
        )

    parser = (
        VisibleTextHTMLParser(
            base_url=base_url
        )
    )

    parser.feed(
        html
    )

    text = "\n".join(
        part
        for part
        in parser.text_parts
        if part
    )

    links = deduplicate_links(
        parser.links
    )

    return (
        text,
        links,
    )


def extract_plain_text(
    body: bytes,
    *,
    encoding: str,
) -> str:
    try:
        return body.decode(
            encoding,
            errors="replace",
        )

    except LookupError:
        return body.decode(
            "utf-8",
            errors="replace",
        )


def normalized_target_ids(
    values: Any,
) -> list[str]:
    if not isinstance(
        values,
        list,
    ):
        return []

    result: list[str] = []
    seen: set[str] = set()

    for value in values:
        text = clean_text(
            value
        )

        if not text:
            continue

        key = text.lower()

        if key in seen:
            continue

        seen.add(
            key
        )

        result.append(
            text
        )

    return result


def compact_mapping(
    value: Any,
    fields: tuple[str, ...],
) -> dict[str, Any]:
    if not isinstance(
        value,
        dict,
    ):
        return {}

    result: dict[
        str,
        Any
    ] = {}

    for field in fields:
        item = value.get(
            field
        )

        if isinstance(
            item,
            str,
        ):
            item = item.strip()

            if item:
                result[
                    field
                ] = item

        elif isinstance(
            item,
            (
                int,
                float,
                bool,
            ),
        ):
            result[
                field
            ] = item

    return result


def compact_record_list(
    value: Any,
    fields: tuple[str, ...],
) -> list[dict[str, Any]]:
    if not isinstance(
        value,
        list,
    ):
        return []

    result: list[
        dict[str, Any]
    ] = []

    for row in value:
        compact = compact_mapping(
            row,
            fields,
        )

        if compact:
            result.append(
                compact
            )

    return result


def build_csaf_target_slice(
    data: Any,
    *,
    vulnerability_ids: Any,
) -> tuple[
    dict[str, Any] | None,
    list[str],
    bool,
]:
    """
    Build a narrow semantic slice for CSAF/VEX-like JSON.

    Full raw JSON remains preserved in response_body.bin.
    This slice only reduces downstream semantic noise.

    No vulnerability truth or Trigger semantics are inferred.
    """

    if not isinstance(
        data,
        dict,
    ):
        return (
            None,
            [],
            False,
        )

    document = data.get(
        "document"
    )

    vulnerabilities = data.get(
        "vulnerabilities"
    )

    csaf_like = (
        isinstance(
            document,
            dict,
        )
        and isinstance(
            vulnerabilities,
            list,
        )
        and "product_tree"
        in data
    )

    if not csaf_like:
        return (
            None,
            [],
            False,
        )

    targets = {
        value.lower()
        for value
        in normalized_target_ids(
            vulnerability_ids
        )
    }

    if not targets:
        return (
            None,
            [],
            True,
        )

    matched_rows: list[
        dict[str, Any]
    ] = []

    matched_ids: list[
        str
    ] = []

    for row in vulnerabilities:
        if not isinstance(
            row,
            dict,
        ):
            continue

        cve = clean_text(
            row.get(
                "cve"
            )
        )

        if (
            not cve
            or cve.lower()
            not in targets
        ):
            continue

        sliced: dict[
            str,
            Any
        ] = {
            "cve":
                cve,
        }

        for field in (
            "title",
            "discovery_date",
            "release_date",
        ):
            value = clean_text(
                row.get(
                    field
                )
            )

            if value:
                sliced[
                    field
                ] = value

        notes = compact_record_list(
            row.get(
                "notes"
            ),
            (
                "category",
                "title",
                "text",
            ),
        )

        if notes:
            sliced[
                "notes"
            ] = notes

        threats = compact_record_list(
            row.get(
                "threats"
            ),
            (
                "category",
                "details",
            ),
        )

        if threats:
            sliced[
                "threats"
            ] = threats

        remediations = compact_record_list(
            row.get(
                "remediations"
            ),
            (
                "category",
                "details",
                "date",
            ),
        )

        if remediations:
            sliced[
                "remediations"
            ] = remediations

        matched_rows.append(
            sliced
        )

        matched_ids.append(
            cve
        )

    if not matched_rows:
        return (
            None,
            [],
            True,
        )

    compact_document: dict[
        str,
        Any
    ] = {}

    for field in (
        "category",
        "title",
    ):
        value = clean_text(
            document.get(
                field
            )
        )

        if value:
            compact_document[
                field
            ] = value

    tracking = compact_mapping(
        document.get(
            "tracking"
        ),
        (
            "id",
            "status",
            "version",
        ),
    )

    if tracking:
        compact_document[
            "tracking"
        ] = tracking

    payload: dict[
        str,
        Any
    ] = {
        "vulnerabilities":
            matched_rows,
    }

    if compact_document:
        payload[
            "document"
        ] = compact_document

    return (
        payload,
        matched_ids,
        True,
    )


def extract_json_evidence_text(
    body: bytes,
    *,
    encoding: str,
    vulnerability_ids: Any,
) -> tuple[
    str,
    str,
    dict[str, Any],
]:
    """
    Validate JSON and return deterministic evidence text.

    Generic JSON:
        canonical full JSON text.

    CSAF/VEX-like JSON:
        target-specific semantic slice only.

    The complete original response body is still retained
    separately for provenance.
    """

    raw_text = extract_plain_text(
        body,
        encoding=encoding,
    )

    data = json.loads(
        raw_text
    )

    (
        target_slice,
        matched_ids,
        csaf_like,
    ) = build_csaf_target_slice(
        data,
        vulnerability_ids=(
            vulnerability_ids
        ),
    )

    if target_slice is not None:
        return (
            json.dumps(
                target_slice,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            ),
            "json_csaf_target_slice",
            {
                "csaf_like":
                    True,

                "target_slice_applied":
                    True,

                "matched_target_ids":
                    matched_ids,
            },
        )

    if csaf_like:
        return (
            "",
            "json_csaf_target_unresolved",
            {
                "csaf_like":
                    True,

                "target_slice_applied":
                    False,

                "matched_target_ids":
                    [],
            },
        )

    return (
        json.dumps(
            data,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ),
        "json_canonical_text",
        {
            "csaf_like":
                False,

            "target_slice_applied":
                False,

            "matched_target_ids":
                [],
        },
    )


def extract_json_text(
    body: bytes,
    *,
    encoding: str,
) -> str:
    """
    Backward-compatible generic JSON canonicalizer.
    """

    (
        text,
        _,
        _,
    ) = extract_json_evidence_text(
        body,
        encoding=encoding,
        vulnerability_ids=[],
    )

    return text


def cache_paths(
    cache_dir: Path,
    source_key: str,
) -> dict[
    str,
    Path
]:
    source_dir = (
        cache_dir
        / safe_component(
            source_key
        )
    )

    return {
        "metadata":
            source_dir
            / "metadata.json",

        "body":
            source_dir
            / "response_body.bin",

        "text":
            source_dir
            / "extracted_text.txt",

        "links":
            source_dir
            / "links.json",
    }


def build_session() -> (
    requests.Session
):
    session = requests.Session()

    session.headers.update(
        {
            "User-Agent":
                (
                    "CodeSentryGen/"
                    "RQ1-Generic-Evidence-"
                    "Acquisition"
                ),

            "Accept":
                (
                    "application/json,"
                    "application/*+json;q=0.95,"
                    "text/html;q=0.9,"
                    "text/plain;q=0.8,"
                    "*/*;q=0.2"
                ),
        }
    )

    return session


def read_cached_result(
    *,
    paths: dict[
        str,
        Path
    ],
    source_key: str,
    requested_url: str,
) -> (
    dict[str, Any]
    | None
):
    metadata_path = (
        paths[
            "metadata"
        ]
    )

    body_path = (
        paths[
            "body"
        ]
    )

    text_path = (
        paths[
            "text"
        ]
    )

    links_path = (
        paths[
            "links"
        ]
    )

    if not (
        metadata_path.is_file()
        and body_path.is_file()
        and text_path.is_file()
        and links_path.is_file()
    ):
        return None

    try:
        metadata = load_json(
            metadata_path
        )

    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
    ):
        return None

    if (
        metadata.get(
            "schema_version"
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
                "requested_url"
            )
        )
        != requested_url
    ):
        return None

    try:
        body = (
            body_path.read_bytes()
        )

        text = (
            text_path.read_text(
                encoding="utf-8"
            )
        )

        links_data = load_json(
            links_path
        )

    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
    ):
        return None

    expected_body_sha = (
        clean_text(
            metadata.get(
                "body_sha256"
            )
        )
    )

    expected_text_sha = (
        clean_text(
            metadata.get(
                "text_sha256"
            )
        )
    )

    if (
        expected_body_sha
        != sha256_bytes(
            body
        )
    ):
        return None

    if (
        expected_text_sha
        != sha256_text(
            text
        )
    ):
        return None

    links = links_data.get(
        "links",
        [],
    )

    if not isinstance(
        links,
        list,
    ):
        return None

    result = dict(
        metadata.get(
            "result",
            {}
        )
    )

    if not isinstance(
        result,
        dict,
    ):
        return None

    result[
        "cache_hit"
    ] = True

    result[
        "network_fetch"
    ] = False

    return result


def fetch_source(
    *,
    session: requests.Session,
    source: dict[str, Any],
    cache_dir: Path,
    timeout_seconds: int,
    max_bytes: int,
) -> dict[str, Any]:
    source_key = clean_text(
        source.get(
            "source_key"
        )
    )

    target = source.get(
        "target",
        {},
    )

    if not isinstance(
        target,
        dict,
    ):
        target = {}

    requested_url = (
        normalized_http_url(
            target.get(
                "url"
            )
        )
    )

    base_result: dict[
        str,
        Any
    ] = {
        "source_key":
            source_key,

        "distribution":
            clean_text(
                source.get(
                    "distribution"
                )
            ),

        "vulnerability_ids":
            source.get(
                "vulnerability_ids",
                [],
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
            clean_text(
                source.get(
                    "acquisition_backend"
                )
            ),

        "acquisition_version":
            ACQUISITION_VERSION,

        "requested_url":
            requested_url,

        "status":
            "unresolved",

        "reason":
            "",

        "cache_hit":
            False,

        "network_fetch":
            False,
    }

    if not source_key:
        base_result[
            "reason"
        ] = (
            "missing_source_key"
        )

        return base_result

    if not requested_url:
        base_result[
            "reason"
        ] = (
            "invalid_or_missing_http_url"
        )

        return base_result

    paths = cache_paths(
        cache_dir,
        source_key,
    )

    cached = (
        read_cached_result(
            paths=paths,
            source_key=source_key,
            requested_url=requested_url,
        )
    )

    if cached is not None:
        return cached

    try:
        response = session.get(
            requested_url,
            timeout=timeout_seconds,
            allow_redirects=True,
            stream=True,
        )

    except requests.RequestException as exc:
        base_result[
            "reason"
        ] = (
            "network_error:"
            + type(exc).__name__
        )

        return base_result

    base_result[
        "network_fetch"
    ] = True

    base_result[
        "http_status"
    ] = response.status_code

    base_result[
        "final_url"
    ] = clean_text(
        response.url
    )

    raw_content_type = (
        response.headers.get(
            "Content-Type",
            "",
        )
    )

    content_type = (
        content_type_base(
            raw_content_type
        )
    )

    base_result[
        "content_type"
    ] = content_type

    if not (
        200
        <= response.status_code
        < 300
    ):
        base_result[
            "reason"
        ] = (
            "http_status_"
            + str(
                response.status_code
            )
        )

        return base_result

    if (
        content_type
        and not is_supported_content_type(
            content_type
        )
    ):
        base_result[
            "reason"
        ] = (
            "unsupported_content_type:"
            + content_type
        )

        return base_result

    chunks: list[
        bytes
    ] = []

    total_bytes = 0

    try:
        for chunk in (
            response.iter_content(
                chunk_size=65536
            )
        ):
            if not chunk:
                continue

            total_bytes += len(
                chunk
            )

            if (
                total_bytes
                > max_bytes
            ):
                base_result[
                    "reason"
                ] = (
                    "response_too_large"
                )

                return base_result

            chunks.append(
                chunk
            )

    except requests.RequestException as exc:
        base_result[
            "reason"
        ] = (
            "response_read_error:"
            + type(exc).__name__
        )

        return base_result

    body = b"".join(
        chunks
    )

    if not body:
        base_result[
            "reason"
        ] = (
            "empty_response_body"
        )

        return base_result

    encoding = (
        response.encoding
        or response.apparent_encoding
        or "utf-8"
    )

    links: list[
        dict[str, str]
    ] = []

    if (
        content_type
        in {
            "text/html",
            "application/xhtml+xml",
        }
        or (
            not content_type
            and b"<html"
            in body[:4096].lower()
        )
    ):
        text, links = (
            extract_html(
                body,
                base_url=clean_text(
                    response.url
                )
                or requested_url,
                encoding=encoding,
            )
        )

        extraction_mode = (
            "html_visible_text"
        )

    elif is_json_content_type(
        content_type
    ):
        try:
            (
                text,
                extraction_mode,
                json_metadata,
            ) = extract_json_evidence_text(
                body,
                encoding=encoding,
                vulnerability_ids=(
                    base_result.get(
                        "vulnerability_ids",
                        [],
                    )
                ),
            )

        except json.JSONDecodeError:
            base_result[
                "reason"
            ] = (
                "invalid_json_response"
            )

            return base_result

        base_result[
            "json_csaf_like"
        ] = bool(
            json_metadata.get(
                "csaf_like"
            )
        )

        base_result[
            "json_target_slice_applied"
        ] = bool(
            json_metadata.get(
                "target_slice_applied"
            )
        )

        base_result[
            "json_matched_target_ids"
        ] = json_metadata.get(
            "matched_target_ids",
            [],
        )

        if (
            extraction_mode
            == "json_csaf_target_unresolved"
        ):
            base_result[
                "reason"
            ] = (
                "json_target_vulnerability_not_found"
            )

            return base_result

    else:
        text = (
            extract_plain_text(
                body,
                encoding=encoding,
            )
        )

        extraction_mode = (
            "plain_text"
        )

    text = text.strip()

    if not text:
        base_result[
            "reason"
        ] = (
            "no_visible_text"
        )

        return base_result

    paths[
        "metadata"
    ].parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    paths[
        "body"
    ].write_bytes(
        body
    )

    paths[
        "text"
    ].write_text(
        text,
        encoding="utf-8",
    )

    write_json(
        paths[
            "links"
        ],
        {
            "schema_version":
                (
                    "avcs_trigger_"
                    "generic_http_links_v0.1"
                ),

            "source_key":
                source_key,

            "base_url":
                clean_text(
                    response.url
                )
                or requested_url,

            "links":
                links,
        },
    )

    body_sha = (
        sha256_bytes(
            body
        )
    )

    text_sha = (
        sha256_text(
            text
        )
    )

    base_result.update(
        {
            "status":
                "resolved",

            "reason":
                "",

            "final_url":
                clean_text(
                    response.url
                )
                or requested_url,

            "content_type":
                content_type,

            "encoding":
                encoding,

            "extraction_mode":
                extraction_mode,

            "body_sha256":
                body_sha,

            "body_size_bytes":
                len(
                    body
                ),

            "text_sha256":
                text_sha,

            "text_size_chars":
                len(
                    text
                ),

            "link_count":
                len(
                    links
                ),

            "cache_body_path":
                relative_project_path(
                    paths[
                        "body"
                    ]
                ),

            "cache_text_path":
                relative_project_path(
                    paths[
                        "text"
                    ]
                ),

            "cache_links_path":
                relative_project_path(
                    paths[
                        "links"
                    ]
                ),

            "cache_metadata_path":
                relative_project_path(
                    paths[
                        "metadata"
                    ]
                ),
        }
    )

    metadata = {
        "schema_version":
            CACHE_SCHEMA_VERSION,

        "acquisition_version":
            ACQUISITION_VERSION,

        "source_key":
            source_key,

        "requested_url":
            requested_url,

        "body_sha256":
            body_sha,

        "text_sha256":
            text_sha,

        "result":
            base_result,
    }

    write_json(
        paths[
            "metadata"
        ],
        metadata,
    )

    return base_result


def acquire(
    *,
    plan: dict[str, Any],
    cache_dir: Path,
    timeout_seconds: int,
    max_bytes: int,
) -> dict[str, Any]:
    raw_sources = plan.get(
        "sources",
        [],
    )

    if not isinstance(
        raw_sources,
        list,
    ):
        raise ValueError(
            "Plan field 'sources' must be a list."
        )

    selected_sources = [
        source
        for source
        in raw_sources
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
            == PHASE_GENERIC_WEB
            and clean_text(
                source.get(
                    "acquisition_backend"
                )
            )
            in SUPPORTED_BACKENDS
        )
    ]

    session = build_session()

    results = [
        fetch_source(
            session=session,
            source=source,
            cache_dir=cache_dir,
            timeout_seconds=(
                timeout_seconds
            ),
            max_bytes=max_bytes,
        )
        for source
        in selected_sources
    ]

    status_counts = Counter(
        clean_text(
            row.get(
                "status"
            )
        )
        for row in results
    )

    domain_counts = Counter()

    for row in results:
        url = clean_text(
            row.get(
                "requested_url"
            )
        )

        try:
            domain = (
                urlparse(
                    url
                ).hostname
                or ""
            ).lower()

        except ValueError:
            domain = ""

        if domain:
            domain_counts[
                domain
            ] += 1

    resolved_count = (
        status_counts[
            "resolved"
        ]
    )

    unresolved_count = (
        len(
            results
        )
        - resolved_count
    )

    return {
        "schema_version":
            SCHEMA_VERSION,

        "acquisition_version":
            ACQUISITION_VERSION,

        "status":
            (
                "resolved"
                if unresolved_count == 0
                else "partial"
            ),

        "source_mode":
            (
                "single_page_"
                "generic_http_acquisition"
            ),

        "semantic_boundary": {
            "fetches_single_pages_only":
                True,

            "supports_validated_json_transport":
                True,

            "json_transport_implies_semantic_validity":
                False,

            "supports_csaf_target_slicing":
                True,

            "csaf_full_product_tree_enters_semantic_text":
                False,

            "csaf_reference_urls_enter_semantic_text":
                False,

            "csaf_target_slice_implies_trigger_truth":
                False,

            "recursive_crawling":
                False,

            "uses_browser_or_javascript":
                False,

            "bypasses_access_controls":
                False,

            "infers_trigger_semantics":
                False,

            "creates_trigger_rules":
                False,

            "uses_llm_semantic_inference":
                False,

            "consumes_trigger_raw_ground_truth":
                False,

            "preserves_fetch_failures":
                True,
        },

        "summary": {
            "selected_source_count":
                len(
                    selected_sources
                ),

            "resolved_source_count":
                resolved_count,

            "unresolved_source_count":
                unresolved_count,

            "cache_hit_count":
                sum(
                    1
                    for row in results
                    if row.get(
                        "cache_hit"
                    )
                    is True
                ),

            "network_fetch_count":
                sum(
                    1
                    for row in results
                    if row.get(
                        "network_fetch"
                    )
                    is True
                ),

            "extracted_link_count":
                sum(
                    int(
                        row.get(
                            "link_count",
                            0,
                        )
                        or 0
                    )
                    for row
                    in results
                    if row.get(
                        "status"
                    )
                    == "resolved"
                ),

            "status_counts":
                dict(
                    sorted(
                        status_counts.items()
                    )
                ),

            "domain_counts":
                dict(
                    sorted(
                        domain_counts.items()
                    )
                ),
        },

        "results":
            results,
    }


def main() -> None:
    parser = (
        argparse.ArgumentParser(
            description=(
                "Acquire Phase-3 generic HTTP "
                "Trigger Evidence source pages "
                "without inferring vulnerability "
                "semantics."
            )
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
        default=(
            DEFAULT_TIMEOUT_SECONDS
        ),
    )

    parser.add_argument(
        "--max-bytes",
        type=int,
        default=(
            DEFAULT_MAX_BYTES
        ),
    )

    args = parser.parse_args()

    if args.timeout <= 0:
        raise ValueError(
            "--timeout must be > 0."
        )

    if args.max_bytes <= 0:
        raise ValueError(
            "--max-bytes must be > 0."
        )

    result = acquire(
        plan=load_json(
            args.plan
        ),
        cache_dir=args.cache_dir,
        timeout_seconds=(
            args.timeout
        ),
        max_bytes=(
            args.max_bytes
        ),
    )

    write_json(
        args.out,
        result,
    )

    summary = result.get(
        "summary",
        {},
    )

    print(
        "=" * 60
    )

    print(
        "TRIGGER GENERIC HTTP ACQUISITION SUMMARY"
    )

    print(
        "=" * 60
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
        summary.get(
            "selected_source_count",
            0,
        ),
    )

    print(
        "[OK] resolved sources:",
        summary.get(
            "resolved_source_count",
            0,
        ),
    )

    print(
        "[OK] unresolved sources:",
        summary.get(
            "unresolved_source_count",
            0,
        ),
    )

    print(
        "[OK] cache hits:",
        summary.get(
            "cache_hit_count",
            0,
        ),
    )

    print(
        "[OK] network fetches:",
        summary.get(
            "network_fetch_count",
            0,
        ),
    )

    print(
        "[OK] extracted links:",
        summary.get(
            "extracted_link_count",
            0,
        ),
    )

    print(
        "[OK] statuses:",
        json.dumps(
            summary.get(
                "status_counts",
                {},
            ),
            ensure_ascii=False,
            sort_keys=True,
        ),
    )

    print(
        "[OK] domains:",
        json.dumps(
            summary.get(
                "domain_counts",
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