from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

SCHEMA_VERSION = (
    "avcs_trigger_candidate_evidence_corpus_v0.1"
)

BUILDER_VERSION = (
    "trigger_candidate_evidence_corpus_builder_v0.1"
)

DEFAULT_PLAN = (
    ROOT
    / "output"
    / "avcs_trigger_source_acquisition_plan_v0.json"
)

DEFAULT_LOCAL = (
    ROOT
    / "output"
    / "avcs_trigger_local_structured_acquisition_v0.json"
)

DEFAULT_GITHUB_FILES = (
    ROOT
    / "output"
    / "avcs_trigger_github_file_acquisition_v0.json"
)

DEFAULT_GITHUB_COMMITS = (
    ROOT
    / "output"
    / "avcs_trigger_github_commit_acquisition_v0.json"
)

DEFAULT_GITHUB_METADATA = (
    ROOT
    / "output"
    / "avcs_trigger_github_metadata_acquisition_v0.json"
)

DEFAULT_OUTPUT = (
    ROOT
    / "output"
    / "avcs_trigger_candidate_evidence_corpus_v0.json"
)


STRUCTURED_PHASES = {
    "phase_1_structured_evidence",
    "phase_2_structured_metadata",
}

LOCAL_BACKENDS = {
    "local_evidence_file",
    "osv_api_record",
}

GITHUB_FILE_BACKENDS = {
    "github_blob_url",
    "github_repository_file",
}

GITHUB_COMMIT_BACKENDS = {
    "github_commit_url",
    "github_repository_commit",
}

GITHUB_METADATA_BACKENDS = {
    "github_security_advisory_url",
    "github_pull_request_url",
    "github_issue_url",
    "github_release_url",
}

SUPPORTED_BACKENDS = (
    LOCAL_BACKENDS
    | GITHUB_FILE_BACKENDS
    | GITHUB_COMMIT_BACKENDS
    | GITHUB_METADATA_BACKENDS
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


def sha256_bytes(
    data: bytes,
) -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            data
        ).hexdigest()
    )


def sha256_text(
    text: str,
) -> str:
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


def resolve_project_path(
    path_text: Any,
) -> tuple[
    Path | None,
    str,
]:
    text = clean_text(
        path_text
    )

    if not text:
        return (
            None,
            "missing_artifact_path",
        )

    candidate = (
        ROOT
        / Path(
            text
        )
    ).resolve()

    try:
        candidate.relative_to(
            ROOT.resolve()
        )

    except ValueError:
        return (
            None,
            "artifact_path_outside_project_root",
        )

    if not candidate.exists():
        return (
            candidate,
            "artifact_not_found",
        )

    if not candidate.is_file():
        return (
            candidate,
            "artifact_path_not_file",
        )

    return (
        candidate,
        "resolved",
    )


def rows_from(
    data: dict[str, Any],
) -> list[
    dict[str, Any]
]:
    rows = data.get(
        "results",
        [],
    )

    if not isinstance(
        rows,
        list,
    ):
        return []

    return [
        row
        for row in rows
        if isinstance(
            row,
            dict,
        )
    ]


def index_rows(
    datasets: list[
        tuple[
            str,
            dict[str, Any],
        ]
    ],
) -> tuple[
    dict[str, dict[str, Any]],
    dict[str, list[str]],
]:
    index: dict[
        str,
        dict[str, Any],
    ] = {}

    duplicates: dict[
        str,
        list[str],
    ] = {}

    for (
        dataset_name,
        data,
    ) in datasets:
        for row in rows_from(
            data
        ):
            source_key = clean_text(
                row.get(
                    "source_key"
                )
            )

            if not source_key:
                continue

            wrapped = {
                "dataset":
                    dataset_name,

                "row":
                    row,
            }

            if source_key in index:
                existing_dataset = clean_text(
                    index[
                        source_key
                    ].get(
                        "dataset"
                    )
                )

                duplicates.setdefault(
                    source_key,
                    [
                        existing_dataset
                    ],
                ).append(
                    dataset_name
                )

            else:
                index[
                    source_key
                ] = wrapped

    return (
        index,
        duplicates,
    )


def make_unit(
    source_key: str,
    ordinal: int,
    unit_kind: str,
    text: Any,
    locator: (
        dict[str, Any]
        | None
    ) = None,
) -> (
    dict[str, Any]
    | None
):
    if not isinstance(
        text,
        str,
    ):
        return None

    if not text.strip():
        return None

    return {
        "unit_id":
            (
                f"{source_key}"
                f"::unit_{ordinal:03d}"
            ),

        "unit_kind":
            unit_kind,

        "text":
            text,

        "text_sha256":
            sha256_text(
                text
            ),

        "size_chars":
            len(
                text
            ),

        "locator":
            (
                locator
                or {}
            ),
    }


def append_unit(
    units: list[
        dict[str, Any]
    ],
    source_key: str,
    unit_kind: str,
    text: Any,
    locator: (
        dict[str, Any]
        | None
    ) = None,
) -> None:
    unit = make_unit(
        source_key=source_key,
        ordinal=(
            len(
                units
            )
            + 1
        ),
        unit_kind=unit_kind,
        text=text,
        locator=locator,
    )

    if unit is not None:
        units.append(
            unit
        )


def artifact_info(
    path_text: Any,
    expected_sha256: Any,
    expected_size: Any,
) -> tuple[
    dict[str, Any],
    bytes | None,
]:
    (
        path,
        path_status,
    ) = resolve_project_path(
        path_text
    )

    info: dict[
        str,
        Any,
    ] = {
        "path":
            clean_text(
                path_text
            ),

        "status":
            path_status,

        "expected_sha256":
            clean_text(
                expected_sha256
            ),

        "expected_size_bytes":
            expected_size,

        "verified":
            False,
    }

    if (
        path_status
        != "resolved"
        or path is None
    ):
        return (
            info,
            None,
        )

    try:
        payload = (
            path.read_bytes()
        )

    except OSError as exc:
        info[
            "status"
        ] = (
            "artifact_read_error"
        )

        info[
            "error"
        ] = str(
            exc
        )

        return (
            info,
            None,
        )

    actual_sha256 = (
        sha256_bytes(
            payload
        )
    )

    actual_size = len(
        payload
    )

    info.update(
        {
            "path":
                relative_project_path(
                    path
                ),

            "actual_sha256":
                actual_sha256,

            "actual_size_bytes":
                actual_size,
        }
    )

    expected_hash = clean_text(
        expected_sha256
    )

    if (
        expected_hash
        and expected_hash
        != actual_sha256
    ):
        info[
            "status"
        ] = (
            "artifact_sha256_mismatch"
        )

        return (
            info,
            None,
        )

    if (
        isinstance(
            expected_size,
            int,
        )
        and expected_size >= 0
        and expected_size
        != actual_size
    ):
        info[
            "status"
        ] = (
            "artifact_size_mismatch"
        )

        return (
            info,
            None,
        )

    info[
        "status"
    ] = "resolved"

    info[
        "verified"
    ] = True

    return (
        info,
        payload,
    )


def decode_utf8(
    payload: bytes,
) -> tuple[
    str,
    str,
]:
    try:
        return (
            payload.decode(
                "utf-8"
            ),
            "resolved",
        )

    except UnicodeDecodeError:
        try:
            return (
                payload.decode(
                    "utf-8-sig"
                ),
                "resolved_utf8_sig",
            )

        except UnicodeDecodeError:
            return (
                "",
                "non_utf8_text",
            )


def parse_json_bytes(
    payload: bytes,
) -> tuple[
    dict[str, Any] | None,
    str,
]:
    (
        text,
        decode_status,
    ) = decode_utf8(
        payload
    )

    if not text:
        return (
            None,
            decode_status,
        )

    try:
        data = json.loads(
            text
        )

    except json.JSONDecodeError:
        return (
            None,
            "invalid_json",
        )

    if not isinstance(
        data,
        dict,
    ):
        return (
            None,
            "json_not_object",
        )

    return (
        data,
        "resolved",
    )


def build_local_units(
    source_key: str,
    row: dict[str, Any],
) -> tuple[
    list[dict[str, Any]],
    dict[str, Any],
    dict[str, Any],
]:
    (
        provenance,
        payload,
    ) = artifact_info(
        row.get(
            "local_path"
        ),
        row.get(
            "sha256"
        ),
        row.get(
            "size_bytes"
        ),
    )

    units: list[
        dict[str, Any]
    ] = []

    canonical_identity: dict[
        str,
        Any,
    ] = {}

    if (
        row.get(
            "acquisition_backend"
        )
        == "osv_api_record"
    ):
        canonical_identity = {
            "requested_vulnerability_id":
                clean_text(
                    row.get(
                        "requested_vulnerability_id"
                    )
                ),

            "matched_record_id":
                clean_text(
                    row.get(
                        "matched_record_id"
                    )
                ),

            "matched_via":
                clean_text(
                    row.get(
                        "matched_via"
                    )
                ),
        }

    else:
        canonical_identity = {
            "path":
                clean_text(
                    row.get(
                        "local_path"
                    )
                ),

            "record_id":
                clean_text(
                    row.get(
                        "record_id"
                    )
                ),
        }

    if payload is None:
        return (
            units,
            provenance,
            canonical_identity,
        )

    (
        data,
        json_status,
    ) = parse_json_bytes(
        payload
    )

    provenance[
        "content_parse_status"
    ] = json_status

    if data is None:
        return (
            units,
            provenance,
            canonical_identity,
        )

    append_unit(
        units,
        source_key,
        "structured_json_summary",
        data.get(
            "summary"
        ),
        {
            "json_field":
                "summary",
        },
    )

    append_unit(
        units,
        source_key,
        "structured_json_details",
        data.get(
            "details"
        ),
        {
            "json_field":
                "details",
        },
    )

    canonical_json = (
        json.dumps(
            data,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )

    append_unit(
        units,
        source_key,
        "structured_json_record",
        canonical_json,
        {
            "content_kind":
                (
                    clean_text(
                        row.get(
                            "content_kind"
                        )
                    )
                    or "json"
                ),
        },
    )

    return (
        units,
        provenance,
        canonical_identity,
    )


def build_github_file_units(
    source_key: str,
    row: dict[str, Any],
) -> tuple[
    list[dict[str, Any]],
    dict[str, Any],
    dict[str, Any],
]:
    (
        provenance,
        payload,
    ) = artifact_info(
        row.get(
            "cache_content_path"
        ),
        row.get(
            "content_sha256"
        ),
        row.get(
            "content_size_bytes"
        ),
    )

    provenance[
        "cache_metadata_path"
    ] = clean_text(
        row.get(
            "cache_metadata_path"
        )
    )

    provenance[
        "github_blob_sha"
    ] = clean_text(
        row.get(
            "github_blob_sha"
        )
    )

    provenance[
        "content_mode"
    ] = clean_text(
        row.get(
            "content_mode"
        )
    )

    canonical_identity = {
        "repository":
            clean_text(
                row.get(
                    "repository"
                )
            ),

        "ref":
            clean_text(
                row.get(
                    "ref"
                )
            ),

        "path":
            clean_text(
                row.get(
                    "path"
                )
            ),

        "github_blob_sha":
            clean_text(
                row.get(
                    "github_blob_sha"
                )
            ),
    }

    units: list[
        dict[str, Any]
    ] = []

    if payload is None:
        return (
            units,
            provenance,
            canonical_identity,
        )

    (
        text,
        decode_status,
    ) = decode_utf8(
        payload
    )

    provenance[
        "content_decode_status"
    ] = decode_status

    append_unit(
        units,
        source_key,
        "github_source_file_text",
        text,
        {
            "repository":
                clean_text(
                    row.get(
                        "repository"
                    )
                ),

            "ref":
                clean_text(
                    row.get(
                        "ref"
                    )
                ),

            "path":
                clean_text(
                    row.get(
                        "path"
                    )
                ),
        },
    )

    return (
        units,
        provenance,
        canonical_identity,
    )


def build_github_commit_units(
    source_key: str,
    row: dict[str, Any],
) -> tuple[
    list[dict[str, Any]],
    dict[str, Any],
    dict[str, Any],
]:
    (
        provenance,
        payload,
    ) = artifact_info(
        row.get(
            "cache_response_path"
        ),
        row.get(
            "response_sha256"
        ),
        row.get(
            "response_size_bytes"
        ),
    )

    provenance[
        "cache_metadata_path"
    ] = clean_text(
        row.get(
            "cache_metadata_path"
        )
    )

    canonical_identity = {
        "repository":
            clean_text(
                row.get(
                    "repository"
                )
            ),

        "requested_commit":
            clean_text(
                row.get(
                    "requested_commit"
                )
            ),

        "canonical_commit_sha":
            clean_text(
                row.get(
                    "canonical_commit_sha"
                )
            ),
    }

    units: list[
        dict[str, Any]
    ] = []

    if payload is None:
        return (
            units,
            provenance,
            canonical_identity,
        )

    (
        data,
        json_status,
    ) = parse_json_bytes(
        payload
    )

    provenance[
        "content_parse_status"
    ] = json_status

    if data is None:
        return (
            units,
            provenance,
            canonical_identity,
        )

    commit_data = data.get(
        "commit",
        {},
    )

    if not isinstance(
        commit_data,
        dict,
    ):
        commit_data = {}

    append_unit(
        units,
        source_key,
        "github_commit_message",
        commit_data.get(
            "message"
        ),
        {
            "json_field":
                "commit.message",
        },
    )

    files = data.get(
        "files",
        [],
    )

    if not isinstance(
        files,
        list,
    ):
        files = []

    for file_item in files:
        if not isinstance(
            file_item,
            dict,
        ):
            continue

        append_unit(
            units,
            source_key,
            "github_commit_patch",
            file_item.get(
                "patch"
            ),
            {
                "filename":
                    clean_text(
                        file_item.get(
                            "filename"
                        )
                    ),

                "status":
                    clean_text(
                        file_item.get(
                            "status"
                        )
                    ),
            },
        )

    provenance[
        "changed_file_count"
    ] = len(
        [
            item
            for item in files
            if isinstance(
                item,
                dict,
            )
        ]
    )

    provenance[
        "patch_unit_count"
    ] = sum(
        1
        for unit in units
        if (
            unit.get(
                "unit_kind"
            )
            == "github_commit_patch"
        )
    )

    return (
        units,
        provenance,
        canonical_identity,
    )


def build_github_metadata_units(
    source_key: str,
    row: dict[str, Any],
) -> tuple[
    list[dict[str, Any]],
    dict[str, Any],
    dict[str, Any],
]:
    (
        provenance,
        payload,
    ) = artifact_info(
        row.get(
            "cache_response_path"
        ),
        row.get(
            "response_sha256"
        ),
        row.get(
            "response_size_bytes"
        ),
    )

    provenance[
        "cache_metadata_path"
    ] = clean_text(
        row.get(
            "cache_metadata_path"
        )
    )

    provenance[
        "api_url"
    ] = clean_text(
        row.get(
            "api_url"
        )
    )

    canonical_identity = (
        row.get(
            "canonical_identity",
            {},
        )
    )

    if not isinstance(
        canonical_identity,
        dict,
    ):
        canonical_identity = {}

    units: list[
        dict[str, Any]
    ] = []

    if payload is None:
        return (
            units,
            provenance,
            canonical_identity,
        )

    (
        data,
        json_status,
    ) = parse_json_bytes(
        payload
    )

    provenance[
        "content_parse_status"
    ] = json_status

    if data is None:
        return (
            units,
            provenance,
            canonical_identity,
        )

    backend = clean_text(
        row.get(
            "acquisition_backend"
        )
    )

    if (
        backend
        == "github_security_advisory_url"
    ):
        append_unit(
            units,
            source_key,
            "github_advisory_summary",
            data.get(
                "summary"
            ),
            {
                "json_field":
                    "summary",
            },
        )

        append_unit(
            units,
            source_key,
            "github_advisory_description",
            data.get(
                "description"
            ),
            {
                "json_field":
                    "description",
            },
        )

    elif (
        backend
        == "github_pull_request_url"
    ):
        append_unit(
            units,
            source_key,
            "github_pull_request_title",
            data.get(
                "title"
            ),
            {
                "json_field":
                    "title",
            },
        )

        append_unit(
            units,
            source_key,
            "github_pull_request_body",
            data.get(
                "body"
            ),
            {
                "json_field":
                    "body",
            },
        )

    elif (
        backend
        == "github_issue_url"
    ):
        append_unit(
            units,
            source_key,
            "github_issue_title",
            data.get(
                "title"
            ),
            {
                "json_field":
                    "title",
            },
        )

        append_unit(
            units,
            source_key,
            "github_issue_body",
            data.get(
                "body"
            ),
            {
                "json_field":
                    "body",
            },
        )

    elif (
        backend
        == "github_release_url"
    ):
        release_title = (
            data.get(
                "name"
            )
            or data.get(
                "tag_name"
            )
        )

        append_unit(
            units,
            source_key,
            "github_release_title",
            release_title,
            {
                "json_field":
                    "name_or_tag_name",
            },
        )

        append_unit(
            units,
            source_key,
            "github_release_body",
            data.get(
                "body"
            ),
            {
                "json_field":
                    "body",
            },
        )

    return (
        units,
        provenance,
        canonical_identity,
    )


def build_entry(
    plan_source: dict[str, Any],
    indexed: (
        dict[str, Any]
        | None
    ),
    duplicate_datasets: (
        list[str]
        | None
    ),
) -> dict[str, Any]:
    source_key = clean_text(
        plan_source.get(
            "source_key"
        )
    )

    backend = clean_text(
        plan_source.get(
            "acquisition_backend"
        )
    )

    vulnerability_ids = (
        plan_source.get(
            "vulnerability_ids",
            [],
        )
    )

    if not isinstance(
        vulnerability_ids,
        list,
    ):
        vulnerability_ids = []

    target = plan_source.get(
        "target",
        {},
    )

    if not isinstance(
        target,
        dict,
    ):
        target = {}

    base: dict[
        str,
        Any,
    ] = {
        "source_key":
            source_key,

        "distribution":
            clean_text(
                plan_source.get(
                    "distribution"
                )
            ),

        "vulnerability_ids":
            vulnerability_ids,

        "source_id":
            clean_text(
                plan_source.get(
                    "source_id"
                )
            ),

        "source_type":
            clean_text(
                plan_source.get(
                    "source_type"
                )
            ),

        "acquisition_phase":
            clean_text(
                plan_source.get(
                    "acquisition_phase"
                )
            ),

        "acquisition_backend":
            backend,

        "target":
            target,

        "locator_note":
            clean_text(
                plan_source.get(
                    "locator_note"
                )
            ),

        "has_claim":
            bool(
                plan_source.get(
                    "has_claim"
                )
            ),

        "corpus_status":
            "unresolved",

        "reason":
            "",

        "canonical_identity":
            {},

        "provenance":
            {},

        "evidence_units":
            [],
    }

    if duplicate_datasets:
        base[
            "reason"
        ] = (
            "duplicate_acquisition_results"
        )

        base[
            "duplicate_datasets"
        ] = duplicate_datasets

        return base

    if indexed is None:
        base[
            "reason"
        ] = (
            "acquisition_result_missing"
        )

        return base

    dataset_name = clean_text(
        indexed.get(
            "dataset"
        )
    )

    row = indexed.get(
        "row",
        {},
    )

    if not isinstance(
        row,
        dict,
    ):
        base[
            "reason"
        ] = (
            "acquisition_result_invalid"
        )

        return base

    base[
        "acquisition_dataset"
    ] = dataset_name

    base[
        "acquisition_status"
    ] = clean_text(
        row.get(
            "status"
        )
    )

    if (
        base[
            "acquisition_status"
        ]
        != "resolved"
    ):
        base[
            "reason"
        ] = (
            "acquisition_not_resolved"
        )

        return base

    if (
        clean_text(
            row.get(
                "acquisition_backend"
            )
        )
        != backend
    ):
        base[
            "reason"
        ] = (
            "acquisition_backend_mismatch"
        )

        return base

    units: list[
        dict[str, Any]
    ] = []

    provenance: dict[
        str,
        Any,
    ] = {}

    canonical_identity: dict[
        str,
        Any,
    ] = {}

    if backend in LOCAL_BACKENDS:
        (
            units,
            provenance,
            canonical_identity,
        ) = build_local_units(
            source_key,
            row,
        )

    elif backend in GITHUB_FILE_BACKENDS:
        (
            units,
            provenance,
            canonical_identity,
        ) = build_github_file_units(
            source_key,
            row,
        )

    elif backend in GITHUB_COMMIT_BACKENDS:
        (
            units,
            provenance,
            canonical_identity,
        ) = build_github_commit_units(
            source_key,
            row,
        )

    elif backend in GITHUB_METADATA_BACKENDS:
        (
            units,
            provenance,
            canonical_identity,
        ) = build_github_metadata_units(
            source_key,
            row,
        )

    else:
        base[
            "reason"
        ] = (
            "unsupported_backend"
        )

        return base

    base[
        "canonical_identity"
    ] = canonical_identity

    base[
        "provenance"
    ] = provenance

    base[
        "evidence_units"
    ] = units

    artifact_verified = (
        provenance.get(
            "verified"
        )
        is True
    )

    if not artifact_verified:
        base[
            "reason"
        ] = (
            clean_text(
                provenance.get(
                    "status"
                )
            )
            or "artifact_not_verified"
        )

        return base

    if not units:
        base[
            "corpus_status"
        ] = "partial"

        base[
            "reason"
        ] = (
            "no_extractable_text_units"
        )

        return base

    base[
        "corpus_status"
    ] = "resolved"

    base[
        "reason"
    ] = ""

    return base


def build_corpus(
    plan: dict[str, Any],
    local_data: dict[str, Any],
    github_file_data: dict[str, Any],
    github_commit_data: dict[str, Any],
    github_metadata_data: dict[str, Any],
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

    structured_sources = [
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
            in STRUCTURED_PHASES
        )
    ]

    (
        acquisition_index,
        duplicates,
    ) = index_rows(
        [
            (
                "local_structured",
                local_data,
            ),
            (
                "github_file",
                github_file_data,
            ),
            (
                "github_commit",
                github_commit_data,
            ),
            (
                "github_metadata",
                github_metadata_data,
            ),
        ]
    )

    entries = [
        build_entry(
            plan_source=source,
            indexed=(
                acquisition_index.get(
                    clean_text(
                        source.get(
                            "source_key"
                        )
                    )
                )
            ),
            duplicate_datasets=(
                duplicates.get(
                    clean_text(
                        source.get(
                            "source_key"
                        )
                    )
                )
            ),
        )
        for source in structured_sources
    ]

    status_counter = Counter(
        clean_text(
            entry.get(
                "corpus_status"
            )
        )
        for entry in entries
    )

    backend_counter = Counter(
        clean_text(
            entry.get(
                "acquisition_backend"
            )
        )
        for entry in entries
    )

    phase_counter = Counter(
        clean_text(
            entry.get(
                "acquisition_phase"
            )
        )
        for entry in entries
    )

    unit_kind_counter: Counter[
        str
    ] = Counter()

    evidence_unit_count = 0
    evidence_text_chars = 0

    for entry in entries:
        units = entry.get(
            "evidence_units",
            [],
        )

        if not isinstance(
            units,
            list,
        ):
            continue

        for unit in units:
            if not isinstance(
                unit,
                dict,
            ):
                continue

            evidence_unit_count += 1

            evidence_text_chars += int(
                unit.get(
                    "size_chars",
                    0,
                )
                or 0
            )

            unit_kind_counter[
                clean_text(
                    unit.get(
                        "unit_kind"
                    )
                )
            ] += 1

    structured_source_keys = {
        clean_text(
            source.get(
                "source_key"
            )
        )
        for source
        in structured_sources
        if clean_text(
            source.get(
                "source_key"
            )
        )
    }

    acquisition_source_keys = set(
        acquisition_index
    )

    orphan_acquisition_keys = sorted(
        acquisition_source_keys
        - structured_source_keys
    )

    generic_web_source_count = sum(
        1
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
            == "phase_3_generic_web"
        )
    )

    unresolved_entries = [
        {
            "source_key":
                clean_text(
                    entry.get(
                        "source_key"
                    )
                ),

            "status":
                clean_text(
                    entry.get(
                        "corpus_status"
                    )
                ),

            "reason":
                clean_text(
                    entry.get(
                        "reason"
                    )
                ),
        }
        for entry in entries
        if (
            entry.get(
                "corpus_status"
            )
            != "resolved"
        )
    ]

    overall_status = (
        "resolved"
        if (
            not unresolved_entries
            and not duplicates
            and not orphan_acquisition_keys
        )
        else "partial"
    )

    return {
        "schema_version":
            SCHEMA_VERSION,

        "builder_version":
            BUILDER_VERSION,

        "status":
            overall_status,

        "source_mode":
            (
                "structured_trigger_evidence_"
                "candidate_corpus"
            ),

        "semantic_boundary": {
            "contains_acquired_source_text":
                True,

            "infers_trigger_semantics":
                False,

            "creates_resolved_trigger_rules":
                False,

            "intended_next_stage":
                "candidate_fact_extraction",
        },

        "summary": {
            "plan_source_count":
                len(
                    [
                        source
                        for source
                        in plan_sources
                        if isinstance(
                            source,
                            dict,
                        )
                    ]
                ),

            "structured_plan_source_count":
                len(
                    structured_sources
                ),

            "generic_web_source_count_deferred":
                generic_web_source_count,

            "corpus_entry_count":
                len(
                    entries
                ),

            "resolved_entry_count":
                status_counter.get(
                    "resolved",
                    0,
                ),

            "partial_entry_count":
                status_counter.get(
                    "partial",
                    0,
                ),

            "unresolved_entry_count":
                status_counter.get(
                    "unresolved",
                    0,
                ),

            "evidence_unit_count":
                evidence_unit_count,

            "evidence_text_chars":
                evidence_text_chars,

            "phase_counts":
                dict(
                    sorted(
                        phase_counter.items()
                    )
                ),

            "backend_counts":
                dict(
                    sorted(
                        backend_counter.items()
                    )
                ),

            "unit_kind_counts":
                dict(
                    sorted(
                        unit_kind_counter.items()
                    )
                ),

            "duplicate_acquisition_source_count":
                len(
                    duplicates
                ),

            "orphan_acquisition_source_count":
                len(
                    orphan_acquisition_keys
                ),
        },

        "issues": {
            "duplicate_acquisition_sources":
                duplicates,

            "orphan_acquisition_source_keys":
                orphan_acquisition_keys,

            "non_resolved_entries":
                unresolved_entries,
        },

        "entries":
            entries,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Build a unified evidence corpus "
            "from resolved Trigger Evidence "
            "Phase-1/Phase-2 acquisition artifacts "
            "without inferring trigger semantics."
        )
    )

    parser.add_argument(
        "--plan",
        type=Path,
        default=DEFAULT_PLAN,
    )

    parser.add_argument(
        "--local",
        type=Path,
        default=DEFAULT_LOCAL,
    )

    parser.add_argument(
        "--github-files",
        type=Path,
        default=DEFAULT_GITHUB_FILES,
    )

    parser.add_argument(
        "--github-commits",
        type=Path,
        default=DEFAULT_GITHUB_COMMITS,
    )

    parser.add_argument(
        "--github-metadata",
        type=Path,
        default=DEFAULT_GITHUB_METADATA,
    )

    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUTPUT,
    )

    args = parser.parse_args()

    corpus = build_corpus(
        plan=load_json(
            args.plan
        ),
        local_data=load_json(
            args.local
        ),
        github_file_data=load_json(
            args.github_files
        ),
        github_commit_data=load_json(
            args.github_commits
        ),
        github_metadata_data=load_json(
            args.github_metadata
        ),
    )

    write_json(
        args.out,
        corpus,
    )

    summary = corpus.get(
        "summary",
        {},
    )

    print(
        "=" * 60
    )

    print(
        "TRIGGER CANDIDATE EVIDENCE CORPUS SUMMARY"
    )

    print(
        "=" * 60
    )

    print(
        f"[OK] schema: "
        f"{corpus.get('schema_version')}"
    )

    print(
        f"[OK] status: "
        f"{corpus.get('status')}"
    )

    print(
        f"[OK] plan sources: "
        f"{summary.get('plan_source_count', 0)}"
    )

    print(
        f"[OK] structured sources: "
        f"{summary.get('structured_plan_source_count', 0)}"
    )

    print(
        f"[OK] corpus entries: "
        f"{summary.get('corpus_entry_count', 0)}"
    )

    print(
        f"[OK] resolved entries: "
        f"{summary.get('resolved_entry_count', 0)}"
    )

    print(
        f"[OK] partial entries: "
        f"{summary.get('partial_entry_count', 0)}"
    )

    print(
        f"[OK] unresolved entries: "
        f"{summary.get('unresolved_entry_count', 0)}"
    )

    print(
        f"[OK] evidence units: "
        f"{summary.get('evidence_unit_count', 0)}"
    )

    print(
        "[OK] deferred generic web sources: "
        f"{summary.get('generic_web_source_count_deferred', 0)}"
    )

    print(
        f"[OK] saved: "
        f"{args.out}"
    )

    if (
        corpus.get(
            "status"
        )
        != "resolved"
    ):
        sys.exit(
            1
        )


if __name__ == "__main__":
    main()