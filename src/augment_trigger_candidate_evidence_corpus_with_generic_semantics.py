from __future__ import annotations

import argparse
import copy
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

BASE_SCHEMA_VERSION = (
    "avcs_trigger_candidate_evidence_corpus_v0.1"
)

AUGMENTATION_VERSION = (
    "generic_http_semantics_corpus_augmentation_v0.1"
)

DEFAULT_CORPUS = (
    ROOT
    / "output"
    / "avcs_trigger_candidate_evidence_corpus_v0.json"
)

DEFAULT_GENERIC_HTTP = (
    ROOT
    / "output"
    / "avcs_trigger_generic_http_acquisition_v0.json"
)

DEFAULT_OUTPUT = (
    ROOT
    / "output"
    / "avcs_trigger_candidate_evidence_corpus_with_generic_semantics_v0.json"
)

MIN_TEXT_CHARS = 200

GENERIC_HTTP_BACKEND = (
    "generic_http_url"
)

GENERIC_WEB_PHASE = (
    "phase_3_generic_web"
)

GENERIC_UNIT_KIND = (
    "generic_http_semantics_text"
)


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


def sha256_text(
    text: str,
) -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            text.encode(
                "utf-8"
            )
        ).hexdigest()
    )


def resolve_project_file(
    value: Any,
) -> tuple[
    Path | None,
    str,
]:
    text = clean_text(
        value
    )

    if not text:
        return (
            None,
            "missing_path",
        )

    path = Path(
        text
    )

    if not path.is_absolute():
        path = (
            ROOT
            / path
        )

    path = path.resolve()

    try:
        path.relative_to(
            ROOT.resolve()
        )

    except ValueError:
        return (
            None,
            "path_outside_project_root",
        )

    if not path.is_file():
        return (
            path,
            "file_not_found",
        )

    return (
        path,
        "resolved",
    )


def normalized_ids(
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


def exact_target_ids_in_text(
    text: str,
    vulnerability_ids: list[str],
) -> list[str]:
    lower = text.lower()

    return [
        vulnerability_id
        for vulnerability_id
        in vulnerability_ids
        if (
            vulnerability_id.lower()
            in lower
        )
    ]


def read_verified_text(
    row: dict[str, Any],
) -> tuple[
    str,
    str,
]:
    (
        path,
        path_status,
    ) = resolve_project_file(
        row.get(
            "cache_text_path"
        )
    )

    if (
        path_status
        != "resolved"
        or path is None
    ):
        return (
            "",
            path_status,
        )

    try:
        text = path.read_text(
            encoding="utf-8"
        )

    except OSError:
        return (
            "",
            "text_read_error",
        )

    expected_hash = clean_text(
        row.get(
            "text_sha256"
        )
    )

    actual_hash = (
        sha256_text(
            text
        )
    )

    if (
        not expected_hash
        or expected_hash
        != actual_hash
    ):
        return (
            "",
            "text_sha256_mismatch",
        )

    return (
        text,
        "resolved",
    )


def build_semantics_entry(
    row: dict[str, Any],
    *,
    text: str,
    matched_ids: list[str],
) -> dict[str, Any]:
    source_key = clean_text(
        row.get(
            "source_key"
        )
    )

    requested_url = clean_text(
        row.get(
            "requested_url"
        )
    )

    final_url = clean_text(
        row.get(
            "final_url"
        )
    )

    text_hash = clean_text(
        row.get(
            "text_sha256"
        )
    )

    return {
        "source_key":
            source_key,

        "distribution":
            clean_text(
                row.get(
                    "distribution"
                )
            ),

        "vulnerability_ids":
            normalized_ids(
                row.get(
                    "vulnerability_ids"
                )
            ),

        "source_id":
            clean_text(
                row.get(
                    "source_id"
                )
            ),

        "source_type":
            clean_text(
                row.get(
                    "source_type"
                )
            ),

        "acquisition_phase":
            GENERIC_WEB_PHASE,

        "acquisition_backend":
            GENERIC_HTTP_BACKEND,

        "target": {
            "requested_url":
                requested_url,

            "final_url":
                final_url,
        },

        "locator_note":
            (
                "Admitted as target-specific "
                "generic HTTP semantic evidence "
                "because the acquired page body "
                "contains at least one exact "
                "target vulnerability identifier."
            ),

        "has_claim":
            False,

        "corpus_status":
            "resolved",

        "reason":
            "",

        "canonical_identity": {
            "requested_url":
                requested_url,

            "final_url":
                final_url,
        },

        "provenance": {
            "verified":
                True,

            "status":
                "resolved",

            "acquisition_version":
                clean_text(
                    row.get(
                        "acquisition_version"
                    )
                ),

            "cache_text_path":
                clean_text(
                    row.get(
                        "cache_text_path"
                    )
                ),

            "text_sha256":
                text_hash,

            "content_type":
                clean_text(
                    row.get(
                        "content_type"
                    )
                ),

            "evidence_role":
                (
                    "target_specific_"
                    "semantics_only"
                ),

            "matched_target_ids":
                matched_ids,

            "version_facts_allowed":
                False,
        },

        "evidence_units": [
            {
                "unit_id":
                    (
                        source_key
                        + "::unit_001"
                    ),

                "unit_kind":
                    GENERIC_UNIT_KIND,

                "text":
                    text,

                "text_sha256":
                    text_hash,

                "size_chars":
                    len(
                        text
                    ),

                "locator": {
                    "requested_url":
                        requested_url,

                    "final_url":
                        final_url,

                    "matched_target_ids":
                        matched_ids,
                },

                "fact_policy": {
                    "allow_semantic_text_facts":
                        True,

                    "allow_version_facts":
                        False,
                },
            }
        ],
    }


def recompute_summary(
    corpus: dict[str, Any],
    *,
    evaluated_count: int,
    included_count: int,
    exclusion_counts: Counter[str],
) -> None:
    entries = corpus.get(
        "entries",
        [],
    )

    if not isinstance(
        entries,
        list,
    ):
        entries = []

    status_counter: Counter[
        str
    ] = Counter()

    phase_counter: Counter[
        str
    ] = Counter()

    backend_counter: Counter[
        str
    ] = Counter()

    unit_kind_counter: Counter[
        str
    ] = Counter()

    evidence_unit_count = 0

    evidence_text_chars = 0

    for entry in entries:
        if not isinstance(
            entry,
            dict,
        ):
            continue

        status_counter[
            clean_text(
                entry.get(
                    "corpus_status"
                )
            )
        ] += 1

        phase_counter[
            clean_text(
                entry.get(
                    "acquisition_phase"
                )
            )
        ] += 1

        backend_counter[
            clean_text(
                entry.get(
                    "acquisition_backend"
                )
            )
        ] += 1

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

    old_summary = corpus.get(
        "summary",
        {},
    )

    if not isinstance(
        old_summary,
        dict,
    ):
        old_summary = {}

    old_deferred = int(
        old_summary.get(
            "generic_web_source_count_deferred",
            0,
        )
        or 0
    )

    summary = dict(
        old_summary
    )

    summary.update(
        {
            "corpus_entry_count":
                len(
                    [
                        entry
                        for entry in entries
                        if isinstance(
                            entry,
                            dict,
                        )
                    ]
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

            "generic_web_source_count_deferred":
                max(
                    0,
                    old_deferred
                    - included_count,
                ),

            "generic_http_evaluated_source_count":
                evaluated_count,

            "generic_http_semantics_included_source_count":
                included_count,

            "generic_http_excluded_source_count":
                (
                    evaluated_count
                    - included_count
                ),

            "generic_http_exclusion_reason_counts":
                dict(
                    sorted(
                        exclusion_counts.items()
                    )
                ),
        }
    )

    corpus[
        "summary"
    ] = summary


def augment_corpus(
    base_corpus: dict[str, Any],
    generic_data: dict[str, Any],
) -> dict[str, Any]:
    if (
        clean_text(
            base_corpus.get(
                "schema_version"
            )
        )
        != BASE_SCHEMA_VERSION
    ):
        raise ValueError(
            "Unexpected base corpus schema."
        )

    result = copy.deepcopy(
        base_corpus
    )

    entries = result.get(
        "entries",
        [],
    )

    if not isinstance(
        entries,
        list,
    ):
        raise ValueError(
            "Corpus field 'entries' must be a list."
        )

    generic_rows = (
        generic_data.get(
            "results",
            [],
        )
    )

    if not isinstance(
        generic_rows,
        list,
    ):
        raise ValueError(
            "Generic acquisition field "
            "'results' must be a list."
        )

    existing_source_keys = {
        clean_text(
            entry.get(
                "source_key"
            )
        )
        for entry in entries
        if (
            isinstance(
                entry,
                dict,
            )
            and clean_text(
                entry.get(
                    "source_key"
                )
            )
        )
    }

    decisions: list[
        dict[str, Any]
    ] = []

    exclusion_counts: Counter[
        str
    ] = Counter()

    included_count = 0

    evaluated_count = 0

    for row in generic_rows:
        if not isinstance(
            row,
            dict,
        ):
            continue

        if (
            clean_text(
                row.get(
                    "acquisition_backend"
                )
            )
            != GENERIC_HTTP_BACKEND
        ):
            continue

        evaluated_count += 1

        source_key = clean_text(
            row.get(
                "source_key"
            )
        )

        decision: dict[
            str,
            Any
        ] = {
            "source_key":
                source_key,

            "distribution":
                clean_text(
                    row.get(
                        "distribution"
                    )
                ),

            "requested_url":
                clean_text(
                    row.get(
                        "requested_url"
                    )
                ),

            "status":
                "excluded",

            "reason":
                "",

            "matched_target_ids":
                [],
        }

        if (
            clean_text(
                row.get(
                    "status"
                )
            )
            != "resolved"
        ):
            reason = (
                "acquisition_not_resolved"
            )

            decision[
                "reason"
            ] = reason

            exclusion_counts[
                reason
            ] += 1

            decisions.append(
                decision
            )

            continue

        if (
            not source_key
            or source_key
            in existing_source_keys
        ):
            reason = (
                "missing_or_duplicate_source_key"
            )

            decision[
                "reason"
            ] = reason

            exclusion_counts[
                reason
            ] += 1

            decisions.append(
                decision
            )

            continue

        (
            text,
            text_status,
        ) = read_verified_text(
            row
        )

        if (
            text_status
            != "resolved"
        ):
            reason = (
                "text_verification_failed:"
                + text_status
            )

            decision[
                "reason"
            ] = reason

            exclusion_counts[
                reason
            ] += 1

            decisions.append(
                decision
            )

            continue

        if len(
            text.strip()
        ) < MIN_TEXT_CHARS:
            reason = (
                "content_too_short"
            )

            decision[
                "reason"
            ] = reason

            exclusion_counts[
                reason
            ] += 1

            decisions.append(
                decision
            )

            continue

        vulnerability_ids = (
            normalized_ids(
                row.get(
                    "vulnerability_ids"
                )
            )
        )

        matched_ids = (
            exact_target_ids_in_text(
                text,
                vulnerability_ids,
            )
        )

        decision[
            "matched_target_ids"
        ] = matched_ids

        if not matched_ids:
            reason = (
                "target_id_not_found_in_body"
            )

            decision[
                "reason"
            ] = reason

            exclusion_counts[
                reason
            ] += 1

            decisions.append(
                decision
            )

            continue

        entry = (
            build_semantics_entry(
                row,
                text=text,
                matched_ids=matched_ids,
            )
        )

        entries.append(
            entry
        )

        existing_source_keys.add(
            source_key
        )

        included_count += 1

        decision[
            "status"
        ] = "included"

        decision[
            "reason"
        ] = (
            "exact_target_id_"
            "in_verified_page_body"
        )

        decisions.append(
            decision
        )

    result[
        "entries"
    ] = entries

    result[
        "augmentation_version"
    ] = (
        AUGMENTATION_VERSION
    )

    result[
        "source_mode"
    ] = (
        "structured_plus_"
        "target_specific_generic_"
        "semantics_candidate_corpus"
    )

    boundary = result.get(
        "semantic_boundary",
        {},
    )

    if not isinstance(
        boundary,
        dict,
    ):
        boundary = {}

    boundary.update(
        {
            "generic_http_sources_are_semantics_only":
                True,

            "generic_http_version_facts_allowed":
                False,

            "generic_http_requires_exact_target_id_in_body":
                True,

            "generic_http_minimum_text_chars":
                MIN_TEXT_CHARS,

            "generic_http_recursive_link_following":
                False,

            "infers_trigger_semantics":
                False,

            "creates_resolved_trigger_rules":
                False,
        }
    )

    result[
        "semantic_boundary"
    ] = boundary

    result[
        "generic_http_semantics_augmentation"
    ] = {
        "augmentation_version":
            AUGMENTATION_VERSION,

        "evaluated_source_count":
            evaluated_count,

        "included_source_count":
            included_count,

        "excluded_source_count":
            (
                evaluated_count
                - included_count
            ),

        "exclusion_reason_counts":
            dict(
                sorted(
                    exclusion_counts.items()
                )
            ),

        "decisions":
            decisions,
    }

    recompute_summary(
        result,
        evaluated_count=(
            evaluated_count
        ),
        included_count=(
            included_count
        ),
        exclusion_counts=(
            exclusion_counts
        ),
    )

    unresolved_entries = [
        entry
        for entry in entries
        if (
            isinstance(
                entry,
                dict,
            )
            and clean_text(
                entry.get(
                    "corpus_status"
                )
            )
            != "resolved"
        )
    ]

    result[
        "status"
    ] = (
        "resolved"
        if not unresolved_entries
        else "partial"
    )

    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Augment an existing structured "
            "Trigger Candidate Evidence Corpus "
            "with target-specific Generic HTTP "
            "semantic evidence while preventing "
            "generic web pages from contributing "
            "version facts."
        )
    )

    parser.add_argument(
        "--corpus",
        type=Path,
        default=DEFAULT_CORPUS,
    )

    parser.add_argument(
        "--generic-http",
        type=Path,
        default=DEFAULT_GENERIC_HTTP,
    )

    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUTPUT,
    )

    args = parser.parse_args()

    result = augment_corpus(
        load_json(
            args.corpus
        ),
        load_json(
            args.generic_http
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
        "GENERIC HTTP SEMANTICS CORPUS AUGMENTATION"
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
        "[OK] evaluated generic HTTP:",
        summary.get(
            "generic_http_evaluated_source_count",
            0,
        ),
    )

    print(
        "[OK] included semantics sources:",
        summary.get(
            "generic_http_semantics_included_source_count",
            0,
        ),
    )

    print(
        "[OK] excluded generic HTTP:",
        summary.get(
            "generic_http_excluded_source_count",
            0,
        ),
    )

    print(
        "[OK] corpus entries:",
        summary.get(
            "corpus_entry_count",
            0,
        ),
    )

    print(
        "[OK] evidence units:",
        summary.get(
            "evidence_unit_count",
            0,
        ),
    )

    print(
        "[OK] deferred generic web:",
        summary.get(
            "generic_web_source_count_deferred",
            0,
        ),
    )

    print(
        "[OK] exclusion reasons:",
        json.dumps(
            summary.get(
                "generic_http_exclusion_reason_counts",
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