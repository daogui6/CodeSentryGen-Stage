from __future__ import annotations

import argparse
import json
import statistics
from collections import Counter
from pathlib import Path
from typing import Any
import time

from datetime import datetime, timezone


ROOT = Path(__file__).resolve().parents[1]

RESULT_SCHEMA_VERSION = (
    "python_fact_trigger_utility_review_results_v0.2"
)

REVIEWER_VERSION = (
    "python_fact_trigger_utility_interactive_reviewer_v0.2"
)

DEFAULT_SHEET = (
    ROOT
    / "data"
    / "avcs_validation"
    / "rq1_review"
    / "python_fact_trigger_utility_review_sheet_v0.json"
)

DEFAULT_OUTPUT = (
    ROOT
    / "data"
    / "avcs_validation"
    / "rq1_review"
    / "python_fact_trigger_utility_review_results_v0.json"
)


def clean_text(value: Any) -> str:
    return str(
        value
        if value is not None
        else ""
    ).strip()


def utc_now_text() -> str:
    return (
        datetime.now(
            timezone.utc
        )
        .replace(
            microsecond=0
        )
        .isoformat()
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


def dict_rows(
    value: Any,
) -> list[dict[str, Any]]:
    if not isinstance(
        value,
        list,
    ):
        return []

    return [
        row
        for row in value
        if isinstance(
            row,
            dict,
        )
    ]


def write_json_atomic(
    path: Path,
    data: dict[str, Any],
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary = path.with_suffix(
        path.suffix + ".tmp"
    )

    temporary.write_text(
        json.dumps(
            data,
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    temporary.replace(
        path
    )


def initialize_results(
    sheet: dict[str, Any],
) -> dict[str, Any]:
    reviews = []

    for source_row in dict_rows(
        sheet.get("reviews")
    ):
        row = dict(
            source_row
        )

        # 人工字段必须重新保持空白。
        row["review_status"] = "pending"
        row["atomic_correctness"] = ""
        row["trigger_utility"] = ""
        row["reviewed_source_keys"] = []
        row["source_lookup_count"] = 0
        row["review_seconds"] = None
        row["review_reason"] = ""
        row[
            "additional_evidence_required"
        ] = None
        row[
            "additional_evidence_note"
        ] = ""
        row["completed_at_utc"] = None

        reviews.append(
            row
        )

    result = {
        "schema_version": (
            RESULT_SCHEMA_VERSION
        ),

        "reviewer_version": (
            REVIEWER_VERSION
        ),

        "status": (
            "pending_human_review"
        ),

        "source_review_sheet": {
            "schema_version": (
                sheet.get(
                    "schema_version"
                )
            ),
            "builder_version": (
                sheet.get(
                    "builder_version"
                )
            ),
            "review_count": len(
                reviews
            ),
        },

        "semantic_boundary": {
            "human_labels_only": True,
            "labels_are_not_prepopulated": True,
            "review_time_is_measured": True,
            "pipeline_outcome_is_not_used_as_truth": (
                True
            ),
            "sampling_weights_required_for_population_estimates": (
                True
            ),
        },

        # 后面 reviewer 会直接从这里显示漏洞上下文。
        "case_contexts": sheet.get(
            "case_contexts",
            {},
        ),

        "candidate_source_contexts": sheet.get(
            "candidate_source_contexts",
            {},
        ),

        "summary": {},

        "reviews": reviews,
    }

    update_summary(
        result
    )

    return result


def validate_resume_compatibility(
    sheet: dict[str, Any],
    results: dict[str, Any],
) -> None:
    sheet_rows = dict_rows(
        sheet.get("reviews")
    )

    result_rows = dict_rows(
        results.get("reviews")
    )

    sheet_ids = [
        clean_text(
            row.get("review_id")
        )
        for row in sheet_rows
    ]

    result_ids = [
        clean_text(
            row.get("review_id")
        )
        for row in result_rows
    ]

    if (
        sheet_ids
        != result_ids
    ):
        raise ValueError(
            "Existing review result does "
            "not match current review IDs."
        )

    for (
        sheet_row,
        result_row,
    ) in zip(
        sheet_rows,
        result_rows,
    ):
        # Candidate Fact 和抽样信息属于自动输入，
        # 恢复人工审核时绝对不能发生漂移。
        if (
            sheet_row.get(
                "candidate_fact"
            )
            != result_row.get(
                "candidate_fact"
            )
        ):
            raise ValueError(
                "Candidate Fact changed; "
                "refusing resume."
            )

        if (
            sheet_row.get(
                "sampling"
            )
            != result_row.get(
                "sampling"
            )
        ):
            raise ValueError(
                "Sampling metadata changed; "
                "refusing resume."
            )

    if (
        sheet.get(
            "case_contexts"
        )
        != results.get(
            "case_contexts"
        )
    ):
        raise ValueError(
            "Case evidence context changed; "
            "refusing resume."
        )

    if (
            sheet.get(
                "candidate_source_contexts"
            )
            != results.get(
        "candidate_source_contexts"
    )
    ):
        raise ValueError(
            "Candidate source context changed; "
            "refusing resume."
        )


def update_summary(
    results: dict[str, Any],
) -> None:
    reviews = dict_rows(
        results.get("reviews")
    )

    completed = [
        row
        for row in reviews
        if row.get(
            "review_status"
        ) == "completed"
    ]

    pending = [
        row
        for row in reviews
        if row.get(
            "review_status"
        ) != "completed"
    ]

    atomic_counts = Counter(
        clean_text(
            row.get(
                "atomic_correctness"
            )
        )
        for row in completed
        if clean_text(
            row.get(
                "atomic_correctness"
            )
        )
    )

    utility_counts = Counter(
        clean_text(
            row.get(
                "trigger_utility"
            )
        )
        for row in completed
        if clean_text(
            row.get(
                "trigger_utility"
            )
        )
    )

    review_seconds = [
        float(
            row["review_seconds"]
        )
        for row in completed
        if isinstance(
            row.get(
                "review_seconds"
            ),
            (int, float),
        )
    ]

    results["summary"] = {
        "review_count": len(
            reviews
        ),

        "completed_review_count": len(
            completed
        ),

        "pending_review_count": len(
            pending
        ),

        "completion_rate": round(
            (
                len(completed)
                / len(reviews)
            )
            if reviews
            else 0.0,
            6,
        ),

        "atomic_correctness_counts": (
            dict(
                sorted(
                    atomic_counts.items()
                )
            )
        ),

        "trigger_utility_counts": (
            dict(
                sorted(
                    utility_counts.items()
                )
            )
        ),

        "measured_review_seconds_total": (
            round(
                sum(
                    review_seconds
                ),
                3,
            )
        ),

        "measured_review_seconds_mean": (
            round(
                statistics.mean(
                    review_seconds
                ),
                3,
            )
            if review_seconds
            else None
        ),

        "measured_review_seconds_median": (
            round(
                statistics.median(
                    review_seconds
                ),
                3,
            )
            if review_seconds
            else None
        ),
    }

    if (
        reviews
        and not pending
    ):
        results[
            "status"
        ] = "completed"

    elif completed:
        results[
            "status"
        ] = "in_progress"

    else:
        results[
            "status"
        ] = "pending_human_review"


PREVIEW_TEXT_LIMIT = 4000


def get_context_sources(
    results: dict[str, Any],
    review: dict[str, Any],
) -> list[dict[str, Any]]:
    contexts = results.get(
        "case_contexts",
        {},
    )

    if not isinstance(
        contexts,
        dict,
    ):
        return []

    distribution = clean_text(
        review.get(
            "context_distribution"
        )
        or review.get(
            "distribution"
        )
    )

    context = contexts.get(
        distribution,
        {},
    )

    if not isinstance(
        context,
        dict,
    ):
        return []

    return dict_rows(
        context.get("sources")
    )


def print_review_header(
    *,
    review: dict[str, Any],
    current_number: int,
    total_number: int,
    sources: list[dict[str, Any]],
) -> None:
    print()
    print("=" * 80)

    print(
        f"[{current_number}/{total_number}] "
        f"{review.get('distribution')} | "
        f"{review.get('fact_kind')}"
    )

    print("=" * 80)

    print(
        "Fact ID:",
        review.get("fact_id"),
    )

    vulnerability_ids = review.get(
        "vulnerability_ids",
        [],
    )

    if isinstance(
        vulnerability_ids,
        list,
    ):
        print(
            "Vulnerability IDs:",
            ", ".join(
                str(value)
                for value
                in vulnerability_ids
            ),
        )

    fact = review.get(
        "candidate_fact",
        {},
    )

    if not isinstance(
        fact,
        dict,
    ):
        fact = {}

    print()
    print("Candidate Fact:")

    print(
        json.dumps(
            fact.get(
                "structured_value"
            ),
            ensure_ascii=False,
            indent=2,
        )
    )

    print()
    print(
        "Evidence excerpt:",
        fact.get(
            "evidence_excerpt"
        ),
    )

    locator = fact.get(
        "evidence_locator",
        {},
    )

    if isinstance(
        locator,
        dict,
    ):
        print(
            "Source location:",
            locator.get("repository"),
            "@",
            locator.get("ref"),
            "|",
            locator.get("path"),
            "| line",
            fact.get("line_number"),
        )


    print()
    print("Available vulnerability evidence:")

    for index, source in enumerate(
        sources,
        start=1,
    ):
        print(
            f"  {index}. "
            f"[{source.get('source_type')}] "
            f"{source.get('source_key')} "
            f"(units="
            f"{len(dict_rows(source.get('evidence_units')))}"
            f")"
        )

    print()
    print("Commands:")

    print(
        "  c      view Candidate Fact "
        "source context"
    )

    print(
        "  v N    view vulnerability "
        "evidence source N"
    )

    print(
        "  vf N   view full vulnerability "
        "evidence source N"
    )

    print(
        "  label  submit the human label"
    )

    print(
        "  s      skip this sample "
        "for now"
    )

    print(
        "  q      save completed reviews "
        "and quit"
    )

    print()

    print(
        "[FORMAL HUMAN REVIEW]"
    )


def print_evidence_source(
    source: dict[str, Any],
    *,
    full: bool,
) -> None:
    print()
    print("-" * 80)

    print(
        "SOURCE:",
        source.get(
            "source_key"
        ),
    )

    print(
        "TYPE:",
        source.get(
            "source_type"
        ),
    )

    print("-" * 80)

    units = dict_rows(
        source.get(
            "evidence_units"
        )
    )

    for unit in units:
        print()
        print(
            "UNIT:",
            unit.get(
                "unit_id"
            ),
        )

        text = clean_text(
            unit.get("text")
        )

        if (
            not full
            and len(text)
            > PREVIEW_TEXT_LIMIT
        ):
            print(
                text[
                    :PREVIEW_TEXT_LIMIT
                ]
            )

            print()
            print(
                f"[TRUNCATED: "
                f"{len(text)} chars total. "
                f"Use 'vf N' for full text.]"
            )

        else:
            print(text)

    print()
    print("-" * 80)


def print_candidate_source_context(
    results: dict[str, Any],
    review: dict[str, Any],
    *,
    radius: int = 12,
) -> bool:
    contexts = results.get(
        "candidate_source_contexts",
        {},
    )

    if not isinstance(
        contexts,
        dict,
    ):
        print(
            "[ERROR] Candidate source "
            "contexts are unavailable."
        )
        return False

    fact = review.get(
        "candidate_fact",
        {},
    )

    if not isinstance(
        fact,
        dict,
    ):
        print(
            "[ERROR] Candidate Fact "
            "is unavailable."
        )
        return False

    source_key = clean_text(
        fact.get("source_key")
    )

    context = contexts.get(
        source_key
    )

    if not isinstance(
        context,
        dict,
    ):
        print(
            "[ERROR] Candidate source "
            "context not found:",
            source_key,
        )
        return False

    line_number = fact.get(
        "line_number"
    )

    excerpt = clean_text(
        fact.get(
            "evidence_excerpt"
        )
    )

    units = dict_rows(
        context.get(
            "evidence_units"
        )
    )

    target_lines = None
    target_line_number = None
    target_unit_id = None

    # 优先使用原始文件行号。
    for unit in units:
        raw_text = unit.get(
            "text"
        )

        if not isinstance(
            raw_text,
            str,
        ):
            continue

        lines = raw_text.splitlines()

        if (
            isinstance(
                line_number,
                int,
            )
            and 1
            <= line_number
            <= len(lines)
        ):
            target_lines = lines
            target_line_number = (
                line_number
            )
            target_unit_id = (
                unit.get(
                    "unit_id"
                )
            )
            break

    # 如果 corpus 中的文本不是完整文件，
    # 则退化为按 evidence excerpt 定位。
    if target_lines is None:
        for unit in units:
            raw_text = unit.get(
                "text"
            )

            if not isinstance(
                raw_text,
                str,
            ):
                continue

            if not excerpt:
                continue

            position = raw_text.find(
                excerpt
            )

            if position < 0:
                continue

            target_lines = (
                raw_text.splitlines()
            )

            target_line_number = (
                raw_text[
                    :position
                ].count("\n")
                + 1
            )

            target_unit_id = (
                unit.get(
                    "unit_id"
                )
            )

            break

    if (
        target_lines is None
        or target_line_number is None
    ):
        print(
            "[ERROR] Could not locate "
            "Candidate Fact in source."
        )
        return False

    first_line = max(
        1,
        target_line_number
        - radius,
    )

    last_line = min(
        len(target_lines),
        target_line_number
        + radius,
    )

    print()
    print("-" * 80)

    print(
        "CANDIDATE SOURCE:",
        source_key,
    )

    print(
        "UNIT:",
        target_unit_id,
    )

    print(
        "TARGET LINE:",
        target_line_number,
    )

    print("-" * 80)

    for current_line in range(
        first_line,
        last_line + 1,
    ):
        marker = (
            ">>>"
            if current_line
            == target_line_number
            else "   "
        )

        print(
            f"{marker} "
            f"{current_line:5d} | "
            f"{target_lines[current_line - 1]}"
        )

    print("-" * 80)

    return True


def ask_atomic_correctness() -> str:
    options = [
        "correct",
        "incorrect",
        "uncertain",
    ]

    print()
    print("Atomic correctness:")
    print("  1. correct")
    print("  2. incorrect")
    print("  3. uncertain")

    while True:
        raw = input(
            "> "
        ).strip().lower()

        if raw in {
            "1",
            "2",
            "3",
        }:
            return options[
                int(raw) - 1
            ]

        if raw in options:
            return raw

        print(
            "Enter 1/2/3 or "
            "correct/incorrect/uncertain."
        )


def ask_trigger_utility() -> str:
    print()
    print("Trigger utility:")

    print(
        "  A. Trigger-critical"
    )

    print(
        "  B. Trigger-supporting"
    )

    print(
        "  C. Non-material"
    )

    print(
        "  U. Uncertain"
    )

    while True:
        raw = input(
            "> "
        ).strip().upper()

        if raw in {
            "A",
            "B",
            "C",
            "U",
        }:
            return raw

        print(
            "Enter A, B, C, or U."
        )


def ask_review_reason() -> str:
    print()
    print(
        "Review reason "
        "(required, one concise sentence):"
    )

    while True:
        reason = input(
            "> "
        ).strip()

        if reason:
            return reason

        print(
            "Review reason cannot be blank."
        )


def ask_yes_no(
    prompt: str,
) -> bool:
    while True:
        raw = input(
            prompt
        ).strip().lower()

        if raw in {
            "y",
            "yes",
            "1",
        }:
            return True

        if raw in {
            "n",
            "no",
            "0",
        }:
            return False

        print(
            "Enter y or n."
        )


def review_evidence_ready(
    *,
    sources: list[dict[str, Any]],
    viewed_source_keys: set[str],
    candidate_source_viewed: bool,
) -> tuple[
    bool,
    list[str],
]:
    missing = []

    if not candidate_source_viewed:
        missing.append(
            "candidate source context (c)"
        )

    viewed_types = {
        clean_text(
            source.get(
                "source_type"
            )
        )
        for source in sources
        if clean_text(
            source.get(
                "source_key"
            )
        )
        in viewed_source_keys
    }

    has_vulnerability_semantics = any(
        (
            "advisory"
            in source_type
            or source_type
            == "upstream_security_issue"
        )
        for source_type
        in viewed_types
    )

    if not has_vulnerability_semantics:
        missing.append(
            "at least one advisory/"
            "security-issue source"
        )

    has_fix_evidence = any(
        source_type
        in {
            "upstream_fix_commit",
            "upstream_fix_pull_request",
        }
        for source_type
        in viewed_types
    )

    if not has_fix_evidence:
        missing.append(
            "at least one fix commit/"
            "fix PR source"
        )

    return (
        not missing,
        missing,
    )


def complete_formal_review(
    *,
    review: dict[str, Any],
    viewed_source_keys: set[str],
    candidate_source_viewed: bool,
    review_seconds: float,
) -> None:
    atomic = (
        ask_atomic_correctness()
    )

    utility = (
        ask_trigger_utility()
    )

    reason = (
        ask_review_reason()
    )

    if utility == "U":
        additional_required = True

        print()
        print(
            "Trigger utility U implies "
            "additional evidence is required."
        )

    else:
        additional_required = (
            ask_yes_no(
                "Additional evidence "
                "required? [y/n] > "
            )
        )

    additional_note = ""

    if additional_required:
        print(
            "Additional evidence note "
            "(required):"
        )

        while True:
            additional_note = input(
                "> "
            ).strip()

            if additional_note:
                break

            print(
                "Additional evidence note "
                "cannot be blank."
            )

    available_source_keys = (
        review.get(
            "available_source_keys",
            [],
        )
    )

    if not isinstance(
        available_source_keys,
        list,
    ):
        available_source_keys = []

    reviewed_source_keys = [
        source_key
        for source_key
        in available_source_keys
        if source_key
        in viewed_source_keys
    ]

    review[
        "atomic_correctness"
    ] = atomic

    review[
        "trigger_utility"
    ] = utility

    review[
        "review_reason"
    ] = reason

    review[
        "reviewed_source_keys"
    ] = reviewed_source_keys

    review[
        "source_lookup_count"
    ] = len(
        reviewed_source_keys
    )

    review[
        "candidate_source_viewed"
    ] = candidate_source_viewed

    review[
        "review_seconds"
    ] = round(
        review_seconds,
        3,
    )

    review[
        "additional_evidence_required"
    ] = additional_required

    review[
        "additional_evidence_note"
    ] = additional_note

    review[
        "review_status"
    ] = "completed"

    review[
        "completed_at_utc"
    ] = utc_now_text()


def parse_source_command(
    raw: str,
) -> tuple[
    bool,
    int,
] | None:
    parts = raw.split()

    if len(parts) != 2:
        return None

    command = parts[0].lower()

    if command not in {
        "v",
        "vf",
    }:
        return None

    try:
        index = int(
            parts[1]
        )

    except ValueError:
        return None

    return (
        command == "vf",
        index,
    )


def run_interactive_review(
    results: dict[str, Any],
    output_path: Path,
) -> None:
    reviews = dict_rows(
        results.get("reviews")
    )

    total = len(
        reviews
    )

    while True:
        pending_indexes = [
            index
            for index, row
            in enumerate(reviews)
            if row.get(
                "review_status"
            )
            != "completed"
        ]

        if not pending_indexes:
            update_summary(
                results
            )

            write_json_atomic(
                output_path,
                results,
            )

            print()
            print(
                "[OK] All formal reviews "
                "are completed."
            )

            return

        skipped_in_pass = 0

        for review_index in (
            pending_indexes
        ):
            review = reviews[
                review_index
            ]

            sources = (
                get_context_sources(
                    results,
                    review,
                )
            )

            print_review_header(
                review=review,
                current_number=(
                    review_index + 1
                ),
                total_number=total,
                sources=sources,
            )

            viewed_source_keys: set[
                str
            ] = set()

            candidate_source_viewed = (
                False
            )

            start_time = (
                time.monotonic()
            )

            while True:
                raw = input(
                    "review> "
                ).strip()

                if not raw:
                    continue

                command = (
                    raw.lower()
                )

                if command == "q":
                    update_summary(
                        results
                    )

                    write_json_atomic(
                        output_path,
                        results,
                    )

                    print()
                    print(
                        "[OK] Completed reviews "
                        "saved."
                    )

                    print(
                        "[INFO] Unfinished current "
                        "sample was not labeled."
                    )

                    return

                if command == "s":
                    skipped_in_pass += 1
                    break

                if command == "c":
                    viewed = (
                        print_candidate_source_context(
                            results,
                            review,
                        )
                    )

                    if viewed:
                        candidate_source_viewed = (
                            True
                        )

                    continue

                if command == "label":
                    (
                        ready,
                        missing,
                    ) = (
                        review_evidence_ready(
                            sources=sources,
                            viewed_source_keys=(
                                viewed_source_keys
                            ),
                            candidate_source_viewed=(
                                candidate_source_viewed
                            ),
                        )
                    )

                    if not ready:
                        print()
                        print(
                            "[NOT READY] Review "
                            "requires:"
                        )

                        for item in missing:
                            print(
                                "  -",
                                item,
                            )

                        continue

                    atomic = (
                        ask_atomic_correctness()
                    )

                    utility = (
                        ask_trigger_utility()
                    )

                    reason = (
                        ask_review_reason()
                    )

                    if utility == "U":
                        additional_required = (
                            True
                        )

                        print()
                        print(
                            "Trigger utility U "
                            "requires additional "
                            "evidence."
                        )

                    else:
                        additional_required = (
                            ask_yes_no(
                                "Additional evidence "
                                "required? [y/n] > "
                            )
                        )

                    additional_note = ""

                    if additional_required:
                        print(
                            "Additional evidence "
                            "note (required):"
                        )

                        while True:
                            additional_note = (
                                input(
                                    "> "
                                ).strip()
                            )

                            if additional_note:
                                break

                            print(
                                "Additional evidence "
                                "note cannot be blank."
                            )

                    elapsed = (
                        time.monotonic()
                        - start_time
                    )

                    available_source_keys = (
                        review.get(
                            "available_source_keys",
                            [],
                        )
                    )

                    if not isinstance(
                        available_source_keys,
                        list,
                    ):
                        available_source_keys = []

                    reviewed_source_keys = [
                        key
                        for key
                        in available_source_keys
                        if key
                        in viewed_source_keys
                    ]

                    review[
                        "atomic_correctness"
                    ] = atomic

                    review[
                        "trigger_utility"
                    ] = utility

                    review[
                        "review_reason"
                    ] = reason

                    review[
                        "reviewed_source_keys"
                    ] = reviewed_source_keys

                    review[
                        "source_lookup_count"
                    ] = len(
                        reviewed_source_keys
                    )

                    review[
                        "candidate_source_viewed"
                    ] = (
                        candidate_source_viewed
                    )

                    review[
                        "review_seconds"
                    ] = round(
                        elapsed,
                        3,
                    )

                    review[
                        "additional_evidence_required"
                    ] = (
                        additional_required
                    )

                    review[
                        "additional_evidence_note"
                    ] = (
                        additional_note
                    )

                    review[
                        "review_status"
                    ] = "completed"

                    review[
                        "completed_at_utc"
                    ] = utc_now_text()

                    update_summary(
                        results
                    )

                    write_json_atomic(
                        output_path,
                        results,
                    )

                    print()
                    print(
                        "[OK] Formal review saved:",
                        review.get(
                            "review_id"
                        ),
                    )

                    break

                parsed = (
                    parse_source_command(
                        raw
                    )
                )

                if parsed is None:
                    print(
                        "Use: c, v N, vf N, "
                        "label, s, or q."
                    )
                    continue

                full, source_number = (
                    parsed
                )

                if (
                    source_number < 1
                    or source_number
                    > len(sources)
                ):
                    print(
                        "Evidence source number "
                        "out of range."
                    )
                    continue

                source = sources[
                    source_number - 1
                ]

                print_evidence_source(
                    source,
                    full=full,
                )

                source_key = clean_text(
                    source.get(
                        "source_key"
                    )
                )

                if source_key:
                    viewed_source_keys.add(
                        source_key
                    )

        if (
            skipped_in_pass
            == len(
                pending_indexes
            )
        ):
            update_summary(
                results
            )

            write_json_atomic(
                output_path,
                results,
            )

            print()
            print(
                "[OK] All remaining samples "
                "were skipped; progress saved."
            )

            return


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Interactively review retained "
            "Python Candidate Fact Trigger utility."
        )
    )

    parser.add_argument(
        "--sheet",
        type=Path,
        default=DEFAULT_SHEET,
    )

    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUTPUT,
    )

    parser.add_argument(
        "--init-only",
        action="store_true",
    )

    args = parser.parse_args()

    sheet = load_json(
        args.sheet
    )

    if args.out.exists():
        results = load_json(
            args.out
        )

        validate_resume_compatibility(
            sheet,
            results,
        )

        print(
            "[OK] Resuming existing "
            "review result:"
        )

    else:
        results = initialize_results(
            sheet
        )

        write_json_atomic(
            args.out,
            results,
        )

        print(
            "[OK] Initialized "
            "review result:"
        )

    print(
        "     ",
        args.out.resolve(),
    )

    update_summary(
        results
    )

    write_json_atomic(
        args.out,
        results,
    )

    summary = results[
        "summary"
    ]

    print(
        "[INFO] total:",
        summary[
            "review_count"
        ],
    )

    print(
        "[INFO] completed:",
        summary[
            "completed_review_count"
        ],
    )

    print(
        "[INFO] pending:",
        summary[
            "pending_review_count"
        ],
    )

    if args.init_only:
        print(
            "[OK] Initialization "
            "check complete."
        )
        return

    run_interactive_review(
        results,
        args.out,
    )

if __name__ == "__main__":
    main()