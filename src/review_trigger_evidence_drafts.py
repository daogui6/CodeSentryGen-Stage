from __future__ import annotations

import argparse
import json
import statistics
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

RESULT_SCHEMA_VERSION = (
    "avcs_trigger_draft_review_results_dev_v0.1"
)

REVIEWER_VERSION = (
    "trigger_draft_interactive_reviewer_v0.1"
)

DEFAULT_SHEET = (
    ROOT
    / "output"
    / "avcs_trigger_draft_review_sheet_v0.json"
)

DEFAULT_OUTPUT = (
    ROOT
    / "data"
    / "avcs_validation"
    / "rq1_review"
    / "avcs_trigger_draft_review_results_dev_v0.json"
)


def clean_text(value: Any) -> str:
    return str(
        value
        if value is not None
        else ""
    ).strip()


def load_json(path: Path) -> dict[str, Any]:
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


def initialize_results(
    sheet: dict[str, Any],
) -> dict[str, Any]:
    reviews = []

    for source_row in dict_rows(
        sheet.get(
            "reviews"
        )
    ):
        row = dict(
            source_row
        )

        row[
            "review_status"
        ] = "pending"

        row[
            "review_decision"
        ] = ""

        row[
            "modification_required"
        ] = None

        row[
            "review_seconds"
        ] = None

        row[
            "source_lookup_count"
        ] = None

        row[
            "reviewed_source_keys"
        ] = []

        row[
            "review_note"
        ] = ""

        row[
            "modified_rule"
        ] = None

        row[
            "additional_evidence_required"
        ] = None

        row[
            "additional_evidence_note"
        ] = ""

        row[
            "completed_at_utc"
        ] = None

        reviews.append(
            row
        )

    result = {
        "schema_version":
            RESULT_SCHEMA_VERSION,

        "reviewer_version":
            REVIEWER_VERSION,

        "status":
            "pending_human_review",

        "development_set_only":
            True,

        "held_out_workload_claims_allowed":
            False,

        "source_review_sheet": {
            "schema_version":
                sheet.get(
                    "schema_version"
                ),

            "builder_version":
                sheet.get(
                    "builder_version"
                ),

            "review_unit_count":
                len(
                    reviews
                ),
        },

        "semantic_boundary": {
            "human_decisions_only":
                True,

            "review_time_is_measured":
                True,

            "review_time_is_not_synthetic":
                True,

            "automatic_component_is_immutable":
                True,

            "review_result_is_development_set_evidence":
                True,

            "review_result_is_held_out_evidence":
                False,

            "review_result_is_benchmark_ground_truth":
                False,
        },

        "summary":
            {},

        "reviews":
            reviews,
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
        sheet.get(
            "reviews"
        )
    )

    result_rows = dict_rows(
        results.get(
            "reviews"
        )
    )

    sheet_ids = [
        clean_text(
            row.get(
                "review_id"
            )
        )
        for row in sheet_rows
    ]

    result_ids = [
        clean_text(
            row.get(
                "review_id"
            )
        )
        for row in result_rows
    ]

    if sheet_ids != result_ids:
        raise ValueError(
            "Existing review result does not match "
            "the current review-sheet review IDs."
        )

    for sheet_row, result_row in zip(
        sheet_rows,
        result_rows,
    ):
        if (
            sheet_row.get(
                "automatic_component"
            )
            != result_row.get(
                "automatic_component"
            )
        ):
            raise ValueError(
                "Existing review result changed an "
                "automatic_component; refusing resume."
            )


def update_summary(
    results: dict[str, Any],
) -> None:
    reviews = dict_rows(
        results.get(
            "reviews"
        )
    )

    completed = [
        row
        for row in reviews
        if (
            row.get(
                "review_status"
            )
            == "completed"
        )
    ]

    pending = [
        row
        for row in reviews
        if (
            row.get(
                "review_status"
            )
            != "completed"
        )
    ]

    decision_counter = Counter(
        clean_text(
            row.get(
                "review_decision"
            )
        )
        for row in completed
        if clean_text(
            row.get(
                "review_decision"
            )
        )
    )

    unit_counter = Counter(
        clean_text(
            row.get(
                "review_unit_type"
            )
        )
        for row in reviews
    )

    completed_unit_counter = Counter(
        clean_text(
            row.get(
                "review_unit_type"
            )
        )
        for row in completed
    )

    review_seconds = [
        float(
            row[
                "review_seconds"
            ]
        )
        for row in completed
        if isinstance(
            row.get(
                "review_seconds"
            ),
            (int, float),
        )
    ]

    summary = {
        "review_unit_count":
            len(
                reviews
            ),

        "completed_review_count":
            len(
                completed
            ),

        "pending_review_count":
            len(
                pending
            ),

        "completion_rate":
            round(
                (
                    len(
                        completed
                    )
                    / len(
                        reviews
                    )
                )
                if reviews
                else 0.0,
                6,
            ),

        "review_unit_type_counts":
            dict(
                sorted(
                    unit_counter.items()
                )
            ),

        "completed_unit_type_counts":
            dict(
                sorted(
                    completed_unit_counter.items()
                )
            ),

        "decision_counts":
            dict(
                sorted(
                    decision_counter.items()
                )
            ),

        "measured_review_seconds_total":
            round(
                sum(
                    review_seconds
                ),
                3,
            ),

        "measured_review_seconds_mean":
            round(
                statistics.mean(
                    review_seconds
                ),
                3,
            )
            if review_seconds
            else None,

        "measured_review_seconds_median":
            round(
                statistics.median(
                    review_seconds
                ),
                3,
            )
            if review_seconds
            else None,
    }

    results[
        "summary"
    ] = summary

    results[
        "status"
    ] = (
        "completed"
        if (
            reviews
            and not pending
        )
        else "in_progress"
        if completed
        else "pending_human_review"
    )


def print_header(
    current_number: int,
    total_number: int,
    review: dict[str, Any],
) -> None:
    print()

    print(
        "="
        * 72
    )

    print(
        f"[{current_number}/{total_number}] "
        f"{review.get('distribution')} — "
        f"{review.get('review_unit_type')}"
    )

    print(
        "="
        * 72
    )

    vulnerability_ids = (
        review.get(
            "vulnerability_ids",
            [],
        )
    )

    if vulnerability_ids:
        print(
            "Vulnerability IDs:",
            ", ".join(
                str(value)
                for value
                in vulnerability_ids
            ),
        )

    if clean_text(
        review.get(
            "proposal_kind"
        )
    ):
        print(
            "Proposal kind:",
            review.get(
                "proposal_kind"
            ),
        )

    if clean_text(
        review.get(
            "api_symbol"
        )
    ):
        print(
            "API symbol:",
            review.get(
                "api_symbol"
            ),
        )

    print()

    print(
        "Automatic component:"
    )

    print(
        json.dumps(
            review.get(
                "automatic_component"
            ),
            ensure_ascii=False,
            indent=2,
        )
    )

    source_keys = review.get(
        "available_source_keys",
        [],
    )

    if isinstance(
        source_keys,
        list,
    ) and source_keys:
        print()

        print(
            "Available evidence sources:"
        )

        for index, source_key in enumerate(
            source_keys,
            start=1,
        ):
            print(
                f"  {index}. {source_key}"
            )


def ask_decision(
    review: dict[str, Any],
) -> tuple[
    str | None,
    float | None,
]:
    options = review.get(
        "decision_options",
        [],
    )

    if not isinstance(
        options,
        list,
    ) or not options:
        raise ValueError(
            "Review unit has no decision options."
        )

    print()

    print(
        "Decision:"
    )

    for index, option in enumerate(
        options,
        start=1,
    ):
        print(
            f"  {index}. {option}"
        )

    print(
        "  s. skip this unit"
    )

    print(
        "  q. save and quit"
    )

    start_time = time.monotonic()

    while True:
        answer = input(
            "> "
        ).strip().lower()

        if answer == "q":
            return (
                None,
                None,
            )

        if answer == "s":
            return (
                "__skip__",
                None,
            )

        try:
            selected = int(
                answer
            )

        except ValueError:
            print(
                "Please enter an option number, s, or q."
            )

            continue

        if (
            selected < 1
            or selected
            > len(
                options
            )
        ):
            print(
                "Decision number out of range."
            )

            continue

        elapsed = (
            time.monotonic()
            - start_time
        )

        return (
            clean_text(
                options[
                    selected - 1
                ]
            ),
            round(
                elapsed,
                3,
            ),
        )


def ask_nonnegative_int(
    prompt: str,
) -> int:
    while True:
        raw = input(
            prompt
        ).strip()

        try:
            value = int(
                raw
            )

        except ValueError:
            print(
                "Please enter a non-negative integer."
            )

            continue

        if value < 0:
            print(
                "Please enter a non-negative integer."
            )

            continue

        return value


def ask_yes_no(
    prompt: str,
) -> bool:
    while True:
        value = input(
            prompt
        ).strip().lower()

        if value in {
            "y",
            "yes",
            "1",
        }:
            return True

        if value in {
            "n",
            "no",
            "0",
        }:
            return False

        print(
            "Please enter y or n."
        )


def ask_reviewed_source_keys(
    available_source_keys: Any,
) -> list[str]:
    if not isinstance(
        available_source_keys,
        list,
    ):
        available_source_keys = []

    if not available_source_keys:
        return []

    print()

    print(
        "Enter evidence-source numbers you actually "
        "opened during this review."
    )

    print(
        "Example: 1,3   Leave blank for none."
    )

    while True:
        raw = input(
            "> "
        ).strip()

        if not raw:
            return []

        parts = [
            value.strip()
            for value
            in raw.split(",")
            if value.strip()
        ]

        try:
            indexes = [
                int(
                    value
                )
                for value
                in parts
            ]

        except ValueError:
            print(
                "Use comma-separated source numbers."
            )

            continue

        if any(
            index < 1
            or index
            > len(
                available_source_keys
            )
            for index
            in indexes
        ):
            print(
                "One or more source numbers are out of range."
            )

            continue

        result = []

        for index in indexes:
            source_key = clean_text(
                available_source_keys[
                    index - 1
                ]
            )

            if (
                source_key
                and source_key
                not in result
            ):
                result.append(
                    source_key
                )

        return result


def ask_modified_component() -> Any:
    print()

    print(
        "Describe the modified rule/component."
    )

    print(
        "You may enter JSON or a short textual description."
    )

    while True:
        raw = input(
            "> "
        ).strip()

        if not raw:
            print(
                "A modified decision requires a modification."
            )

            continue

        try:
            return json.loads(
                raw
            )

        except json.JSONDecodeError:
            return raw


def complete_review(
    review: dict[str, Any],
    decision: str,
    review_seconds: float,
) -> None:
    review[
        "review_decision"
    ] = decision

    review[
        "review_seconds"
    ] = review_seconds

    modification_required = (
        decision
        == "modified"
    )

    review[
        "modification_required"
    ] = modification_required

    if modification_required:
        review[
            "modified_rule"
        ] = (
            ask_modified_component()
        )

    else:
        review[
            "modified_rule"
        ] = None

    source_lookup_count = (
        ask_nonnegative_int(
            "How many evidence sources did you open? > "
        )
    )

    reviewed_source_keys = (
        ask_reviewed_source_keys(
            review.get(
                "available_source_keys",
                [],
            )
        )
    )

    while (
        source_lookup_count
        < len(
            reviewed_source_keys
        )
    ):
        print(
            "source_lookup_count cannot be smaller "
            "than the number of selected source keys."
        )

        source_lookup_count = (
            ask_nonnegative_int(
                "How many evidence sources did you open? > "
            )
        )

    review[
        "source_lookup_count"
    ] = source_lookup_count

    review[
        "reviewed_source_keys"
    ] = reviewed_source_keys

    review[
        "review_note"
    ] = input(
        "Review note (optional) > "
    ).strip()

    additional_required = ask_yes_no(
        "Additional evidence required? [y/n] > "
    )

    review[
        "additional_evidence_required"
    ] = additional_required

    if additional_required:
        review[
            "additional_evidence_note"
        ] = input(
            "Additional evidence note > "
        ).strip()

    else:
        review[
            "additional_evidence_note"
        ] = ""

    review[
        "review_status"
    ] = "completed"

    review[
        "completed_at_utc"
    ] = utc_now_text()


def run_interactive_review(
    results: dict[str, Any],
    output_path: Path,
) -> None:
    reviews = dict_rows(
        results.get(
            "reviews"
        )
    )

    total = len(
        reviews
    )

    while True:
        pending_indexes = [
            index
            for index, row
            in enumerate(
                reviews
            )
            if (
                row.get(
                    "review_status"
                )
                != "completed"
            )
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
                "[OK] All review units are completed."
            )

            return

        skipped_in_pass = 0

        for review_index in (
            pending_indexes
        ):
            review = reviews[
                review_index
            ]

            print_header(
                current_number=(
                    review_index + 1
                ),
                total_number=total,
                review=review,
            )

            (
                decision,
                review_seconds,
            ) = ask_decision(
                review
            )

            if decision is None:
                update_summary(
                    results
                )

                write_json_atomic(
                    output_path,
                    results,
                )

                print()

                print(
                    "[OK] Progress saved."
                )

                return

            if (
                decision
                == "__skip__"
            ):
                skipped_in_pass += 1
                continue

            assert (
                review_seconds
                is not None
            )

            complete_review(
                review,
                decision,
                review_seconds,
            )

            update_summary(
                results
            )

            write_json_atomic(
                output_path,
                results,
            )

            print(
                "[OK] Review saved:",
                review.get(
                    "review_id"
                ),
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
                "[OK] All remaining units were skipped; "
                "progress saved."
            )

            return


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Interactively review RQ1 Trigger Evidence "
            "Draft utility units with real timing."
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
        help=(
            "Initialize/validate the review result file "
            "without starting interactive review."
        ),
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
            "[OK] Resuming existing review result:"
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
            "[OK] Initialized review result:"
        )

    print(
        "     ",
        args.out.resolve(),
    )

    update_summary(
        results
    )

    summary = results[
        "summary"
    ]

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
        write_json_atomic(
            args.out,
            results,
        )

        print(
            "[OK] Initialization check complete."
        )

        return

    run_interactive_review(
        results,
        args.out,
    )


if __name__ == "__main__":
    main()