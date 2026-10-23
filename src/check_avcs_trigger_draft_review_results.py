from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

EXPECTED_RESULT_SCHEMA = (
    "avcs_trigger_draft_review_results_dev_v0.1"
)

EXPECTED_REVIEWER_VERSION = (
    "trigger_draft_interactive_reviewer_v0.1"
)

DEFAULT_SHEET = (
    ROOT
    / "output"
    / "avcs_trigger_draft_review_sheet_v0.json"
)

DEFAULT_RESULTS = (
    ROOT
    / "data"
    / "avcs_validation"
    / "rq1_review"
    / "avcs_trigger_draft_review_results_dev_v0.json"
)

EXPECTED_REVIEW_UNIT_COUNT = 23
EXPECTED_PROPOSAL_COUNT = 11
EXPECTED_FIXED_COUNT = 6
EXPECTED_RANGE_COUNT = 6


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


class CheckState:
    def __init__(self) -> None:
        self.passed = 0
        self.failed: list[str] = []

    def check(
        self,
        condition: bool,
        label: str,
    ) -> None:
        if condition:
            self.passed += 1
        else:
            self.failed.append(
                label
            )


def check_completed_review(
    state: CheckState,
    review: dict[str, Any],
    label: str,
) -> None:
    unit_type = clean_text(
        review.get(
            "review_unit_type"
        )
    )

    options = review.get(
        "decision_options",
        [],
    )

    if not isinstance(
        options,
        list,
    ):
        options = []

    decision = clean_text(
        review.get(
            "review_decision"
        )
    )

    state.check(
        decision in options,
        f"{label}::legal_decision",
    )

    review_seconds = review.get(
        "review_seconds"
    )

    state.check(
        isinstance(
            review_seconds,
            (int, float),
        )
        and review_seconds >= 0,
        f"{label}::measured_review_seconds",
    )

    source_lookup_count = review.get(
        "source_lookup_count"
    )

    state.check(
        isinstance(
            source_lookup_count,
            int,
        )
        and source_lookup_count >= 0,
        f"{label}::source_lookup_count",
    )

    reviewed_source_keys = review.get(
        "reviewed_source_keys",
        [],
    )

    available_source_keys = review.get(
        "available_source_keys",
        [],
    )

    state.check(
        isinstance(
            reviewed_source_keys,
            list,
        ),
        f"{label}::reviewed_source_keys_list",
    )

    if not isinstance(
        reviewed_source_keys,
        list,
    ):
        reviewed_source_keys = []

    if not isinstance(
        available_source_keys,
        list,
    ):
        available_source_keys = []

    state.check(
        set(
            reviewed_source_keys
        ).issubset(
            set(
                available_source_keys
            )
        ),
        f"{label}::reviewed_sources_available",
    )

    if isinstance(
        source_lookup_count,
        int,
    ):
        state.check(
            source_lookup_count
            >= len(
                reviewed_source_keys
            ),
            (
                f"{label}::"
                "lookup_count_covers_selected_sources"
            ),
        )

    modification_required = (
        review.get(
            "modification_required"
        )
    )

    if decision == "modified":
        state.check(
            modification_required
            is True,
            f"{label}::modified_flag",
        )

        modified_rule = review.get(
            "modified_rule"
        )

        state.check(
            modified_rule
            not in {
                None,
                "",
            },
            f"{label}::modified_rule_present",
        )

    else:
        state.check(
            modification_required
            is False,
            (
                f"{label}::"
                "no_modification_flag"
            ),
        )

    state.check(
        isinstance(
            review.get(
                "additional_evidence_required"
            ),
            bool,
        ),
        (
            f"{label}::"
            "additional_evidence_boolean"
        ),
    )

    if (
        review.get(
            "additional_evidence_required"
        )
        is True
    ):
        state.check(
            bool(
                clean_text(
                    review.get(
                        "additional_evidence_note"
                    )
                )
            ),
            (
                f"{label}::"
                "additional_evidence_note"
            ),
        )

    state.check(
        bool(
            clean_text(
                review.get(
                    "completed_at_utc"
                )
            )
        ),
        f"{label}::completed_at",
    )

    if (
        unit_type
        == "structural_rule_proposal"
    ):
        state.check(
            decision
            in {
                "accepted",
                "modified",
                "rejected",
                "unresolved",
            },
            (
                f"{label}::"
                "proposal_decision_domain"
            ),
        )

    else:
        state.check(
            decision
            in {
                "accepted",
                "modified",
                "conflicted",
                "unresolved",
            },
            (
                f"{label}::"
                "component_decision_domain"
            ),
        )


def check_pending_review(
    state: CheckState,
    review: dict[str, Any],
    label: str,
) -> None:
    state.check(
        clean_text(
            review.get(
                "review_decision"
            )
        )
        == "",
        f"{label}::pending_decision_empty",
    )

    state.check(
        review.get(
            "review_seconds"
        )
        is None,
        f"{label}::pending_time_empty",
    )

    state.check(
        review.get(
            "source_lookup_count"
        )
        is None,
        f"{label}::pending_lookup_empty",
    )

    state.check(
        review.get(
            "reviewed_source_keys"
        )
        == [],
        f"{label}::pending_sources_empty",
    )

    state.check(
        review.get(
            "completed_at_utc"
        )
        is None,
        f"{label}::pending_completed_at_empty",
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Check RQ1 Trigger Draft human-review "
            "result integrity and progress."
        )
    )

    parser.add_argument(
        "--sheet",
        type=Path,
        default=DEFAULT_SHEET,
    )

    parser.add_argument(
        "--results",
        type=Path,
        default=DEFAULT_RESULTS,
    )

    args = parser.parse_args()

    sheet = load_json(
        args.sheet
    )

    results = load_json(
        args.results
    )

    state = CheckState()

    state.check(
        results.get(
            "schema_version"
        )
        == EXPECTED_RESULT_SCHEMA,
        "schema_version",
    )

    state.check(
        results.get(
            "reviewer_version"
        )
        == EXPECTED_REVIEWER_VERSION,
        "reviewer_version",
    )

    state.check(
        results.get(
            "development_set_only"
        )
        is True,
        "development_set_only",
    )

    state.check(
        results.get(
            "held_out_workload_claims_allowed"
        )
        is False,
        "no_held_out_claim",
    )

    boundary = results.get(
        "semantic_boundary",
        {},
    )

    if not isinstance(
        boundary,
        dict,
    ):
        boundary = {}

    state.check(
        boundary.get(
            "human_decisions_only"
        )
        is True,
        "boundary::human_decisions_only",
    )

    state.check(
        boundary.get(
            "review_time_is_measured"
        )
        is True,
        "boundary::measured_time",
    )

    state.check(
        boundary.get(
            "review_time_is_not_synthetic"
        )
        is True,
        "boundary::no_synthetic_time",
    )

    state.check(
        boundary.get(
            "automatic_component_is_immutable"
        )
        is True,
        "boundary::automatic_component_immutable",
    )

    state.check(
        boundary.get(
            "review_result_is_held_out_evidence"
        )
        is False,
        "boundary::not_held_out",
    )

    state.check(
        boundary.get(
            "review_result_is_benchmark_ground_truth"
        )
        is False,
        "boundary::not_ground_truth",
    )

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

    state.check(
        len(
            sheet_rows
        )
        == EXPECTED_REVIEW_UNIT_COUNT,
        "sheet::review_count",
    )

    state.check(
        len(
            result_rows
        )
        == EXPECTED_REVIEW_UNIT_COUNT,
        "results::review_count",
    )

    sheet_index = {
        clean_text(
            row.get(
                "review_id"
            )
        ):
            row
        for row in sheet_rows
        if clean_text(
            row.get(
                "review_id"
            )
        )
    }

    result_ids: set[str] = set()

    unit_counter: Counter[str] = Counter()
    completed_counter = 0
    pending_counter = 0
    decision_counter: Counter[str] = Counter()

    for index, review in enumerate(
        result_rows
    ):
        label = (
            f"review[{index}]"
        )

        review_id = clean_text(
            review.get(
                "review_id"
            )
        )

        state.check(
            bool(
                review_id
            ),
            f"{label}::review_id",
        )

        state.check(
            review_id
            not in result_ids,
            f"{label}::unique_review_id",
        )

        if review_id:
            result_ids.add(
                review_id
            )

        source_row = sheet_index.get(
            review_id
        )

        state.check(
            source_row is not None,
            f"{label}::exists_in_sheet",
        )

        if source_row is not None:
            state.check(
                review.get(
                    "automatic_component"
                )
                == source_row.get(
                    "automatic_component"
                ),
                (
                    f"{label}::"
                    "automatic_component_unchanged"
                ),
            )

            state.check(
                review.get(
                    "decision_options"
                )
                == source_row.get(
                    "decision_options"
                ),
                (
                    f"{label}::"
                    "decision_options_unchanged"
                ),
            )

            state.check(
                review.get(
                    "available_source_keys"
                )
                == source_row.get(
                    "available_source_keys"
                ),
                (
                    f"{label}::"
                    "available_sources_unchanged"
                ),
            )

        unit_type = clean_text(
            review.get(
                "review_unit_type"
            )
        )

        unit_counter[
            unit_type
        ] += 1

        review_status = clean_text(
            review.get(
                "review_status"
            )
        )

        if review_status == "completed":
            completed_counter += 1

            decision = clean_text(
                review.get(
                    "review_decision"
                )
            )

            decision_counter[
                decision
            ] += 1

            check_completed_review(
                state,
                review,
                label,
            )

        else:
            pending_counter += 1

            state.check(
                review_status
                == "pending",
                f"{label}::pending_status",
            )

            check_pending_review(
                state,
                review,
                label,
            )

    state.check(
        unit_counter[
            "structural_rule_proposal"
        ]
        == EXPECTED_PROPOSAL_COUNT,
        "baseline::proposal_count",
    )

    state.check(
        unit_counter[
            "fixed_release_component"
        ]
        == EXPECTED_FIXED_COUNT,
        "baseline::fixed_count",
    )

    state.check(
        unit_counter[
            "version_range_component"
        ]
        == EXPECTED_RANGE_COUNT,
        "baseline::range_count",
    )

    summary = results.get(
        "summary",
        {},
    )

    if not isinstance(
        summary,
        dict,
    ):
        summary = {}

    state.check(
        summary.get(
            "review_unit_count"
        )
        == EXPECTED_REVIEW_UNIT_COUNT,
        "summary::review_unit_count",
    )

    state.check(
        summary.get(
            "completed_review_count"
        )
        == completed_counter,
        "summary::completed_count",
    )

    state.check(
        summary.get(
            "pending_review_count"
        )
        == pending_counter,
        "summary::pending_count",
    )

    expected_status = (
        "completed"
        if (
            completed_counter
            == EXPECTED_REVIEW_UNIT_COUNT
        )
        else "in_progress"
        if completed_counter > 0
        else "pending_human_review"
    )

    state.check(
        results.get(
            "status"
        )
        == expected_status,
        "status_matches_progress",
    )

    print(
        "="
        * 60
    )

    print(
        "AVCS TRIGGER DRAFT "
        "REVIEW RESULTS CHECK"
    )

    print(
        "="
        * 60
    )

    print(
        "[INFO] review units:",
        len(
            result_rows
        ),
    )

    print(
        "[INFO] completed:",
        completed_counter,
    )

    print(
        "[INFO] pending:",
        pending_counter,
    )

    print(
        "[INFO] decisions:",
        dict(
            sorted(
                decision_counter.items()
            )
        ),
    )

    print(
        "[INFO] checks passed:",
        state.passed,
    )

    print(
        "[INFO] checks failed:",
        len(
            state.failed
        ),
    )

    if state.failed:
        print()

        print(
            "[FAIL] failed checks:"
        )

        for failure in (
            state.failed
        ):
            print(
                "  -",
                failure,
            )

        raise SystemExit(
            1
        )

    print(
        "[OK] ALL CHECKS PASS"
    )


if __name__ == "__main__":
    main()