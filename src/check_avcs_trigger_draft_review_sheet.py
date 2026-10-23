from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

EXPECTED_SCHEMA_VERSION = (
    "avcs_trigger_draft_review_sheet_v0.1"
)

EXPECTED_BUILDER_VERSION = (
    "trigger_draft_review_sheet_builder_v0.1"
)

DEFAULT_JSON = (
    ROOT
    / "output"
    / "avcs_trigger_draft_review_sheet_v0.json"
)

DEFAULT_CSV = (
    ROOT
    / "output"
    / "avcs_trigger_draft_review_sheet_v0.csv"
)


EXPECTED_CASE_COUNT = 6
EXPECTED_REVIEW_UNIT_COUNT = 23
EXPECTED_PROPOSAL_REVIEW_COUNT = 11
EXPECTED_FIXED_REVIEW_COUNT = 6
EXPECTED_RANGE_REVIEW_COUNT = 6

EXPECTED_PROPOSAL_COUNTS = {
    "aiohttp": 0,
    "numpy": 0,
    "pyjwt": 4,
    "pyyaml": 0,
    "requests": 0,
    "urllib3": 7,
}

ALLOWED_UNIT_TYPES = {
    "structural_rule_proposal",
    "fixed_release_component",
    "version_range_component",
}

PROPOSAL_DECISIONS = {
    "accepted",
    "modified",
    "rejected",
    "unresolved",
}

COMPONENT_DECISIONS = {
    "accepted",
    "modified",
    "conflicted",
    "unresolved",
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
    def __init__(
        self,
    ) -> None:
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


def load_csv_rows(
    path: Path,
) -> list[dict[str, str]]:
    with path.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as file:
        return list(
            csv.DictReader(
                file
            )
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Check AVCS Trigger Draft "
            "human-review sheet generation."
        )
    )

    parser.add_argument(
        "--json",
        type=Path,
        default=DEFAULT_JSON,
    )

    parser.add_argument(
        "--csv",
        type=Path,
        default=DEFAULT_CSV,
    )

    args = parser.parse_args()

    data = load_json(
        args.json
    )

    csv_rows = load_csv_rows(
        args.csv
    )

    state = CheckState()

    state.check(
        data.get(
            "schema_version"
        )
        == EXPECTED_SCHEMA_VERSION,
        "schema_version",
    )

    state.check(
        data.get(
            "builder_version"
        )
        == EXPECTED_BUILDER_VERSION,
        "builder_version",
    )

    state.check(
        data.get(
            "status"
        )
        == "pending_human_review",
        "status",
    )

    boundary = data.get(
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
            "consumes_trigger_raw_ground_truth"
        )
        is False,
        "boundary::no_trigger_raw",
    )

    state.check(
        boundary.get(
            "review_sheet_is_ground_truth"
        )
        is False,
        "boundary::not_ground_truth",
    )

    state.check(
        boundary.get(
            "prepopulates_review_decisions"
        )
        is False,
        (
            "boundary::"
            "no_prepopulated_decisions"
        ),
    )

    state.check(
        boundary.get(
            "requires_human_decisions"
        )
        is True,
        (
            "boundary::"
            "human_decisions_required"
        ),
    )

    state.check(
        boundary.get(
            "review_time_is_not_synthetic"
        )
        is True,
        (
            "boundary::"
            "no_synthetic_review_time"
        ),
    )

    state.check(
        boundary.get(
            "development_set_only"
        )
        is True,
        (
            "boundary::"
            "development_set_only"
        ),
    )

    state.check(
        boundary.get(
            "held_out_workload_claims_allowed"
        )
        is False,
        (
            "boundary::"
            "no_held_out_claim"
        ),
    )

    summary = data.get(
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
            "case_count"
        )
        == EXPECTED_CASE_COUNT,
        "baseline::case_count",
    )

    state.check(
        summary.get(
            "review_unit_count"
        )
        == EXPECTED_REVIEW_UNIT_COUNT,
        (
            "baseline::"
            "review_unit_count"
        ),
    )

    state.check(
        summary.get(
            "structural_rule_proposal_review_count"
        )
        == EXPECTED_PROPOSAL_REVIEW_COUNT,
        (
            "baseline::"
            "proposal_review_count"
        ),
    )

    state.check(
        summary.get(
            "fixed_release_review_count"
        )
        == EXPECTED_FIXED_REVIEW_COUNT,
        (
            "baseline::"
            "fixed_review_count"
        ),
    )

    state.check(
        summary.get(
            "version_range_review_count"
        )
        == EXPECTED_RANGE_REVIEW_COUNT,
        (
            "baseline::"
            "range_review_count"
        ),
    )

    state.check(
        summary.get(
            "pending_review_count"
        )
        == EXPECTED_REVIEW_UNIT_COUNT,
        (
            "baseline::"
            "pending_review_count"
        ),
    )

    reviews = dict_rows(
        data.get(
            "reviews"
        )
    )

    state.check(
        len(
            reviews
        )
        == EXPECTED_REVIEW_UNIT_COUNT,
        "reviews::count",
    )

    review_ids: set[str] = set()

    unit_counter: Counter[
        str
    ] = Counter()

    proposal_counter: Counter[
        str
    ] = Counter()

    fixed_conflict_count = 0

    for index, review in enumerate(
        reviews
    ):
        label = (
            f"review[{index}]"
        )

        review_id = clean_text(
            review.get(
                "review_id"
            )
        )

        distribution = clean_text(
            review.get(
                "distribution"
            )
        ).lower()

        unit_type = clean_text(
            review.get(
                "review_unit_type"
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
            not in review_ids,
            f"{label}::unique_review_id",
        )

        if review_id:
            review_ids.add(
                review_id
            )

        state.check(
            bool(
                distribution
            ),
            f"{label}::distribution",
        )

        state.check(
            unit_type
            in ALLOWED_UNIT_TYPES,
            f"{label}::unit_type",
        )

        unit_counter[
            unit_type
        ] += 1

        state.check(
            review.get(
                "review_status"
            )
            == "pending",
            f"{label}::pending",
        )

        state.check(
            clean_text(
                review.get(
                    "review_decision"
                )
            )
            == "",
            (
                f"{label}::"
                "decision_not_prepopulated"
            ),
        )

        state.check(
            review.get(
                "modification_required"
            )
            is None,
            (
                f"{label}::"
                "modification_not_prepopulated"
            ),
        )

        state.check(
            review.get(
                "review_seconds"
            )
            is None,
            (
                f"{label}::"
                "time_not_prepopulated"
            ),
        )

        state.check(
            review.get(
                "source_lookup_count"
            )
            is None,
            (
                f"{label}::"
                "lookup_not_prepopulated"
            ),
        )

        state.check(
            review.get(
                "reviewed_source_keys"
            )
            == [],
            (
                f"{label}::"
                "reviewed_sources_empty"
            ),
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

        if (
            unit_type
            == "structural_rule_proposal"
        ):
            state.check(
                set(
                    options
                )
                == PROPOSAL_DECISIONS,
                (
                    f"{label}::"
                    "proposal_options"
                ),
            )

            proposal_counter[
                distribution
            ] += 1

            component = review.get(
                "automatic_component",
                {},
            )

            if not isinstance(
                component,
                dict,
            ):
                component = {}

            state.check(
                component.get(
                    "proposal_status"
                )
                == (
                    "proposed_requires_review"
                ),
                (
                    f"{label}::"
                    "proposal_requires_review"
                ),
            )

            state.check(
                component.get(
                    "review_required"
                )
                is True,
                (
                    f"{label}::"
                    "proposal_review_required"
                ),
            )

        else:
            state.check(
                set(
                    options
                )
                == COMPONENT_DECISIONS,
                (
                    f"{label}::"
                    "component_options"
                ),
            )

        if (
            unit_type
            == "fixed_release_component"
        ):
            component = review.get(
                "automatic_component",
                {},
            )

            if not isinstance(
                component,
                dict,
            ):
                component = {}

            if (
                component.get(
                    "status"
                )
                == "conflicted"
            ):
                fixed_conflict_count += 1

                state.check(
                    distribution
                    == "numpy",
                    (
                        f"{label}::"
                        "expected_numpy_conflict"
                    ),
                )

                state.check(
                    component.get(
                        "fixed_release"
                    )
                    is None,
                    (
                        f"{label}::"
                        "conflict_no_selected_release"
                    ),
                )

    state.check(
        unit_counter[
            "structural_rule_proposal"
        ]
        == EXPECTED_PROPOSAL_REVIEW_COUNT,
        (
            "baseline::"
            "proposal_unit_count"
        ),
    )

    state.check(
        unit_counter[
            "fixed_release_component"
        ]
        == EXPECTED_FIXED_REVIEW_COUNT,
        (
            "baseline::"
            "fixed_unit_count"
        ),
    )

    state.check(
        unit_counter[
            "version_range_component"
        ]
        == EXPECTED_RANGE_REVIEW_COUNT,
        (
            "baseline::"
            "range_unit_count"
        ),
    )

    for (
        distribution,
        expected_count,
    ) in (
        EXPECTED_PROPOSAL_COUNTS.items()
    ):
        state.check(
            proposal_counter[
                distribution
            ]
            == expected_count,
            (
                "baseline::"
                "proposal_count::"
                f"{distribution}"
            ),
        )

    state.check(
        fixed_conflict_count
        == 1,
        (
            "baseline::"
            "fixed_conflict_count"
        ),
    )

    state.check(
        len(
            csv_rows
        )
        == EXPECTED_REVIEW_UNIT_COUNT,
        "csv::row_count",
    )

    csv_ids = {
        clean_text(
            row.get(
                "review_id"
            )
        )
        for row in csv_rows
        if clean_text(
            row.get(
                "review_id"
            )
        )
    }

    state.check(
        csv_ids
        == review_ids,
        "csv::review_ids_match_json",
    )

    for index, row in enumerate(
        csv_rows
    ):
        state.check(
            clean_text(
                row.get(
                    "review_decision"
                )
            )
            == "",
            (
                f"csv[{index}]::"
                "decision_empty"
            ),
        )

        state.check(
            clean_text(
                row.get(
                    "review_seconds"
                )
            )
            == "",
            (
                f"csv[{index}]::"
                "time_empty"
            ),
        )

    serialized_input = json.dumps(
        data.get(
            "input",
            {},
        ),
        ensure_ascii=False,
    ).lower()

    state.check(
        "trigger_raw"
        not in serialized_input,
        "input::no_trigger_raw",
    )

    print(
        "="
        * 60
    )

    print(
        "AVCS TRIGGER DRAFT "
        "REVIEW SHEET CHECK"
    )

    print(
        "="
        * 60
    )

    print(
        "[INFO] review units:",
        len(
            reviews
        ),
    )

    print(
        "[INFO] proposal reviews:",
        unit_counter[
            "structural_rule_proposal"
        ],
    )

    print(
        "[INFO] fixed-release reviews:",
        unit_counter[
            "fixed_release_component"
        ],
    )

    print(
        "[INFO] version-range reviews:",
        unit_counter[
            "version_range_component"
        ],
    )

    print(
        "[INFO] fixed conflicts:",
        fixed_conflict_count,
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