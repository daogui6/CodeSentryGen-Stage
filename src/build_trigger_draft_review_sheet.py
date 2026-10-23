from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

SCHEMA_VERSION = (
    "avcs_trigger_draft_review_sheet_v0.1"
)

BUILDER_VERSION = (
    "trigger_draft_review_sheet_builder_v0.1"
)

DEFAULT_DRAFTS = (
    ROOT
    / "output"
    / "avcs_trigger_evidence_drafts_v0.json"
)

DEFAULT_JSON_OUTPUT = (
    ROOT
    / "output"
    / "avcs_trigger_draft_review_sheet_v0.json"
)

DEFAULT_CSV_OUTPUT = (
    ROOT
    / "output"
    / "avcs_trigger_draft_review_sheet_v0.csv"
)


PROPOSAL_DECISIONS = [
    "accepted",
    "modified",
    "rejected",
    "unresolved",
]

COMPONENT_DECISIONS = [
    "accepted",
    "modified",
    "conflicted",
    "unresolved",
]


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


def stable_json(
    value: Any,
) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def make_review_id(
    *,
    distribution: str,
    unit_type: str,
    unit_key: str,
) -> str:
    payload = stable_json(
        {
            "distribution":
                distribution.lower(),
            "unit_type":
                unit_type,
            "unit_key":
                unit_key,
        }
    )

    digest = hashlib.sha256(
        payload.encode(
            "utf-8"
        )
    ).hexdigest()[:16]

    return (
        "triggerreview_"
        + digest
    )


def source_keys_from_draft(
    draft: dict[str, Any],
) -> list[str]:
    raw = draft.get(
        "raw_trigger_evidence_draft",
        {},
    )

    if not isinstance(
        raw,
        dict,
    ):
        return []

    result: list[str] = []

    for source in dict_rows(
        raw.get(
            "sources"
        )
    ):
        source_key = clean_text(
            source.get(
                "source_key"
            )
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


def base_review_fields(
    *,
    review_id: str,
    distribution: str,
    vulnerability_ids: list[str],
    unit_type: str,
    decision_options: list[str],
    available_source_keys: list[str],
) -> dict[str, Any]:
    return {
        "review_id":
            review_id,

        "distribution":
            distribution,

        "vulnerability_ids":
            vulnerability_ids,

        "review_unit_type":
            unit_type,

        "review_status":
            "pending",

        "decision_options":
            decision_options,

        "review_decision":
            "",

        "modification_required":
            None,

        "review_seconds":
            None,

        "source_lookup_count":
            None,

        "available_source_keys":
            available_source_keys,

        "reviewed_source_keys":
            [],

        "review_note":
            "",

        "modified_rule":
            None,

        "additional_evidence_required":
            None,

        "additional_evidence_note":
            "",
    }


def build_proposal_reviews(
    draft: dict[str, Any],
) -> list[dict[str, Any]]:
    distribution = clean_text(
        draft.get(
            "distribution"
        )
    )

    vulnerability_ids_raw = (
        draft.get(
            "vulnerability_ids",
            [],
        )
    )

    vulnerability_ids = (
        [
            clean_text(value)
            for value
            in vulnerability_ids_raw
            if clean_text(value)
        ]
        if isinstance(
            vulnerability_ids_raw,
            list,
        )
        else []
    )

    available_source_keys = (
        source_keys_from_draft(
            draft
        )
    )

    result: list[
        dict[str, Any]
    ] = []

    proposals = dict_rows(
        draft.get(
            "structural_rule_proposals"
        )
    )

    for index, proposal in enumerate(
        proposals
    ):
        proposal_key = stable_json(
            {
                "index":
                    index,
                "kind":
                    proposal.get(
                        "kind"
                    ),
                "api_symbol":
                    proposal.get(
                        "api_symbol"
                    ),
                "keyword_argument":
                    proposal.get(
                        "keyword_argument"
                    ),
                "receiver_provenance":
                    proposal.get(
                        "receiver_provenance"
                    ),
            }
        )

        review_id = make_review_id(
            distribution=distribution,
            unit_type=(
                "structural_rule_proposal"
            ),
            unit_key=proposal_key,
        )

        row = base_review_fields(
            review_id=review_id,
            distribution=distribution,
            vulnerability_ids=(
                vulnerability_ids
            ),
            unit_type=(
                "structural_rule_proposal"
            ),
            decision_options=(
                PROPOSAL_DECISIONS
            ),
            available_source_keys=(
                available_source_keys
            ),
        )

        row.update(
            {
                "proposal_index":
                    index,

                "proposal_kind":
                    proposal.get(
                        "kind"
                    ),

                "api_symbol":
                    proposal.get(
                        "api_symbol"
                    ),

                "automatic_component":
                    proposal,

                "automatic_component_status":
                    proposal.get(
                        "proposal_status"
                    ),
            }
        )

        result.append(
            row
        )

    return result


def build_fixed_release_review(
    draft: dict[str, Any],
) -> dict[str, Any]:
    distribution = clean_text(
        draft.get(
            "distribution"
        )
    )

    vulnerability_ids = (
        draft.get(
            "vulnerability_ids",
            [],
        )
    )

    if not isinstance(
        vulnerability_ids,
        list,
    ):
        vulnerability_ids = []

    raw = draft.get(
        "raw_trigger_evidence_draft",
        {},
    )

    if not isinstance(
        raw,
        dict,
    ):
        raw = {}

    fix = raw.get(
        "fix_evidence",
        {},
    )

    if not isinstance(
        fix,
        dict,
    ):
        fix = {}

    review_id = make_review_id(
        distribution=distribution,
        unit_type=(
            "fixed_release_component"
        ),
        unit_key="fixed_release",
    )

    row = base_review_fields(
        review_id=review_id,
        distribution=distribution,
        vulnerability_ids=[
            clean_text(value)
            for value
            in vulnerability_ids
            if clean_text(value)
        ],
        unit_type=(
            "fixed_release_component"
        ),
        decision_options=(
            COMPONENT_DECISIONS
        ),
        available_source_keys=(
            source_keys_from_draft(
                draft
            )
        ),
    )

    row.update(
        {
            "automatic_component":
                {
                    "status":
                        fix.get(
                            "status"
                        ),

                    "fixed_release":
                        fix.get(
                            "fixed_release"
                        ),

                    "distinct_fixed_versions":
                        fix.get(
                            "distinct_fixed_versions",
                            [],
                        ),

                    "conflicting_versions":
                        fix.get(
                            "conflicting_versions",
                            [],
                        ),

                    "fixed_release_candidates":
                        fix.get(
                            "fixed_release_candidates",
                            [],
                        ),
                },

            "automatic_component_status":
                fix.get(
                    "status"
                ),
        }
    )

    return row


def build_version_range_review(
    draft: dict[str, Any],
) -> dict[str, Any]:
    distribution = clean_text(
        draft.get(
            "distribution"
        )
    )

    vulnerability_ids = (
        draft.get(
            "vulnerability_ids",
            [],
        )
    )

    if not isinstance(
        vulnerability_ids,
        list,
    ):
        vulnerability_ids = []

    raw = draft.get(
        "raw_trigger_evidence_draft",
        {},
    )

    if not isinstance(
        raw,
        dict,
    ):
        raw = {}

    scope = raw.get(
        "scope",
        {},
    )

    if not isinstance(
        scope,
        dict,
    ):
        scope = {}

    range_drafts = dict_rows(
        scope.get(
            "osv_range_drafts"
        )
    )

    review_id = make_review_id(
        distribution=distribution,
        unit_type=(
            "version_range_component"
        ),
        unit_key="version_range",
    )

    row = base_review_fields(
        review_id=review_id,
        distribution=distribution,
        vulnerability_ids=[
            clean_text(value)
            for value
            in vulnerability_ids
            if clean_text(value)
        ],
        unit_type=(
            "version_range_component"
        ),
        decision_options=(
            COMPONENT_DECISIONS
        ),
        available_source_keys=(
            source_keys_from_draft(
                draft
            )
        ),
    )

    row.update(
        {
            "automatic_component":
                {
                    "scope_status":
                        scope.get(
                            "status"
                        ),

                    "osv_range_drafts":
                        range_drafts,

                    "trigger_semantics_version_scope":
                        scope.get(
                            "trigger_semantics_version_scope"
                        ),
                },

            "automatic_component_status":
                scope.get(
                    "status"
                ),
        }
    )

    return row


def build_review_sheet(
    draft_data: dict[str, Any],
) -> dict[str, Any]:
    reviews: list[
        dict[str, Any]
    ] = []

    drafts = dict_rows(
        draft_data.get(
            "drafts"
        )
    )

    for draft in drafts:
        reviews.extend(
            build_proposal_reviews(
                draft
            )
        )

        reviews.append(
            build_fixed_release_review(
                draft
            )
        )

        reviews.append(
            build_version_range_review(
                draft
            )
        )

    unit_type_counts = Counter(
        clean_text(
            row.get(
                "review_unit_type"
            )
        )
        for row in reviews
    )

    distribution_counts = Counter(
        clean_text(
            row.get(
                "distribution"
            )
        ).lower()
        for row in reviews
    )

    return {
        "schema_version":
            SCHEMA_VERSION,

        "builder_version":
            BUILDER_VERSION,

        "status":
            "pending_human_review",

        "source_mode":
            (
                "trigger_evidence_"
                "draft_utility_review"
            ),

        "input": {
            "draft_schema_version":
                draft_data.get(
                    "schema_version"
                ),

            "draft_compiler_version":
                draft_data.get(
                    "compiler_version"
                ),
        },

        "semantic_boundary": {
            "consumes_trigger_evidence_drafts":
                True,

            "consumes_trigger_raw_ground_truth":
                False,

            "review_sheet_is_ground_truth":
                False,

            "prepopulates_review_decisions":
                False,

            "requires_human_decisions":
                True,

            "review_time_is_not_synthetic":
                True,

            "development_set_only":
                True,

            "held_out_workload_claims_allowed":
                False,
        },

        "summary": {
            "case_count":
                len(
                    drafts
                ),

            "review_unit_count":
                len(
                    reviews
                ),

            "structural_rule_proposal_review_count":
                unit_type_counts[
                    "structural_rule_proposal"
                ],

            "fixed_release_review_count":
                unit_type_counts[
                    "fixed_release_component"
                ],

            "version_range_review_count":
                unit_type_counts[
                    "version_range_component"
                ],

            "pending_review_count":
                len(
                    reviews
                ),

            "review_unit_type_counts":
                dict(
                    sorted(
                        unit_type_counts.items()
                    )
                ),

            "review_unit_counts_by_distribution":
                dict(
                    sorted(
                        distribution_counts.items()
                    )
                ),
        },

        "reviews":
            reviews,
    }


def csv_value(
    value: Any,
) -> Any:
    if isinstance(
        value,
        (
            dict,
            list,
        ),
    ):
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
        )

    if value is None:
        return ""

    return value


def write_csv(
    path: Path,
    reviews: list[
        dict[str, Any]
    ],
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fieldnames = [
        "review_id",
        "distribution",
        "vulnerability_ids",
        "review_unit_type",
        "proposal_index",
        "proposal_kind",
        "api_symbol",
        "automatic_component_status",
        "automatic_component",
        "decision_options",
        "review_status",
        "review_decision",
        "modification_required",
        "review_seconds",
        "source_lookup_count",
        "available_source_keys",
        "reviewed_source_keys",
        "review_note",
        "modified_rule",
        "additional_evidence_required",
        "additional_evidence_note",
    ]

    with path.open(
        "w",
        encoding="utf-8-sig",
        newline="",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
            extrasaction="ignore",
        )

        writer.writeheader()

        for review in reviews:
            writer.writerow(
                {
                    field:
                        csv_value(
                            review.get(
                                field
                            )
                        )
                    for field
                    in fieldnames
                }
            )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Build a human-review sheet "
            "for AVCS Trigger Evidence drafts."
        )
    )

    parser.add_argument(
        "--drafts",
        type=Path,
        default=DEFAULT_DRAFTS,
    )

    parser.add_argument(
        "--json-out",
        type=Path,
        default=DEFAULT_JSON_OUTPUT,
    )

    parser.add_argument(
        "--csv-out",
        type=Path,
        default=DEFAULT_CSV_OUTPUT,
    )

    args = parser.parse_args()

    draft_data = load_json(
        args.drafts
    )

    result = build_review_sheet(
        draft_data
    )

    write_json(
        args.json_out,
        result,
    )

    write_csv(
        args.csv_out,
        dict_rows(
            result.get(
                "reviews"
            )
        ),
    )

    summary = result[
        "summary"
    ]

    print(
        "="
        * 60
    )

    print(
        "TRIGGER DRAFT REVIEW "
        "SHEET SUMMARY"
    )

    print(
        "="
        * 60
    )

    print(
        "[OK] schema:",
        SCHEMA_VERSION,
    )

    print(
        "[OK] cases:",
        summary[
            "case_count"
        ],
    )

    print(
        "[OK] review units:",
        summary[
            "review_unit_count"
        ],
    )

    print(
        "[OK] proposal reviews:",
        summary[
            "structural_rule_proposal_review_count"
        ],
    )

    print(
        "[OK] fixed-release reviews:",
        summary[
            "fixed_release_review_count"
        ],
    )

    print(
        "[OK] version-range reviews:",
        summary[
            "version_range_review_count"
        ],
    )

    print(
        "[OK] pending reviews:",
        summary[
            "pending_review_count"
        ],
    )

    print(
        "[OK] JSON saved:",
        args.json_out.resolve(),
    )

    print(
        "[OK] CSV saved:",
        args.csv_out.resolve(),
    )


if __name__ == "__main__":
    main()