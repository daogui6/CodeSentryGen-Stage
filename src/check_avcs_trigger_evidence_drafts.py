from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

EXPECTED_SCHEMA_VERSION = (
    "avcs_trigger_evidence_draft_v0.1"
)

EXPECTED_COMPILER_VERSION = (
    "trigger_evidence_draft_compiler_v0.2"
)

DEFAULT_DRAFTS = (
    ROOT
    / "output"
    / "avcs_trigger_evidence_drafts_v0.json"
)

DEFAULT_FACTS = (
    ROOT
    / "output"
    / "avcs_trigger_candidate_facts_v0.json"
)

DEFAULT_VALIDATION = (
    ROOT
    / "output"
    / "avcs_trigger_candidate_fact_validation_v0.json"
)


EXPECTED_AUTOMATIC_SUPPORTED_FACT_COUNT = 483
EXPECTED_CASE_COUNT = 6
EXPECTED_STRUCTURAL_PROPOSAL_COUNT = 11
EXPECTED_FIXED_RELEASE_CONFLICT_CASE_COUNT = 1

EXPECTED_PROPOSAL_COUNTS = {
    "aiohttp": 0,
    "numpy": 0,
    "pyjwt": 4,
    "pyyaml": 0,
    "requests": 0,
    "urllib3": 7,
}

EXPECTED_FIXED_RELEASES = {
    "aiohttp": "3.9.2",
    "pyjwt": "2.4.0",
    "pyyaml": "5.4",
    "requests": "2.32.4",
    "urllib3": "2.5.0",
}

ALLOWED_PROPOSAL_KINDS = {
    "keyword_literal_condition",
    "keyword_argument_condition",
    "keyword_call_condition",
    (
        "receiver_producer_"
        "keyword_literal_condition"
    ),
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
            return

        self.failed.append(
            label
        )


def build_fact_index(
    candidate_data: dict[str, Any],
) -> dict[
    str,
    dict[str, Any],
]:
    result: dict[
        str,
        dict[str, Any],
    ] = {}

    for fact in dict_rows(
        candidate_data.get(
            "facts"
        )
    ):
        fact_id = clean_text(
            fact.get(
                "fact_id"
            )
        )

        if fact_id:
            result[
                fact_id
            ] = fact

    return result


def build_validation_index(
    validation_data: dict[str, Any],
) -> dict[
    str,
    dict[str, Any],
]:
    result: dict[
        str,
        dict[str, Any],
    ] = {}

    for record in dict_rows(
        validation_data.get(
            "validation_records"
        )
    ):
        fact_id = clean_text(
            record.get(
                "fact_id"
            )
        )

        if fact_id:
            result[
                fact_id
            ] = record

    return result


def check_semantic_boundary(
    state: CheckState,
    data: dict[str, Any],
) -> None:
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
            "consumes_candidate_facts"
        )
        is True,
        (
            "boundary::"
            "consumes_candidate_facts"
        ),
    )

    state.check(
        boundary.get(
            "consumes_validation_sidecar"
        )
        is True,
        (
            "boundary::"
            "consumes_validation_sidecar"
        ),
    )

    state.check(
        boundary.get(
            "consumes_trigger_raw_ground_truth"
        )
        is False,
        (
            "boundary::"
            "no_trigger_raw_ground_truth"
        ),
    )

    state.check(
        boundary.get(
            "uses_only_automatic_supported_facts"
        )
        is True,
        (
            "boundary::"
            "supported_facts_only"
        ),
    )

    state.check(
        boundary.get(
            "uses_llm_semantic_inference"
        )
        is False,
        (
            "boundary::"
            "no_llm_semantic_inference"
        ),
    )

    state.check(
        boundary.get(
            "creates_trigger_evidence_drafts"
        )
        is True,
        (
            "boundary::"
            "creates_drafts"
        ),
    )

    state.check(
        boundary.get(
            "creates_resolved_trigger_rules"
        )
        is False,
        (
            "boundary::"
            "no_resolved_trigger_rules"
        ),
    )

    state.check(
        boundary.get(
            "draft_is_benchmark_ground_truth"
        )
        is False,
        (
            "boundary::"
            "draft_not_ground_truth"
        ),
    )

    state.check(
        boundary.get(
            "human_final_review_required"
        )
        is True,
        (
            "boundary::"
            "human_review_required"
        ),
    )


def check_fixed_release(
    state: CheckState,
    draft: dict[str, Any],
) -> None:
    distribution = clean_text(
        draft.get(
            "distribution"
        )
    ).lower()

    raw = draft.get(
        "raw_trigger_evidence_draft",
        {},
    )

    if not isinstance(
        raw,
        dict,
    ):
        state.check(
            False,
            (
                f"fixed::{distribution}::"
                "raw_draft_present"
            ),
        )
        return

    fix = raw.get(
        "fix_evidence",
        {},
    )

    if not isinstance(
        fix,
        dict,
    ):
        state.check(
            False,
            (
                f"fixed::{distribution}::"
                "fix_object"
            ),
        )
        return

    candidates = dict_rows(
        fix.get(
            "fixed_release_candidates"
        )
    )

    for index, candidate in enumerate(
        candidates
    ):
        state.check(
            bool(
                clean_text(
                    candidate.get(
                        "version"
                    )
                )
            ),
            (
                f"fixed::{distribution}::"
                f"candidate[{index}]::version"
            ),
        )

        state.check(
            bool(
                clean_text(
                    candidate.get(
                        "fact_id"
                    )
                )
            ),
            (
                f"fixed::{distribution}::"
                f"candidate[{index}]::fact_id"
            ),
        )

    if distribution == "numpy":
        state.check(
            fix.get(
                "status"
            )
            == "conflicted",
            "fixed::numpy::conflicted",
        )

        state.check(
            fix.get(
                "fixed_release"
            )
            is None,
            (
                "fixed::numpy::"
                "no_selected_release"
            ),
        )

        distinct = set(
            fix.get(
                "distinct_fixed_versions",
                [],
            )
        )

        state.check(
            distinct
            == {
                "1.16.1",
                "1.16.3",
            },
            (
                "fixed::numpy::"
                "conflict_versions"
            ),
        )

        return

    expected = (
        EXPECTED_FIXED_RELEASES.get(
            distribution
        )
    )

    if expected is None:
        return

    state.check(
        fix.get(
            "status"
        )
        == "supported",
        (
            f"fixed::{distribution}::"
            "supported"
        ),
    )

    state.check(
        clean_text(
            fix.get(
                "fixed_release"
            )
        )
        == expected,
        (
            f"fixed::{distribution}::"
            "selected_release"
        ),
    )


def check_proposal(
    state: CheckState,
    proposal: dict[str, Any],
    fact_index: dict[
        str,
        dict[str, Any],
    ],
    validation_index: dict[
        str,
        dict[str, Any],
    ],
    label: str,
) -> None:
    kind = clean_text(
        proposal.get(
            "kind"
        )
    )

    state.check(
        proposal.get(
            "proposal_type"
        )
        == (
            "conditional_"
            "trigger_rule_shape"
        ),
        f"{label}::proposal_type",
    )

    state.check(
        proposal.get(
            "proposal_status"
        )
        == (
            "proposed_requires_review"
        ),
        f"{label}::proposal_status",
    )

    state.check(
        proposal.get(
            "review_required"
        )
        is True,
        f"{label}::review_required",
    )

    state.check(
        kind
        in ALLOWED_PROPOSAL_KINDS,
        f"{label}::allowed_kind",
    )

    state.check(
        bool(
            clean_text(
                proposal.get(
                    "api_symbol"
                )
            )
        ),
        f"{label}::api_symbol",
    )

    state.check(
        proposal.get(
            "version_scope"
        )
        is None,
        f"{label}::version_scope_unresolved",
    )

    # Draft proposal 不能偷偷变成最终规则。
    state.check(
        "trigger_id"
        not in proposal,
        f"{label}::no_trigger_id",
    )

    state.check(
        "status"
        not in proposal,
        f"{label}::no_resolved_status",
    )

    state.check(
        "confidence"
        not in proposal,
        f"{label}::no_final_confidence",
    )

    supporting_fact_ids = (
        proposal.get(
            "supporting_fact_ids",
            [],
        )
    )

    state.check(
        isinstance(
            supporting_fact_ids,
            list,
        )
        and len(
            supporting_fact_ids
        )
        > 0,
        f"{label}::supporting_fact_ids",
    )

    if not isinstance(
        supporting_fact_ids,
        list,
    ):
        return

    for fact_id_raw in (
        supporting_fact_ids
    ):
        fact_id = clean_text(
            fact_id_raw
        )

        fact = fact_index.get(
            fact_id
        )

        validation = (
            validation_index.get(
                fact_id
            )
        )

        state.check(
            fact is not None,
            (
                f"{label}::"
                f"fact_exists::{fact_id}"
            ),
        )

        state.check(
            validation is not None,
            (
                f"{label}::"
                f"validation_exists::{fact_id}"
            ),
        )

        if validation is None:
            continue

        state.check(
            validation.get(
                "validation_status"
            )
            == "supported",
            (
                f"{label}::"
                f"fact_supported::{fact_id}"
            ),
        )

        state.check(
            validation.get(
                "automatic_decision"
            )
            is True,
            (
                f"{label}::"
                f"automatic_decision::{fact_id}"
            ),
        )

        state.check(
            validation.get(
                "review_required"
            )
            is False,
            (
                f"{label}::"
                f"atomic_review_not_required::{fact_id}"
            ),
        )


def check_key_proposals(
    state: CheckState,
    drafts: list[
        dict[str, Any]
    ],
) -> None:
    proposals: list[
        tuple[
            str,
            dict[str, Any],
        ]
    ] = []

    for draft in drafts:
        distribution = clean_text(
            draft.get(
                "distribution"
            )
        ).lower()

        for proposal in dict_rows(
            draft.get(
                "structural_rule_proposals"
            )
        ):
            proposals.append(
                (
                    distribution,
                    proposal,
                )
            )

    pyjwt_found = any(
        (
            distribution
            == "pyjwt"
            and proposal.get(
                "kind"
            )
            == "keyword_call_condition"
            and proposal.get(
                "api_symbol"
            )
            == "jwt.decode"
            and proposal.get(
                "keyword_argument"
            )
            == {
                "name":
                    "algorithms",
                "required_call_symbol":
                    (
                        "jwt.algorithms."
                        "get_default_algorithms"
                    ),
            }
        )
        for (
            distribution,
            proposal,
        ) in proposals
    )

    state.check(
        pyjwt_found,
        (
            "key_proposal::"
            "pyjwt_decode_default_algorithms"
        ),
    )

    urllib3_zero_found = any(
        (
            distribution
            == "urllib3"
            and proposal.get(
                "kind"
            )
            == (
                "receiver_producer_"
                "keyword_literal_condition"
            )
            and proposal.get(
                "api_symbol"
            )
            == (
                "urllib3."
                "PoolManager.request"
            )
            and proposal.get(
                "receiver_provenance"
            )
            == {
                "producer_api_symbol":
                    "urllib3.PoolManager",

                "producer_keyword_argument":
                    {
                        "name":
                            "retries",
                        "required_literal":
                            0,
                    },
            }
        )
        for (
            distribution,
            proposal,
        ) in proposals
    )

    state.check(
        urllib3_zero_found,
        (
            "key_proposal::"
            "urllib3_poolmanager_retries_zero"
        ),
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Check conservative AVCS "
            "Trigger Evidence draft compilation."
        )
    )

    parser.add_argument(
        "--drafts",
        type=Path,
        default=DEFAULT_DRAFTS,
    )

    parser.add_argument(
        "--facts",
        type=Path,
        default=DEFAULT_FACTS,
    )

    parser.add_argument(
        "--validation",
        type=Path,
        default=DEFAULT_VALIDATION,
    )

    args = parser.parse_args()

    data = load_json(
        args.drafts
    )

    candidate_data = load_json(
        args.facts
    )

    validation_data = load_json(
        args.validation
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
            "compiler_version"
        )
        == EXPECTED_COMPILER_VERSION,
        "compiler_version",
    )

    state.check(
        data.get(
            "status"
        )
        == "resolved",
        "status",
    )

    state.check(
        data.get(
            "source_mode"
        )
        == (
            "validated_atomic_fact_to_"
            "trigger_evidence_draft"
        ),
        "source_mode",
    )

    check_semantic_boundary(
        state,
        data,
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
            "automatic_supported_fact_count"
        )
        == (
            EXPECTED_AUTOMATIC_SUPPORTED_FACT_COUNT
        ),
        (
            "baseline::"
            "automatic_supported_fact_count"
        ),
    )

    state.check(
        summary.get(
            "case_count"
        )
        == EXPECTED_CASE_COUNT,
        "baseline::case_count",
    )

    state.check(
        summary.get(
            "structural_rule_proposal_count"
        )
        == EXPECTED_STRUCTURAL_PROPOSAL_COUNT,
        (
            "baseline::"
            "structural_rule_proposal_count"
        ),
    )

    state.check(
        summary.get(
            "fixed_release_conflict_case_count"
        )
        == (
            EXPECTED_FIXED_RELEASE_CONFLICT_CASE_COUNT
        ),
        (
            "baseline::"
            "fixed_release_conflict_case_count"
        ),
    )

    state.check(
        summary.get(
            "join_issue_count"
        )
        == 0,
        "baseline::join_issue_count",
    )

    drafts = dict_rows(
        data.get(
            "drafts"
        )
    )

    state.check(
        len(
            drafts
        )
        == EXPECTED_CASE_COUNT,
        "draft_count",
    )

    fact_index = build_fact_index(
        candidate_data
    )

    validation_index = (
        build_validation_index(
            validation_data
        )
    )

    proposal_counter: Counter[
        str
    ] = Counter()

    total_proposals = 0

    for draft_index, draft in enumerate(
        drafts
    ):
        distribution = clean_text(
            draft.get(
                "distribution"
            )
        ).lower()

        label = (
            f"draft[{draft_index}]::"
            f"{distribution}"
        )

        state.check(
            bool(
                distribution
            ),
            f"{label}::distribution",
        )

        manual_review = draft.get(
            "manual_review",
            {},
        )

        if not isinstance(
            manual_review,
            dict,
        ):
            manual_review = {}

        state.check(
            manual_review.get(
                "required"
            )
            is True,
            f"{label}::manual_review_required",
        )

        raw = draft.get(
            "raw_trigger_evidence_draft",
            {},
        )

        if not isinstance(
            raw,
            dict,
        ):
            raw = {}

        # Draft 的 trigger_candidates 必须保持空，
        # 防止绕过人工 review 直接进入 normalizer。
        state.check(
            raw.get(
                "trigger_candidates"
            )
            == [],
            f"{label}::no_resolved_trigger_candidates",
        )

        state.check(
            raw.get(
                "safe_alternatives"
            )
            == [],
            f"{label}::no_safe_alternatives",
        )

        check_fixed_release(
            state,
            draft,
        )

        proposals = dict_rows(
            draft.get(
                "structural_rule_proposals"
            )
        )

        proposal_counter[
            distribution
        ] += len(
            proposals
        )

        total_proposals += len(
            proposals
        )

        for proposal_index, proposal in enumerate(
            proposals
        ):
            check_proposal(
                state,
                proposal,
                fact_index,
                validation_index,
                (
                    f"{label}::"
                    f"proposal[{proposal_index}]"
                ),
            )

    state.check(
        total_proposals
        == EXPECTED_STRUCTURAL_PROPOSAL_COUNT,
        "baseline::total_proposals",
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
                "baseline::proposal_count::"
                f"{distribution}"
            ),
        )

    check_key_proposals(
        state,
        drafts,
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
        "AVCS TRIGGER EVIDENCE "
        "DRAFT CHECK"
    )

    print(
        "="
        * 60
    )

    print(
        "[INFO] drafts:",
        len(
            drafts
        ),
    )

    print(
        "[INFO] structural proposals:",
        total_proposals,
    )

    print(
        "[INFO] fixed-release conflicts:",
        summary.get(
            "fixed_release_conflict_case_count",
            0,
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