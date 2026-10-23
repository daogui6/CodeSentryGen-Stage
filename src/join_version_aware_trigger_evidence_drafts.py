from __future__ import annotations

import argparse
import hashlib
import json
from copy import deepcopy
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

SCHEMA_VERSION = (
    "avcs_version_aware_trigger_evidence_draft_v0.1"
)

JOINER_VERSION = (
    "version_aware_trigger_evidence_joiner_v0.1"
)

EXPECTED_VERSION_SCHEMA = (
    "avcs_trigger_evidence_draft_v0.1"
)

EXPECTED_SEMANTIC_SCHEMA = (
    "avcs_trigger_semantic_draft_v0.1"
)

DEFAULT_VERSION_DRAFTS = (
    ROOT
    / "output"
    / "avcs_trigger_evidence_drafts_v0.json"
)

DEFAULT_SEMANTIC_DRAFTS = (
    ROOT
    / "output"
    / "avcs_trigger_semantic_drafts_v0.json"
)

DEFAULT_OUTPUT = (
    ROOT
    / "output"
    / "avcs_version_aware_trigger_evidence_drafts_v0.json"
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


def stable_json(
    value: Any,
) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(
            ",",
            ":",
        ),
    )


def make_id(
    prefix: str,
    payload: Any,
) -> str:
    digest = hashlib.sha256(
        stable_json(
            payload
        ).encode(
            "utf-8"
        )
    ).hexdigest()[:20]

    return (
        prefix
        + digest
    )


def normalized_ids(
    value: Any,
) -> tuple[str, ...]:
    if not isinstance(
        value,
        list,
    ):
        return tuple()

    return tuple(
        sorted(
            {
                clean_text(item).lower()
                for item in value
                if clean_text(item)
            }
        )
    )


def case_key(
    row: dict[str, Any],
) -> tuple[
    str,
    tuple[str, ...],
]:
    return (
        clean_text(
            row.get(
                "distribution"
            )
        ).lower(),

        normalized_ids(
            row.get(
                "vulnerability_ids"
            )
        ),
    )


def build_version_index(
    version_data: dict[str, Any],
) -> dict[
    tuple[
        str,
        tuple[str, ...],
    ],
    dict[str, Any],
]:
    drafts = version_data.get(
        "drafts",
        [],
    )

    if not isinstance(
        drafts,
        list,
    ):
        raise ValueError(
            "Version artifact field "
            "'drafts' must be a list."
        )

    index = {}

    for draft in drafts:
        if not isinstance(
            draft,
            dict,
        ):
            continue

        key = case_key(
            draft
        )

        if not key[0]:
            continue

        if key in index:
            raise ValueError(
                "Duplicate version draft case: "
                + str(
                    key
                )
            )

        index[
            key
        ] = draft

    return index


def build_semantic_index(
    semantic_data: dict[str, Any],
) -> dict[
    tuple[
        str,
        tuple[str, ...],
    ],
    dict[str, Any],
]:
    cases = semantic_data.get(
        "cases",
        [],
    )

    if not isinstance(
        cases,
        list,
    ):
        raise ValueError(
            "Semantic artifact field "
            "'cases' must be a list."
        )

    index = {}

    for case in cases:
        if not isinstance(
            case,
            dict,
        ):
            continue

        key = case_key(
            case
        )

        if not key[0]:
            continue

        if key in index:
            raise ValueError(
                "Duplicate semantic draft case: "
                + str(
                    key
                )
            )

        index[
            key
        ] = case

    return index


def extract_version_evidence(
    version_draft: dict[str, Any],
) -> dict[str, Any]:
    raw = version_draft.get(
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

    fix = raw.get(
        "fix_evidence",
        {},
    )

    if not isinstance(
        fix,
        dict,
    ):
        fix = {}

    automatic = version_draft.get(
        "automatic_components",
        {},
    )

    if not isinstance(
        automatic,
        dict,
    ):
        automatic = {}

    range_status = clean_text(
        scope.get(
            "status"
        )
    )

    fix_status = clean_text(
        fix.get(
            "status"
        )
    )

    if (
        range_status
        == "supported_atomic_range_events"
        and fix_status
        == "supported"
    ):
        binding_status = (
            "supported_version_evidence"
        )

    elif (
        fix_status
        == "conflicted"
    ):
        binding_status = (
            "conflicted_version_evidence"
        )

    else:
        binding_status = (
            "partial_version_evidence"
        )

    return {
        "status":
            binding_status,

        "association_basis":
            (
                "same_distribution_and_"
                "vulnerability_identity"
            ),

        "range_status":
            range_status,

        "osv_range_drafts":
            deepcopy(
                scope.get(
                    "osv_range_drafts",
                    [],
                )
            ),

        "fixed_release_status":
            fix_status,

        "fixed_release_resolution_mode":
            fix.get(
                "resolution_mode"
            ),

        "fixed_release":
            fix.get(
                "fixed_release"
            ),

        "distinct_fixed_versions":
            deepcopy(
                fix.get(
                    "distinct_fixed_versions",
                    [],
                )
            ),

        "fixed_release_candidates":
            deepcopy(
                fix.get(
                    "fixed_release_candidates",
                    [],
                )
            ),

        "branch_fixed_releases":
            deepcopy(
                fix.get(
                    "branch_fixed_releases",
                    [],
                )
            ),

        "conflicting_versions":
            deepcopy(
                fix.get(
                    "conflicting_versions",
                    [],
                )
            ),

        "version_source_count":
            version_draft.get(
                "source_count"
            ),

        "automatic_supported_fact_count":
            version_draft.get(
                "automatic_supported_fact_count"
            ),

        "osv_range_draft_count":
            automatic.get(
                "osv_range_draft_count"
            ),

        "fixed_release_candidate_count":
            automatic.get(
                "fixed_release_candidate_count"
            ),

        "semantic_version_transition_proven":
            False,

        "note":
            (
                "Version evidence is reused "
                "without recomputation from the "
                "existing Trigger Evidence draft. "
                "The join associates version and "
                "semantic evidence by the same "
                "package/vulnerability identity; "
                "it does not prove that each "
                "semantic Trigger condition begins "
                "or ends exactly at each version "
                "boundary."
            ),
    }


def build_version_aware_hypothesis(
    *,
    semantic_hypothesis: dict[str, Any],
    version_evidence: dict[str, Any],
) -> dict[str, Any]:
    payload = {
        "semantic_trigger_hypothesis_id":
            semantic_hypothesis.get(
                "trigger_hypothesis_id"
            ),

        "distribution":
            semantic_hypothesis.get(
                "distribution"
            ),

        "vulnerability_ids":
            normalized_ids(
                semantic_hypothesis.get(
                    "vulnerability_ids"
                )
            ),

        "version_resolution_mode":
            version_evidence.get(
                "fixed_release_resolution_mode"
            ),
    }

    draft_id = make_id(
        "vatrigger_",
        payload,
    )

    version_status = clean_text(
        version_evidence.get(
            "status"
        )
    )

    if (
        version_status
        == "supported_version_evidence"
    ):
        status = (
            "version_aware_proposed_requires_review"
        )

    elif (
        version_status
        == "conflicted_version_evidence"
    ):
        status = (
            "version_conflicted_requires_review"
        )

    else:
        status = (
            "partial_version_binding_requires_review"
        )

    review_reasons = list(
        semantic_hypothesis.get(
            "review_reasons",
            [],
        )
    )

    review_reasons.append(
        (
            "Version evidence and semantic "
            "Trigger evidence are associated "
            "by package/vulnerability identity, "
            "not by a proven per-version semantic "
            "transition."
        )
    )

    if (
        version_status
        != "supported_version_evidence"
    ):
        review_reasons.append(
            (
                "Version evidence is not fully "
                "supported and therefore requires "
                "manual resolution."
            )
        )

    return {
        "version_aware_trigger_draft_id":
            draft_id,

        "proposal_type":
            "version_aware_trigger_evidence_draft",

        "proposal_status":
            status,

        "review_required":
            True,

        "distribution":
            semantic_hypothesis.get(
                "distribution"
            ),

        "vulnerability_ids":
            deepcopy(
                semantic_hypothesis.get(
                    "vulnerability_ids",
                    [],
                )
            ),

        "semantic_trigger_hypothesis_id":
            semantic_hypothesis.get(
                "trigger_hypothesis_id"
            ),

        "anchor":
            semantic_hypothesis.get(
                "anchor"
            ),

        "risk_relation_classes":
            deepcopy(
                semantic_hypothesis.get(
                    "risk_relation_classes",
                    [],
                )
            ),

        "security_effects":
            deepcopy(
                semantic_hypothesis.get(
                    "security_effects",
                    [],
                )
            ),

        "required_context_consensus":
            deepcopy(
                semantic_hypothesis.get(
                    "required_context_consensus",
                    [],
                )
            ),

        "context_consensus_status":
            semantic_hypothesis.get(
                "context_consensus_status"
            ),

        "positive_relation_bundle_ids":
            deepcopy(
                semantic_hypothesis.get(
                    "positive_relation_bundle_ids",
                    [],
                )
            ),

        "same_anchor_protective_relation_bundle_ids":
            deepcopy(
                semantic_hypothesis.get(
                    "same_anchor_protective_relation_bundle_ids",
                    [],
                )
            ),

        "case_level_protective_contrast_bundle_ids":
            deepcopy(
                semantic_hypothesis.get(
                    "case_level_protective_contrast_bundle_ids",
                    [],
                )
            ),

        "semantic_positive_source_keys":
            deepcopy(
                semantic_hypothesis.get(
                    "positive_source_keys",
                    [],
                )
            ),

        "semantic_positive_source_types":
            deepcopy(
                semantic_hypothesis.get(
                    "positive_source_types",
                    [],
                )
            ),

        "version_evidence":
            deepcopy(
                version_evidence
            ),

        "version_scope_association":
            {
                "status":
                    (
                        "identity_level_association"
                    ),

                "basis":
                    (
                        "same_distribution_and_"
                        "vulnerability_ids"
                    ),

                "per_version_trigger_semantics_proven":
                    False,
            },

        "executable_rule_ready":
            False,

        "review_reasons":
            review_reasons,

        "proposal_basis":
            (
                "A cross-source-supported semantic "
                "Trigger hypothesis and independently "
                "compiled OSV/version evidence refer "
                "to the same package/vulnerability "
                "identity. They are joined without "
                "recomputing either component. "
                "The result remains a review-required "
                "evidence draft rather than an "
                "executable Trigger rule."
            ),
    }


def build_case(
    *,
    version_draft: dict[str, Any] | None,
    semantic_case: dict[str, Any] | None,
) -> dict[str, Any]:
    source = (
        semantic_case
        if semantic_case is not None
        else version_draft
    )

    if source is None:
        raise ValueError(
            "Case must have at least one input."
        )

    distribution = clean_text(
        source.get(
            "distribution"
        )
    )

    vulnerability_ids_raw = source.get(
        "vulnerability_ids",
        [],
    )

    vulnerability_ids = (
        list(
            normalized_ids(
                vulnerability_ids_raw
            )
        )
    )

    if version_draft is None:
        version_evidence = {
            "status":
                "missing_version_draft",
        }

    else:
        version_evidence = (
            extract_version_evidence(
                version_draft
            )
        )

    semantic_hypotheses = []

    if semantic_case is not None:
        raw_hypotheses = (
            semantic_case.get(
                "semantic_trigger_hypotheses",
                [],
            )
        )

        if isinstance(
            raw_hypotheses,
            list,
        ):
            semantic_hypotheses = [
                row
                for row in raw_hypotheses
                if isinstance(
                    row,
                    dict,
                )
            ]

    version_aware = []

    if (
        version_draft is not None
    ):
        for hypothesis in (
            semantic_hypotheses
        ):
            version_aware.append(
                build_version_aware_hypothesis(
                    semantic_hypothesis=(
                        hypothesis
                    ),
                    version_evidence=(
                        version_evidence
                    ),
                )
            )

    if version_aware:
        status = (
            "version_aware_draft_proposed"
        )

        unresolved_reason = (
            None
        )

    elif (
        not semantic_hypotheses
    ):
        status = (
            "unresolved"
        )

        unresolved_reason = (
            "no_supported_semantic_"
            "trigger_hypothesis"
        )

    elif (
        version_draft is None
    ):
        status = (
            "unresolved"
        )

        unresolved_reason = (
            "matching_version_draft_missing"
        )

    else:
        status = (
            "unresolved"
        )

        unresolved_reason = (
            "version_semantic_join_not_completed"
        )

    return {
        "distribution":
            distribution,

        "vulnerability_ids":
            vulnerability_ids,

        "status":
            status,

        "review_required":
            True,

        "unresolved_reason":
            unresolved_reason,

        "has_version_draft":
            version_draft is not None,

        "has_semantic_case":
            semantic_case is not None,

        "semantic_trigger_hypothesis_count":
            len(
                semantic_hypotheses
            ),

        "version_evidence":
            version_evidence,

        "version_aware_trigger_drafts":
            version_aware,
    }


def join_drafts(
    *,
    version_data: dict[str, Any],
    semantic_data: dict[str, Any],
) -> dict[str, Any]:
    if (
        clean_text(
            version_data.get(
                "schema_version"
            )
        )
        != EXPECTED_VERSION_SCHEMA
    ):
        raise ValueError(
            "Unexpected version draft schema."
        )

    if (
        clean_text(
            semantic_data.get(
                "schema_version"
            )
        )
        != EXPECTED_SEMANTIC_SCHEMA
    ):
        raise ValueError(
            "Unexpected semantic draft schema."
        )

    version_index = (
        build_version_index(
            version_data
        )
    )

    semantic_index = (
        build_semantic_index(
            semantic_data
        )
    )

    all_keys = sorted(
        set(
            version_index
        )
        | set(
            semantic_index
        ),
        key=str,
    )

    cases = []

    join_issues = []

    for key in all_keys:
        version_draft = (
            version_index.get(
                key
            )
        )

        semantic_case = (
            semantic_index.get(
                key
            )
        )

        if (
            version_draft is None
        ):
            join_issues.append(
                {
                    "case_key":
                        [
                            key[0],
                            list(
                                key[1]
                            ),
                        ],

                    "issue":
                        (
                            "version_draft_missing"
                        ),
                }
            )

        if (
            semantic_case is None
        ):
            join_issues.append(
                {
                    "case_key":
                        [
                            key[0],
                            list(
                                key[1]
                            ),
                        ],

                    "issue":
                        (
                            "semantic_case_missing"
                        ),
                }
            )

        cases.append(
            build_case(
                version_draft=(
                    version_draft
                ),
                semantic_case=(
                    semantic_case
                ),
            )
        )

    version_aware_drafts = [
        draft
        for case in cases
        for draft in case.get(
            "version_aware_trigger_drafts",
            [],
        )
    ]

    supported_version_aware = [
        draft
        for draft in version_aware_drafts
        if clean_text(
            draft.get(
                "version_evidence",
                {},
            ).get(
                "status"
            )
        )
        == "supported_version_evidence"
    ]

    multi_branch = [
        draft
        for draft in version_aware_drafts
        if clean_text(
            draft.get(
                "version_evidence",
                {},
            ).get(
                "fixed_release_resolution_mode"
            )
        )
        == "multi_branch"
    ]

    single_release = [
        draft
        for draft in version_aware_drafts
        if clean_text(
            draft.get(
                "version_evidence",
                {},
            ).get(
                "fixed_release_resolution_mode"
            )
        )
        == "single_release"
    ]

    return {
        "schema_version":
            SCHEMA_VERSION,

        "joiner_version":
            JOINER_VERSION,

        "status":
            (
                "resolved"
                if not join_issues
                else "partial"
            ),

        "source_mode":
            (
                "identity_level_version_"
                "semantic_evidence_join"
            ),

        "semantic_boundary": {
            "recomputes_version_evidence":
                False,

            "recomputes_semantic_relations":
                False,

            "joins_by_distribution_and_vulnerability_identity":
                True,

            "asserts_per_version_trigger_semantics":
                False,

            "creates_version_aware_trigger_evidence_drafts":
                True,

            "creates_executable_trigger_rules":
                False,

            "uses_llm_semantic_inference":
                False,

            "consumes_trigger_raw_ground_truth":
                False,

            "all_joined_drafts_require_review":
                True,
        },

        "input": {
            "version_schema":
                version_data.get(
                    "schema_version"
                ),

            "version_compiler_version":
                version_data.get(
                    "compiler_version"
                ),

            "semantic_schema":
                semantic_data.get(
                    "schema_version"
                ),

            "semantic_compiler_version":
                semantic_data.get(
                    "compiler_version"
                ),
        },

        "summary": {
            "case_count":
                len(
                    cases
                ),

            "case_with_semantic_hypothesis_count":
                sum(
                    1
                    for case in cases
                    if int(
                        case.get(
                            "semantic_trigger_hypothesis_count",
                            0,
                        )
                        or 0
                    )
                    > 0
                ),

            "version_aware_trigger_draft_count":
                len(
                    version_aware_drafts
                ),

            "supported_version_evidence_draft_count":
                len(
                    supported_version_aware
                ),

            "single_release_version_aware_draft_count":
                len(
                    single_release
                ),

            "multi_branch_version_aware_draft_count":
                len(
                    multi_branch
                ),

            "unresolved_case_count":
                sum(
                    1
                    for case in cases
                    if case.get(
                        "status"
                    )
                    == "unresolved"
                ),

            "join_issue_count":
                len(
                    join_issues
                ),

            "executable_rule_ready_count":
                sum(
                    1
                    for draft in version_aware_drafts
                    if draft.get(
                        "executable_rule_ready"
                    )
                    is True
                ),
        },

        "join_issues":
            join_issues,

        "cases":
            cases,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Join existing version evidence drafts "
            "with conservative semantic Trigger "
            "hypotheses by package/vulnerability "
            "identity without recomputing either."
        )
    )

    parser.add_argument(
        "--version-drafts",
        type=Path,
        default=DEFAULT_VERSION_DRAFTS,
    )

    parser.add_argument(
        "--semantic-drafts",
        type=Path,
        default=DEFAULT_SEMANTIC_DRAFTS,
    )

    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUTPUT,
    )

    args = parser.parse_args()

    result = join_drafts(
        version_data=load_json(
            args.version_drafts
        ),
        semantic_data=load_json(
            args.semantic_drafts
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
        "VERSION-AWARE TRIGGER EVIDENCE JOIN SUMMARY"
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
        "[OK] cases:",
        summary.get(
            "case_count"
        ),
    )

    print(
        "[OK] cases with semantic hypothesis:",
        summary.get(
            "case_with_semantic_hypothesis_count"
        ),
    )

    print(
        "[OK] version-aware Trigger drafts:",
        summary.get(
            "version_aware_trigger_draft_count"
        ),
    )

    print(
        "[OK] supported version evidence drafts:",
        summary.get(
            "supported_version_evidence_draft_count"
        ),
    )

    print(
        "[OK] single-release drafts:",
        summary.get(
            "single_release_version_aware_draft_count"
        ),
    )

    print(
        "[OK] multi-branch drafts:",
        summary.get(
            "multi_branch_version_aware_draft_count"
        ),
    )

    print(
        "[OK] unresolved cases:",
        summary.get(
            "unresolved_case_count"
        ),
    )

    print(
        "[OK] join issues:",
        summary.get(
            "join_issue_count"
        ),
    )

    print(
        "[OK] executable rules ready:",
        summary.get(
            "executable_rule_ready_count"
        ),
    )

    print(
        "[OK] saved:",
        args.out.resolve(),
    )


if __name__ == "__main__":
    main()