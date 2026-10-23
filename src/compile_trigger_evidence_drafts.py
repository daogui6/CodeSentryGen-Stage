from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

SCHEMA_VERSION = "avcs_trigger_evidence_draft_v0.1"
COMPILER_VERSION = "trigger_evidence_draft_compiler_v0.2"

DEFAULT_CORPUS = (
    ROOT
    / "output"
    / "avcs_trigger_candidate_evidence_corpus_v0.json"
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

DEFAULT_OUTPUT = (
    ROOT
    / "output"
    / "avcs_trigger_evidence_drafts_v0.json"
)


OSV_RANGE_FACT_KINDS = {
    "osv_introduced_version_candidate",
    "osv_fixed_version_candidate",
    "osv_last_affected_version_candidate",
    "osv_limit_version_candidate",
}


def clean_text(value: Any) -> str:
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


def fact_group_key(
    row: dict[str, Any],
) -> tuple[
    str,
    tuple[str, ...],
]:
    return (
        clean_text(
            row.get("distribution")
        ).lower(),
        normalized_ids(
            row.get(
                "vulnerability_ids"
            )
        ),
    )


def build_validation_index(
    validation_data: dict[str, Any],
) -> dict[
    str,
    dict[str, Any],
]:
    index: dict[
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
            index[
                fact_id
            ] = record

    return index


def build_source_index(
    corpus: dict[str, Any],
) -> dict[
    str,
    dict[str, Any],
]:
    index: dict[
        str,
        dict[str, Any],
    ] = {}

    for entry in dict_rows(
        corpus.get(
            "entries"
        )
    ):
        source_key = clean_text(
            entry.get(
                "source_key"
            )
        )

        if source_key:
            index[
                source_key
            ] = entry

    return index


def collect_automatic_supported_facts(
    candidate_data: dict[str, Any],
    validation_index: dict[
        str,
        dict[str, Any],
    ],
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    supported: list[
        dict[str, Any]
    ] = []

    issues: list[
        dict[str, Any]
    ] = []

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

        if not fact_id:
            issues.append(
                {
                    "issue":
                        "candidate_fact_missing_fact_id",
                }
            )
            continue

        validation = (
            validation_index.get(
                fact_id
            )
        )

        if validation is None:
            issues.append(
                {
                    "fact_id":
                        fact_id,
                    "issue":
                        "validation_record_missing",
                }
            )
            continue

        if (
            clean_text(
                validation.get(
                    "validation_status"
                )
            )
            != "supported"
        ):
            continue

        if (
            validation.get(
                "automatic_decision"
            )
            is not True
        ):
            continue

        if (
            validation.get(
                "review_required"
            )
            is True
        ):
            continue

        joined = dict(
            fact
        )

        joined[
            "_validation"
        ] = validation

        supported.append(
            joined
        )

    return (
        supported,
        issues,
    )


def build_osv_range_drafts(
    facts: list[
        dict[str, Any]
    ],
) -> list[
    dict[str, Any]
]:
    groups: dict[
        tuple[
            int,
            int,
            str,
            str,
            str,
        ],
        list[
            dict[str, Any]
        ],
    ] = defaultdict(
        list
    )

    for fact in facts:
        fact_kind = clean_text(
            fact.get(
                "fact_kind"
            )
        )

        if (
            fact_kind
            not in OSV_RANGE_FACT_KINDS
        ):
            continue

        structured = fact.get(
            "structured_value"
        )

        if not isinstance(
            structured,
            dict,
        ):
            continue

        try:
            affected_index = int(
                structured.get(
                    "affected_index",
                    0,
                )
            )

            range_index = int(
                structured.get(
                    "range_index",
                    0,
                )
            )

            event_index = int(
                structured.get(
                    "event_index",
                    0,
                )
            )

        except (
            TypeError,
            ValueError,
        ):
            continue

        key = (
            affected_index,
            range_index,
            clean_text(
                structured.get(
                    "range_type"
                )
            ),
            clean_text(
                structured.get(
                    "package_name"
                )
            ),
            clean_text(
                structured.get(
                    "ecosystem"
                )
            ),
        )

        groups[
            key
        ].append(
            {
                "event_index":
                    event_index,
                "event":
                    clean_text(
                        structured.get(
                            "event"
                        )
                    ),
                "version":
                    clean_text(
                        structured.get(
                            "version"
                        )
                    ),
                "fact_id":
                    fact.get(
                        "fact_id"
                    ),
                "source_key":
                    fact.get(
                        "source_key"
                    ),
                "evidence_unit_id":
                    fact.get(
                        "evidence_unit_id"
                    ),
            }
        )

    drafts: list[
        dict[str, Any]
    ] = []

    for (
        key,
        events,
    ) in sorted(
        groups.items(),
        key=lambda item: item[0],
    ):
        (
            affected_index,
            range_index,
            range_type,
            package_name,
            ecosystem,
        ) = key

        ordered_events = sorted(
            events,
            key=lambda row: (
                int(
                    row.get(
                        "event_index",
                        0,
                    )
                ),
                clean_text(
                    row.get(
                        "event"
                    )
                ),
            ),
        )

        drafts.append(
            {
                "affected_index":
                    affected_index,
                "range_index":
                    range_index,
                "range_type":
                    range_type,
                "package_name":
                    package_name,
                "ecosystem":
                    ecosystem,
                "status":
                    "supported_atomic_range_events",
                "events":
                    ordered_events,
            }
        )

    return drafts


def build_fixed_release_candidates(
    range_drafts: list[
        dict[str, Any]
    ],
) -> list[
    dict[str, Any]
]:
    result: list[
        dict[str, Any]
    ] = []

    seen: set[
        tuple[
            str,
            str,
        ]
    ] = set()

    for range_draft in range_drafts:
        # fixed_release_candidates 表示包管理生态中的
        # 发布版本，因此 v0 只接受 OSV ECOSYSTEM range。
        #
        # GIT range 的 fixed 值通常是 commit SHA，
        # 不能混入 release version。
        if (
                clean_text(
                    range_draft.get(
                        "range_type"
                    )
                ).upper()
                != "ECOSYSTEM"
        ):
            continue

        for event in dict_rows(
                range_draft.get(
                    "events"
                )
        ):
            if (
                clean_text(
                    event.get(
                        "event"
                    )
                )
                != "fixed"
            ):
                continue

            version = clean_text(
                event.get(
                    "version"
                )
            )

            fact_id = clean_text(
                event.get(
                    "fact_id"
                )
            )

            key = (
                version,
                fact_id,
            )

            if (
                not version
                or key in seen
            ):
                continue

            seen.add(
                key
            )

            result.append(
                {
                    "version":
                        version,
                    "fact_id":
                        fact_id,
                    "source_key":
                        event.get(
                            "source_key"
                        ),
                    "evidence_unit_id":
                        event.get(
                            "evidence_unit_id"
                        ),
                    "status":
                        "supported_atomic_fact",
                }
            )

    return result

def build_ecosystem_branch_fixed_releases(
    range_drafts: list[
        dict[str, Any]
    ],
) -> list[
    dict[str, Any]
]:
    result: list[
        dict[str, Any]
    ] = []

    seen: set[
        tuple[
            str,
            str,
            int,
            int,
            str,
            str,
        ]
    ] = set()

    for range_draft in range_drafts:
        if (
            clean_text(
                range_draft.get(
                    "range_type"
                )
            ).upper()
            != "ECOSYSTEM"
        ):
            continue

        affected_index = int(
            range_draft.get(
                "affected_index",
                0,
            )
        )

        range_index = int(
            range_draft.get(
                "range_index",
                0,
            )
        )

        events_by_source: dict[
            tuple[
                str,
                str,
            ],
            list[
                dict[str, Any]
            ],
        ] = defaultdict(
            list
        )

        for event in dict_rows(
            range_draft.get(
                "events"
            )
        ):
            source_key = clean_text(
                event.get(
                    "source_key"
                )
            )

            evidence_unit_id = clean_text(
                event.get(
                    "evidence_unit_id"
                )
            )

            if not source_key:
                continue

            events_by_source[
                (
                    source_key,
                    evidence_unit_id,
                )
            ].append(
                event
            )

        for (
            source_key,
            evidence_unit_id,
        ), events in sorted(
            events_by_source.items()
        ):
            ordered_events = sorted(
                events,
                key=lambda row: (
                    int(
                        row.get(
                            "event_index",
                            0,
                        )
                    ),
                    clean_text(
                        row.get(
                            "event"
                        )
                    ),
                ),
            )

            pending_introduced: (
                dict[str, Any]
                | None
            ) = None

            branch_index = 0

            for event in ordered_events:
                event_kind = clean_text(
                    event.get(
                        "event"
                    )
                )

                if (
                    event_kind
                    == "introduced"
                ):
                    pending_introduced = (
                        event
                    )

                    continue

                if (
                    event_kind
                    != "fixed"
                ):
                    continue

                if (
                    pending_introduced
                    is None
                ):
                    continue

                introduced_version = (
                    clean_text(
                        pending_introduced.get(
                            "version"
                        )
                    )
                )

                fixed_version = clean_text(
                    event.get(
                        "version"
                    )
                )

                if (
                    not introduced_version
                    or not fixed_version
                ):
                    pending_introduced = (
                        None
                    )

                    continue

                key = (
                    source_key,
                    evidence_unit_id,
                    affected_index,
                    range_index,
                    introduced_version,
                    fixed_version,
                )

                if key not in seen:
                    seen.add(
                        key
                    )

                    result.append(
                        {
                            "branch_index":
                                branch_index,

                            "affected_index":
                                affected_index,

                            "range_index":
                                range_index,

                            "introduced_version":
                                introduced_version,

                            "fixed_version":
                                fixed_version,

                            "source_key":
                                source_key,

                            "evidence_unit_id":
                                evidence_unit_id,

                            "introduced_fact_id":
                                (
                                    pending_introduced.get(
                                        "fact_id"
                                    )
                                ),

                            "fixed_fact_id":
                                event.get(
                                    "fact_id"
                                ),

                            "status":
                                (
                                    "supported_atomic_"
                                    "branch_fix_pair"
                                ),
                        }
                    )

                branch_index += 1

                pending_introduced = None

    result.sort(
        key=lambda row: (
            clean_text(
                row.get(
                    "source_key"
                )
            ),
            int(
                row.get(
                    "affected_index",
                    0,
                )
            ),
            int(
                row.get(
                    "range_index",
                    0,
                )
            ),
            int(
                row.get(
                    "branch_index",
                    0,
                )
            ),
            clean_text(
                row.get(
                    "introduced_version"
                )
            ),
            clean_text(
                row.get(
                    "fixed_version"
                )
            ),
        )
    )

    return result


def build_fixed_release_resolution(
    candidates: list[
        dict[str, Any]
    ],
    range_drafts: list[
        dict[str, Any]
    ],
) -> dict[str, Any]:
    by_version: dict[
        str,
        list[
            dict[str, Any]
        ],
    ] = defaultdict(
        list
    )

    for candidate in candidates:
        version = clean_text(
            candidate.get(
                "version"
            )
        )

        if not version:
            continue

        by_version[
            version
        ].append(
            candidate
        )

    distinct_versions = sorted(
        by_version
    )

    branch_fixed_releases = (
        build_ecosystem_branch_fixed_releases(
            range_drafts
        )
    )

    if not distinct_versions:
        return {
            "status":
                "unresolved",

            "resolution_mode":
                "unresolved",

            "selected_version":
                None,

            "distinct_versions":
                [],

            "conflicting_versions":
                [],

            "branch_fixed_releases":
                [],

            "supporting_candidates":
                [],
        }

    if len(
        distinct_versions
    ) == 1:
        version = (
            distinct_versions[0]
        )

        return {
            "status":
                "supported",

            "resolution_mode":
                "single_release",

            "selected_version":
                version,

            "distinct_versions":
                distinct_versions,

            "conflicting_versions":
                [],

            "branch_fixed_releases":
                [
                    row
                    for row
                    in branch_fixed_releases
                    if (
                        clean_text(
                            row.get(
                                "fixed_version"
                            )
                        )
                        == version
                    )
                ],

            "supporting_candidates":
                by_version[
                    version
                ],
        }

    candidate_source_keys = {
        clean_text(
            candidate.get(
                "source_key"
            )
        )
        for candidate
        in candidates
        if clean_text(
            candidate.get(
                "source_key"
            )
        )
    }

    branch_source_keys = {
        clean_text(
            row.get(
                "source_key"
            )
        )
        for row
        in branch_fixed_releases
        if clean_text(
            row.get(
                "source_key"
            )
        )
    }

    branch_versions = {
        clean_text(
            row.get(
                "fixed_version"
            )
        )
        for row
        in branch_fixed_releases
        if clean_text(
            row.get(
                "fixed_version"
            )
        )
    }

    # Conservative multi-branch rule:
    #
    # Multiple fixed releases are treated as
    # supported branch fixes only when all of
    # them originate from the same evidence
    # source and that same source contains
    # explicit introduced -> fixed branch pairs.
    #
    # Different sources reporting different
    # fixed boundaries remain a provenance
    # conflict. This preserves cases such as
    # the NumPy GHSA/PYSEC disagreement.
    is_supported_multi_branch = (
        len(
            candidate_source_keys
        )
        == 1
        and branch_source_keys
        == candidate_source_keys
        and branch_versions
        == set(
            distinct_versions
        )
        and len(
            branch_fixed_releases
        )
        >= 2
    )

    if is_supported_multi_branch:
        return {
            "status":
                "supported",

            "resolution_mode":
                "multi_branch",

            "selected_version":
                None,

            "distinct_versions":
                distinct_versions,

            "conflicting_versions":
                [],

            "branch_fixed_releases":
                branch_fixed_releases,

            "supporting_candidates":
                candidates,
        }

    return {
        "status":
            "conflicted",

        "resolution_mode":
            (
                "cross_source_or_"
                "ambiguous_multiple_fixed"
            ),

        "selected_version":
            None,

        "distinct_versions":
            distinct_versions,

        "conflicting_versions":
            [
                {
                    "version":
                        version,

                    "supporting_candidates":
                        by_version[
                            version
                        ],
                }
                for version
                in distinct_versions
            ],

        "branch_fixed_releases":
            branch_fixed_releases,

        "supporting_candidates":
            candidates,
    }

def build_keyword_rule_proposals(
    facts: list[
        dict[str, Any]
    ],
) -> list[
    dict[str, Any]
]:
    proposals: list[
        dict[str, Any]
    ] = []

    seen: set[str] = set()

    kind_map = {
        "code_expression_keyword_literal_candidate":
            "keyword_literal_condition",

        "code_expression_keyword_symbol_candidate":
            "keyword_argument_condition",

        "code_expression_keyword_call_candidate":
            "keyword_call_condition",
    }

    for fact in facts:
        validation = fact.get(
            "_validation",
            {},
        )

        if not isinstance(
            validation,
            dict,
        ):
            continue

        if (
            clean_text(
                validation.get(
                    "validation_rule"
                )
            )
            != "exact_cross_source_corroboration"
        ):
            continue

        fact_kind = clean_text(
            fact.get(
                "fact_kind"
            )
        )

        proposed_kind = (
            kind_map.get(
                fact_kind
            )
        )

        if proposed_kind is None:
            continue

        structured = fact.get(
            "structured_value",
            {},
        )

        if not isinstance(
            structured,
            dict,
        ):
            continue

        call_symbol = clean_text(
            structured.get(
                "call_symbol"
            )
        )

        keyword_name = clean_text(
            structured.get(
                "keyword_name"
            )
        )

        argument_value = (
            structured.get(
                "argument_value",
                {},
            )
        )

        if not isinstance(
            argument_value,
            dict,
        ):
            continue

        # v0 只接受明确的 qualified API symbol。
        #
        # 例如：
        #
        #   jwt.decode
        #   urllib3.PoolManager
        #
        # 而不是：
        #
        #   print
        #   public_bytes
        #
        if (
            not call_symbol
            or "."
            not in call_symbol
            or not keyword_name
        ):
            continue

        keyword_argument: dict[
            str,
            Any,
        ] = {
            "name":
                keyword_name,
        }

        if (
            proposed_kind
            == "keyword_literal_condition"
        ):
            if (
                argument_value.get(
                    "value_kind"
                )
                != "literal"
            ):
                continue

            keyword_argument[
                "required_literal"
            ] = argument_value.get(
                "value"
            )

        elif (
            proposed_kind
            == "keyword_argument_condition"
        ):
            if (
                argument_value.get(
                    "value_kind"
                )
                != "symbol"
            ):
                continue

            required_symbol = clean_text(
                argument_value.get(
                    "symbol"
                )
            )

            if not required_symbol:
                continue

            keyword_argument[
                "required_symbol"
            ] = required_symbol

        elif (
            proposed_kind
            == "keyword_call_condition"
        ):
            if (
                argument_value.get(
                    "value_kind"
                )
                != "call"
            ):
                continue

            required_call_symbol = (
                clean_text(
                    argument_value.get(
                        "call_symbol"
                    )
                )
            )

            if not required_call_symbol:
                continue

            keyword_argument[
                "required_call_symbol"
            ] = required_call_symbol

        signature = json.dumps(
            {
                "api_symbol":
                    call_symbol,
                "kind":
                    proposed_kind,
                "keyword_argument":
                    keyword_argument,
            },
            ensure_ascii=False,
            sort_keys=True,
        )

        if signature in seen:
            continue

        seen.add(
            signature
        )

        proposals.append(
            {
                "proposal_type":
                    "conditional_trigger_rule_shape",
                "proposal_status":
                    "proposed_requires_review",
                "review_required":
                    True,

                "api_symbol":
                    call_symbol,

                "kind":
                    proposed_kind,

                "keyword_argument":
                    keyword_argument,

                "version_scope":
                    None,

                "supporting_fact_ids": [
                    fact.get(
                        "fact_id"
                    )
                ],

                "supporting_evidence_unit_ids":
                    validation.get(
                        "supporting_evidence_unit_ids",
                        [],
                    ),

                "proposal_basis":
                    (
                        "A supported cross-source "
                        "code-expression fact can be "
                        "mapped deterministically to "
                        "an AVCS conditional rule "
                        "shape. Vulnerability-trigger "
                        "semantics are not asserted."
                    ),
            }
        )

    return proposals

def build_receiver_rule_proposals(
    facts: list[
        dict[str, Any]
    ],
) -> list[
    dict[str, Any]
]:
    exact_facts = []

    for fact in facts:
        validation = fact.get(
            "_validation",
            {},
        )

        if not isinstance(
            validation,
            dict,
        ):
            continue

        if (
            clean_text(
                validation.get(
                    "validation_rule"
                )
            )
            != "exact_cross_source_corroboration"
        ):
            continue

        exact_facts.append(
            fact
        )

    producer_bindings: list[
        dict[str, Any]
    ] = []

    producer_keywords: list[
        dict[str, Any]
    ] = []

    receiver_calls: list[
        dict[str, Any]
    ] = []

    for fact in exact_facts:
        fact_kind = clean_text(
            fact.get(
                "fact_kind"
            )
        )

        structured = fact.get(
            "structured_value",
            {},
        )

        if not isinstance(
            structured,
            dict,
        ):
            continue

        if (
            fact_kind
            == "code_expression_assignment_call_candidate"
        ):
            target_symbol = clean_text(
                structured.get(
                    "target_symbol"
                )
            )

            assigned = structured.get(
                "assigned_value",
                {},
            )

            if not isinstance(
                assigned,
                dict,
            ):
                continue

            call_symbol = clean_text(
                assigned.get(
                    "call_symbol"
                )
            )

            if (
                not target_symbol
                or not call_symbol
            ):
                continue

            if (
                assigned.get(
                    "value_kind"
                )
                != "call"
            ):
                continue

            # 形如：
            #
            # http = urllib3.PoolManager(...)
            #
            # producer API 是 qualified symbol。
            if "." in call_symbol:
                producer_bindings.append(
                    {
                        "receiver":
                            target_symbol,
                        "producer_api_symbol":
                            call_symbol,
                        "fact":
                            fact,
                    }
                )

            # 形如：
            #
            # resp = http.request(...)
            #
            # http.request 的前缀可能对应
            # 上面的 receiver。
            if "." in call_symbol:
                receiver_calls.append(
                    {
                        "call_symbol":
                            call_symbol,
                        "fact":
                            fact,
                    }
                )

        elif (
            fact_kind
            == "code_expression_keyword_literal_candidate"
        ):
            call_symbol = clean_text(
                structured.get(
                    "call_symbol"
                )
            )

            keyword_name = clean_text(
                structured.get(
                    "keyword_name"
                )
            )

            argument_value = (
                structured.get(
                    "argument_value",
                    {},
                )
            )

            if not isinstance(
                argument_value,
                dict,
            ):
                continue

            if (
                not call_symbol
                or "."
                not in call_symbol
                or not keyword_name
                or argument_value.get(
                    "value_kind"
                )
                != "literal"
            ):
                continue

            producer_keywords.append(
                {
                    "producer_api_symbol":
                        call_symbol,
                    "keyword_name":
                        keyword_name,
                    "literal":
                        argument_value.get(
                            "value"
                        ),
                    "fact":
                        fact,
                }
            )

    proposals: list[
        dict[str, Any]
    ] = []

    seen: set[str] = set()

    for binding in producer_bindings:
        receiver = clean_text(
            binding.get(
                "receiver"
            )
        )

        producer_api = clean_text(
            binding.get(
                "producer_api_symbol"
            )
        )

        if not receiver or not producer_api:
            continue

        prefix = (
            receiver
            + "."
        )

        for receiver_call in receiver_calls:
            local_call_symbol = clean_text(
                receiver_call.get(
                    "call_symbol"
                )
            )

            if not local_call_symbol.startswith(
                prefix
            ):
                continue

            method_suffix = (
                local_call_symbol[
                    len(prefix):
                ]
            )

            if not method_suffix:
                continue

            canonical_consumer_api = (
                producer_api
                + "."
                + method_suffix
            )

            for keyword in producer_keywords:
                if (
                    clean_text(
                        keyword.get(
                            "producer_api_symbol"
                        )
                    )
                    != producer_api
                ):
                    continue

                keyword_name = clean_text(
                    keyword.get(
                        "keyword_name"
                    )
                )

                if not keyword_name:
                    continue

                rule = {
                    "api_symbol":
                        canonical_consumer_api,

                    "kind":
                        (
                            "receiver_producer_"
                            "keyword_literal_condition"
                        ),

                    "receiver_provenance": {
                        "producer_api_symbol":
                            producer_api,

                        "producer_keyword_argument": {
                            "name":
                                keyword_name,
                            "required_literal":
                                keyword.get(
                                    "literal"
                                ),
                        },
                    },

                    "version_scope":
                        None,
                }

                signature = json.dumps(
                    rule,
                    ensure_ascii=False,
                    sort_keys=True,
                )

                if signature in seen:
                    continue

                seen.add(
                    signature
                )

                binding_fact = (
                    binding[
                        "fact"
                    ]
                )

                keyword_fact = (
                    keyword[
                        "fact"
                    ]
                )

                consumer_fact = (
                    receiver_call[
                        "fact"
                    ]
                )

                proposals.append(
                    {
                        "proposal_type":
                            (
                                "conditional_"
                                "trigger_rule_shape"
                            ),

                        "proposal_status":
                            "proposed_requires_review",

                        "review_required":
                            True,

                        **rule,

                        "supporting_fact_ids": [
                            binding_fact.get(
                                "fact_id"
                            ),
                            keyword_fact.get(
                                "fact_id"
                            ),
                            consumer_fact.get(
                                "fact_id"
                            ),
                        ],

                        "proposal_basis":
                            (
                                "A direct receiver binding, "
                                "producer keyword literal, "
                                "and subsequent receiver "
                                "method call are all present "
                                "in supported cross-source "
                                "atomic facts. The resulting "
                                "receiver-producer rule shape "
                                "is structural only and still "
                                "requires semantic review."
                            ),
                    }
                )

    return proposals


def compact_atomic_fact(
    fact: dict[str, Any],
) -> dict[str, Any]:
    validation = fact.get(
        "_validation"
    )

    if not isinstance(
        validation,
        dict,
    ):
        validation = {}

    return {
        "fact_id":
            fact.get(
                "fact_id"
            ),
        "fact_kind":
            fact.get(
                "fact_kind"
            ),
        "structured_value":
            fact.get(
                "structured_value"
            ),
        "source_key":
            fact.get(
                "source_key"
            ),
        "source_id":
            fact.get(
                "source_id"
            ),
        "source_type":
            fact.get(
                "source_type"
            ),
        "evidence_unit_id":
            fact.get(
                "evidence_unit_id"
            ),
        "validation_rule":
            validation.get(
                "validation_rule"
            ),
        "supporting_fact_ids":
            validation.get(
                "supporting_fact_ids",
                [],
            ),
        "supporting_evidence_unit_ids":
            validation.get(
                "supporting_evidence_unit_ids",
                [],
            ),
    }


def build_source_summary(
    source_key: str,
    source_index: dict[
        str,
        dict[str, Any],
    ],
) -> dict[str, Any]:
    source = source_index.get(
        source_key,
        {},
    )

    return {
        "source_key":
            source_key,
        "source_id":
            source.get(
                "source_id"
            ),
        "source_type":
            source.get(
                "source_type"
            ),
        "acquisition_phase":
            source.get(
                "acquisition_phase"
            ),
        "acquisition_backend":
            source.get(
                "acquisition_backend"
            ),
        "canonical_identity":
            source.get(
                "canonical_identity",
                {},
            ),
        "corpus_status":
            source.get(
                "corpus_status"
            ),
    }


def build_case_draft(
    facts: list[
        dict[str, Any]
    ],
    source_index: dict[
        str,
        dict[str, Any],
    ],
) -> dict[str, Any]:
    first = facts[0]

    distribution = clean_text(
        first.get(
            "distribution"
        )
    )

    vulnerability_ids_raw = first.get(
        "vulnerability_ids",
        [],
    )

    if not isinstance(
        vulnerability_ids_raw,
        list,
    ):
        vulnerability_ids_raw = []

    vulnerability_ids = [
        clean_text(
            value
        )
        for value
        in vulnerability_ids_raw
        if clean_text(
            value
        )
    ]

    range_drafts = (
        build_osv_range_drafts(
            facts
        )
    )

    fixed_releases = (
        build_fixed_release_candidates(
            range_drafts
        )
    )

    fixed_release_resolution = (
        build_fixed_release_resolution(
            fixed_releases,
            range_drafts,
        )
    )

    keyword_rule_proposals = (
        build_keyword_rule_proposals(
            facts
        )
    )

    receiver_rule_proposals = (
        build_receiver_rule_proposals(
            facts
        )
    )

    structural_rule_proposals = (
            keyword_rule_proposals
            + receiver_rule_proposals
    )

    source_keys = sorted(
        {
            clean_text(
                fact.get(
                    "source_key"
                )
            )
            for fact in facts
            if clean_text(
                fact.get(
                    "source_key"
                )
            )
        }
    )

    fact_kind_counts = Counter(
        clean_text(
            fact.get(
                "fact_kind"
            )
        )
        for fact in facts
    )

    non_range_facts = [
        compact_atomic_fact(
            fact
        )
        for fact in facts
        if (
            clean_text(
                fact.get(
                    "fact_kind"
                )
            )
            not in OSV_RANGE_FACT_KINDS
        )
    ]

    raw_trigger_evidence_draft = {
        "schema_version":
            "avcs_trigger_raw_evidence_draft_v0.1",
        "ecosystem":
            "pypi",
        "distribution":
            distribution,
        "vulnerability_ids":
            vulnerability_ids,
        "scope": {
            "status":
                (
                    "supported_atomic_range_events"
                    if range_drafts
                    else "unresolved"
                ),
            "osv_range_drafts":
                range_drafts,
            "trigger_semantics_version_scope":
                None,
            "note":
                (
                    "Version events are compiled only "
                    "from automatically supported "
                    "atomic OSV facts. Trigger semantics "
                    "and any flattened version specifier "
                    "remain unresolved in v0."
                ),
        },
        "advisory_facts": {
            "status":
                "unresolved",
            "requires_affected_version":
                True,
            "requires_untrusted_input":
                None,
        },
        "trigger_candidates":
            [],
        "safe_alternatives":
            [],
        "fix_evidence": {
            "status":
                fixed_release_resolution[
                    "status"
                ],

            "resolution_mode":
                fixed_release_resolution[
                    "resolution_mode"
                ],

            "fixed_release":
                fixed_release_resolution[
                    "selected_version"
                ],

            "fixed_release_candidates":
                fixed_releases,

            "distinct_fixed_versions":
                fixed_release_resolution[
                    "distinct_versions"
                ],

            "conflicting_versions":
                fixed_release_resolution[
                    "conflicting_versions"
                ],

            "branch_fixed_releases":
                fixed_release_resolution[
                    "branch_fixed_releases"
                ],

            "mechanism":
                None,
        },
        "sources": [
            build_source_summary(
                source_key,
                source_index,
            )
            for source_key
            in source_keys
        ],
    }

    return {
        "distribution":
            distribution,
        "vulnerability_ids":
            vulnerability_ids,
        "draft_status":
            "partial",
        "automatic_supported_fact_count":
            len(
                facts
            ),
        "source_count":
            len(
                source_keys
            ),
        "fact_kind_counts":
            dict(
                sorted(
                    fact_kind_counts.items()
                )
            ),
        "automatic_components": {
            "structural_rule_proposal_count":
                len(
                    structural_rule_proposals
                ),

            "fixed_release_resolution_status":
                fixed_release_resolution[
                    "status"
                ],
            "fixed_release_resolution_mode":
                fixed_release_resolution[
                    "resolution_mode"
                ],
            "osv_range_draft_count":
                len(
                    range_drafts
                ),
            "fixed_release_candidate_count":
                len(
                    fixed_releases
                ),
        },
        "manual_review": {
            "required":
                True,
            "reasons": (
                [
                    (
                        "trigger_semantic_composition_"
                        "not_automatically_resolved_v0"
                    ),
                    (
                        "safe_alternative_semantics_"
                        "not_automatically_resolved_v0"
                    ),
                    (
                        "fix_mechanism_semantics_"
                        "not_automatically_resolved_v0"
                    ),
                ]
                +
                (
                    [
                        "fixed_release_evidence_conflict"
                    ]
                    if (
                        fixed_release_resolution[
                            "status"
                        ]
                        == "conflicted"
                    )
                    else []
                )
            ),
        },
        "structural_rule_proposals":
            structural_rule_proposals,
        "supported_non_range_atomic_facts":
            non_range_facts,
        "raw_trigger_evidence_draft":
            raw_trigger_evidence_draft,
    }


def rate(
    numerator: int,
    denominator: int,
) -> float:
    if denominator <= 0:
        return 0.0

    return round(
        numerator
        / denominator,
        6,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Compile automatically supported "
            "AVCS atomic facts into conservative "
            "Trigger Evidence drafts."
        )
    )

    parser.add_argument(
        "--corpus",
        type=Path,
        default=DEFAULT_CORPUS,
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

    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUTPUT,
    )

    args = parser.parse_args()

    corpus = load_json(
        args.corpus
    )

    candidate_data = load_json(
        args.facts
    )

    validation_data = load_json(
        args.validation
    )

    validation_index = (
        build_validation_index(
            validation_data
        )
    )

    source_index = (
        build_source_index(
            corpus
        )
    )

    (
        supported_facts,
        join_issues,
    ) = (
        collect_automatic_supported_facts(
            candidate_data,
            validation_index,
        )
    )

    grouped: dict[
        tuple[
            str,
            tuple[str, ...],
        ],
        list[
            dict[str, Any]
        ],
    ] = defaultdict(
        list
    )

    for fact in supported_facts:
        grouped[
            fact_group_key(
                fact
            )
        ].append(
            fact
        )

    drafts = [
        build_case_draft(
            group_facts,
            source_index,
        )
        for (
            _,
            group_facts,
        )
        in sorted(
            grouped.items(),
            key=lambda item: item[0],
        )
        if group_facts
    ]

    case_count = len(
        drafts
    )

    cases_with_range = sum(
        1
        for draft in drafts
        if (
            draft[
                "automatic_components"
            ][
                "osv_range_draft_count"
            ]
            > 0
        )
    )

    cases_with_fixed_release = sum(
        1
        for draft in drafts
        if (
            draft[
                "automatic_components"
            ][
                "fixed_release_candidate_count"
            ]
            > 0
        )
    )

    manual_review_case_count = sum(
        1
        for draft in drafts
        if (
            draft[
                "manual_review"
            ][
                "required"
            ]
            is True
        )
    )

    fixed_release_conflict_case_count = sum(
        1
        for draft in drafts
        if (
                draft[
                    "automatic_components"
                ][
                    "fixed_release_resolution_status"
                ]
                == "conflicted"
        )
    )

    structural_rule_proposal_count = sum(
        int(
            draft[
                "automatic_components"
            ][
                "structural_rule_proposal_count"
            ]
        )
        for draft in drafts
    )

    result = {
        "schema_version":
            SCHEMA_VERSION,
        "compiler_version":
            COMPILER_VERSION,
        "status":
            "resolved",
        "source_mode":
            (
                "validated_atomic_fact_to_"
                "trigger_evidence_draft"
            ),
        "input": {
            "corpus_path":
                str(
                    args.corpus.resolve()
                ),
            "candidate_fact_path":
                str(
                    args.facts.resolve()
                ),
            "validation_path":
                str(
                    args.validation.resolve()
                ),
            "candidate_fact_schema_version":
                candidate_data.get(
                    "schema_version"
                ),
            "validation_schema_version":
                validation_data.get(
                    "schema_version"
                ),
        },
        "semantic_boundary": {
            "consumes_candidate_facts":
                True,
            "consumes_validation_sidecar":
                True,
            "consumes_candidate_evidence_corpus":
                True,
            "consumes_trigger_raw_ground_truth":
                False,
            "uses_only_automatic_supported_facts":
                True,
            "uses_llm_semantic_inference":
                False,
            "creates_trigger_evidence_drafts":
                True,
            "creates_resolved_trigger_rules":
                False,
            "draft_is_benchmark_ground_truth":
                False,
            "human_final_review_required":
                True,
            "unresolved_fields_are_preserved":
                True,
            "intended_next_stage":
                (
                    "human_review_or_"
                    "conservative_rule_composition"
                ),
        },
        "compilation_policy": {
            "osv_range_events":
                (
                    "compile_from_automatic_"
                    "supported_atomic_facts"
                ),
            "fixed_release_candidates":
                (
                    "compile_from_supported_"
                    "osv_fixed_events"
                ),
            "trigger_semantic_composition":
                "disabled_v0",
            "safe_alternative_inference":
                "disabled_v0",
            "fix_mechanism_inference":
                "disabled_v0",
            "flattened_version_specifier":
                "disabled_v0",
        },
        "summary": {
            "automatic_supported_fact_count":
                len(
                    supported_facts
                ),
            "case_count":
                case_count,
            "case_with_osv_range_draft_count":
                cases_with_range,
            "case_with_fixed_release_candidate_count":
                cases_with_fixed_release,
            "manual_review_case_count":
                manual_review_case_count,
            "automatic_range_component_rate":
                rate(
                    cases_with_range,
                    case_count,
                ),
            "automatic_fixed_release_component_rate":
                rate(
                    cases_with_fixed_release,
                    case_count,
                ),
            "manual_review_case_rate":
                rate(
                    manual_review_case_count,
                    case_count,
                ),
            "join_issue_count":
                len(
                    join_issues
                ),
            "fixed_release_conflict_case_count":
                fixed_release_conflict_case_count,

            "structural_rule_proposal_count":
                structural_rule_proposal_count,
        },
        "join_issues":
            join_issues,
        "drafts":
            drafts,
    }

    write_json(
        args.out,
        result,
    )

    print(
        "="
        * 60
    )

    print(
        "TRIGGER EVIDENCE DRAFT "
        "COMPILATION SUMMARY"
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
        "[OK] automatic supported facts:",
        len(
            supported_facts
        ),
    )

    print(
        "[OK] cases:",
        case_count,
    )

    print(
        "[OK] cases with OSV range draft:",
        cases_with_range,
    )

    print(
        "[OK] cases with fixed release candidate:",
        cases_with_fixed_release,
    )

    print(
        "[OK] manual-review cases:",
        manual_review_case_count,
    )

    print(
        "[OK] join issues:",
        len(
            join_issues
        ),
    )

    print(
        "[OK] saved:",
        args.out.resolve(),
    )

    print(
        "[OK] fixed-release conflict cases:",
        fixed_release_conflict_case_count,
    )

    print(
        "[OK] structural rule proposals:",
        structural_rule_proposal_count,
    )


if __name__ == "__main__":
    main()