from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

SCHEMA_VERSION = (
    "avcs_trigger_semantic_draft_v0.1"
)

COMPILER_VERSION = (
    "trigger_semantic_draft_compiler_v0.2"
)

EXPECTED_RELATION_SCHEMA = (
    "avcs_trigger_semantic_relation_candidates_v0.1"
)

EXPECTED_VALIDATION_SCHEMA = (
    "avcs_trigger_candidate_fact_validation_v0.1"
)

EXPECTED_FACT_KIND = (
    "security_context_relation_candidate"
)

ACCEPTED_SEMANTIC_VALIDATION_RULES = {
    "exact_cross_source_corroboration",
    (
        "exact_cross_source_corroboration_"
        "with_excerpt_independence"
    ),
}

DEFAULT_CORPUS = (
    ROOT
    / "output"
    / "avcs_trigger_candidate_evidence_corpus_v0.json"
)

DEFAULT_RELATIONS = (
    ROOT
    / "output"
    / "avcs_trigger_semantic_relation_candidates_v0.json"
)

DEFAULT_VALIDATION = (
    ROOT
    / "output"
    / "avcs_trigger_semantic_relation_validation_v0.json"
)

DEFAULT_OUTPUT = (
    ROOT
    / "output"
    / "avcs_trigger_semantic_drafts_v0.json"
)


POSITIVE_RELATION_CLASSES = {
    "affected_context",
    "bypass_context",
    "security_effect_context",
    "mitigation_failure_context",
}

PROTECTIVE_RELATION_CLASSES = {
    "mitigation_context",
    "hardening_context",
    "unaffected_context",
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
                clean_text(item)
                for item in value
                if clean_text(item)
            },
            key=str.lower,
        )
    )


def normalized_context(
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
                clean_text(item)
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


def relation_polarity(
    relation_class: str,
) -> str:
    if (
        relation_class
        in POSITIVE_RELATION_CLASSES
    ):
        return "risk"

    if (
        relation_class
        in PROTECTIVE_RELATION_CLASSES
    ):
        return "protective"

    return "other"


def context_consensus(
    context_sets: list[
        tuple[str, ...]
    ],
) -> dict[str, Any]:
    unique_sets = sorted(
        set(
            context_sets
        )
    )

    if not unique_sets:
        return {
            "status":
                "no_context",

            "consensus":
                [],

            "observed_union":
                [],

            "variants":
                [],
        }

    working_intersection = set(
        unique_sets[0]
    )

    observed_union: set[
        str
    ] = set()

    for context_set in unique_sets:
        working_intersection.intersection_update(
            context_set
        )

        observed_union.update(
            context_set
        )

    consensus = sorted(
        working_intersection
    )

    observed = sorted(
        observed_union
    )

    if len(
        unique_sets
    ) == 1:
        status = (
            "exact"
        )

    elif consensus:
        status = (
            "partial"
        )

    else:
        status = (
            "divergent"
        )

    return {
        "status":
            status,

        "consensus":
            consensus,

        "observed_union":
            observed,

        "variants": [
            list(
                value
            )
            for value
            in unique_sets
        ],
    }


def build_case_inventory(
    corpus: dict[str, Any],
) -> dict[
    tuple[
        str,
        tuple[str, ...],
    ],
    dict[str, Any],
]:
    inventory: dict[
        tuple[
            str,
            tuple[str, ...],
        ],
        dict[str, Any],
    ] = {}

    entries = corpus.get(
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

    for entry in entries:
        if not isinstance(
            entry,
            dict,
        ):
            continue

        distribution = clean_text(
            entry.get(
                "distribution"
            )
        )

        vulnerability_ids = (
            normalized_ids(
                entry.get(
                    "vulnerability_ids"
                )
            )
        )

        if not distribution:
            continue

        key = (
            distribution.lower(),
            vulnerability_ids,
        )

        if key in inventory:
            continue

        inventory[
            key
        ] = {
            "distribution":
                distribution,

            "vulnerability_ids":
                list(
                    vulnerability_ids
                ),
        }

    return inventory


def join_supported_relations(
    relation_data: dict[str, Any],
    validation_data: dict[str, Any],
) -> list[
    dict[str, Any]
]:
    if (
        clean_text(
            relation_data.get(
                "schema_version"
            )
        )
        != EXPECTED_RELATION_SCHEMA
    ):
        raise ValueError(
            "Unexpected semantic relation schema."
        )

    if (
        clean_text(
            validation_data.get(
                "schema_version"
            )
        )
        != EXPECTED_VALIDATION_SCHEMA
    ):
        raise ValueError(
            "Unexpected validation schema."
        )

    raw_facts = relation_data.get(
        "facts",
        [],
    )

    raw_validation = validation_data.get(
        "validation_records",
        [],
    )

    if not isinstance(
        raw_facts,
        list,
    ):
        raise ValueError(
            "Relation artifact field 'facts' "
            "must be a list."
        )

    if not isinstance(
        raw_validation,
        list,
    ):
        raise ValueError(
            "Validation field "
            "'validation_records' "
            "must be a list."
        )

    validation_index = {
        clean_text(
            row.get(
                "fact_id"
            )
        ):
            row
        for row in raw_validation
        if (
            isinstance(
                row,
                dict,
            )
            and clean_text(
                row.get(
                    "fact_id"
                )
            )
        )
    }

    supported = []

    for fact in raw_facts:
        if not isinstance(
            fact,
            dict,
        ):
            continue

        if (
            clean_text(
                fact.get(
                    "fact_kind"
                )
            )
            != EXPECTED_FACT_KIND
        ):
            continue

        fact_id = clean_text(
            fact.get(
                "fact_id"
            )
        )

        validation = (
            validation_index.get(
                fact_id
            )
        )

        if validation is None:
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

        if (
            clean_text(
                validation.get(
                    "validation_rule"
                )
            )
            not in ACCEPTED_SEMANTIC_VALIDATION_RULES
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

    return supported


def build_relation_bundles(
    facts: list[
        dict[str, Any]
    ],
) -> list[
    dict[str, Any]
]:
    groups: dict[
        tuple[
            tuple[
                str,
                tuple[str, ...],
            ],
            str,
            str,
            str | None,
        ],
        list[
            dict[str, Any]
        ],
    ] = defaultdict(
        list
    )

    for fact in facts:
        structured = fact.get(
            "structured_value",
            {},
        )

        if not isinstance(
            structured,
            dict,
        ):
            continue

        anchor = clean_text(
            structured.get(
                "anchor"
            )
        )

        relation_class = clean_text(
            structured.get(
                "relation_class"
            )
        )

        raw_effect = structured.get(
            "security_effect"
        )

        security_effect = (
            clean_text(
                raw_effect
            )
            if raw_effect
            is not None
            else None
        )

        if not anchor:
            continue

        if not relation_class:
            continue

        key = (
            case_key(
                fact
            ),
            anchor,
            relation_class,
            security_effect,
        )

        groups[
            key
        ].append(
            fact
        )

    bundles = []

    for (
        group_key,
        rows,
    ) in sorted(
        groups.items(),
        key=lambda item: str(
            item[0]
        ),
    ):
        (
            (
                distribution,
                vulnerability_ids,
            ),
            anchor,
            relation_class,
            security_effect,
        ) = group_key

        source_keys = sorted(
            {
                clean_text(
                    row.get(
                        "source_key"
                    )
                )
                for row in rows
                if clean_text(
                    row.get(
                        "source_key"
                    )
                )
            }
        )

        source_types = sorted(
            {
                clean_text(
                    row.get(
                        "source_type"
                    )
                )
                for row in rows
                if clean_text(
                    row.get(
                        "source_type"
                    )
                )
            }
        )

        evidence_unit_ids = sorted(
            {
                clean_text(
                    row.get(
                        "evidence_unit_id"
                    )
                )
                for row in rows
                if clean_text(
                    row.get(
                        "evidence_unit_id"
                    )
                )
            }
        )

        fact_ids = sorted(
            {
                clean_text(
                    row.get(
                        "fact_id"
                    )
                )
                for row in rows
                if clean_text(
                    row.get(
                        "fact_id"
                    )
                )
            }
        )

        context = (
            context_consensus(
                [
                    normalized_context(
                        row.get(
                            "context_tags"
                        )
                    )
                    for row in rows
                ]
            )
        )

        polarity = (
            relation_polarity(
                relation_class
            )
        )

        signature_payload = {
            "distribution":
                distribution,

            "vulnerability_ids":
                list(
                    vulnerability_ids
                ),

            "anchor":
                anchor,

            "relation_class":
                relation_class,

            "security_effect":
                security_effect,
        }

        bundle_id = make_id(
            "triggerrelbundle_",
            signature_payload,
        )

        bundles.append(
            {
                "relation_bundle_id":
                    bundle_id,

                "distribution":
                    distribution,

                "vulnerability_ids":
                    list(
                        vulnerability_ids
                    ),

                "anchor":
                    anchor,

                "relation_class":
                    relation_class,

                "security_effect":
                    security_effect,

                "polarity":
                    polarity,

                "validation_status":
                    "supported",

                "validation_basis":
                    (
                        "All records in this "
                        "relation bundle passed "
                        "an accepted conservative "
                        "cross-source corroboration "
                        "rule before composition."
                    ),

                "supported_record_count":
                    len(
                        rows
                    ),

                "independent_source_key_count":
                    len(
                        source_keys
                    ),

                "independent_source_type_count":
                    len(
                        source_types
                    ),

                "source_keys":
                    source_keys,

                "source_types":
                    source_types,

                "supporting_fact_ids":
                    fact_ids,

                "supporting_evidence_unit_ids":
                    evidence_unit_ids,

                "context_consensus":
                    context,

                "evidence_excerpts": [
                    {
                        "source_key":
                            row.get(
                                "source_key"
                            ),

                        "source_type":
                            row.get(
                                "source_type"
                            ),

                        "context_tags":
                            row.get(
                                "context_tags",
                                [],
                            ),

                        "excerpt":
                            row.get(
                                "evidence_excerpt"
                            ),
                    }
                    for row in rows
                ],
            }
        )

    return bundles


def anchor_context_consensus(
    bundles: list[
        dict[str, Any]
    ],
) -> dict[str, Any]:
    contexts = []

    for bundle in bundles:
        consensus = bundle.get(
            "context_consensus",
            {},
        )

        if not isinstance(
            consensus,
            dict,
        ):
            contexts.append(
                tuple()
            )

            continue

        contexts.append(
            normalized_context(
                consensus.get(
                    "consensus"
                )
            )
        )

    return context_consensus(
        contexts
    )


def build_trigger_hypothesis(
    *,
    distribution: str,
    vulnerability_ids: list[str],
    anchor: str,
    positive_bundles: list[
        dict[str, Any]
    ],
    protective_bundles: list[
        dict[str, Any]
    ],
    case_protective_bundles: list[
        dict[str, Any]
    ],
) -> dict[str, Any]:
    positive_bundle_ids = sorted(
        {
            clean_text(
                bundle.get(
                    "relation_bundle_id"
                )
            )
            for bundle
            in positive_bundles
            if clean_text(
                bundle.get(
                    "relation_bundle_id"
                )
            )
        }
    )

    security_effects = sorted(
        {
            clean_text(
                bundle.get(
                    "security_effect"
                )
            )
            for bundle
            in positive_bundles
            if clean_text(
                bundle.get(
                    "security_effect"
                )
            )
        }
    )

    risk_relation_classes = sorted(
        {
            clean_text(
                bundle.get(
                    "relation_class"
                )
            )
            for bundle
            in positive_bundles
            if clean_text(
                bundle.get(
                    "relation_class"
                )
            )
        }
    )

    source_keys = sorted(
        {
            source_key
            for bundle
            in positive_bundles
            for source_key
            in bundle.get(
                "source_keys",
                [],
            )
            if clean_text(
                source_key
            )
        }
    )

    source_types = sorted(
        {
            source_type
            for bundle
            in positive_bundles
            for source_type
            in bundle.get(
                "source_types",
                [],
            )
            if clean_text(
                source_type
            )
        }
    )

    context = (
        anchor_context_consensus(
            positive_bundles
        )
    )

    payload = {
        "distribution":
            distribution,

        "vulnerability_ids":
            vulnerability_ids,

        "anchor":
            anchor,

        "positive_relation_bundle_ids":
            positive_bundle_ids,
    }

    hypothesis_id = make_id(
        "triggerhyp_",
        payload,
    )

    review_reasons = [
        (
            "Supported semantic relations "
            "do not by themselves define "
            "a sound executable static or "
            "runtime matcher."
        ),

        (
            "Version scope is deliberately "
            "not composed in semantic draft "
            "v0."
        ),
    ]

    if (
        context.get(
            "status"
        )
        == "divergent"
    ):
        review_reasons.append(
            (
                "Positive relations do not "
                "share a non-empty context "
                "consensus."
            )
        )

    same_anchor_protective_ids = [
        bundle.get(
            "relation_bundle_id"
        )
        for bundle
        in protective_bundles
    ]

    case_protective_ids = [
        bundle.get(
            "relation_bundle_id"
        )
        for bundle
        in case_protective_bundles
    ]

    return {
        "trigger_hypothesis_id":
            hypothesis_id,

        "proposal_type":
            (
                "semantic_trigger_hypothesis"
            ),

        "proposal_status":
            (
                "proposed_requires_review"
            ),

        "review_required":
            True,

        "distribution":
            distribution,

        "vulnerability_ids":
            vulnerability_ids,

        "anchor":
            anchor,

        "risk_relation_classes":
            risk_relation_classes,

        "security_effects":
            security_effects,

        "required_context_consensus":
            context.get(
                "consensus",
                [],
            ),

        "observed_context_union":
            context.get(
                "observed_union",
                [],
            ),

        "context_consensus_status":
            context.get(
                "status"
            ),

        "context_variants":
            context.get(
                "variants",
                [],
            ),

        "positive_relation_bundle_ids":
            positive_bundle_ids,

        "same_anchor_protective_relation_bundle_ids":
            same_anchor_protective_ids,

        "case_level_protective_contrast_bundle_ids":
            case_protective_ids,

        "independent_positive_source_key_count":
            len(
                source_keys
            ),

        "independent_positive_source_type_count":
            len(
                source_types
            ),

        "positive_source_keys":
            source_keys,

        "positive_source_types":
            source_types,

        "version_scope":
            None,

        "version_binding_status":
            (
                "not_composed_in_semantic_draft_v0"
            ),

        "executable_rule_ready":
            False,

        "review_reasons":
            review_reasons,

        "proposal_basis":
            (
                "One or more unique "
                "cross-source-supported risk "
                "relations share the same "
                "program/configuration anchor. "
                "Context is retained only when "
                "it survives conservative "
                "cross-record consensus. "
                "Protective relations are kept "
                "as contrast evidence rather "
                "than treated as safe "
                "alternatives."
            ),
    }


def build_case_drafts(
    *,
    case_inventory: dict[
        tuple[
            str,
            tuple[str, ...],
        ],
        dict[str, Any],
    ],
    bundles: list[
        dict[str, Any]
    ],
) -> list[
    dict[str, Any]
]:
    bundles_by_case: dict[
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

    for bundle in bundles:
        key = (
            clean_text(
                bundle.get(
                    "distribution"
                )
            ).lower(),
            normalized_ids(
                bundle.get(
                    "vulnerability_ids"
                )
            ),
        )

        bundles_by_case[
            key
        ].append(
            bundle
        )

    cases = []

    for (
        key,
        identity,
    ) in sorted(
        case_inventory.items(),
        key=lambda item: str(
            item[0]
        ),
    ):
        case_bundles = sorted(
            bundles_by_case.get(
                key,
                []
            ),
            key=lambda row: (
                clean_text(
                    row.get(
                        "anchor"
                    )
                ).lower(),
                clean_text(
                    row.get(
                        "relation_class"
                    )
                ),
                clean_text(
                    row.get(
                        "security_effect"
                    )
                ),
            ),
        )

        positive = [
            row
            for row in case_bundles
            if row.get(
                "polarity"
            )
            == "risk"
        ]

        protective = [
            row
            for row in case_bundles
            if row.get(
                "polarity"
            )
            == "protective"
        ]

        positive_by_anchor: dict[
            str,
            list[
                dict[str, Any]
            ],
        ] = defaultdict(
            list
        )

        protective_by_anchor: dict[
            str,
            list[
                dict[str, Any]
            ],
        ] = defaultdict(
            list
        )

        for row in positive:
            positive_by_anchor[
                clean_text(
                    row.get(
                        "anchor"
                    )
                )
            ].append(
                row
            )

        for row in protective:
            protective_by_anchor[
                clean_text(
                    row.get(
                        "anchor"
                    )
                )
            ].append(
                row
            )

        hypotheses = []

        for anchor in sorted(
            positive_by_anchor
        ):
            same_anchor_protective = (
                protective_by_anchor.get(
                    anchor,
                    [],
                )
            )

            other_protective = [
                row
                for row in protective
                if clean_text(
                    row.get(
                        "anchor"
                    )
                )
                != anchor
            ]

            hypotheses.append(
                build_trigger_hypothesis(
                    distribution=(
                        identity[
                            "distribution"
                        ]
                    ),
                    vulnerability_ids=(
                        identity[
                            "vulnerability_ids"
                        ]
                    ),
                    anchor=anchor,
                    positive_bundles=(
                        positive_by_anchor[
                            anchor
                        ]
                    ),
                    protective_bundles=(
                        same_anchor_protective
                    ),
                    case_protective_bundles=(
                        other_protective
                    ),
                )
            )

        if hypotheses:
            status = (
                "proposed_requires_review"
            )

            unresolved_reason = (
                None
            )

        else:
            status = (
                "unresolved"
            )

            unresolved_reason = (
                "no_cross_source_supported_"
                "positive_semantic_relation"
            )

        cases.append(
            {
                "distribution":
                    identity[
                        "distribution"
                    ],

                "vulnerability_ids":
                    identity[
                        "vulnerability_ids"
                    ],

                "status":
                    status,

                "review_required":
                    True,

                "unresolved_reason":
                    unresolved_reason,

                "supported_relation_bundles":
                    case_bundles,

                "supported_positive_relation_bundle_count":
                    len(
                        positive
                    ),

                "supported_protective_relation_bundle_count":
                    len(
                        protective
                    ),

                "semantic_trigger_hypotheses":
                    hypotheses,
            }
        )

    return cases


def compile_drafts(
    *,
    corpus: dict[str, Any],
    relation_data: dict[str, Any],
    validation_data: dict[str, Any],
) -> dict[str, Any]:
    case_inventory = (
        build_case_inventory(
            corpus
        )
    )

    supported = (
        join_supported_relations(
            relation_data,
            validation_data,
        )
    )

    bundles = (
        build_relation_bundles(
            supported
        )
    )

    cases = build_case_drafts(
        case_inventory=(
            case_inventory
        ),
        bundles=bundles,
    )

    positive_bundles = [
        row
        for row in bundles
        if row.get(
            "polarity"
        )
        == "risk"
    ]

    protective_bundles = [
        row
        for row in bundles
        if row.get(
            "polarity"
        )
        == "protective"
    ]

    hypotheses = [
        hypothesis
        for case in cases
        for hypothesis
        in case.get(
            "semantic_trigger_hypotheses",
            [],
        )
    ]

    exact_context_hypotheses = sum(
        1
        for row in hypotheses
        if row.get(
            "context_consensus_status"
        )
        == "exact"
    )

    partial_context_hypotheses = sum(
        1
        for row in hypotheses
        if row.get(
            "context_consensus_status"
        )
        == "partial"
    )

    divergent_context_hypotheses = sum(
        1
        for row in hypotheses
        if row.get(
            "context_consensus_status"
        )
        == "divergent"
    )

    case_with_hypothesis_count = sum(
        1
        for case in cases
        if case.get(
            "semantic_trigger_hypotheses"
        )
    )

    return {
        "schema_version":
            SCHEMA_VERSION,

        "compiler_version":
            COMPILER_VERSION,

        "status":
            "resolved",

        "source_mode":
            (
                "conservative_supported_"
                "semantic_relation_"
                "composition"
            ),

        "semantic_boundary": {
            "consumes_supported_semantic_relations":
                True,

            "requires_exact_cross_source_validation":
                True,

            "deduplicates_supported_fact_records_into_relation_signatures":
                True,

            "retains_context_consensus":
                True,

            "retains_protective_contrast":
                True,

            "protective_contrast_means_safe_alternative":
                False,

            "creates_semantic_trigger_hypotheses":
                True,

            "creates_executable_trigger_rules":
                False,

            "binds_version_scope":
                False,

            "uses_llm_semantic_inference":
                False,

            "consumes_trigger_raw_ground_truth":
                False,

            "all_hypotheses_require_review":
                True,
        },

        "input": {
            "semantic_relation_schema":
                relation_data.get(
                    "schema_version"
                ),

            "semantic_relation_extractor_version":
                relation_data.get(
                    "extractor_version"
                ),

            "validation_schema":
                validation_data.get(
                    "schema_version"
                ),

            "validation_validator_version":
                validation_data.get(
                    "validator_version"
                ),
        },

        "summary": {
            "case_count":
                len(
                    cases
                ),

            "supported_relation_fact_record_count":
                len(
                    supported
                ),

            "unique_supported_relation_signature_count":
                len(
                    bundles
                ),

            "positive_relation_signature_count":
                len(
                    positive_bundles
                ),

            "protective_relation_signature_count":
                len(
                    protective_bundles
                ),

            "case_with_trigger_hypothesis_count":
                case_with_hypothesis_count,

            "unresolved_case_count":
                (
                    len(
                        cases
                    )
                    - case_with_hypothesis_count
                ),

            "semantic_trigger_hypothesis_count":
                len(
                    hypotheses
                ),

            "exact_context_consensus_hypothesis_count":
                exact_context_hypotheses,

            "partial_context_consensus_hypothesis_count":
                partial_context_hypotheses,

            "divergent_context_consensus_hypothesis_count":
                divergent_context_hypotheses,

            "executable_rule_ready_count":
                sum(
                    1
                    for row in hypotheses
                    if row.get(
                        "executable_rule_ready"
                    )
                    is True
                ),
        },

        "supported_relation_bundles":
            bundles,

        "cases":
            cases,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Compile cross-source-supported "
            "semantic relations into "
            "conservative, review-required "
            "Trigger hypotheses."
        )
    )

    parser.add_argument(
        "--corpus",
        type=Path,
        default=DEFAULT_CORPUS,
    )

    parser.add_argument(
        "--relations",
        type=Path,
        default=DEFAULT_RELATIONS,
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

    result = compile_drafts(
        corpus=load_json(
            args.corpus
        ),
        relation_data=load_json(
            args.relations
        ),
        validation_data=load_json(
            args.validation
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
        "TRIGGER SEMANTIC DRAFT COMPILATION SUMMARY"
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
        "[OK] supported relation records:",
        summary.get(
            "supported_relation_fact_record_count"
        ),
    )

    print(
        "[OK] unique supported signatures:",
        summary.get(
            "unique_supported_relation_signature_count"
        ),
    )

    print(
        "[OK] positive signatures:",
        summary.get(
            "positive_relation_signature_count"
        ),
    )

    print(
        "[OK] protective signatures:",
        summary.get(
            "protective_relation_signature_count"
        ),
    )

    print(
        "[OK] cases with Trigger hypothesis:",
        summary.get(
            "case_with_trigger_hypothesis_count"
        ),
    )

    print(
        "[OK] semantic Trigger hypotheses:",
        summary.get(
            "semantic_trigger_hypothesis_count"
        ),
    )

    print(
        "[OK] exact context consensus:",
        summary.get(
            "exact_context_consensus_hypothesis_count"
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