from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

DEFAULT_FACTS = (
    ROOT / "output" / "avcs_trigger_candidate_facts_v0.json"
)
DEFAULT_VALIDATION = (
    ROOT / "output" / "avcs_trigger_candidate_fact_validation_v0.json"
)

EXPECTED_SCHEMA_VERSION = (
    "avcs_trigger_candidate_fact_validation_v0.1"
)
EXPECTED_VALIDATOR_VERSION = (
    "trigger_candidate_fact_validator_v0.1"
)

ALLOWED_STATUSES = {
    "supported",
    "rejected",
    "conflicted",
    "unresolved",
}

EXPECTED_CANDIDATE_FACT_COUNT = 833
EXPECTED_SUPPORTED_FACT_COUNT = 483
EXPECTED_REJECTED_FACT_COUNT = 0
EXPECTED_CONFLICTED_FACT_COUNT = 0
EXPECTED_UNRESOLVED_FACT_COUNT = 350

EXPECTED_RULE_COUNTS = {
    "authoritative_osv_structured_event": 20,
    "exact_cross_source_corroboration": 99,
    "insufficient_conservative_support": 350,
    "official_python_ast_with_cross_source_relevance": 364,
}


class CheckState:
    def __init__(self) -> None:
        self.passed = 0
        self.failed = 0
        self.failures: list[str] = []

    def check(
        self,
        condition: bool,
        label: str,
    ) -> None:
        if condition:
            self.passed += 1
            return

        self.failed += 1
        self.failures.append(label)


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


def rate(
    numerator: int,
    denominator: int,
) -> float:
    if denominator <= 0:
        return 0.0

    return round(
        numerator / denominator,
        6,
    )


def normalized_ids(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
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


def evidence_group_key(
    row: dict[str, Any],
) -> tuple[str, tuple[str, ...]]:
    return (
        clean_text(
            row.get("distribution")
        ).lower(),
        normalized_ids(
            row.get("vulnerability_ids")
        ),
    )


def stable_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def nested_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value

    return {}


def check_rule_semantics(
    state: CheckState,
    facts: list[dict[str, Any]],
    records: list[dict[str, Any]],
) -> None:
    fact_index = {
        clean_text(fact.get("fact_id")): fact
        for fact in facts
        if clean_text(fact.get("fact_id"))
    }

    supported_rules = {
        "authoritative_osv_structured_event",
        "official_python_ast_with_cross_source_relevance",
        "text_fixed_version_corroborated_by_osv",
        "exact_cross_source_corroboration",
    }

    for index, record in enumerate(records):
        prefix = f"semantic_record[{index}]"

        fact_id = clean_text(
            record.get("fact_id")
        )

        fact = fact_index.get(fact_id)

        state.check(
            fact is not None,
            f"{prefix}::fact_exists",
        )

        if fact is None:
            continue

        status = clean_text(
            record.get("validation_status")
        )

        rule = clean_text(
            record.get("validation_rule")
        )

        if status == "supported":
            state.check(
                rule in supported_rules,
                f"{prefix}::supported_rule_allowed",
            )

        if rule == "authoritative_osv_structured_event":
            fact_kind = clean_text(
                fact.get("fact_kind")
            )

            state.check(
                fact_kind.startswith("osv_")
                and fact_kind.endswith(
                    "_version_candidate"
                ),
                f"{prefix}::osv_fact_kind",
            )

            state.check(
                clean_text(
                    fact.get(
                        "extraction_method"
                    )
                )
                == "structured_osv_range_event",
                f"{prefix}::osv_extraction_method",
            )

            state.check(
                clean_text(
                    fact.get("unit_kind")
                )
                == "structured_json_record",
                f"{prefix}::osv_unit_kind",
            )

            state.check(
                clean_text(
                    fact.get(
                        "confidence_level"
                    )
                )
                == "high",
                f"{prefix}::osv_confidence_high",
            )

        elif (
            rule
            == "official_python_ast_with_cross_source_relevance"
        ):
            state.check(
                clean_text(
                    fact.get("fact_kind")
                ).startswith("python_"),
                f"{prefix}::python_fact_kind",
            )

            state.check(
                clean_text(
                    fact.get("source_type")
                )
                == "upstream_release_source",
                f"{prefix}::python_upstream_source",
            )

            state.check(
                clean_text(
                    fact.get("unit_kind")
                )
                == "github_source_file_text",
                f"{prefix}::python_source_unit",
            )

            state.check(
                clean_text(
                    fact.get(
                        "extraction_method"
                    )
                ).startswith("python_ast_"),
                f"{prefix}::python_ast_method",
            )

            gate = nested_dict(
                fact.get("relevance_gate")
            )

            state.check(
                gate.get("status")
                == "supported",
                f"{prefix}::python_gate_supported",
            )

            state.check(
                gate.get(
                    "support_is_cross_source"
                )
                is True,
                f"{prefix}::python_cross_source",
            )

            support_ids = gate.get(
                "supporting_evidence_unit_ids",
                [],
            )

            state.check(
                isinstance(support_ids, list)
                and len(support_ids) > 0,
                f"{prefix}::python_support_present",
            )

        elif rule == "exact_cross_source_corroboration":
            support_fact_ids = record.get(
                "supporting_fact_ids",
                [],
            )

            state.check(
                isinstance(
                    support_fact_ids,
                    list,
                )
                and len(
                    support_fact_ids
                )
                > 0,
                f"{prefix}::cross_source_support_present",
            )

            if not isinstance(
                support_fact_ids,
                list,
            ):
                continue

            for support_fact_id in support_fact_ids:
                peer = fact_index.get(
                    clean_text(
                        support_fact_id
                    )
                )

                state.check(
                    peer is not None,
                    (
                        f"{prefix}::peer_exists::"
                        f"{support_fact_id}"
                    ),
                )

                if peer is None:
                    continue

                state.check(
                    evidence_group_key(peer)
                    == evidence_group_key(fact),
                    (
                        f"{prefix}::peer_same_group::"
                        f"{support_fact_id}"
                    ),
                )

                state.check(
                    clean_text(
                        peer.get("fact_kind")
                    )
                    == clean_text(
                        fact.get("fact_kind")
                    ),
                    (
                        f"{prefix}::peer_same_kind::"
                        f"{support_fact_id}"
                    ),
                )

                state.check(
                    stable_json(
                        peer.get(
                            "structured_value"
                        )
                    )
                    == stable_json(
                        fact.get(
                            "structured_value"
                        )
                    ),
                    (
                        f"{prefix}::peer_same_value::"
                        f"{support_fact_id}"
                    ),
                )

                state.check(
                    clean_text(
                        peer.get("source_key")
                    )
                    != clean_text(
                        fact.get("source_key")
                    ),
                    (
                        f"{prefix}::peer_different_source::"
                        f"{support_fact_id}"
                    ),
                )

                state.check(
                    clean_text(
                        peer.get("source_type")
                    )
                    != clean_text(
                        fact.get("source_type")
                    ),
                    (
                        f"{prefix}::peer_different_type::"
                        f"{support_fact_id}"
                    ),
                )

        elif (
            rule
            == "text_fixed_version_corroborated_by_osv"
        ):
            support_fact_ids = record.get(
                "supporting_fact_ids",
                [],
            )

            state.check(
                isinstance(
                    support_fact_ids,
                    list,
                )
                and len(
                    support_fact_ids
                )
                > 0,
                f"{prefix}::fixed_support_present",
            )

            for support_fact_id in (
                support_fact_ids
                if isinstance(
                    support_fact_ids,
                    list,
                )
                else []
            ):
                peer = fact_index.get(
                    clean_text(
                        support_fact_id
                    )
                )

                state.check(
                    peer is not None,
                    (
                        f"{prefix}::fixed_peer_exists::"
                        f"{support_fact_id}"
                    ),
                )

                if peer is None:
                    continue

                state.check(
                    clean_text(
                        peer.get("fact_kind")
                    )
                    == "osv_fixed_version_candidate",
                    (
                        f"{prefix}::fixed_peer_is_osv::"
                        f"{support_fact_id}"
                    ),
                )

        elif rule == "insufficient_conservative_support":
            state.check(
                status == "unresolved",
                f"{prefix}::insufficient_is_unresolved",
            )

            state.check(
                record.get(
                    "review_required"
                )
                is True,
                f"{prefix}::insufficient_requires_review",
            )

        elif rule == "provenance_integrity_failure":
            state.check(
                status == "rejected",
                f"{prefix}::provenance_is_rejected",
            )

            issues = record.get(
                "issues",
                [],
            )

            state.check(
                isinstance(issues, list)
                and len(issues) > 0,
                f"{prefix}::provenance_issues_present",
            )


def check_key_case_validation(
    state: CheckState,
    facts: list[dict[str, Any]],
    records: list[dict[str, Any]],
) -> None:
    record_index = {
        clean_text(
            record.get("fact_id")
        ): record
        for record in records
    }

    def sv(
        fact: dict[str, Any],
    ) -> dict[str, Any]:
        return nested_dict(
            fact.get("structured_value")
        )

    def argument(
        fact: dict[str, Any],
    ) -> dict[str, Any]:
        return nested_dict(
            sv(fact).get(
                "argument_value"
            )
        )

    def default(
        fact: dict[str, Any],
    ) -> dict[str, Any]:
        return nested_dict(
            sv(fact).get("default")
        )

    def check_supported(
        predicate: Any,
        label: str,
    ) -> None:
        matches = [
            fact
            for fact in facts
            if predicate(fact)
        ]

        state.check(
            len(matches) > 0,
            f"{label}::fact_present",
        )

        supported = any(
            clean_text(
                record_index.get(
                    clean_text(
                        fact.get("fact_id")
                    ),
                    {},
                ).get(
                    "validation_status"
                )
            )
            == "supported"
            for fact in matches
        )

        state.check(
            supported,
            f"{label}::supported",
        )

    def check_unresolved(
        predicate: Any,
        label: str,
    ) -> None:
        matches = [
            fact
            for fact in facts
            if predicate(fact)
        ]

        state.check(
            len(matches) > 0,
            f"{label}::fact_present",
        )

        unresolved = any(
            clean_text(
                record_index.get(
                    clean_text(
                        fact.get("fact_id")
                    ),
                    {},
                ).get(
                    "validation_status"
                )
            )
            == "unresolved"
            and record_index.get(
                clean_text(
                    fact.get("fact_id")
                ),
                {},
            ).get(
                "review_required"
            )
            is True
            for fact in matches
        )

        state.check(
            unresolved,
            f"{label}::conservatively_unresolved",
        )

    # NumPy historical default genuinely changes by release.
    # Both facts should be supported rather than incorrectly
    # treated as a cross-version conflict.
    check_supported(
        lambda fact: (
            clean_text(
                fact.get("distribution")
            ).lower()
            == "numpy"
            and fact.get("fact_kind")
            == "python_parameter_default_candidate"
            and sv(fact).get(
                "function_symbol"
            )
            == "load"
            and sv(fact).get(
                "parameter_name"
            )
            == "allow_pickle"
            and default(fact).get("value")
            is True
            and "1_16_2"
            in clean_text(
                fact.get("source_key")
            )
        ),
        "key_case::numpy_allow_pickle_true",
    )

    check_supported(
        lambda fact: (
            clean_text(
                fact.get("distribution")
            ).lower()
            == "numpy"
            and fact.get("fact_kind")
            == "python_parameter_default_candidate"
            and sv(fact).get(
                "function_symbol"
            )
            == "load"
            and sv(fact).get(
                "parameter_name"
            )
            == "allow_pickle"
            and default(fact).get("value")
            is False
            and "1_16_3"
            in clean_text(
                fact.get("source_key")
            )
        ),
        "key_case::numpy_allow_pickle_false",
    )

    check_unresolved(
        lambda fact: (
            clean_text(
                fact.get("distribution")
            ).lower()
            == "aiohttp"
            and fact.get("fact_kind")
            == "text_assignment_literal_candidate"
            and sv(fact).get("name")
            == "follow_symlinks"
            and sv(fact).get("literal")
            is True
        ),
        "key_case::aiohttp_follow_symlinks_true",
    )

    check_supported(
        lambda fact: (
            clean_text(
                fact.get("distribution")
            ).lower()
            == "pyjwt"
            and fact.get("fact_kind")
            == "code_expression_keyword_call_candidate"
            and sv(fact).get(
                "call_symbol"
            )
            == "jwt.decode"
            and sv(fact).get(
                "keyword_name"
            )
            == "algorithms"
            and argument(fact).get(
                "call_symbol"
            )
            == (
                "jwt.algorithms."
                "get_default_algorithms"
            )
        ),
        "key_case::pyjwt_algorithms_call",
    )

    check_unresolved(
        lambda fact: (
            clean_text(
                fact.get("distribution")
            ).lower()
            == "pyyaml"
            and fact.get("fact_kind")
            == "code_expression_positional_symbol_candidate"
            and sv(fact).get(
                "call_symbol"
            )
            == "yaml.load"
            and sv(fact).get(
                "position"
            )
            == 1
            and argument(fact).get(
                "symbol"
            )
            == "yaml.FullLoader"
        ),
        "key_case::pyyaml_fullloader",
    )

    check_supported(
        lambda fact: (
            clean_text(
                fact.get("distribution")
            ).lower()
            == "urllib3"
            and fact.get("fact_kind")
            == "code_expression_keyword_literal_candidate"
            and sv(fact).get(
                "call_symbol"
            )
            == "urllib3.PoolManager"
            and sv(fact).get(
                "keyword_name"
            )
            == "retries"
            and argument(fact).get(
                "value"
            )
            == 0
        ),
        "key_case::urllib3_retries_zero",
    )

    check_supported(
        lambda fact: (
            clean_text(
                fact.get("distribution")
            ).lower()
            == "urllib3"
            and fact.get("fact_kind")
            == "code_expression_keyword_literal_candidate"
            and sv(fact).get(
                "call_symbol"
            )
            == "urllib3.PoolManager"
            and sv(fact).get(
                "keyword_name"
            )
            == "retries"
            and argument(fact).get(
                "value"
            )
            is False
        ),
        "key_case::urllib3_retries_false",
    )

    check_supported(
        lambda fact: (
            clean_text(
                fact.get("distribution")
            ).lower()
            == "requests"
            and fact.get("fact_kind")
            == "python_parameter_default_candidate"
            and sv(fact).get(
                "function_symbol"
            )
            == "resolve_proxies"
            and sv(fact).get(
                "parameter_name"
            )
            == "trust_env"
            and default(fact).get(
                "value"
            )
            is True
        ),
        "key_case::requests_trust_env_true",
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Validate conservative AVCS "
            "candidate fact validation v0."
        )
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

    candidate_data = load_json(
        args.facts
    )
    validation_data = load_json(
        args.validation
    )

    facts = dict_rows(
        candidate_data.get("facts")
    )
    records = dict_rows(
        validation_data.get(
            "validation_records"
        )
    )

    state = CheckState()

    state.check(
        validation_data.get(
            "schema_version"
        )
        == EXPECTED_SCHEMA_VERSION,
        "schema_version",
    )

    state.check(
        validation_data.get(
            "validator_version"
        )
        == EXPECTED_VALIDATOR_VERSION,
        "validator_version",
    )

    state.check(
        validation_data.get(
            "status"
        )
        == "resolved",
        "status_resolved",
    )

    boundary = validation_data.get(
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
            "uses_llm_semantic_inference"
        )
        is False,
        "boundary::no_llm_semantic_inference",
    )

    state.check(
        boundary.get(
            "modifies_candidate_fact_artifact"
        )
        is False,
        "boundary::candidate_artifact_immutable",
    )

    state.check(
        boundary.get(
            "creates_resolved_trigger_rules"
        )
        is False,
        "boundary::no_trigger_rule_creation",
    )

    state.check(
        boundary.get(
            "supported_means_atomic_fact_support"
        )
        is True,
        "boundary::atomic_fact_support",
    )

    state.check(
        boundary.get(
            "supported_means_trigger_semantics"
        )
        is False,
        "boundary::not_trigger_semantics",
    )

    state.check(
        len(records)
        == len(facts),
        "record_count_matches_candidate_count",
    )

    fact_ids = {
        clean_text(
            fact.get("fact_id")
        )
        for fact in facts
    }

    record_ids = [
        clean_text(
            record.get("fact_id")
        )
        for record in records
    ]

    state.check(
        len(record_ids)
        == len(set(record_ids)),
        "validation_fact_ids_unique",
    )

    state.check(
        set(record_ids)
        == fact_ids,
        "validation_fact_ids_match_candidates",
    )

    total = len(records)

    status_counter: Counter[str] = Counter()
    rule_counter: Counter[str] = Counter()

    automatic_decision_count = 0
    review_required_count = 0

    for index, record in enumerate(
        records
    ):
        prefix = f"record[{index}]"

        status = clean_text(
            record.get(
                "validation_status"
            )
        )

        state.check(
            status in ALLOWED_STATUSES,
            f"{prefix}::status_allowed",
        )

        review_required = record.get(
            "review_required"
        )

        state.check(
            isinstance(
                review_required,
                bool,
            ),
            f"{prefix}::review_required_bool",
        )

        automatic_decision = (
            record.get(
                "automatic_decision"
            )
        )

        expected_automatic = (
            status
            in {
                "supported",
                "rejected",
            }
            and review_required is False
        )

        state.check(
            automatic_decision
            is expected_automatic,
            f"{prefix}::automatic_decision_policy",
        )

        if status in {
            "conflicted",
            "unresolved",
        }:
            state.check(
                review_required is True,
                f"{prefix}::uncertain_requires_review",
            )

        if status in {
            "supported",
            "rejected",
        }:
            state.check(
                review_required is False,
                f"{prefix}::resolved_no_semantic_review",
            )

        state.check(
            bool(
                clean_text(
                    record.get(
                        "validation_rule"
                    )
                )
            ),
            f"{prefix}::rule_present",
        )

        state.check(
            bool(
                clean_text(
                    record.get(
                        "validation_basis"
                    )
                )
            ),
            f"{prefix}::basis_present",
        )

        status_counter[status] += 1

        rule_counter[
            clean_text(
                record.get(
                    "validation_rule"
                )
            )
        ] += 1

        if automatic_decision is True:
            automatic_decision_count += 1

        if review_required is True:
            review_required_count += 1

    summary = validation_data.get(
        "summary",
        {},
    )

    state.check(
        total
        == EXPECTED_CANDIDATE_FACT_COUNT,
        "baseline::candidate_fact_count",
    )

    state.check(
        status_counter["supported"]
        == EXPECTED_SUPPORTED_FACT_COUNT,
        "baseline::supported_fact_count",
    )

    state.check(
        status_counter["rejected"]
        == EXPECTED_REJECTED_FACT_COUNT,
        "baseline::rejected_fact_count",
    )

    state.check(
        status_counter["conflicted"]
        == EXPECTED_CONFLICTED_FACT_COUNT,
        "baseline::conflicted_fact_count",
    )

    state.check(
        status_counter["unresolved"]
        == EXPECTED_UNRESOLVED_FACT_COUNT,
        "baseline::unresolved_fact_count",
    )

    state.check(
        dict(
            sorted(
                rule_counter.items()
            )
        )
        == EXPECTED_RULE_COUNTS,
        "baseline::validation_rule_counts",
    )

    if not isinstance(
        summary,
        dict,
    ):
        summary = {}

    state.check(
        summary.get(
            "candidate_fact_count"
        )
        == total,
        "summary::candidate_fact_count",
    )

    for status in sorted(
        ALLOWED_STATUSES
    ):
        state.check(
            summary.get(
                f"{status}_fact_count"
            )
            == status_counter[status],
            (
                "summary::"
                f"{status}_fact_count"
            ),
        )

    state.check(
        summary.get(
            "automatic_decision_count"
        )
        == automatic_decision_count,
        "summary::automatic_decision_count",
    )

    state.check(
        summary.get(
            "review_required_fact_count"
        )
        == review_required_count,
        "summary::review_required_fact_count",
    )

    state.check(
        summary.get(
            "automatic_decision_rate"
        )
        == rate(
            automatic_decision_count,
            total,
        ),
        "summary::automatic_decision_rate",
    )

    state.check(
        summary.get(
            "manual_review_rate"
        )
        == rate(
            review_required_count,
            total,
        ),
        "summary::manual_review_rate",
    )

    state.check(
        summary.get(
            "validation_status_counts"
        )
        == dict(
            sorted(
                status_counter.items()
            )
        ),
        "summary::status_counts",
    )

    state.check(
        summary.get(
            "validation_rule_counts"
        )
        == dict(
            sorted(
                rule_counter.items()
            )
        ),
        "summary::rule_counts",
    )

    state.check(
        status_counter["supported"]
        > 0,
        "supported_facts_present",
    )

    state.check(
        status_counter["unresolved"]
        > 0,
        "unresolved_facts_present",
    )

    check_rule_semantics(
        state,
        facts,
        records,
    )

    check_key_case_validation(
        state,
        facts,
        records,
    )

    input_text = json.dumps(
        validation_data.get(
            "input",
            {},
        ),
        ensure_ascii=False,
    ).lower()

    state.check(
        "trigger_raw" not in input_text,
        "input_does_not_reference_trigger_raw",
    )

    print("=" * 60)
    print(
        "AVCS TRIGGER CANDIDATE FACT VALIDATION CHECK"
    )
    print("=" * 60)
    print(
        "[INFO] candidate facts:",
        len(facts),
    )
    print(
        "[INFO] validation records:",
        len(records),
    )
    print(
        "[INFO] supported:",
        status_counter["supported"],
    )
    print(
        "[INFO] rejected:",
        status_counter["rejected"],
    )
    print(
        "[INFO] conflicted:",
        status_counter["conflicted"],
    )
    print(
        "[INFO] unresolved:",
        status_counter["unresolved"],
    )
    print(
        "[INFO] checks passed:",
        state.passed,
    )
    print(
        "[INFO] checks failed:",
        state.failed,
    )

    if state.failures:
        print("")
        print("[FAIL] failed checks:")

        for failure in state.failures:
            print("  -", failure)

        sys.exit(1)

    print("[OK] ALL CHECKS PASS")


if __name__ == "__main__":
    main()