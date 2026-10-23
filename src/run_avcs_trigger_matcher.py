from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

from evaluate_avcs_overlap import (
    call_uses_keyword,
    get_keyword_argument_symbol,
    match_conditional_trigger_rule,
    match_direct_trigger_rule,
    match_safe_api_rule,
)


SCHEMA_VERSION = (
    "avcs_executable_trigger_match_v0.1"
)

MATCHER_VERSION = (
    "avcs_executable_trigger_matcher_v0.1"
)


UNRESOLVED_REASONS = {
    "version_evidence_not_provided",
    "keyword_name_missing_from_rule",
    "required_call_symbol_missing_from_rule",
    "required_literal_missing_from_rule",
    "positional_argument_position_missing",
    "unsupported_url_condition",
    "producer_api_symbol_missing_from_rule",
    "producer_keyword_name_missing_from_rule",
    "producer_required_literal_missing_from_rule",
    "omission_requirement_not_enabled",
    "historical_default_missing",
    "unsupported_rule_kind",
    "safe_rule_incomplete",
}


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


def clean_text(
    value: Any,
) -> str:
    if value is None:
        return ""

    return str(
        value
    ).strip()


def normalize_exposed_versions(
    versions: list[str],
) -> list[dict[str, str]]:
    result = []

    seen = set()

    for version in versions:
        text = clean_text(
            version
        )

        if (
            not text
            or text in seen
        ):
            continue

        seen.add(
            text
        )

        result.append(
            {
                "version":
                    text,
            }
        )

    return result


def select_trigger_entry(
    evidence: dict[str, Any],
    distribution: str | None,
    vulnerability_id: str | None,
) -> dict[str, Any]:
    entries = evidence.get(
        "entries",
        [],
    )

    if not isinstance(
        entries,
        list,
    ):
        raise ValueError(
            "Trigger evidence field "
            "'entries' must be a list."
        )

    candidates = [
        row
        for row in entries
        if isinstance(
            row,
            dict,
        )
    ]

    if distribution:
        wanted_distribution = (
            distribution
            .strip()
            .lower()
        )

        candidates = [
            row
            for row in candidates
            if clean_text(
                row.get(
                    "normalized_distribution",
                    row.get(
                        "distribution"
                    ),
                )
            ).lower()
            == wanted_distribution
        ]

    if vulnerability_id:
        wanted_id = (
            vulnerability_id
            .strip()
            .lower()
        )

        candidates = [
            row
            for row in candidates
            if wanted_id
            in {
                clean_text(
                    value
                ).lower()
                for value
                in row.get(
                    "vulnerability_ids",
                    [],
                )
            }
        ]

    if len(
        candidates
    ) != 1:
        raise ValueError(
            "Expected exactly one Trigger Evidence "
            "entry after selection, got "
            f"{len(candidates)}."
        )

    return candidates[0]


def classify_match_result(
    result: dict[str, Any],
) -> str:
    if result.get(
        "matched"
    ) is True:
        return "matched"

    reason = clean_text(
        result.get(
            "reason"
        )
    )

    if (
        reason in UNRESOLVED_REASONS
        or "unresolved" in reason
        or "missing_from_rule" in reason
        or "star_kwargs" in reason
    ):
        return "unresolved"

    return "not_matched"


def classify_safe_result(
    *,
    call: dict[str, Any],
    rule: dict[str, Any],
    result: dict[str, Any],
) -> str:
    if result.get(
        "matched"
    ) is True:
        return "matched"

    reason = clean_text(
        result.get(
            "reason"
        )
    )

    if (
        reason in UNRESOLVED_REASONS
        or "unresolved" in reason
        or "star_kwargs" in reason
    ):
        return "unresolved"

    if (
        reason
        == "safe_keyword_symbol_not_matched"
    ):
        keyword_rule = rule.get(
            "keyword_argument",
            {},
        )

        if isinstance(
            keyword_rule,
            dict,
        ):
            keyword_name = clean_text(
                keyword_rule.get(
                    "name"
                )
            )

            if (
                keyword_name
                and call_uses_keyword(
                    call=call,
                    keyword_name=keyword_name,
                )
                and get_keyword_argument_symbol(
                    call=call,
                    keyword_name=keyword_name,
                )
                is None
            ):
                return "unresolved"

    return "not_matched"


def call_snapshot(
    call: dict[str, Any],
) -> dict[str, Any]:
    return {
        "api_symbol":
            call.get(
                "api_symbol"
            ),

        "call_text":
            call.get(
                "call_text"
            ),

        "location":
            call.get(
                "location",
                {},
            ),

        "call_shape":
            call.get(
                "call_shape",
                {},
            ),

        "receiver_provenance":
            call.get(
                "receiver_provenance",
                {},
            ),
    }


def no_call_evaluation(
    *,
    rule: dict[str, Any],
    rule_group: str,
) -> dict[str, Any]:
    return {
        "rule_group":
            rule_group,

        "trigger_id":
            rule.get(
                "trigger_id"
            ),

        "api_symbol":
            rule.get(
                "api_symbol"
            ),

        "kind":
            rule.get(
                "kind"
            ),

        "match_status":
            "not_matched",

        "reason":
            "api_symbol_not_observed",

        "call":
            None,

        "raw_match":
            {
                "matched":
                    False,

                "reason":
                    "api_symbol_not_observed",
            },
    }


def evaluate_trigger_rule(
    *,
    calls: list[dict[str, Any]],
    rule: dict[str, Any],
    rule_group: str,
    confirmed_exposed_releases: list[
        dict[str, str]
    ],
) -> list[dict[str, Any]]:
    api_symbol = clean_text(
        rule.get(
            "api_symbol"
        )
    )

    related_calls = [
        call
        for call in calls
        if clean_text(
            call.get(
                "api_symbol"
            )
        )
        == api_symbol
    ]

    if not related_calls:
        return [
            no_call_evaluation(
                rule=rule,
                rule_group=rule_group,
            )
        ]

    results = []

    version_scope = clean_text(
        rule.get(
            "version_scope"
        )
    )

    for call in related_calls:
        if (
            version_scope
            and not confirmed_exposed_releases
        ):
            raw_match = {
                "trigger_id":
                    rule.get(
                        "trigger_id"
                    ),

                "api_symbol":
                    api_symbol,

                "kind":
                    rule.get(
                        "kind"
                    ),

                "version_scope":
                    version_scope,

                "matched":
                    False,

                "reason":
                    "version_evidence_not_provided",

                "scoped_exposed_releases":
                    [],
            }

        elif (
            rule_group
            == "direct_rule"
        ):
            raw_match = (
                match_direct_trigger_rule(
                    call=call,
                    rule=rule,
                    confirmed_exposed_releases=(
                        confirmed_exposed_releases
                    ),
                )
            )

        else:
            raw_match = (
                match_conditional_trigger_rule(
                    call=call,
                    rule=rule,
                    confirmed_exposed_releases=(
                        confirmed_exposed_releases
                    ),
                )
            )

        match_status = (
            classify_match_result(
                raw_match
            )
        )

        results.append(
            {
                "rule_group":
                    rule_group,

                "trigger_id":
                    rule.get(
                        "trigger_id"
                    ),

                "api_symbol":
                    api_symbol,

                "kind":
                    rule.get(
                        "kind"
                    ),

                "match_status":
                    match_status,

                "reason":
                    raw_match.get(
                        "reason"
                    ),

                "call":
                    call_snapshot(
                        call
                    ),

                "raw_match":
                    raw_match,
            }
        )

    return results


def evaluate_safe_rule(
    *,
    calls: list[dict[str, Any]],
    rule: dict[str, Any],
) -> list[dict[str, Any]]:
    api_symbol = clean_text(
        rule.get(
            "api_symbol"
        )
    )

    related_calls = [
        call
        for call in calls
        if clean_text(
            call.get(
                "api_symbol"
            )
        )
        == api_symbol
    ]

    if not related_calls:
        return [
            {
                "rule_group":
                    "safe_rule",

                "api_symbol":
                    api_symbol,

                "match_status":
                    "not_matched",

                "reason":
                    "api_symbol_not_observed",

                "call":
                    None,

                "raw_match": {
                    "matched":
                        False,

                    "reason":
                        "api_symbol_not_observed",
                },
            }
        ]

    results = []

    for call in related_calls:
        raw_match = (
            match_safe_api_rule(
                call=call,
                rule=rule,
            )
        )

        results.append(
            {
                "rule_group":
                    "safe_rule",

                "api_symbol":
                    api_symbol,

                "match_status":
                    classify_safe_result(
                        call=call,
                        rule=rule,
                        result=raw_match,
                    ),

                "reason":
                    raw_match.get(
                        "reason"
                    ),

                "call":
                    call_snapshot(
                        call
                    ),

                "raw_match":
                    raw_match,
            }
        )

    return results


def match_trigger_entry(
    *,
    api_call_evidence: dict[str, Any],
    trigger_entry: dict[str, Any],
    confirmed_exposed_releases: list[
        dict[str, str]
    ],
) -> dict[str, Any]:
    parse_status = clean_text(
        api_call_evidence.get(
            "parse_status"
        )
    )

    calls = api_call_evidence.get(
        "api_calls",
        [],
    )

    if not isinstance(
        calls,
        list,
    ):
        calls = []

    calls = [
        row
        for row in calls
        if isinstance(
            row,
            dict,
        )
    ]

    trigger_conditions = (
        trigger_entry.get(
            "trigger_conditions",
            {},
        )
    )

    if not isinstance(
        trigger_conditions,
        dict,
    ):
        trigger_conditions = {}

    direct_rules = (
        trigger_conditions.get(
            "direct_api_rules",
            [],
        )
    )

    conditional_rules = (
        trigger_conditions.get(
            "conditional_api_rules",
            [],
        )
    )

    safe_rules = trigger_entry.get(
        "safe_api_rules",
        [],
    )

    safe_api_symbols = trigger_entry.get(
        "safe_api_symbols",
        [],
    )

    direct_rules = [
        row
        for row in direct_rules
        if isinstance(
            row,
            dict,
        )
    ]

    conditional_rules = [
        row
        for row in conditional_rules
        if isinstance(
            row,
            dict,
        )
    ]

    safe_rules = [
        row
        for row in safe_rules
        if isinstance(
            row,
            dict,
        )
    ]

    evaluations = []

    if parse_status != "ok":
        return {
            "schema_version":
                SCHEMA_VERSION,

            "matcher_version":
                MATCHER_VERSION,

            "sample_id":
                api_call_evidence.get(
                    "sample_id"
                ),

            "distribution":
                trigger_entry.get(
                    "normalized_distribution",
                    trigger_entry.get(
                        "distribution"
                    ),
                ),

            "vulnerability_ids":
                trigger_entry.get(
                    "vulnerability_ids",
                    [],
                ),

            "parse_status":
                parse_status,

            "trigger_rule_evaluations":
                [],

            "safe_evaluations":
                [],

            "summary": {
                "overall_trigger_status":
                    "unresolved",

                "reason":
                    "api_call_parse_not_ok",
            },
        }

    for rule in direct_rules:
        evaluations.extend(
            evaluate_trigger_rule(
                calls=calls,
                rule=rule,
                rule_group="direct_rule",
                confirmed_exposed_releases=(
                    confirmed_exposed_releases
                ),
            )
        )

    for rule in conditional_rules:
        evaluations.extend(
            evaluate_trigger_rule(
                calls=calls,
                rule=rule,
                rule_group="conditional_rule",
                confirmed_exposed_releases=(
                    confirmed_exposed_releases
                ),
            )
        )

    # Legacy direct API symbols remain supported only when
    # no explicit direct rules are available.
    if not direct_rules:
        legacy_symbols = sorted(
            {
                clean_text(
                    value
                )
                for value
                in trigger_conditions.get(
                    "api_symbols",
                    [],
                )
                if clean_text(
                    value
                )
            }
        )

        for symbol in legacy_symbols:
            related_calls = [
                call
                for call in calls
                if clean_text(
                    call.get(
                        "api_symbol"
                    )
                )
                == symbol
            ]

            if not related_calls:
                evaluations.append(
                    {
                        "rule_group":
                            "legacy_direct_api",

                        "api_symbol":
                            symbol,

                        "kind":
                            "legacy_direct_api",

                        "match_status":
                            "not_matched",

                        "reason":
                            "api_symbol_not_observed",

                        "call":
                            None,
                    }
                )

                continue

            for call in related_calls:
                evaluations.append(
                    {
                        "rule_group":
                            "legacy_direct_api",

                        "api_symbol":
                            symbol,

                        "kind":
                            "legacy_direct_api",

                        "match_status":
                            "matched",

                        "reason":
                            "legacy_direct_api_symbol_matched",

                        "call":
                            call_snapshot(
                                call
                            ),
                    }
                )

    safe_evaluations = []

    for rule in safe_rules:
        safe_evaluations.extend(
            evaluate_safe_rule(
                calls=calls,
                rule=rule,
            )
        )

    for symbol in sorted(
        {
            clean_text(
                value
            )
            for value
            in safe_api_symbols
            if clean_text(
                value
            )
        }
    ):
        related_calls = [
            call
            for call in calls
            if clean_text(
                call.get(
                    "api_symbol"
                )
            )
            == symbol
        ]

        safe_evaluations.append(
            {
                "rule_group":
                    "safe_direct_api",

                "api_symbol":
                    symbol,

                "match_status":
                    (
                        "matched"
                        if related_calls
                        else "not_matched"
                    ),

                "reason":
                    (
                        "safe_api_symbol_observed"
                        if related_calls
                        else "api_symbol_not_observed"
                    ),

                "calls":
                    [
                        call_snapshot(
                            call
                        )
                        for call in related_calls
                    ],
            }
        )

    trigger_status_counts = Counter(
        row.get(
            "match_status"
        )
        for row in evaluations
    )

    safe_status_counts = Counter(
        row.get(
            "match_status"
        )
        for row in safe_evaluations
    )

    if not evaluations:
        overall_status = "unresolved"
        overall_reason = (
            "no_executable_trigger_rule_available"
        )

    elif (
        trigger_status_counts.get(
            "matched",
            0,
        )
        > 0
    ):
        overall_status = "matched"
        overall_reason = (
            "at_least_one_trigger_rule_matched"
        )

    elif (
        trigger_status_counts.get(
            "unresolved",
            0,
        )
        > 0
    ):
        overall_status = "unresolved"
        overall_reason = (
            "trigger_rule_evaluation_unresolved"
        )

    else:
        overall_status = "not_matched"
        overall_reason = (
            "all_trigger_rule_evaluations_not_matched"
        )

    if (
        safe_status_counts.get(
            "matched",
            0,
        )
        > 0
    ):
        overall_safe_status = "matched"

    elif (
        safe_status_counts.get(
            "unresolved",
            0,
        )
        > 0
    ):
        overall_safe_status = "unresolved"

    else:
        overall_safe_status = "not_matched"

    return {
        "schema_version":
            SCHEMA_VERSION,

        "matcher_version":
            MATCHER_VERSION,

        "sample_id":
            api_call_evidence.get(
                "sample_id"
            ),

        "code_file":
            api_call_evidence.get(
                "code_file"
            ),

        "parse_status":
            parse_status,

        "distribution":
            trigger_entry.get(
                "normalized_distribution",
                trigger_entry.get(
                    "distribution"
                ),
            ),

        "vulnerability_ids":
            trigger_entry.get(
                "vulnerability_ids",
                [],
            ),

        "confirmed_exposed_releases":
            confirmed_exposed_releases,

        "trigger_rule_evaluations":
            evaluations,

        "safe_evaluations":
            safe_evaluations,

        "summary": {
            "api_call_count":
                len(
                    calls
                ),

            "trigger_rule_evaluation_count":
                len(
                    evaluations
                ),

            "matched_trigger_evaluation_count":
                trigger_status_counts.get(
                    "matched",
                    0,
                ),

            "not_matched_trigger_evaluation_count":
                trigger_status_counts.get(
                    "not_matched",
                    0,
                ),

            "unresolved_trigger_evaluation_count":
                trigger_status_counts.get(
                    "unresolved",
                    0,
                ),

            "overall_trigger_status":
                overall_status,

            "overall_trigger_reason":
                overall_reason,

            "safe_evaluation_count":
                len(
                    safe_evaluations
                ),

            "matched_safe_evaluation_count":
                safe_status_counts.get(
                    "matched",
                    0,
                ),

            "unresolved_safe_evaluation_count":
                safe_status_counts.get(
                    "unresolved",
                    0,
                ),

            "overall_safe_status":
                overall_safe_status,
        },

        "semantic_boundary": {
            "consumes_static_api_call_evidence":
                True,

            "executes_trigger_rules":
                True,

            "uses_llm_judgment":
                False,

            "performs_runtime_execution":
                False,

            "evaluates_taint_or_untrusted_input":
                False,

            "evaluates_environment_preconditions":
                False,

            "version_scope_uses_supplied_exposed_releases":
                True,

            "matched_trigger_is_full_exploit_proof":
                False,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Execute normalized AVCS Trigger rules "
            "against extracted Python API calls."
        )
    )

    parser.add_argument(
        "--api-calls",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--trigger-evidence",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--distribution",
    )

    parser.add_argument(
        "--vulnerability-id",
    )

    parser.add_argument(
        "--exposed-version",
        action="append",
        default=[],
    )

    parser.add_argument(
        "--out",
        required=True,
        type=Path,
    )

    args = parser.parse_args()

    api_calls = load_json(
        args.api_calls
    )

    trigger_evidence = load_json(
        args.trigger_evidence
    )

    trigger_entry = select_trigger_entry(
        evidence=trigger_evidence,
        distribution=args.distribution,
        vulnerability_id=args.vulnerability_id,
    )

    exposed_releases = (
        normalize_exposed_versions(
            args.exposed_version
        )
    )

    result = match_trigger_entry(
        api_call_evidence=api_calls,
        trigger_entry=trigger_entry,
        confirmed_exposed_releases=(
            exposed_releases
        ),
    )

    result[
        "inputs"
    ] = {
        "api_calls":
            str(
                args.api_calls
            ).replace(
                "\\",
                "/",
            ),

        "trigger_evidence":
            str(
                args.trigger_evidence
            ).replace(
                "\\",
                "/",
            ),

        "exposed_versions":
            args.exposed_version,
    }

    args.out.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    args.out.write_text(
        json.dumps(
            result,
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    summary = result.get(
        "summary",
        {},
    )

    print(
        "[OK] matcher:",
        MATCHER_VERSION,
    )

    print(
        "[OK] overall trigger status:",
        summary.get(
            "overall_trigger_status"
        ),
    )

    print(
        "[OK] matched:",
        summary.get(
            "matched_trigger_evaluation_count",
            0,
        ),
    )

    print(
        "[OK] not matched:",
        summary.get(
            "not_matched_trigger_evaluation_count",
            0,
        ),
    )

    print(
        "[OK] unresolved:",
        summary.get(
            "unresolved_trigger_evaluation_count",
            0,
        ),
    )

    print(
        "[OK] saved:",
        args.out,
    )


if __name__ == "__main__":
    main()
