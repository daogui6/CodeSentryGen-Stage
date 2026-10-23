from __future__ import annotations

import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

TARGET_DISTRIBUTION = "pyjwt"

TARGET_API_SYMBOL = "jwt.decode"

TARGET_PARAMETER = "algorithms"

TARGET_RULE_ID = (
    "pyjwt_decode_algorithms_keyword"
)

NESTED_API_SYMBOL = (
    "jwt.algorithms.get_default_algorithms"
)

NESTED_RULE_ID = (
    "pyjwt_get_default_algorithms_zero_arg"
)

EXPECTED_SPECIFIER = ">=1.0.0"


def read_json(
    path: Path,
) -> dict[str, Any]:
    return json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )


def check(
    name: str,
    expected: Any,
    actual: Any,
) -> bool:
    passed = (
        expected == actual
    )

    status = (
        "PASS"
        if passed
        else "FAIL"
    )

    print(
        f"[{status}] {name} | "
        f"expected={expected!r} | "
        f"actual={actual!r}"
    )

    return passed


def check_true(
    name: str,
    actual: Any,
) -> bool:
    return check(
        name=name,
        expected=True,
        actual=bool(actual),
    )


def find_entry(
    history: dict[str, Any],
    api_symbol: str,
) -> dict[str, Any]:
    entries = history.get(
        "entries",
        [],
    )

    if not isinstance(
        entries,
        list,
    ):
        return {}

    for entry in entries:
        if not isinstance(
            entry,
            dict,
        ):
            continue

        if (
            entry.get(
                "api_symbol"
            )
            == api_symbol
        ):
            return entry

    return {}


def find_rule(
    entry: dict[str, Any],
    rule_id: str,
) -> dict[str, Any]:
    rules = entry.get(
        "version_rules",
        [],
    )

    if not isinstance(
        rules,
        list,
    ):
        return {}

    for rule in rules:
        if not isinstance(
            rule,
            dict,
        ):
            continue

        if (
            rule.get(
                "rule_id"
            )
            == rule_id
        ):
            return rule

    return {}


def find_call_constraint(
    constraints: dict[str, Any],
    api_symbol: str,
) -> dict[str, Any]:
    rows = constraints.get(
        "call_constraints",
        [],
    )

    if not isinstance(
        rows,
        list,
    ):
        return {}

    for row in rows:
        if not isinstance(
            row,
            dict,
        ):
            continue

        if (
            row.get(
                "api_symbol"
            )
            == api_symbol
        ):
            return row

    return {}


def find_distribution_constraint(
    constraints: dict[str, Any],
    normalized_distribution: str,
) -> dict[str, Any]:
    rows = constraints.get(
        "distribution_constraints",
        [],
    )

    if not isinstance(
        rows,
        list,
    ):
        return {}

    for row in rows:
        if not isinstance(
            row,
            dict,
        ):
            continue

        if (
            row.get(
                "normalized_distribution"
            )
            == normalized_distribution
        ):
            return row

    return {}


def main() -> None:
    batch = read_json(
        ROOT
        / "output"
        / (
            "avcs_pyjwt_jwt_decode_"
            "api_release_history_"
            "full_stable_v0.json"
        )
    )

    refined = read_json(
        ROOT
        / "output"
        / (
            "avcs_pyjwt_jwt_decode_"
            "api_release_history_"
            "refined_full_stable_v0.json"
        )
    )

    candidate = read_json(
        ROOT
        / "output"
        / (
            "avcs_pyjwt_jwt_decode_"
            "api_history_candidate_"
            "full_stable_v0.json"
        )
    )

    base_history = read_json(
        ROOT
        / "data"
        / "avcs_validation"
        / "api_history"
        / "pyjwt_api_history_evidence_v0.json"
    )

    automatic_history = read_json(
        ROOT
        / "output"
        / (
            "avcs_pyjwt_api_history_"
            "evidence_auto_v0.json"
        )
    )

    constraints = read_json(
        ROOT
        / "output"
        / (
            "avcs_pyjwt_api_constraints_"
            "auto_history_v0.json"
        )
    )

    results: list[bool] = []

    # ========================================================
    # Layer 1:
    # Full stable release acquisition
    # ========================================================

    selected_release_count = int(
        batch.get(
            "selected_release_count",
            0,
        )
        or 0
    )

    source_resolved_count = int(
        batch.get(
            "source_index_resolved_count",
            0,
        )
        or 0
    )

    source_error_count = int(
        batch.get(
            "source_index_error_count",
            0,
        )
        or 0
    )

    public_resolved_count = int(
        batch.get(
            "public_symbol_resolved_count",
            0,
        )
        or 0
    )

    public_unresolved_count = int(
        batch.get(
            "public_symbol_unresolved_count",
            0,
        )
        or 0
    )

    public_error_count = int(
        batch.get(
            "public_symbol_error_count",
            0,
        )
        or 0
    )

    public_blocked_count = int(
        batch.get(
            "public_symbol_blocked_count",
            0,
        )
        or 0
    )

    results.extend(
        [
            check(
                "release batch schema",
                (
                    "avcs_python_api_"
                    "release_history_v0.1"
                ),
                batch.get(
                    "schema_version"
                ),
            ),

            check(
                "release batch distribution",
                "PyJWT",
                batch.get(
                    "distribution"
                ),
            ),

            check(
                "release batch API symbol",
                TARGET_API_SYMBOL,
                batch.get(
                    "api_symbol"
                ),
            ),

            check_true(
                "release batch is non-empty",
                selected_release_count > 0,
            ),

            check(
                "all selected releases have source indexes",
                selected_release_count,
                source_resolved_count,
            ),

            check(
                "source index errors",
                0,
                source_error_count,
            ),

            check(
                "all selected releases resolve public symbol",
                selected_release_count,
                public_resolved_count,
            ),

            check(
                "public symbol unresolved",
                0,
                public_unresolved_count,
            ),

            check(
                "public symbol errors",
                0,
                public_error_count,
            ),

            check(
                "public symbol blocked",
                0,
                public_blocked_count,
            ),
        ]
    )

    # ========================================================
    # Layer 2:
    # Release compatibility refinement
    # ========================================================

    refined_release_count = int(
        refined.get(
            "release_count",
            0,
        )
        or 0
    )

    supported_count = int(
        refined.get(
            "supported_count",
            0,
        )
        or 0
    )

    unsupported_count = int(
        refined.get(
            "unsupported_count",
            0,
        )
        or 0
    )

    unknown_count = int(
        refined.get(
            "unknown_count",
            0,
        )
        or 0
    )

    signature_only_count = int(
        refined.get(
            "signature_only_count",
            0,
        )
        or 0
    )

    forwarding_attempt_count = int(
        refined.get(
            "keyword_forwarding_attempt_count",
            0,
        )
        or 0
    )

    forwarding_resolved_count = int(
        refined.get(
            "keyword_forwarding_resolved_count",
            0,
        )
        or 0
    )

    results.extend(
        [
            check(
                "refined history schema",
                (
                    "avcs_python_api_"
                    "release_history_refined_v0.1"
                ),
                refined.get(
                    "schema_version"
                ),
            ),

            check(
                "refined release count matches batch",
                selected_release_count,
                refined_release_count,
            ),

            check(
                "support states cover every release",
                refined_release_count,
                (
                    supported_count
                    + unsupported_count
                    + unknown_count
                ),
            ),

            check_true(
                "refined history has supported releases",
                supported_count > 0,
            ),

            check_true(
                "refined history has unsupported releases",
                unsupported_count > 0,
            ),

            check(
                "refined history unknown releases",
                0,
                unknown_count,
            ),

            check(
                "all forwarding attempts resolve",
                forwarding_attempt_count,
                forwarding_resolved_count,
            ),

            check(
                "signature and forwarding paths cover releases",
                refined_release_count,
                (
                    signature_only_count
                    + forwarding_attempt_count
                ),
            ),
        ]
    )

    # ========================================================
    # Layer 3:
    # Full-history candidate
    # ========================================================

    coverage = candidate.get(
        "coverage",
        {},
    )

    if not isinstance(
        coverage,
        dict,
    ):
        coverage = {}

    lower_bound = candidate.get(
        "lower_bound_candidate",
        {},
    )

    if not isinstance(
        lower_bound,
        dict,
    ):
        lower_bound = {}

    transitions = candidate.get(
        "transitions",
        [],
    )

    if not isinstance(
        transitions,
        list,
    ):
        transitions = []

    transition = (
        transitions[0]
        if len(transitions) == 1
        and isinstance(
            transitions[0],
            dict,
        )
        else {}
    )

    results.extend(
        [
            check(
                "candidate schema",
                (
                    "avcs_python_api_"
                    "release_history_candidate_v0.1"
                ),
                candidate.get(
                    "schema_version"
                ),
            ),

            check(
                "candidate release count",
                refined_release_count,
                candidate.get(
                    "release_count"
                ),
            ),

            check(
                "candidate supported count",
                supported_count,
                candidate.get(
                    "supported_count"
                ),
            ),

            check(
                "candidate unsupported count",
                unsupported_count,
                candidate.get(
                    "unsupported_count"
                ),
            ),

            check(
                "candidate unknown count",
                0,
                candidate.get(
                    "unknown_count"
                ),
            ),

            check(
                "candidate coverage status",
                "complete",
                coverage.get(
                    "coverage_status"
                ),
            ),

            check(
                "candidate coverage complete",
                True,
                coverage.get(
                    "coverage_complete"
                ),
            ),

            check(
                "candidate coverage scope",
                "all_confirmed_stable_releases",
                coverage.get(
                    "coverage_scope"
                ),
            ),

            check(
                "coverage selected release count",
                refined_release_count,
                coverage.get(
                    "selected_release_count"
                ),
            ),

            check(
                "coverage expected release count",
                refined_release_count,
                coverage.get(
                    "expected_release_count"
                ),
            ),

            check(
                "candidate scope",
                "stable_release_history_candidate",
                candidate.get(
                    "candidate_scope"
                ),
            ),

            check(
                "lower-bound status",
                "candidate",
                lower_bound.get(
                    "status"
                ),
            ),

            check(
                "lower-bound specifier",
                EXPECTED_SPECIFIER,
                lower_bound.get(
                    "version_specifier"
                ),
            ),

            check(
                "lower-bound boundary",
                "1.0.0",
                lower_bound.get(
                    "boundary_version"
                ),
            ),

            check(
                "support transition count",
                1,
                candidate.get(
                    "support_transition_count"
                ),
            ),

            check(
                "transition list count",
                1,
                len(
                    transitions
                ),
            ),

            check(
                "transition from version",
                "0.4.3",
                transition.get(
                    "from_version"
                ),
            ),

            check(
                "transition to version",
                "1.0.0",
                transition.get(
                    "to_version"
                ),
            ),

            check(
                "transition from state",
                "unsupported",
                transition.get(
                    "from_support_status"
                ),
            ),

            check(
                "transition to state",
                "supported",
                transition.get(
                    "to_support_status"
                ),
            ),
        ]
    )

    # ========================================================
    # Layer 4:
    # Candidate -> existing API History schema
    # ========================================================

    base_decode_entry = find_entry(
        base_history,
        TARGET_API_SYMBOL,
    )

    automatic_decode_entry = find_entry(
        automatic_history,
        TARGET_API_SYMBOL,
    )

    base_decode_rule = find_rule(
        base_decode_entry,
        TARGET_RULE_ID,
    )

    automatic_decode_rule = find_rule(
        automatic_decode_entry,
        TARGET_RULE_ID,
    )

    base_nested_entry = find_entry(
        base_history,
        NESTED_API_SYMBOL,
    )

    automatic_nested_entry = find_entry(
        automatic_history,
        NESTED_API_SYMBOL,
    )

    automatic_nested_rule = find_rule(
        automatic_nested_entry,
        NESTED_RULE_ID,
    )

    compilation = automatic_history.get(
        "automatic_compilation",
        {},
    )

    if not isinstance(
        compilation,
        dict,
    ):
        compilation = {}

    results.extend(
        [
            check(
                "automatic history schema preserved",
                "avcs_api_history_evidence_v0.1",
                automatic_history.get(
                    "schema_version"
                ),
            ),

            check(
                "automatic history source mode",
                (
                    "mixed_curated_and_"
                    "automatic_release_history"
                ),
                automatic_history.get(
                    "source_mode"
                ),
            ),

            check(
                "history entry count preserved",
                len(
                    base_history.get(
                        "entries",
                        [],
                    )
                ),
                len(
                    automatic_history.get(
                        "entries",
                        [],
                    )
                ),
            ),

            check_true(
                "target decode rule preserved",
                bool(
                    automatic_decode_rule
                ),
            ),

            check(
                "decode rule compiled specifier",
                EXPECTED_SPECIFIER,
                automatic_decode_rule.get(
                    "version_specifier"
                ),
            ),

            check(
                "decode rule evidence is automatic",
                (
                    "automatic_release_"
                    "history_evidence"
                ),
                automatic_decode_rule.get(
                    "evidence_type"
                ),
            ),

            check(
                "decode positional minimum preserved",
                base_decode_rule.get(
                    "required_positional_args_min"
                ),
                automatic_decode_rule.get(
                    "required_positional_args_min"
                ),
            ),

            check(
                "decode positional maximum preserved",
                base_decode_rule.get(
                    "required_positional_args_max"
                ),
                automatic_decode_rule.get(
                    "required_positional_args_max"
                ),
            ),

            check(
                "decode required keywords preserved",
                base_decode_rule.get(
                    "required_keyword_args"
                ),
                automatic_decode_rule.get(
                    "required_keyword_args"
                ),
            ),

            check(
                "decode supported keywords preserved",
                base_decode_rule.get(
                    "supported_keyword_args"
                ),
                automatic_decode_rule.get(
                    "supported_keyword_args"
                ),
            ),

            check(
                "decode forbidden keywords preserved",
                base_decode_rule.get(
                    "forbidden_keyword_args"
                ),
                automatic_decode_rule.get(
                    "forbidden_keyword_args"
                ),
            ),

            check(
                "unrelated nested API entry unchanged",
                base_nested_entry,
                automatic_nested_entry,
            ),

            check(
                "nested rule still curated",
                "real_api_history_evidence",
                automatic_nested_rule.get(
                    "evidence_type"
                ),
            ),

            check(
                "nested rule specifier preserved",
                EXPECTED_SPECIFIER,
                automatic_nested_rule.get(
                    "version_specifier"
                ),
            ),

            check(
                "automatic compilation target rule",
                TARGET_RULE_ID,
                compilation.get(
                    "target_rule_id"
                ),
            ),

            check(
                "automatic compilation candidate scope",
                "stable_release_history_candidate",
                compilation.get(
                    "candidate_scope"
                ),
            ),

            check(
                "automatic compilation coverage complete",
                True,
                compilation.get(
                    "coverage_complete"
                ),
            ),

            check(
                "automatic compilation old specifier",
                EXPECTED_SPECIFIER,
                compilation.get(
                    "old_version_specifier"
                ),
            ),

            check(
                "automatic compilation new specifier",
                EXPECTED_SPECIFIER,
                compilation.get(
                    "compiled_version_specifier"
                ),
            ),
        ]
    )

    # ========================================================
    # Layer 5:
    # Existing resolver -> S_api
    # ========================================================

    decode_constraint = (
        find_call_constraint(
            constraints,
            TARGET_API_SYMBOL,
        )
    )

    nested_constraint = (
        find_call_constraint(
            constraints,
            NESTED_API_SYMBOL,
        )
    )

    distribution_constraint = (
        find_distribution_constraint(
            constraints,
            TARGET_DISTRIBUTION,
        )
    )

    s_api = (
        distribution_constraint.get(
            "s_api",
            {},
        )
    )

    if not isinstance(
        s_api,
        dict,
    ):
        s_api = {}

    decode_matched_rules = (
        decode_constraint.get(
            "matched_rules",
            [],
        )
    )

    if not isinstance(
        decode_matched_rules,
        list,
    ):
        decode_matched_rules = []

    decode_rule_evidence = (
        decode_matched_rules[0]
        if decode_matched_rules
        and isinstance(
            decode_matched_rules[0],
            dict,
        )
        else {}
    )

    evidence_rule_ids = s_api.get(
        "evidence_rule_ids",
        [],
    )

    if not isinstance(
        evidence_rule_ids,
        list,
    ):
        evidence_rule_ids = []

    results.extend(
        [
            check(
                "resolver schema",
                "api_version_constraint_v0.1",
                constraints.get(
                    "schema_version"
                ),
            ),

            check(
                "resolver overall status",
                "resolved",
                constraints.get(
                    "status"
                ),
            ),

            check(
                "resolver unresolved calls",
                0,
                constraints.get(
                    "unresolved_api_call_count"
                ),
            ),

            check(
                "resolver all calls resolved",
                constraints.get(
                    "api_call_count"
                ),
                constraints.get(
                    "resolved_api_call_count"
                ),
            ),

            check(
                "decode call resolved",
                "resolved",
                decode_constraint.get(
                    "status"
                ),
            ),

            check(
                "decode call specifier",
                EXPECTED_SPECIFIER,
                decode_constraint.get(
                    "simplified_version_specifier"
                ),
            ),

            check(
                "decode matched automatic evidence",
                (
                    "automatic_release_"
                    "history_evidence"
                ),
                decode_rule_evidence.get(
                    "evidence_type"
                ),
            ),

            check(
                "nested call resolved",
                "resolved",
                nested_constraint.get(
                    "status"
                ),
            ),

            check(
                "nested call specifier",
                EXPECTED_SPECIFIER,
                nested_constraint.get(
                    "simplified_version_specifier"
                ),
            ),

            check(
                "distribution constraint resolved",
                "resolved",
                distribution_constraint.get(
                    "status"
                ),
            ),

            check(
                "final S_api raw specifier",
                EXPECTED_SPECIFIER,
                s_api.get(
                    "raw_specifier"
                ),
            ),

            check(
                "final S_api simplified specifier",
                EXPECTED_SPECIFIER,
                s_api.get(
                    "simplified_specifier"
                ),
            ),

            check(
                "S_api evidence rule ids",
                {
                    TARGET_RULE_ID,
                    NESTED_RULE_ID,
                },
                set(
                    evidence_rule_ids
                ),
            ),
        ]
    )

    passed = sum(
        1
        for result
        in results
        if result
    )

    total = len(
        results
    )

    print("")
    print(
        f"[SUMMARY] "
        f"{passed}/{total} PASS"
    )

    if passed != total:
        raise SystemExit(1)


if __name__ == "__main__":
    main()