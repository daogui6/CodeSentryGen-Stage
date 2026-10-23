from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

EXPECTED_REDUCTION = (
    1.0 - 36 / 55
)

EXPECTED_EXPOSURE_RATIO = (
    17 / 36
)


CASES = {
    "true": {
        "prefix":
            "pyjwt_default_algorithms_true",

        "sample_id":
            "avcs_pyjwt_default_algorithms_true",

        "api_call_count":
            2,

        "api_rule_ids": [
            "pyjwt_decode_algorithms_keyword",
            "pyjwt_get_default_algorithms_zero_arg",
        ],

        "resolved_call_symbol":
            (
                "jwt.algorithms."
                "get_default_algorithms"
            ),

        "trigger_matched":
            True,

        "trigger_reason":
            "keyword_call_matched",

        "candidate":
            True,

        "assessment":
            "candidate_requires_input_review",

        "risk_card_count":
            1,
    },

    "false": {
        "prefix":
            "pyjwt_explicit_algorithms_false",

        "sample_id":
            "avcs_pyjwt_explicit_algorithms_false",

        "api_call_count":
            1,

        "api_rule_ids": [
            "pyjwt_decode_algorithms_keyword",
        ],

        "resolved_call_symbol":
            None,

        "trigger_matched":
            False,

        "trigger_reason":
            "keyword_call_unresolved",

        "candidate":
            False,

        "assessment":
            "trigger_api_not_observed",

        "risk_card_count":
            0,
    },
}


def read_json(
    path: Path,
) -> dict[str, Any]:
    return json.loads(
        path.read_text(
            encoding="utf-8",
        )
    )


def read_jsonl(
    path: Path,
) -> list[dict[str, Any]]:
    if not path.exists():
        return []

    rows: list[dict[str, Any]] = []

    for line in path.read_text(
        encoding="utf-8",
    ).splitlines():
        line = line.strip()

        if not line:
            continue

        rows.append(
            json.loads(line)
        )

    return rows


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


def check_float(
    name: str,
    expected: float,
    actual: Any,
) -> bool:
    passed = (
        isinstance(
            actual,
            (int, float),
        )
        and math.isclose(
            float(actual),
            expected,
            rel_tol=1e-12,
            abs_tol=1e-12,
        )
    )

    status = (
        "PASS"
        if passed
        else "FAIL"
    )

    print(
        f"[{status}] {name} | "
        f"expected≈{expected!r} | "
        f"actual={actual!r}"
    )

    return passed


def find_call_constraint(
    api_constraints: dict[str, Any],
    api_symbol: str,
) -> dict[str, Any]:
    for call in api_constraints.get(
        "call_constraints",
        [],
    ):
        if (
            call.get("api_symbol")
            == api_symbol
        ):
            return call

    return {}


def get_decode_trigger_match(
    evaluation: dict[str, Any],
) -> dict[str, Any]:
    rows = evaluation.get(
        "conditional_trigger_rule_evaluations",
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
            row.get("api_symbol")
            != "jwt.decode"
        ):
            continue

        match = row.get(
            "trigger_rule_match",
            {},
        )

        if isinstance(
            match,
            dict,
        ):
            return match

    return {}


def main() -> None:
    results: list[bool] = []

    # --------------------------------------------------
    # Shared Real Trigger Evidence
    # --------------------------------------------------

    vulnerability_data = read_json(
        ROOT
        / "output"
        / (
            "pyjwt_ghsa_ffqj_6fqr_9h24_"
            "vulnerability_constraints_"
            "trigger_v0.json"
        )
    )

    vulnerability = (
        vulnerability_data[
            "vulnerabilities"
        ][0]
    )

    trigger_rule = (
        vulnerability[
            "trigger_conditions"
        ][
            "conditional_api_rules"
        ][0]
    )

    keyword_rule = (
        trigger_rule.get(
            "keyword_argument",
            {},
        )
    )

    results.extend(
        [
            check(
                "Trigger evidence status",
                "resolved",
                vulnerability.get(
                    "trigger_evidence_status"
                ),
            ),

            check(
                "Trigger rule kind",
                "keyword_call_condition",
                trigger_rule.get(
                    "kind"
                ),
            ),

            check(
                "Trigger keyword",
                "algorithms",
                keyword_rule.get(
                    "name"
                ),
            ),

            check(
                "Required call symbol",
                (
                    "jwt.algorithms."
                    "get_default_algorithms"
                ),
                keyword_rule.get(
                    "required_call_symbol"
                ),
            ),

            check(
                "Trigger version scope",
                ">=1.5.0,<2.4.0",
                trigger_rule.get(
                    "version_scope"
                ),
            ),

            check(
                "Fixed version specifier",
                ">=2.4.0",
                vulnerability.get(
                    "fixed_version_specifier"
                ),
            ),
        ]
    )

    # --------------------------------------------------
    # True / False controlled cases
    # --------------------------------------------------

    for (
        case_name,
        expected,
    ) in CASES.items():

        print("")
        print("=" * 60)
        print(
            f"Validate PyJWT {case_name}"
        )
        print("=" * 60)

        prefix = str(
            expected["prefix"]
        )

        api_constraints = read_json(
            ROOT
            / "output"
            / (
                f"{prefix}_"
                "api_constraints_v0.json"
            )
        )

        api_compatible = read_json(
            ROOT
            / "output"
            / (
                f"{prefix}_"
                "api_compatible_v0.json"
            )
        )

        feasible = read_json(
            ROOT
            / "output"
            / (
                f"{prefix}_"
                "feasible_v0.json"
            )
        )

        exposed = read_json(
            ROOT
            / "output"
            / (
                f"{prefix}_"
                "exposed_v0.json"
            )
        )

        evaluation_result = read_json(
            ROOT
            / "output"
            / (
                f"{prefix}_"
                "evaluation_v0.json"
            )
        )

        evidence_strength = read_json(
            ROOT
            / "output"
            / (
                f"{prefix}_"
                "evidence_strength_v0.json"
            )
        )

        risk_cards = read_jsonl(
            ROOT
            / "output"
            / (
                f"{prefix}_"
                "risk_cards_v0.jsonl"
            )
        )

        decode_call = (
            find_call_constraint(
                api_constraints,
                "jwt.decode",
            )
        )

        keyword_values = (
            decode_call
            .get(
                "call_shape",
                {},
            )
            .get(
                "keyword_arg_values",
                {},
            )
        )

        algorithms_evidence = (
            keyword_values.get(
                "algorithms",
                {},
            )
        )

        all_rule_ids = sorted(
            str(
                rule.get(
                    "rule_id",
                    "",
                )
            )
            for call
            in api_constraints.get(
                "call_constraints",
                [],
            )
            for rule
            in call.get(
                "matched_rules",
                [],
            )
        )

        exposed_row = (
            exposed[
                "evaluations"
            ][0]
        )

        evaluation = (
            evaluation_result[
                "evaluations"
            ][0]
        )

        strength = (
            evidence_strength[
                "evaluations"
            ][0]
        )

        trigger_match = (
            get_decode_trigger_match(
                evaluation
            )
        )

        distribution_constraint = (
            api_constraints[
                "distribution_constraints"
            ][0]
        )

        results.extend(
            [
                check(
                    f"{case_name} sample id",
                    expected["sample_id"],
                    api_constraints.get(
                        "sample_id"
                    ),
                ),

                check(
                    f"{case_name} API status",
                    "resolved",
                    api_constraints.get(
                        "status"
                    ),
                ),

                check(
                    f"{case_name} API call count",
                    expected[
                        "api_call_count"
                    ],
                    api_constraints.get(
                        "api_call_count"
                    ),
                ),

                check(
                    (
                        f"{case_name} "
                        "resolved API call count"
                    ),
                    expected[
                        "api_call_count"
                    ],
                    api_constraints.get(
                        "resolved_api_call_count"
                    ),
                ),

                check(
                    f"{case_name} S_api",
                    ">=1.0.0",
                    (
                        distribution_constraint
                        .get(
                            "s_api",
                            {},
                        )
                        .get(
                            "simplified_specifier"
                        )
                    ),
                ),

                check(
                    (
                        f"{case_name} "
                        "API evidence rules"
                    ),
                    sorted(
                        expected[
                            "api_rule_ids"
                        ]
                    ),
                    all_rule_ids,
                ),

                check(
                    (
                        f"{case_name} "
                        "resolved call symbol"
                    ),
                    expected[
                        "resolved_call_symbol"
                    ],
                    algorithms_evidence.get(
                        "resolved_call_symbol"
                    ),
                ),

                check(
                    (
                        f"{case_name} "
                        "API-compatible count"
                    ),
                    36,
                    api_compatible.get(
                        "confirmed_api_compatible_release_count"
                    ),
                ),

                check(
                    (
                        f"{case_name} "
                        "manifest-compatible count"
                    ),
                    36,
                    feasible.get(
                        "confirmed_manifest_compatible_release_count"
                    ),
                ),

                check(
                    f"{case_name} exposed count",
                    17,
                    exposed_row.get(
                        "confirmed_exposed_release_count"
                    ),
                ),

                check(
                    (
                        f"{case_name} "
                        "version evidence mode"
                    ),
                    (
                        "discrete_"
                        "confirmed_releases"
                    ),
                    evaluation.get(
                        "version_evidence_mode"
                    ),
                ),

                check(
                    (
                        f"{case_name} "
                        "discrete evidence status"
                    ),
                    "matched",
                    evaluation.get(
                        "discrete_evidence_status"
                    ),
                ),

                check(
                    f"{case_name} intersection",
                    ">=1.5.0,<2.4.0",
                    evaluation.get(
                        "intersection_specifier"
                    ),
                ),

                check(
                    (
                        f"{case_name} "
                        "evaluation exposed count"
                    ),
                    17,
                    evaluation.get(
                        "confirmed_exposed_release_count"
                    ),
                ),

                check(
                    (
                        f"{case_name} "
                        "trigger matched"
                    ),
                    expected[
                        "trigger_matched"
                    ],
                    trigger_match.get(
                        "matched"
                    ),
                ),

                check(
                    (
                        f"{case_name} "
                        "trigger reason"
                    ),
                    expected[
                        "trigger_reason"
                    ],
                    trigger_match.get(
                        "reason"
                    ),
                ),

                check(
                    f"{case_name} candidate",
                    expected["candidate"],
                    evaluation.get(
                        "risk_card_candidate"
                    ),
                ),

                check(
                    f"{case_name} assessment",
                    expected["assessment"],
                    evaluation.get(
                        "assessment"
                    ),
                ),

                check(
                    (
                        f"{case_name} "
                        "Evidence Strength status"
                    ),
                    "resolved",
                    evidence_strength.get(
                        "status"
                    ),
                ),

                check(
                    (
                        f"{case_name} "
                        "release history status"
                    ),
                    (
                        "current_registry_"
                        "file_evidence_complete"
                    ),
                    evidence_strength.get(
                        "release_history_status"
                    ),
                ),

                check(
                    f"{case_name} V_before_api",
                    55,
                    strength.get(
                        "v_before_api_count"
                    ),
                ),

                check(
                    f"{case_name} V_feasible",
                    36,
                    strength.get(
                        "v_feasible_count"
                    ),
                ),

                check(
                    f"{case_name} V_exposed",
                    17,
                    strength.get(
                        "v_exposed_count"
                    ),
                ),

                check_float(
                    f"{case_name} Reduction",
                    EXPECTED_REDUCTION,
                    strength.get(
                        "reduction"
                    ),
                ),

                check_float(
                    (
                        f"{case_name} "
                        "ExposureRatio"
                    ),
                    EXPECTED_EXPOSURE_RATIO,
                    strength.get(
                        "exposure_ratio"
                    ),
                ),

                check(
                    (
                        f"{case_name} "
                        "FixedExcluded"
                    ),
                    False,
                    strength.get(
                        "fixed_excluded"
                    ),
                ),

                check(
                    (
                        f"{case_name} "
                        "uncertainty reasons"
                    ),
                    [],
                    strength.get(
                        "uncertainty_reasons"
                    ),
                ),

                check(
                    (
                        f"{case_name} "
                        "Risk Card count"
                    ),
                    expected[
                        "risk_card_count"
                    ],
                    len(risk_cards),
                ),
            ]
        )

        if (
            expected[
                "risk_card_count"
            ]
            == 1
        ):
            card = (
                risk_cards[0]
                if risk_cards
                else {}
            )

            results.extend(
                [
                    check(
                        (
                            f"{case_name} "
                            "Risk Card status"
                        ),
                        "candidate",
                        card.get(
                            "status"
                        ),
                    ),

                    check(
                        (
                            f"{case_name} "
                            "Risk Card evidence level"
                        ),
                        "moderate",
                        card.get(
                            "evidence_level"
                        ),
                    ),

                    check(
                        (
                            f"{case_name} "
                            "Risk Card vulnerability"
                        ),
                        (
                            "GHSA-ffqj-"
                            "6fqr-9h24"
                        ),
                        (
                            card
                            .get(
                                "evidence",
                                {},
                            )
                            .get(
                                "vulnerability",
                                {},
                            )
                            .get(
                                "vulnerability_id"
                            )
                        ),
                    ),

                    check(
                        (
                            f"{case_name} "
                            "Risk Card fixed version"
                        ),
                        ">=2.4.0",
                        (
                            card
                            .get(
                                "evidence",
                                {},
                            )
                            .get(
                                "version_constraints",
                                {},
                            )
                            .get(
                                "fixed_version_specifier"
                            )
                        ),
                    ),

                    check(
                        (
                            f"{case_name} "
                            "Risk Card repair"
                        ),
                        (
                            'python -m pip install '
                            '"pyjwt>=2.4.0"'
                        ),
                        (
                            card
                            .get(
                                "repair",
                                {},
                            )
                            .get(
                                "command"
                            )
                        ),
                    ),
                ]
            )

    passed = sum(results)
    total = len(results)

    print("")
    print("=" * 60)
    print(
        "AVCS PyJWT Trigger E2E"
    )
    print("=" * 60)

    print(
        f"[OK] total checks: {total}"
    )

    print(
        f"[OK] passed: {passed}"
    )

    print(
        f"[OK] failed: "
        f"{total - passed}"
    )

    if passed != total:
        raise SystemExit(1)

    print(
        "[OK] AVCS PyJWT "
        "Trigger E2E ALL PASS"
    )


if __name__ == "__main__":
    main()