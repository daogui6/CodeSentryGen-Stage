from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


EXPECTED_REDUCTION = (
    1.0 - 118 / 136
)

EXPECTED_EXPOSURE_RATIO = (
    29 / 118
)


EXPLICIT_TRIGGER_ID = (
    "numpy_load_allow_pickle_true"
)

OMITTED_TRIGGER_ID = (
    "numpy_load_omitted_"
    "allow_pickle_historical_true"
)


CASES = {
    "true": {
        "sample_id":
            "avcs_numpy_allow_pickle_true",

        "expected_api_rules": [
            "numpy_load_one_positional",
            "numpy_load_allow_pickle_keyword",
        ],

        "expected_explicit_matched":
            True,

        "expected_explicit_reason":
            "keyword_literal_matched",

        "expected_omitted_matched":
            False,

        "expected_omitted_reason":
            "keyword_is_explicitly_provided",

        "expected_candidate":
            True,

        "expected_assessment":
            "candidate_requires_input_review",

        "expected_risk_card_count":
            1,
    },

    "false": {
        "sample_id":
            "avcs_numpy_allow_pickle_false",

        "expected_api_rules": [
            "numpy_load_one_positional",
            "numpy_load_allow_pickle_keyword",
        ],

        "expected_explicit_matched":
            False,

        "expected_explicit_reason":
            "keyword_literal_not_matched",

        "expected_omitted_matched":
            False,

        "expected_omitted_reason":
            "keyword_is_explicitly_provided",

        "expected_candidate":
            False,

        "expected_assessment":
            "trigger_api_not_observed",

        "expected_risk_card_count":
            0,
    },

    "omitted": {
        "sample_id":
            "avcs_numpy_allow_pickle_omitted",

        "expected_api_rules": [
            "numpy_load_one_positional",
        ],

        "expected_explicit_matched":
            False,

        "expected_explicit_reason":
            "required_keyword_not_observed",

        "expected_omitted_matched":
            True,

        "expected_omitted_reason":
            (
                "keyword_omitted_and_"
                "historical_default_applies"
            ),

        "expected_candidate":
            True,

        "expected_assessment":
            "candidate_requires_input_review",

        "expected_risk_card_count":
            1,
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
    rows: list[dict[str, Any]] = []

    if not path.exists():
        return rows

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


def get_trigger_match(
    evaluation: dict[str, Any],
    trigger_id: str,
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

        match = row.get(
            "trigger_rule_match",
            {},
        )

        if not isinstance(
            match,
            dict,
        ):
            continue

        if (
            match.get("trigger_id")
            == trigger_id
        ):
            return match

    return {}


def main() -> None:
    results: list[bool] = []

    for (
        case_name,
        expected,
    ) in CASES.items():

        print("")
        print("=" * 60)
        print(
            f"Validate NumPy {case_name}"
        )
        print("=" * 60)

        prefix = (
            "numpy_allow_pickle_"
            f"{case_name}"
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

        call_constraint = (
            api_constraints[
                "call_constraints"
            ][0]
        )

        matched_rule_ids = [
            str(
                rule.get(
                    "rule_id",
                    "",
                )
            )
            for rule
            in call_constraint.get(
                "matched_rules",
                [],
            )
        ]

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

        explicit_match = (
            get_trigger_match(
                evaluation,
                EXPLICIT_TRIGGER_ID,
            )
        )

        omitted_match = (
            get_trigger_match(
                evaluation,
                OMITTED_TRIGGER_ID,
            )
        )

        results.extend(
            [
                check(
                    (
                        f"{case_name} "
                        "sample id"
                    ),
                    expected[
                        "sample_id"
                    ],
                    api_constraints.get(
                        "sample_id"
                    ),
                ),

                check(
                    (
                        f"{case_name} "
                        "S_api"
                    ),
                    ">=1.10.0b1",
                    (
                        api_constraints
                        .get(
                            "distribution_constraints",
                            [],
                        )[0]
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
                        "API rules"
                    ),
                    expected[
                        "expected_api_rules"
                    ],
                    matched_rule_ids,
                ),

                check(
                    (
                        f"{case_name} "
                        "API-compatible count"
                    ),
                    118,
                    api_compatible.get(
                        "confirmed_api_compatible_release_count"
                    ),
                ),

                check(
                    (
                        f"{case_name} "
                        "manifest-compatible count"
                    ),
                    118,
                    feasible.get(
                        "confirmed_manifest_compatible_release_count"
                    ),
                ),

                check(
                    (
                        f"{case_name} "
                        "exposed count"
                    ),
                    29,
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
                        "intersection"
                    ),
                    (
                        ">=1.10.0b1,"
                        "<1.16.3"
                    ),
                    evaluation.get(
                        "intersection_specifier"
                    ),
                ),

                check(
                    (
                        f"{case_name} "
                        "explicit trigger matched"
                    ),
                    expected[
                        "expected_explicit_matched"
                    ],
                    explicit_match.get(
                        "matched"
                    ),
                ),

                check(
                    (
                        f"{case_name} "
                        "explicit trigger reason"
                    ),
                    expected[
                        "expected_explicit_reason"
                    ],
                    explicit_match.get(
                        "reason"
                    ),
                ),

                check(
                    (
                        f"{case_name} "
                        "omitted trigger matched"
                    ),
                    expected[
                        "expected_omitted_matched"
                    ],
                    omitted_match.get(
                        "matched"
                    ),
                ),

                check(
                    (
                        f"{case_name} "
                        "omitted trigger reason"
                    ),
                    expected[
                        "expected_omitted_reason"
                    ],
                    omitted_match.get(
                        "reason"
                    ),
                ),

                check(
                    (
                        f"{case_name} "
                        "candidate"
                    ),
                    expected[
                        "expected_candidate"
                    ],
                    evaluation.get(
                        "risk_card_candidate"
                    ),
                ),

                check(
                    (
                        f"{case_name} "
                        "assessment"
                    ),
                    expected[
                        "expected_assessment"
                    ],
                    evaluation.get(
                        "assessment"
                    ),
                ),

                check(
                    (
                        f"{case_name} "
                        "Evidence Strength status"
                    ),
                    "partial",
                    evidence_strength.get(
                        "status"
                    ),
                ),

                check(
                    (
                        f"{case_name} "
                        "V_before_api"
                    ),
                    136,
                    strength.get(
                        "v_before_api_count"
                    ),
                ),

                check(
                    (
                        f"{case_name} "
                        "V_feasible"
                    ),
                    118,
                    strength.get(
                        "v_feasible_count"
                    ),
                ),

                check(
                    (
                        f"{case_name} "
                        "V_exposed"
                    ),
                    29,
                    strength.get(
                        "v_exposed_count"
                    ),
                ),

                check_float(
                    (
                        f"{case_name} "
                        "Reduction"
                    ),
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
                    [
                        (
                            "time_unknown_release_"
                            "labels_may_affect_"
                            "v_before_api"
                        )
                    ],
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
                        "expected_risk_card_count"
                    ],
                    len(risk_cards),
                ),
            ]
        )

        if expected[
            "expected_risk_card_count"
        ] == 1:
            risk_text = json.dumps(
                risk_cards,
                ensure_ascii=False,
            )

            results.extend(
                [
                    check(
                        (
                            f"{case_name} "
                            "Risk Card status"
                        ),
                        "candidate",
                        (
                            risk_cards[0]
                            .get("status")
                            if risk_cards
                            else None
                        ),
                    ),

                    check(
                        (
                            f"{case_name} "
                            "Risk Card evidence level"
                        ),
                        "moderate",
                        (
                            risk_cards[0]
                            .get(
                                "evidence_level"
                            )
                            if risk_cards
                            else None
                        ),
                    ),

                    check(
                        (
                            f"{case_name} "
                            "Risk Card vulnerability"
                        ),
                        (
                            "GHSA-9fq2-"
                            "x9r6-wfmf"
                        ),
                        (
                            risk_cards[0]
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
                            if risk_cards
                            else None
                        ),
                    ),

                    check(
                        (
                            f"{case_name} "
                            "generic review text"
                        ),
                        True,
                        (
                            "vulnerability-relevant "
                            "inputs or resources"
                            in risk_text
                        ),
                    ),
                ]
            )

    passed = sum(results)
    total = len(results)

    print("")
    print("=" * 60)
    print(
        "AVCS NumPy Trigger E2E"
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
        "[OK] AVCS NumPy "
        "Trigger E2E ALL PASS"
    )


if __name__ == "__main__":
    main()