from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


EXPECTED_REDUCTION = (
    1.0 - 159 / 312
)

EXPECTED_EXPOSURE_RATIO = (
    73 / 159
)


CASES = {
    "true": {
        "sample_id":
            "avcs_aiohttp_follow_symlinks_true",

        "expected_api_rules": [
            "aiohttp_web_static_two_positional",
            "aiohttp_web_static_follow_symlinks_keyword",
        ],

        "expected_trigger_matched":
            True,

        "expected_trigger_reason":
            "keyword_literal_matched",

        "expected_candidate":
            True,

        "expected_assessment":
            "candidate_requires_input_review",

        "expected_risk_card_count":
            1,
    },

    "false": {
        "sample_id":
            "avcs_aiohttp_follow_symlinks_false",

        "expected_api_rules": [
            "aiohttp_web_static_two_positional",
            "aiohttp_web_static_follow_symlinks_keyword",
        ],

        "expected_trigger_matched":
            False,

        "expected_trigger_reason":
            "keyword_literal_not_matched",

        "expected_candidate":
            False,

        "expected_assessment":
            "trigger_api_not_observed",

        "expected_risk_card_count":
            0,
    },

    "omitted": {
        "sample_id":
            "avcs_aiohttp_follow_symlinks_omitted",

        "expected_api_rules": [
            "aiohttp_web_static_two_positional",
        ],

        "expected_trigger_matched":
            False,

        "expected_trigger_reason":
            "required_keyword_not_observed",

        "expected_candidate":
            False,

        "expected_assessment":
            "trigger_api_not_observed",

        "expected_risk_card_count":
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
            == (
                "aiohttp_web_static_"
                "follow_symlinks_true"
            )
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
            f"Validate aiohttp {case_name}"
        )
        print("=" * 60)

        prefix = (
            "aiohttp_follow_symlinks_"
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

        trigger_match = (
            get_trigger_match(
                evaluation
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
                    ">=3.1.0",
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
                    159,
                    api_compatible.get(
                        "confirmed_api_compatible_release_count"
                    ),
                ),

                check(
                    (
                        f"{case_name} "
                        "manifest-compatible count"
                    ),
                    159,
                    feasible.get(
                        "confirmed_manifest_compatible_release_count"
                    ),
                ),

                check(
                    (
                        f"{case_name} "
                        "exposed count"
                    ),
                    73,
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
                    ">=3.1.0,<3.9.2",
                    evaluation.get(
                        "intersection_specifier"
                    ),
                ),

                check(
                    (
                        f"{case_name} "
                        "trigger matched"
                    ),
                    expected[
                        "expected_trigger_matched"
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
                        "expected_trigger_reason"
                    ],
                    trigger_match.get(
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
                        "V_before_api"
                    ),
                    312,
                    strength.get(
                        "v_before_api_count"
                    ),
                ),

                check(
                    (
                        f"{case_name} "
                        "V_feasible"
                    ),
                    159,
                    strength.get(
                        "v_feasible_count"
                    ),
                ),

                check(
                    (
                        f"{case_name} "
                        "V_exposed"
                    ),
                    73,
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
                        "Risk Card count"
                    ),
                    expected[
                        "expected_risk_card_count"
                    ],
                    len(risk_cards),
                ),
            ]
        )

        if case_name == "true":
            risk_text = json.dumps(
                risk_cards,
                ensure_ascii=False,
            )

            results.extend(
                [
                    check(
                        (
                            "true Risk Card "
                            "status"
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
                            "true Risk Card "
                            "evidence level"
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
                            "true Risk Card "
                            "contains YAML text"
                        ),
                        False,
                        (
                            "YAML" in risk_text
                            or "PyYAML"
                            in risk_text
                        ),
                    ),

                    check(
                        (
                            "true Risk Card "
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
        "AVCS aiohttp Trigger E2E"
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
        "[OK] AVCS aiohttp "
        "Trigger E2E ALL PASS"
    )


if __name__ == "__main__":
    main()