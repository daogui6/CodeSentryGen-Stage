from __future__ import annotations

import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


CASES = {
    "full_loader": {
        "expected_api_rule":
            "pyyaml_load_loader_keyword",

        "expected_api_compatible_count":
            31,

        "expected_manifest_compatible_count":
            31,

        "expected_exposed_count":
            23,

        "expected_candidate":
            True,

        "expected_assessment":
            "candidate_requires_input_review",

        "expected_trigger_apis":
            ["yaml.load"],

        "expected_safe_apis":
            [],

        "expected_trigger_ids": [
            "pyyaml_load_explicit_full_loader"
        ],

        "expected_safe_match_states":
            [False],

        "expected_safe_call_count":
            0,
    },

    "safe_loader": {
        "expected_api_rule":
            "pyyaml_load_loader_keyword",

        "expected_api_compatible_count":
            31,

        "expected_manifest_compatible_count":
            31,

        "expected_exposed_count":
            23,

        "expected_candidate":
            False,

        "expected_assessment":
            "trigger_api_not_observed",

        "expected_trigger_apis":
            [],

        "expected_safe_apis":
            ["yaml.load"],

        "expected_trigger_ids":
            [],

        "expected_safe_match_states":
            [True],

        "expected_safe_call_count":
            1,
    },

    "loader_omitted": {
        "expected_api_rule":
            "pyyaml_load_loader_omitted",

        "expected_api_compatible_count":
            25,

        "expected_manifest_compatible_count":
            25,

        "expected_exposed_count":
            23,

        "expected_candidate":
            True,

        "expected_assessment":
            "candidate_requires_input_review",

        "expected_trigger_apis":
            ["yaml.load"],

        "expected_safe_apis":
            [],

        "expected_trigger_ids": [
            "pyyaml_load_default_full_loader"
        ],

        "expected_safe_match_states":
            [False],

        "expected_safe_call_count":
            0,
    },
}


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
    passed = expected == actual

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


def get_matched_trigger_ids(
    evaluation: dict[str, Any],
) -> list[str]:
    result: list[str] = []

    for call in evaluation.get(
        "observed_trigger_calls",
        [],
    ):
        match = call.get(
            "trigger_rule_match",
            {},
        )

        if not isinstance(
            match,
            dict,
        ):
            continue

        trigger_id = str(
            match.get(
                "trigger_id",
                "",
            )
        )

        if trigger_id:
            result.append(
                trigger_id
            )

    return sorted(result)


def get_safe_match_states(
    evaluation: dict[str, Any],
) -> list[bool]:
    result: list[bool] = []

    for item in evaluation.get(
        "safe_rule_evaluations",
        [],
    ):
        match = item.get(
            "safe_rule_match",
            {},
        )

        if not isinstance(
            match,
            dict,
        ):
            continue

        result.append(
            bool(
                match.get(
                    "matched",
                    False,
                )
            )
        )

    return result


def main() -> None:
    results: list[bool] = []

    for (
        case_name,
        expected,
    ) in CASES.items():

        print("")
        print(
            "=" * 60
        )
        print(
            f"Validate {case_name}"
        )
        print(
            "=" * 60
        )

        api_constraints = read_json(
            ROOT
            / "output"
            / (
                "avcs_yaml_load_"
                f"{case_name}_"
                "api_constraints_v0.json"
            )
        )

        api_compatible = read_json(
            ROOT
            / "output"
            / (
                "avcs_yaml_load_"
                f"{case_name}_"
                "api_compatible_releases_v0.json"
            )
        )

        manifest_compatible = (
            read_json(
                ROOT
                / "output"
                / (
                    "avcs_yaml_load_"
                    f"{case_name}_"
                    "manifest_compatible_"
                    "releases_v0.json"
                )
            )
        )

        exposed = read_json(
            ROOT
            / "output"
            / (
                "avcs_yaml_load_"
                f"{case_name}_"
                "exposed_releases_v0.json"
            )
        )

        evaluation_result = (
            read_json(
                ROOT
                / "output"
                / (
                    "avcs_yaml_load_"
                    f"{case_name}_"
                    "evaluation_v0.json"
                )
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

        results.extend(
            [
                check(
                    (
                        f"{case_name} "
                        "API rule"
                    ),
                    [
                        expected[
                            "expected_api_rule"
                        ]
                    ],
                    matched_rule_ids,
                ),

                check(
                    (
                        f"{case_name} "
                        "API-compatible count"
                    ),
                    expected[
                        "expected_api_compatible_count"
                    ],
                    api_compatible.get(
                        "confirmed_api_compatible_release_count"
                    ),
                ),

                check(
                    (
                        f"{case_name} "
                        "manifest-compatible count"
                    ),
                    expected[
                        "expected_manifest_compatible_count"
                    ],
                    manifest_compatible.get(
                        "confirmed_manifest_compatible_release_count"
                    ),
                ),

                check(
                    (
                        f"{case_name} "
                        "exposed count"
                    ),
                    expected[
                        "expected_exposed_count"
                    ],
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
                        "intersection semantics"
                    ),
                    (
                        "interval_summary_only"
                    ),
                    evaluation.get(
                        "intersection_semantics"
                    ),
                ),

                check(
                    (
                        f"{case_name} "
                        "conditional rule count"
                    ),
                    2,
                    len(
                        evaluation.get(
                            "conditional_trigger_"
                            "rule_evaluations",
                            [],
                        )
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
                        "trigger APIs"
                    ),
                    expected[
                        "expected_trigger_apis"
                    ],
                    evaluation.get(
                        "observed_trigger_apis"
                    ),
                ),

                check(
                    (
                        f"{case_name} "
                        "safe APIs"
                    ),
                    expected[
                        "expected_safe_apis"
                    ],
                    evaluation.get(
                        "observed_safe_apis"
                    ),
                ),

                check(
                    (
                        f"{case_name} "
                        "matched trigger IDs"
                    ),
                    sorted(
                        expected[
                            "expected_trigger_ids"
                        ]
                    ),
                    get_matched_trigger_ids(
                        evaluation
                    ),
                ),

                check(
                    (
                        f"{case_name} "
                        "safe rule matches"
                    ),
                    expected[
                        "expected_safe_match_states"
                    ],
                    get_safe_match_states(
                        evaluation
                    ),
                ),

                check(
                    (
                        f"{case_name} "
                        "observed safe rule calls"
                    ),
                    expected[
                        "expected_safe_call_count"
                    ],
                    len(
                        evaluation.get(
                            "observed_safe_rule_calls",
                            [],
                        )
                    ),
                ),
            ]
        )

    passed = sum(results)
    total = len(results)

    print("")
    print(
        "=" * 60
    )
    print(
        "AVCS yaml.load Trigger E2E"
    )
    print(
        "=" * 60
    )

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
        "[OK] AVCS yaml.load "
        "Trigger E2E ALL PASS"
    )


if __name__ == "__main__":
    main()