from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

EXPECTED_REDUCTION = 0.0
EXPECTED_EXPOSURE_RATIO = 152 / 160


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
            == "requests_netrc_host_confusion"
        ):
            return match

    return {}


def main() -> None:
    results: list[bool] = []

    prefix = (
        "avcs_requests_netrc_"
        "host_confusion_true"
    )

    api_constraints = read_json(
        ROOT
        / "output"
        / (
            f"{prefix}_"
            "api_constraints_v0.json"
        )
    )

    release_history = read_json(
        ROOT
        / "output"
        / (
            f"{prefix}_"
            "release_history_v0.json"
        )
    )

    api_compatible = read_json(
        ROOT
        / "output"
        / (
            f"{prefix}_"
            "api_compatible_releases_v0.json"
        )
    )

    manifest_constraints = read_json(
        ROOT
        / "output"
        / (
            f"{prefix}_"
            "manifest_constraints_v0.json"
        )
    )

    feasible = read_json(
        ROOT
        / "output"
        / (
            f"{prefix}_"
            "manifest_compatible_releases_v0.json"
        )
    )

    vulnerability_constraints = read_json(
        ROOT
        / "output"
        / (
            f"{prefix}_"
            "vulnerability_constraints_"
            "trigger_enriched_v0.json"
        )
    )

    exposed = read_json(
        ROOT
        / "output"
        / (
            f"{prefix}_"
            "exposed_releases_v0.json"
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
        api_constraints.get(
            "call_constraints",
            [],
        )[0]
    )

    distribution_constraint = (
        api_constraints.get(
            "distribution_constraints",
            [],
        )[0]
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

    positional_values = (
        call_constraint
        .get(
            "call_shape",
            {},
        )
        .get(
            "positional_arg_values",
            [],
        )
    )

    first_positional = (
        positional_values[0]
        if positional_values
        else {}
    )

    vulnerability = (
        vulnerability_constraints.get(
            "vulnerabilities",
            [],
        )[0]
    )

    environment_preconditions = (
        vulnerability
        .get(
            "trigger_evidence",
            {},
        )
        .get(
            "scope",
            {},
        )
        .get(
            "environment_preconditions",
            {},
        )
    )

    exposed_evaluation = (
        exposed.get(
            "evaluations",
            [],
        )[0]
    )

    evaluation = (
        evaluation_result.get(
            "evaluations",
            [],
        )[0]
    )

    strength = (
        evidence_strength.get(
            "evaluations",
            [],
        )[0]
    )

    trigger_match = (
        get_trigger_match(
            evaluation
        )
    )

    risk_card = (
        risk_cards[0]
        if risk_cards
        else {}
    )

    risk_trigger_conditions = (
        risk_card
        .get(
            "evidence",
            {},
        )
        .get(
            "trigger_conditions",
            {},
        )
    )

    repair = risk_card.get(
        "repair",
        {},
    )

    confirmed_exposed = {
        str(
            row.get(
                "version",
                "",
            )
        )
        for row
        in exposed_evaluation.get(
            "confirmed_exposed_releases",
            [],
        )
    }

    confirmed_not_affected = {
        str(
            row.get(
                "version",
                "",
            )
        )
        for row
        in exposed_evaluation.get(
            "confirmed_not_affected_releases",
            [],
        )
    }

    results.extend(
        [
            check(
                "sample id",
                (
                    "avcs_requests_"
                    "netrc_host_confusion_true"
                ),
                api_constraints.get(
                    "sample_id"
                ),
            ),

            check(
                "API status",
                "resolved",
                api_constraints.get(
                    "status"
                ),
            ),

            check(
                "API symbol",
                "requests.get",
                call_constraint.get(
                    "api_symbol"
                ),
            ),

            check(
                "API evidence rules",
                [
                    "requests_get_one_positional"
                ],
                matched_rule_ids,
            ),

            check(
                "S_api",
                ">=0.2.0",
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
                "URL positional literal",
                (
                    "http://github.com:"
                    "@evil.example.net"
                ),
                first_positional.get(
                    "literal_value"
                ),
            ),

            check(
                "release history status",
                "partial",
                release_history.get(
                    "release_history_status"
                ),
            ),

            check(
                "confirmed releases before API",
                160,
                release_history.get(
                    "confirmed_release_count_"
                    "as_of_time_view"
                ),
            ),

            check(
                "latest confirmed release",
                "2.34.2",
                release_history.get(
                    "latest_confirmed_version_"
                    "as_of_time_view"
                ),
            ),

            check(
                "API-compatible count",
                160,
                api_compatible.get(
                    "confirmed_api_compatible_"
                    "release_count"
                ),
            ),

            check(
                "manifest status",
                "resolved",
                manifest_constraints.get(
                    "status"
                ),
            ),

            check(
                "manifest kind",
                "unconstrained",
                manifest_constraints.get(
                    "constraint_kind"
                ),
            ),

            check(
                "manifest-compatible count",
                160,
                feasible.get(
                    "confirmed_manifest_compatible_"
                    "release_count"
                ),
            ),

            check(
                "vulnerability id",
                "GHSA-9hjg-9r4m-mvj7",
                vulnerability.get(
                    "vulnerability_id"
                ),
            ),

            check(
                "S_vuln",
                "<2.32.4",
                vulnerability.get(
                    "affected_version_specifier"
                ),
            ),

            check(
                "fixed version specifier",
                ">=2.32.4",
                vulnerability.get(
                    "fixed_version_specifier"
                ),
            ),

            check(
                "Trigger evidence status",
                "resolved",
                vulnerability.get(
                    "trigger_evidence_status"
                ),
            ),

            check(
                "netrc credentials required",
                True,
                environment_preconditions.get(
                    "netrc_credentials_required"
                ),
            ),

            check(
                "trust_env must not be false",
                True,
                environment_preconditions.get(
                    "trust_env_must_not_be_false"
                ),
            ),

            check(
                "environment evidence status",
                "not_statically_evaluated",
                environment_preconditions.get(
                    "evaluation_status"
                ),
            ),

            check(
                "exposed count",
                152,
                exposed_evaluation.get(
                    "confirmed_exposed_release_count"
                ),
            ),

            check(
                "2.32.3 exposed",
                True,
                "2.32.3"
                in confirmed_exposed,
            ),

            check(
                "2.32.4 not exposed",
                False,
                "2.32.4"
                in confirmed_exposed,
            ),

            check(
                "2.32.4 not affected",
                True,
                "2.32.4"
                in confirmed_not_affected,
            ),

            check(
                "version evidence mode",
                "discrete_confirmed_releases",
                evaluation.get(
                    "version_evidence_mode"
                ),
            ),

            check(
                "evaluation exposed count",
                152,
                evaluation.get(
                    "confirmed_exposed_release_count"
                ),
            ),

            check(
                "Trigger kind",
                "positional_url_condition",
                trigger_match.get(
                    "kind"
                ),
            ),

            check(
                "Trigger matched",
                True,
                trigger_match.get(
                    "matched"
                ),
            ),

            check(
                "Trigger reason",
                (
                    "url_authority_host_"
                    "confusion_matched"
                ),
                trigger_match.get(
                    "reason"
                ),
            ),

            check(
                "requires untrusted input",
                True,
                evaluation.get(
                    "requires_untrusted_input"
                ),
            ),

            check(
                "environment preconditions present",
                True,
                evaluation.get(
                    "environment_preconditions_present"
                ),
            ),

            check(
                "requires environment review",
                True,
                evaluation.get(
                    "requires_environment_review"
                ),
            ),

            check(
                "assessment",
                (
                    "candidate_requires_"
                    "environment_review"
                ),
                evaluation.get(
                    "assessment"
                ),
            ),

            check(
                "Risk Card candidate",
                True,
                evaluation.get(
                    "risk_card_candidate"
                ),
            ),

            check(
                "Evidence Strength status",
                "partial",
                evidence_strength.get(
                    "status"
                ),
            ),

            check(
                "V_before_api",
                160,
                strength.get(
                    "v_before_api_count"
                ),
            ),

            check(
                "V_feasible",
                160,
                strength.get(
                    "v_feasible_count"
                ),
            ),

            check(
                "V_exposed",
                152,
                strength.get(
                    "v_exposed_count"
                ),
            ),

            check_float(
                "Reduction",
                EXPECTED_REDUCTION,
                strength.get(
                    "reduction"
                ),
            ),

            check_float(
                "ExposureRatio",
                EXPECTED_EXPOSURE_RATIO,
                strength.get(
                    "exposure_ratio"
                ),
            ),

            check(
                "FixedExcluded",
                False,
                strength.get(
                    "fixed_excluded"
                ),
            ),

            check(
                "Risk Card count",
                1,
                len(risk_cards),
            ),

            check(
                "Risk Card status",
                "candidate",
                risk_card.get(
                    "status"
                ),
            ),

            check(
                "Risk Card evidence level",
                "moderate",
                risk_card.get(
                    "evidence_level"
                ),
            ),

            check(
                (
                    "Risk Card requires "
                    "environment review"
                ),
                True,
                risk_trigger_conditions.get(
                    "requires_environment_review"
                ),
            ),

            check(
                "Risk Card assessment",
                (
                    "candidate_requires_"
                    "environment_review"
                ),
                risk_trigger_conditions.get(
                    "assessment"
                ),
            ),

            check(
                "Risk Card repair action",
                (
                    "upgrade_dependency_and_"
                    "review_environment"
                ),
                repair.get(
                    "action"
                ),
            ),

            check(
                "Risk Card repair command",
                (
                    "python -m pip install "
                    "\"requests>=2.32.4\""
                ),
                repair.get(
                    "command"
                ),
            ),
        ]
    )

    passed = sum(results)
    total = len(results)

    print("")
    print("=" * 60)
    print(
        "AVCS Requests Trigger E2E"
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
        "[OK] AVCS Requests "
        "Trigger E2E ALL PASS"
    )


if __name__ == "__main__":
    main()