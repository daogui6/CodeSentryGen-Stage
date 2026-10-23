from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

EXPECTED_REDUCTION = 17 / 104
EXPECTED_EXPOSURE_RATIO = 81 / 87


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


def find_call_constraint(
    api_constraints: dict[str, Any],
    api_symbol: str,
) -> dict[str, Any]:
    rows = api_constraints.get(
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
            row.get("api_symbol")
            == api_symbol
        ):
            return row

    return {}


def get_trigger_match(
    evaluation: dict[str, Any],
) -> dict[str, Any]:
    rows = evaluation.get(
        "conditional_trigger_rule_evaluations",
        [],
    )

    if isinstance(
        rows,
        dict,
    ):
        rows = [rows]

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
            == "urllib3_poolmanager_retries_zero_request"
        ):
            return match

    return {}


def main() -> None:
    results: list[bool] = []

    prefix = (
        "avcs_urllib3_"
        "poolmanager_retries_true"
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

    producer_call = find_call_constraint(
        api_constraints,
        "urllib3.PoolManager",
    )

    consumer_call = find_call_constraint(
        api_constraints,
        "urllib3.PoolManager.request",
    )

    producer_rule_ids = [
        str(
            rule.get(
                "rule_id",
                "",
            )
        )
        for rule
        in producer_call.get(
            "matched_rules",
            [],
        )
    ]

    consumer_rule_ids = [
        str(
            rule.get(
                "rule_id",
                "",
            )
        )
        for rule
        in consumer_call.get(
            "matched_rules",
            [],
        )
    ]

    producer_retries = (
        producer_call
        .get(
            "call_shape",
            {},
        )
        .get(
            "keyword_arg_values",
            {},
        )
        .get(
            "retries",
            {},
        )
    )

    receiver_provenance = (
        consumer_call.get(
            "receiver_provenance",
            {},
        )
    )

    provenance_retries = (
        receiver_provenance
        .get(
            "producer_call_shape",
            {},
        )
        .get(
            "keyword_arg_values",
            {},
        )
        .get(
            "retries",
            {},
        )
    )

    distribution_constraints = (
        api_constraints.get(
            "distribution_constraints",
            [],
        )
    )

    distribution_constraint = (
        distribution_constraints[0]
        if distribution_constraints
        else {}
    )

    vulnerabilities = (
        vulnerability_constraints.get(
            "vulnerabilities",
            [],
        )
    )

    vulnerability = (
        vulnerabilities[0]
        if vulnerabilities
        else {}
    )

    trigger_scope = (
        vulnerability
        .get(
            "trigger_evidence",
            {},
        )
        .get(
            "scope",
            {},
        )
    )

    exposed_evaluations = (
        exposed.get(
            "evaluations",
            [],
        )
    )

    exposed_evaluation = (
        exposed_evaluations[0]
        if exposed_evaluations
        else {}
    )

    evaluations = (
        evaluation_result.get(
            "evaluations",
            [],
        )
    )

    evaluation = (
        evaluations[0]
        if evaluations
        else {}
    )

    strength_evaluations = (
        evidence_strength.get(
            "evaluations",
            [],
        )
    )

    strength = (
        strength_evaluations[0]
        if strength_evaluations
        else {}
    )

    trigger_match = get_trigger_match(
        evaluation
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

    risk_api = (
        risk_card
        .get(
            "evidence",
            {},
        )
        .get(
            "api",
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
                "avcs_urllib3_poolmanager_retries_true",
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
                "producer API symbol",
                "urllib3.PoolManager",
                producer_call.get(
                    "api_symbol"
                ),
            ),

            check(
                "producer API evidence rules",
                [
                    "urllib3_poolmanager_retries_keyword"
                ],
                producer_rule_ids,
            ),

            check(
                "producer retries literal",
                0,
                producer_retries.get(
                    "literal_value"
                ),
            ),

            check(
                "consumer API symbol",
                "urllib3.PoolManager.request",
                consumer_call.get(
                    "api_symbol"
                ),
            ),

            check(
                "consumer API evidence rules",
                [
                    "urllib3_poolmanager_request_two_positional"
                ],
                consumer_rule_ids,
            ),

            check(
                "receiver name",
                "http",
                receiver_provenance.get(
                    "receiver_name"
                ),
            ),

            check(
                "receiver producer API",
                "urllib3.PoolManager",
                receiver_provenance.get(
                    "producer_api_symbol"
                ),
            ),

            check(
                "receiver producer binding type",
                "module_import",
                receiver_provenance.get(
                    "producer_binding_type"
                ),
            ),

            check(
                "receiver producer retries literal",
                0,
                provenance_retries.get(
                    "literal_value"
                ),
            ),

            check(
                "S_api",
                ">=1.9",
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
                "release history status",
                "partial",
                release_history.get(
                    "release_history_status"
                ),
            ),

            check(
                "confirmed releases before API",
                104,
                release_history.get(
                    "confirmed_release_count_"
                    "as_of_time_view"
                ),
            ),

            check(
                "latest confirmed release",
                "2.7.0",
                release_history.get(
                    "latest_confirmed_version_"
                    "as_of_time_view"
                ),
            ),

            check(
                "API-compatible count",
                87,
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
                87,
                feasible.get(
                    "confirmed_manifest_compatible_"
                    "release_count"
                ),
            ),

            check(
                "vulnerability id",
                "GHSA-pq67-6m6q-mj2v",
                vulnerability.get(
                    "vulnerability_id"
                ),
            ),

            check(
                "S_vuln",
                "<2.5.0",
                vulnerability.get(
                    "affected_version_specifier"
                ),
            ),

            check(
                "fixed version specifier",
                ">=2.5.0",
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
                "Trigger scope status",
                "resolved_with_scope",
                trigger_scope.get(
                    "status"
                ),
            ),

            check(
                "module-level binding supported",
                True,
                (
                    trigger_scope
                    .get(
                        "runtime_flow_limitations",
                        {},
                    )
                    .get(
                        "module_level_direct_"
                        "call_result_binding_supported"
                    )
                ),
            ),

            check(
                "retries=0 supported",
                True,
                (
                    trigger_scope
                    .get(
                        "runtime_flow_limitations",
                        {},
                    )
                    .get(
                        "retries_zero_literal_supported"
                    )
                ),
            ),

            check(
                "exposed count",
                81,
                exposed_evaluation.get(
                    "confirmed_exposed_release_count"
                ),
            ),

            check(
                "2.4.0 exposed",
                True,
                "2.4.0"
                in confirmed_exposed,
            ),

            check(
                "2.5.0 not exposed",
                False,
                "2.5.0"
                in confirmed_exposed,
            ),

            check(
                "2.5.0 not affected",
                True,
                "2.5.0"
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
                81,
                evaluation.get(
                    "confirmed_exposed_release_count"
                ),
            ),

            check(
                "Trigger kind",
                (
                    "receiver_producer_"
                    "keyword_literal_condition"
                ),
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
                    "receiver_producer_"
                    "keyword_literal_matched"
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
                "requires environment review",
                False,
                evaluation.get(
                    "requires_environment_review"
                ),
            ),

            check(
                "assessment",
                "candidate_requires_input_review",
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
                104,
                strength.get(
                    "v_before_api_count"
                ),
            ),

            check(
                "V_feasible",
                87,
                strength.get(
                    "v_feasible_count"
                ),
            ),

            check(
                "V_exposed",
                81,
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
                "Risk Card review priority",
                "high",
                risk_card.get(
                    "review_priority"
                ),
            ),

            check(
                "Risk Card observed APIs",
                [
                    "urllib3.PoolManager",
                    "urllib3.PoolManager.request",
                ],
                risk_api.get(
                    "observed_api_symbols"
                ),
            ),

            check(
                (
                    "Risk Card requires "
                    "environment review"
                ),
                False,
                risk_trigger_conditions.get(
                    "requires_environment_review"
                ),
            ),

            check(
                "Risk Card assessment",
                "candidate_requires_input_review",
                risk_trigger_conditions.get(
                    "assessment"
                ),
            ),

            check(
                "Risk Card repair action",
                (
                    "upgrade_dependency_and_"
                    "review_input"
                ),
                repair.get(
                    "action"
                ),
            ),

            check(
                "Risk Card repair command",
                (
                    "python -m pip install "
                    "\"urllib3>=2.5.0\""
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
        "AVCS urllib3 Trigger E2E"
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
        "[OK] AVCS urllib3 "
        "Trigger E2E ALL PASS"
    )


if __name__ == "__main__":
    main()