from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def make_risk_id(
    sample_id: str,
    distribution: str,
    vulnerability_id: str,
) -> str:
    value = "|".join(
        [
            sample_id,
            distribution,
            vulnerability_id,
            "api_vulnerability_compatibility",
        ]
    )

    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()[:16]


def build_avcs_risk_cards(
    evaluation_path: Path,
) -> list[dict[str, Any]]:
    evaluation_data = load_json(evaluation_path)

    sample_id = str(
        evaluation_data.get("sample_id", "")
    )
    distribution = str(
        evaluation_data.get("distribution", "")
    )

    sample_context = evaluation_data.get(
        "sample_context",
        {},
    )

    if not isinstance(sample_context, dict):
        sample_context = {}

    prompt_id = sample_context.get("prompt_id")
    model = sample_context.get("model")

    cards: list[dict[str, Any]] = []

    for evaluation in evaluation_data.get(
        "evaluations",
        [],
    ):
        if not evaluation.get(
            "risk_card_candidate",
            False,
        ):
            continue

        vulnerability_id = str(
            evaluation.get(
                "vulnerability_id",
                "",
            )
        )

        trigger_calls = evaluation.get(
            "observed_trigger_calls",
            [],
        )

        primary_trigger_call = (
            trigger_calls[0]
            if (
                    isinstance(trigger_calls, list)
                    and trigger_calls
                    and isinstance(trigger_calls[0], dict)
            )
            else {}
        )

        primary_location = (
            primary_trigger_call.get(
                "location",
                {},
            )
            if isinstance(
                primary_trigger_call,
                dict,
            )
            else {}
        )

        requires_input_review = bool(
            evaluation.get(
                "requires_untrusted_input",
                False,
            )
        )

        requires_environment_review = bool(
            evaluation.get(
                "requires_environment_review",
                False,
            )
        )

        environment_preconditions_status = str(
            evaluation.get(
                "environment_preconditions_status",
                "not_required",
            )
        )

        environment_preconditions = (
            evaluation.get(
                "environment_preconditions",
                {},
            )
        )

        if not isinstance(
                environment_preconditions,
                dict,
        ):
            environment_preconditions = {}

        requires_context_review = (
                requires_input_review
                or requires_environment_review
        )

        fixed_version_specifier = str(
            evaluation.get(
                "fixed_version_specifier",
                "",
            )
        ).strip()

        repair_command = (
            "python -m pip install "
            f"\"{distribution}{fixed_version_specifier}\""
            if fixed_version_specifier
            else None
        )

        if requires_context_review:
            evidence_level = "moderate"
            review_priority = "high"
            status = "candidate"
        else:
            evidence_level = "strong"
            review_priority = "high"
            status = "probable"

        cards.append(
            {
                "schema_version": "pilot_v0.2",
                "risk_id": make_risk_id(
                    sample_id,
                    distribution,
                    vulnerability_id,
                ),
                "sample_id": sample_id,
                "prompt_id": prompt_id,
                "model": model,
                "title": (
                    "API-compatible vulnerable version "
                    f"candidate: {distribution}"
                ),
                "type": (
                    "api_vulnerability_compatibility"
                ),
                "subtype": (
                    "vulnerable_version_overlap"
                ),
                "status": status,
                "severity": evaluation.get(
                    "severity",
                    "not_calibrated",
                ),
                "evidence_level": evidence_level,
                "review_priority": review_priority,
                "introduced_by": {
                    "file": primary_location.get(
                        "file"
                    ),
                    "line": primary_location.get(
                        "line"
                    ),
                    "entity": distribution,
                    "raw_name": distribution,
                    "source_type": "api_call",
                },
                "install_reachability": {
                    "level": "not_evaluated",
                    "original_level": None,
                    "v2_level": None,
                    "evidence": None,
                },
                "evidence": {
                    "sample_context": {
                        "status": evaluation_data.get(
                            "sample_context_status",
                            "not_provided",
                        ),
                        "source_sample_id": sample_context.get(
                            "source_sample_id"
                        ),
                        "source_dataset": sample_context.get(
                            "source_dataset"
                        ),
                        "source": sample_context.get(
                            "source"
                        ),
                        "language": sample_context.get(
                            "language"
                        ),
                        "ecosystem": sample_context.get(
                            "ecosystem"
                        ),
                        "generation_time": sample_context.get(
                            "generation_time"
                        ),
                    },
                    "api": {
                        "observed_api_symbols": (
                            evaluation.get(
                                "observed_api_symbols",
                                [],
                            )
                        ),
                        "observed_trigger_apis": (
                            evaluation.get(
                                "observed_trigger_apis",
                                [],
                            )
                        ),
                        "observed_safe_apis": (
                            evaluation.get(
                                "observed_safe_apis",
                                [],
                            )
                        ),
                        "observed_trigger_calls": (
                            trigger_calls
                        ),
                    },
                    "version_constraints": {
                        "s_api": evaluation.get(
                            "s_api",
                            "",
                        ),
                        "s_vuln": evaluation.get(
                            "s_vuln",
                            "",
                        ),
                        "fixed_version_specifier": (
                            fixed_version_specifier
                        ),
                        "intersection_specifier": (
                            evaluation.get(
                                "intersection_specifier",
                                "",
                            )
                        ),
                        "version_evidence_mode": (
                            evaluation.get(
                                "version_evidence_mode",
                                "",
                            )
                        ),
                        "intersection_semantics": (
                            evaluation.get(
                                "intersection_semantics",
                                "",
                            )
                        ),
                    },
                    "vulnerability": {
                        "vulnerability_id": (
                            vulnerability_id
                        ),
                        "evidence_ref": (
                            evaluation.get(
                                "evidence_ref",
                                "",
                            )
                        ),
                    },
                                        "trigger_conditions": {
                        "requires_untrusted_input": (
                            requires_input_review
                        ),

                        "requires_environment_review": (
                            requires_environment_review
                        ),

                        "environment_preconditions_status": (
                            environment_preconditions_status
                        ),

                        "environment_preconditions": (
                            environment_preconditions
                        ),

                        "assessment": (
                            evaluation.get(
                                "assessment",
                                "",
                            )
                        ),
                    },
                    "reason": (
                        "The generated code uses a "
                        "vulnerability-triggering API, and "
                        "the API-compatible version range "
                        "overlaps the affected version range."
                    ),
                },
                "attribution": {
                    "observable_labels": [
                        "api_constraint_resolved",
                        "vulnerable_version_overlap",
                        "trigger_api_observed",
                    ],
                    "hypotheses": [
                        {
                            "name": (
                                "vulnerable_dependency_version"
                            ),
                            "rank": 1,
                            "rationale": (
                                "A package version can satisfy "
                                "the observed API requirements "
                                "while remaining inside the "
                                "vulnerability-affected range."
                            ),
                        }
                    ],
                },
                                "repair": {
                    "action": (
                        (
                            "upgrade_dependency_and_review_environment"
                        )
                        if requires_environment_review
                        else (
                            "upgrade_dependency_and_review_input"
                        )
                    ),

                    "command": repair_command,

                    "patch": None,

                    "verify": (
                        (
                            "Upgrade to a fixed version, rerun "
                            "tests, and review the vulnerability-"
                            "relevant runtime environment and "
                            "configuration preconditions before "
                            "treating the trigger as confirmed."
                        )
                        if requires_environment_review
                        else (
                            "Upgrade to a fixed version, rerun "
                            "tests, and review whether "
                            "vulnerability-relevant inputs or "
                            "resources can be controlled by an "
                            "untrusted source."
                        )
                    ),
                },
            }
        )

    return cards


def write_jsonl(
    path: Path,
    rows: list[dict[str, Any]],
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with path.open(
        "w",
        encoding="utf-8",
    ) as file:
        for row in rows:
            file.write(
                json.dumps(
                    row,
                    ensure_ascii=False,
                )
                + "\n"
            )


def main() -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--evaluation",
        type=Path,
        required=True,
    )

    parser.add_argument(
        "--out",
        type=Path,
        required=True,
    )

    args = parser.parse_args()

    cards = build_avcs_risk_cards(
        evaluation_path=args.evaluation,
    )

    write_jsonl(
        args.out,
        cards,
    )

    print(
        f"[OK] AVCS Risk Cards: {len(cards)}"
    )
    print(
        f"[OK] result saved to: {args.out}"
    )


if __name__ == "__main__":
    main()