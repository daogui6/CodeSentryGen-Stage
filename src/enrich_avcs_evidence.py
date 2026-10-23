from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "avcs_trigger_evidence_for_sceg_v0.1"


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )


def build_trigger_evidence(
    evaluation: dict[str, Any],
) -> dict[str, Any]:
    """
    将 AVCS evaluation 转换为 SCEG 可消费的 trigger evidence。

    输入：
        evaluate_avcs_overlap.py 输出

    输出：
        SCEG evidence.trigger
    """

    distribution = evaluation.get(
        "distribution",
        "",
    )

    trigger_calls = []

    evaluations = evaluation.get(
        "evaluations",
        [],
    )

    vulnerability_id = None
    severity = None

    observed_trigger_apis = []
    trigger_api_symbols = []

    risk_candidate = False
    assessment = None

    version_constraint = {}

    if evaluations:
        row = evaluations[0]

        vulnerability_id = row.get(
            "vulnerability_id"
        )

        severity = row.get(
            "severity"
        )

        observed_trigger_apis = row.get(
            "observed_trigger_apis",
            [],
        )

        trigger_api_symbols = row.get(
            "trigger_api_symbols",
            [],
        )

        trigger_calls = row.get(
            "observed_trigger_calls",
            [],
        )

        risk_candidate = row.get(
            "risk_card_candidate",
            False,
        )

        assessment = row.get(
            "assessment"
        )

        version_constraint = {
            "s_api": row.get(
                "s_api",
                "",
            ),
            "s_vuln": row.get(
                "s_vuln",
                "",
            ),
            "intersection_specifier": row.get(
                "intersection_specifier",
                "",
            ),
            "fixed_version_specifier": row.get(
                "fixed_version_specifier",
                "",
            ),
            "version_evidence_mode": row.get(
                "version_evidence_mode",
                "",
            ),
        }

    return {
        "schema_version": SCHEMA_VERSION,

        "distribution": distribution,

        "vulnerability": {
            "vulnerability_id": vulnerability_id,
            "severity": severity,
        },

        "trigger": {
            "matched": bool(
                trigger_calls
            ),

            "risk_candidate": risk_candidate,

            "assessment": assessment,

            "trigger_api_symbols": trigger_api_symbols,

            "observed_trigger_apis": observed_trigger_apis,

            "trigger_calls": trigger_calls,
        },

        "version_constraint": version_constraint,

        "evidence_source": {
            "source_type": "avcs_evaluation",
            "source_schema_version": evaluation.get(
                "schema_version"
            ),
            "sample_id": evaluation.get(
                "sample_id"
            ),
        },
    }


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Convert AVCS evaluation "
            "into SCEG trigger evidence."
        )
    )

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

    evaluation = load_json(
        args.evaluation
    )

    result = build_trigger_evidence(
        evaluation
    )

    args.out.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    args.out.write_text(
        json.dumps(
            result,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    print(
        "[OK] AVCS trigger evidence generated"
    )

    print(
        f"[OK] sample: {result['evidence_source']['sample_id']}"
    )

    print(
        f"[OK] vulnerability: "
        f"{result['vulnerability']['vulnerability_id']}"
    )

    print(
        f"[OK] trigger matched: "
        f"{result['trigger']['matched']}"
    )

    print(
        f"[OK] saved: {args.out}"
    )


if __name__ == "__main__":
    main()