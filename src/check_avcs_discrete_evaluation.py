from __future__ import annotations

import csv
import json
import tempfile
from pathlib import Path
from typing import Any

from evaluate_avcs_overlap import evaluate_avcs


ROOT = Path(__file__).resolve().parents[1]

OUTPUT_PATH = (
    ROOT
    / "output"
    / "avcs_discrete_evaluation_validation.csv"
)


def write_json(
    path: Path,
    data: dict[str, Any],
) -> None:
    path.write_text(
        json.dumps(
            data,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )


def add_check(
    rows: list[dict[str, str]],
    check_id: str,
    expected: Any,
    actual: Any,
) -> None:
    rows.append(
        {
            "check_id": check_id,
            "expected": json.dumps(
                expected,
                ensure_ascii=False,
            ),
            "actual": json.dumps(
                actual,
                ensure_ascii=False,
            ),
            "status": (
                "PASS"
                if expected == actual
                else "FAIL"
            ),
        }
    )


def main() -> None:
    api_constraints = {
        "sample_id": "discrete_control",
        "call_constraints": [
            {
                "api_symbol": "demo.danger",
            }
        ],
        "distribution_constraints": [
            {
                "distribution": "DemoPkg",
                "normalized_distribution": "demopkg",
                "status": "resolved",
                "s_api": {
                    "simplified_specifier": ">=1",
                },
            }
        ],
    }

    vulnerability_constraints = {
        "distribution": "DemoPkg",
        "vulnerabilities": [
            {
                "vulnerability_id": "CVE-TEST-DISCRETE",
                "severity": "high",
                "affected_version_specifier": (
                    ">=1,<2"
                ),
                "fixed_version_specifier": ">=2",
                "trigger_conditions": {
                    "api_symbols": [
                        "demo.danger"
                    ],
                    "requires_untrusted_input": False,
                },
                "safe_api_symbols": [],
                "evidence_ref": "fixture",
            }
        ],
    }

    # 关键控制条件：
    #
    # 旧的区间判断：
    # >=1 ∩ >=1,<2
    # 明明存在交集。
    #
    # 但离散历史版本分析告诉我们：
    # confirmed exposed releases = 0。
    #
    # 因此最终必须以离散证据为准，
    # 不能产生 Risk Card candidate。
    exposed_releases = {
        "sample_id": "discrete_control",
        "distribution": "DemoPkg",
        "normalized_distribution": "demopkg",
        "evaluations": [
            {
                "vulnerability_id": (
                    "CVE-TEST-DISCRETE"
                ),
                "confirmed_api_compatible_release_count": 2,
                "confirmed_exposed_release_count": 0,
                "confirmed_not_affected_release_count": 2,
                "confirmed_exposed_releases": [],
                "time_unknown_exposed_release_labels": [],
            }
        ],
    }

    unresolved_vulnerability_constraints = {
        "distribution": "DemoPkg",
        "vulnerabilities": [
            {
                "vulnerability_id":
                    "CVE-TEST-UNRESOLVED",
                "severity": "high",

                "constraint_status":
                    "unsupported_range_shape",

                "affected_version_specifier":
                    "",

                "fixed_version_specifier":
                    "",

                "trigger_conditions": {
                    "api_symbols": [
                        "demo.danger"
                    ],
                    "requires_untrusted_input":
                        False,
                },

                "safe_api_symbols": [],
                "evidence_ref":
                    "fixture-unresolved",
            }
        ],
    }

    unresolved_exposed_releases = {
        "sample_id":
            "discrete_control",

        "distribution":
            "DemoPkg",

        "normalized_distribution":
            "demopkg",

        "evaluations": [
            {
                "vulnerability_id":
                    "CVE-TEST-UNRESOLVED",

                "status": (
                    "vulnerability_constraint_"
                    "unsupported_range_shape"
                ),

                "vulnerability_constraint_status":
                    "unsupported_range_shape",

                "confirmed_api_compatible_release_count":
                    2,

                "confirmed_exposed_release_count":
                    None,

                "confirmed_not_affected_release_count":
                    None,

                "confirmed_exposed_releases":
                    [],

                "time_unknown_exposed_release_labels":
                    [],
            }
        ],
    }

    with tempfile.TemporaryDirectory() as temp_dir:
        temp = Path(temp_dir)

        api_path = temp / "api.json"
        vuln_path = temp / "vuln.json"
        exposed_path = temp / "exposed.json"

        write_json(
            api_path,
            api_constraints,
        )

        write_json(
            vuln_path,
            vulnerability_constraints,
        )

        write_json(
            exposed_path,
            exposed_releases,
        )

        result = evaluate_avcs(
            api_constraints_path=api_path,
            vulnerability_constraints_path=(
                vuln_path
            ),
            exposed_releases_path=(
                exposed_path
            ),
        )

        unresolved_vuln_path = (
            temp / "unresolved_vuln.json"
        )

        unresolved_exposed_path = (
            temp / "unresolved_exposed.json"
        )

        write_json(
            unresolved_vuln_path,
            unresolved_vulnerability_constraints,
        )

        write_json(
            unresolved_exposed_path,
            unresolved_exposed_releases,
        )

        unresolved_result = evaluate_avcs(
            api_constraints_path=api_path,
            vulnerability_constraints_path=(
                unresolved_vuln_path
            ),
            exposed_releases_path=(
                unresolved_exposed_path
            ),
        )

    evaluation = result["evaluations"][0]

    unresolved_evaluation = (
        unresolved_result[
            "evaluations"
        ][0]
    )

    rows: list[dict[str, str]] = []

    add_check(
        rows,
        "interval_overlap_still_true",
        True,
        evaluation["version_overlap"],
    )

    add_check(
        rows,
        "version_evidence_mode",
        "discrete_confirmed_releases",
        evaluation["version_evidence_mode"],
    )

    add_check(
        rows,
        "discrete_exposed_count",
        0,
        evaluation[
            "confirmed_exposed_release_count"
        ],
    )

    add_check(
        rows,
        "has_version_exposure",
        False,
        evaluation["has_version_exposure"],
    )

    add_check(
        rows,
        "assessment_uses_discrete_result",
        "no_version_overlap",
        evaluation["assessment"],
    )

    add_check(
        rows,
        "candidate_suppressed_by_discrete_result",
        False,
        evaluation["risk_card_candidate"],
    )

    add_check(
        rows,
        "unresolved_vulnerability_constraint_status",
        "unsupported_range_shape",
        unresolved_evaluation[
            "vulnerability_constraint_status"
        ],
    )

    add_check(
        rows,
        "unresolved_discrete_evidence_status",
        (
            "vulnerability_constraint_"
            "unsupported_range_shape"
        ),
        unresolved_evaluation[
            "discrete_evidence_status"
        ],
    )

    add_check(
        rows,
        "unresolved_version_evidence_mode",
        "discrete_evidence_unresolved",
        unresolved_evaluation[
            "version_evidence_mode"
        ],
    )

    add_check(
        rows,
        "unresolved_has_version_exposure",
        None,
        unresolved_evaluation[
            "has_version_exposure"
        ],
    )

    add_check(
        rows,
        "unresolved_version_overlap",
        None,
        unresolved_evaluation[
            "version_overlap"
        ],
    )

    add_check(
        rows,
        "unresolved_assessment",
        "vulnerability_constraint_requires_review",
        unresolved_evaluation[
            "assessment"
        ],
    )

    add_check(
        rows,
        "unresolved_candidate",
        False,
        unresolved_evaluation[
            "risk_card_candidate"
        ],
    )

    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with OUTPUT_PATH.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "check_id",
                "expected",
                "actual",
                "status",
            ],
        )

        writer.writeheader()
        writer.writerows(rows)

    passed = sum(
        row["status"] == "PASS"
        for row in rows
    )

    failed = len(rows) - passed

    print(
        f"[OK] total tests: {len(rows)}"
    )
    print(
        f"[OK] passed: {passed}"
    )
    print(
        f"[OK] failed: {failed}"
    )
    print(
        f"[OK] result saved to: "
        f"{OUTPUT_PATH}"
    )

    for row in rows:
        print(
            f"[{row['status']}] "
            f"{row['check_id']}"
        )

    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()