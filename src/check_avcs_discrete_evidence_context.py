from __future__ import annotations

import csv
import json
import tempfile
from pathlib import Path
from typing import Any

from evaluate_avcs_overlap import evaluate_avcs


ROOT = Path(__file__).resolve().parents[1]
OUTPUT_PATH = ROOT / "output" / "avcs_discrete_evidence_context_validation.csv"


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


def run_case(
    exposed_sample_id: str,
    exposed_distribution: str,
    exposed_vulnerability_id: str,
) -> dict[str, Any]:
    api_constraints = {
        "sample_id": "sample_A",
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
                "vulnerability_id": "CVE-DEMO-001",
                "severity": "high",
                "affected_version_specifier": ">=1,<2",
                "trigger_conditions": {
                    "api_symbols": [
                        "demo.danger"
                    ],
                    "requires_untrusted_input": False,
                },
                "safe_api_symbols": [],
            }
        ],
    }

    exposed_releases = {
        "sample_id": exposed_sample_id,
        "distribution": exposed_distribution,
        "normalized_distribution": (
            exposed_distribution.lower()
        ),
        "evaluations": [
            {
                "vulnerability_id": (
                    exposed_vulnerability_id
                ),
                "confirmed_api_compatible_release_count": 2,
                "confirmed_exposed_release_count": 1,
                "confirmed_not_affected_release_count": 1,
                "confirmed_exposed_releases": [
                    {
                        "version": "1.5",
                    }
                ],
                "time_unknown_exposed_release_labels": [],
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
            exposed_releases_path=exposed_path,
        )

    return result["evaluations"][0]


def check(
    name: str,
    expected: Any,
    actual: Any,
) -> bool:
    passed = expected == actual

    print(
        f"[{'PASS' if passed else 'FAIL'}] "
        f"{name} | "
        f"expected={expected!r} | "
        f"actual={actual!r}"
    )

    return passed

def make_validation_row(
    check_id: str,
    description: str,
    expected: Any,
    actual: Any,
) -> dict[str, str]:
    passed = expected == actual

    def format_value(value: Any) -> str:
        if value is None:
            return "null"
        if isinstance(value, bool):
            return str(value).lower()
        return str(value)

    return {
        "check_id": check_id,
        "description": description,
        "expected": format_value(expected),
        "actual": format_value(actual),
        "status": "PASS" if passed else "FAIL",
    }

def main() -> None:
    results: list[bool] = []

    # 1. 全部一致
    matched = run_case(
        exposed_sample_id="sample_A",
        exposed_distribution="DemoPkg",
        exposed_vulnerability_id="CVE-DEMO-001",
    )

    results.append(
        check(
            "matched_status",
            "matched",
            matched[
                "discrete_evidence_status"
            ],
        )
    )

    results.append(
        check(
            "matched_mode",
            "discrete_confirmed_releases",
            matched[
                "version_evidence_mode"
            ],
        )
    )

    # 2. 故意串另一个 sample
    sample_mismatch = run_case(
        exposed_sample_id="sample_B",
        exposed_distribution="DemoPkg",
        exposed_vulnerability_id="CVE-DEMO-001",
    )

    results.append(
        check(
            "sample_mismatch_status",
            "sample_id_mismatch",
            sample_mismatch[
                "discrete_evidence_status"
            ],
        )
    )

    results.append(
        check(
            "sample_mismatch_candidate",
            False,
            sample_mismatch[
                "risk_card_candidate"
            ],
        )
    )

    # 3. 故意串另一个 package
    distribution_mismatch = run_case(
        exposed_sample_id="sample_A",
        exposed_distribution="OtherPkg",
        exposed_vulnerability_id="CVE-DEMO-001",
    )

    results.append(
        check(
            "distribution_mismatch_status",
            "distribution_mismatch",
            distribution_mismatch[
                "discrete_evidence_status"
            ],
        )
    )

    results.append(
        check(
            "distribution_mismatch_candidate",
            False,
            distribution_mismatch[
                "risk_card_candidate"
            ],
        )
    )

    # 4. 故意串另一个 CVE
    vulnerability_mismatch = run_case(
        exposed_sample_id="sample_A",
        exposed_distribution="DemoPkg",
        exposed_vulnerability_id="CVE-OTHER",
    )

    results.append(
        check(
            "vulnerability_mismatch_status",
            "vulnerability_not_found",
            vulnerability_mismatch[
                "discrete_evidence_status"
            ],
        )
    )

    results.append(
        check(
            "vulnerability_mismatch_candidate",
            False,
            vulnerability_mismatch[
                "risk_card_candidate"
            ],
        )
    )

    results.append(
        check(
            "vulnerability_mismatch_assessment",
            "discrete_evidence_requires_review",
            vulnerability_mismatch[
                "assessment"
            ],
        )
    )

    passed = sum(results)
    failed = len(results) - passed

    validation_rows = [
        make_validation_row(
            "matched_status",
            "正确的离散版本证据与当前样本匹配",
            "matched",
            matched["discrete_evidence_status"],
        ),
        make_validation_row(
            "matched_mode",
            "匹配成功后使用离散真实版本证据",
            "discrete_confirmed_releases",
            matched["version_evidence_mode"],
        ),
        make_validation_row(
            "sample_mismatch_status",
            "样本不匹配时识别证据串线",
            "sample_id_mismatch",
            sample_mismatch["discrete_evidence_status"],
        ),
        make_validation_row(
            "sample_mismatch_candidate",
            "样本不匹配时不生成风险候选",
            False,
            sample_mismatch["risk_card_candidate"],
        ),
        make_validation_row(
            "distribution_mismatch_status",
            "软件包不匹配时识别证据串线",
            "distribution_mismatch",
            distribution_mismatch["discrete_evidence_status"],
        ),
        make_validation_row(
            "distribution_mismatch_candidate",
            "软件包不匹配时不生成风险候选",
            False,
            distribution_mismatch["risk_card_candidate"],
        ),
        make_validation_row(
            "vulnerability_mismatch_status",
            "漏洞编号不匹配时识别错误漏洞证据",
            "vulnerability_not_found",
            vulnerability_mismatch["discrete_evidence_status"],
        ),
        make_validation_row(
            "vulnerability_mismatch_candidate",
            "漏洞编号不匹配时不生成风险候选",
            False,
            vulnerability_mismatch["risk_card_candidate"],
        ),
        make_validation_row(
            "vulnerability_mismatch_assessment",
            "漏洞证据不匹配时保留人工复核状态",
            "discrete_evidence_requires_review",
            vulnerability_mismatch["assessment"],
        ),
    ]

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_PATH.open(
            "w",
            encoding="utf-8-sig",
            newline="",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "check_id",
                "description",
                "expected",
                "actual",
                "status",
            ],
        )
        writer.writeheader()
        writer.writerows(validation_rows)

    print()
    print(f"[OK] total tests: {len(results)}")
    print(f"[OK] passed: {passed}")
    print(f"[OK] failed: {failed}")
    print(f"[OK] result saved to: {OUTPUT_PATH}")

    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()