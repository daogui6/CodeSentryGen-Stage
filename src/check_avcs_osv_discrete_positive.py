from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(
        path.read_text(encoding="utf-8")
    )


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    with path.open("r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if line:
                rows.append(json.loads(line))

    return rows


def check(
    name: str,
    expected: Any,
    actual: Any,
) -> bool:
    passed = expected == actual

    status = "PASS" if passed else "FAIL"

    print(
        f"[{status}] {name} | "
        f"expected={expected!r} | "
        f"actual={actual!r}"
    )

    return passed


def check_close(
    name: str,
    expected: float,
    actual: float | None,
    tolerance: float = 1e-9,
) -> bool:
    passed = (
        actual is not None
        and math.isclose(
            actual,
            expected,
            rel_tol=tolerance,
            abs_tol=tolerance,
        )
    )

    status = "PASS" if passed else "FAIL"

    print(
        f"[{status}] {name} | "
        f"expected≈{expected!r} | "
        f"actual={actual!r}"
    )

    return passed


def main() -> None:
    vulnerability = read_json(
        ROOT
        / "output"
        / (
            "avcs_control_full_load_discrete_"
            "vulnerability_constraints_"
            "trigger_enriched_v0.json"
        )
    )

    release_history = read_json(
        ROOT
        / "output"
        / (
            "avcs_control_full_load_discrete_"
            "pyyaml_release_history_v0.json"
        )
    )

    api_compatible = read_json(
        ROOT
        / "output"
        / (
            "avcs_control_full_load_discrete_"
            "api_compatible_releases_v0.json"
        )
    )

    manifest_compatible = read_json(
        ROOT
        / "output"
        / (
            "avcs_control_full_load_discrete_"
            "manifest_compatible_releases_v0.json"
        )
    )

    exposed = read_json(
        ROOT
        / "output"
        / (
            "avcs_control_full_load_discrete_"
            "exposed_releases_v0.json"
        )
    )

    evaluation = read_json(
        ROOT
        / "output"
        / (
            "avcs_control_full_load_discrete_"
            "evaluation_v0.json"
        )
    )

    evidence_strength = read_json(
        ROOT
        / "output"
        / (
            "avcs_control_full_load_discrete_"
            "evidence_strength_status_v0.json"
        )
    )

    cards = read_jsonl(
        ROOT
        / "output"
        / (
            "avcs_control_full_load_discrete_"
            "risk_cards_v0.jsonl"
        )
    )

    vuln = vulnerability["vulnerabilities"][0]
    eval_row = evaluation["evaluations"][0]
    exposed_row = exposed["evaluations"][0]

    strength_row = (
        evidence_strength["evaluations"][0]
    )

    results = [
        check(
            "OSV source mode",
            "normalized_osv_evidence",
            vulnerability.get("source_mode"),
        ),
        check(
            "OSV vulnerability id",
            "PYSEC-2021-142",
            vuln.get("vulnerability_id"),
        ),
        check(
            "OSV S_vuln",
            "<5.4",
            vuln.get(
                "affected_version_specifier"
            ),
        ),
        check(
            "fixed version",
            ">=5.4",
            vuln.get(
                "fixed_version_specifier"
            ),
        ),
        check(
            "trigger evidence resolved",
            "resolved",
            vuln.get(
                "trigger_evidence_status"
            ),
        ),
        check(
            "confirmed releases",
            31,
            release_history.get(
                "confirmed_release_count_as_of_time_view"
            ),
        ),
        check(
            "API-compatible releases",
            18,
            api_compatible.get(
                "confirmed_api_compatible_release_count"
            ),
        ),
        check(
            "manifest-compatible releases",
            18,
            manifest_compatible.get(
                "confirmed_manifest_compatible_release_count"
            ),
        ),
        check(
            "exposed releases",
            10,
            exposed_row.get(
                "confirmed_exposed_release_count"
            ),
        ),
        check(
            "PyYAML 5.4b1 explicitly affected",
            True,
            any(
                str(release.get("version", ""))
                == "5.4b1"
                for release in exposed_row.get(
                    "confirmed_exposed_releases",
                    [],
                )
            ),
        ),

        check(
            "PyYAML 5.4b2 explicitly affected",
            True,
            any(
                str(release.get("version", ""))
                == "5.4b2"
                for release in exposed_row.get(
                    "confirmed_exposed_releases",
                    [],
                )
            ),
        ),
        check(
            "version evidence mode",
            "discrete_confirmed_releases",
            eval_row.get(
                "version_evidence_mode"
            ),
        ),
        check(
            "intersection semantics",
            "interval_summary_only",
            eval_row.get(
                "intersection_semantics"
            ),
        ),
        check(
            "version exposure",
            True,
            eval_row.get(
                "has_version_exposure"
            ),
        ),
        check(
            "trigger API",
            ["yaml.full_load"],
            eval_row.get(
                "observed_trigger_apis"
            ),
        ),
        check(
            "assessment",
            "candidate_requires_input_review",
            eval_row.get("assessment"),
        ),
        check(
            "candidate count",
            1,
            evaluation.get(
                "risk_card_candidate_count"
            ),
        ),
        check(
            "Risk Card count",
            1,
            len(cards),
        ),
        check(
            "Risk Card intersection semantics",
            "interval_summary_only",
            (
                cards[0]
                .get("evidence", {})
                .get("version_constraints", {})
                .get("intersection_semantics")
                if cards
                else None
            ),
        ),
        check(
            "evidence strength status",
            "partial",
            evidence_strength.get(
                "status"
            ),
        ),

        check(
            "strength evaluation status",
            "partial",
            strength_row.get(
                "status"
            ),
        ),

        check(
            "V_before_api status",
            "partial",
            strength_row.get(
                "v_before_api_status"
            ),
        ),

        check(
            "time-unknown before API",
            9,
            strength_row.get(
                "time_unknown_before_api_candidate_count"
            ),
        ),

        check(
            "V_feasible status",
            "resolved",
            strength_row.get(
                "v_feasible_status"
            ),
        ),

        check(
            "time-unknown feasible",
            0,
            strength_row.get(
                "time_unknown_feasible_candidate_count"
            ),
        ),

        check(
            "V_exposed status",
            "resolved",
            strength_row.get(
                "v_exposed_status"
            ),
        ),

        check(
            "time-unknown exposed",
            0,
            strength_row.get(
                "time_unknown_exposed_candidate_count"
            ),
        ),

        check(
            "Reduction status",
            "partial",
            strength_row.get(
                "reduction_status"
            ),
        ),

        check(
            "ExposureRatio status",
            "resolved",
            strength_row.get(
                "exposure_ratio_status"
            ),
        ),

        check(
            "FixedExcluded status",
            "resolved",
            strength_row.get(
                "fixed_excluded_status"
            ),
        ),

        check(
            "V_before_api count",
            31,
            strength_row.get(
                "v_before_api_count"
            ),
        ),

        check(
            "V_feasible count",
            18,
            strength_row.get(
                "v_feasible_count"
            ),
        ),

        check(
            "V_exposed strength count",
            10,
            strength_row.get(
                "v_exposed_count"
            ),
        ),

        check_close(
            "Reduction",
            1.0 - 18.0 / 31.0,
            strength_row.get(
                "reduction"
            ),
        ),

        check_close(
            "ExposureRatio",
            10.0 / 18.0,
            strength_row.get(
                "exposure_ratio"
            ),
        ),

        check(
            "FixedExcluded",
            False,
            strength_row.get(
                "fixed_excluded"
            ),
        ),
    ]

    passed = sum(results)
    total = len(results)

    print("")
    print(f"[OK] total checks: {total}")
    print(f"[OK] passed: {passed}")
    print(
        f"[OK] failed: {total - passed}"
    )

    if passed != total:
        raise SystemExit(1)

    print(
        "[OK] OSV discrete positive "
        "validation ALL PASS"
    )


if __name__ == "__main__":
    main()