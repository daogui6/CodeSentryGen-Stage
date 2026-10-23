from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from resolve_avcs_manifest_constraints import parse_manifest_constraints


ROOT = Path(__file__).resolve().parents[1]
OUTPUT_PATH = ROOT / "output" / "avcs_manifest_constraints_validation.csv"


def check(
    name: str,
    actual: Any,
    expected: Any,
) -> bool:
    passed = actual == expected

    status = "PASS" if passed else "FAIL"

    print(
        f"[{status}] {name} | "
        f"expected={expected!r} | actual={actual!r}"
    )

    return passed

def make_validation_row(
    case_id: str,
    requirements_text: str,
    expected_status: str,
    actual_status: str,
    expected_kind: str,
    actual_kind: str,
    expected_specifier: str,
    actual_specifier: str,
) -> dict[str, str]:
    passed = (
        expected_status == actual_status
        and expected_kind == actual_kind
        and expected_specifier == actual_specifier
    )

    return {
        "case_id": case_id,
        "requirements_text": requirements_text,
        "expected_status": expected_status,
        "actual_status": actual_status,
        "expected_kind": expected_kind,
        "actual_kind": actual_kind,
        "expected_specifier": expected_specifier,
        "actual_specifier": actual_specifier,
        "status": "PASS" if passed else "FAIL",
    }

def main() -> None:
    results: list[bool] = []

    unconstrained = parse_manifest_constraints(
        requirements_text="PyYAML",
        distribution="PyYAML",
    )

    results.append(
        check(
            "unconstrained_status",
            unconstrained["status"],
            "resolved",
        )
    )

    results.append(
        check(
            "unconstrained_kind",
            unconstrained["constraint_kind"],
            "unconstrained",
        )
    )

    versioned = parse_manifest_constraints(
        requirements_text="PyYAML>=5.4",
        distribution="PyYAML",
    )

    results.append(
        check(
            "versioned_status",
            versioned["status"],
            "resolved",
        )
    )

    results.append(
        check(
            "versioned_specifier",
            versioned["specifier"],
            ">=5.4",
        )
    )

    not_declared = parse_manifest_constraints(
        requirements_text="requests>=2.31.0",
        distribution="PyYAML",
    )

    results.append(
        check(
            "not_declared_status",
            not_declared["status"],
            "not_declared",
        )
    )

    results.append(
        check(
            "not_declared_kind",
            not_declared["constraint_kind"],
            "not_declared",
        )
    )

    conditional = parse_manifest_constraints(
        requirements_text='PyYAML>=5.4; python_version >= "3.10"',
        distribution="PyYAML",
    )

    results.append(
        check(
            "conditional_status",
            conditional["status"],
            "conditional",
        )
    )

    results.append(
        check(
            "conditional_specifier",
            conditional["specifier"],
            ">=5.4",
        )
    )

    total = len(results)
    passed = sum(results)
    failed = total - passed

    validation_rows = [
        make_validation_row(
            "unconstrained",
            "PyYAML",
            "resolved",
            unconstrained["status"],
            "unconstrained",
            unconstrained["constraint_kind"],
            "",
            unconstrained["specifier"],
        ),
        make_validation_row(
            "versioned",
            "PyYAML>=5.4",
            "resolved",
            versioned["status"],
            "version_specifier",
            versioned["constraint_kind"],
            ">=5.4",
            versioned["specifier"],
        ),
        make_validation_row(
            "not_declared",
            "requests>=2.31.0",
            "not_declared",
            not_declared["status"],
            "not_declared",
            not_declared["constraint_kind"],
            "",
            not_declared["specifier"],
        ),
        make_validation_row(
            "conditional",
            'PyYAML>=5.4; python_version >= "3.10"',
            "conditional",
            conditional["status"],
            "environment_marker",
            conditional["constraint_kind"],
            ">=5.4",
            conditional["specifier"],
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
                "case_id",
                "requirements_text",
                "expected_status",
                "actual_status",
                "expected_kind",
                "actual_kind",
                "expected_specifier",
                "actual_specifier",
                "status",
            ],
        )
        writer.writeheader()
        writer.writerows(validation_rows)

    print()
    print(f"[OK] total tests: {total}")
    print(f"[OK] passed: {passed}")
    print(f"[OK] failed: {failed}")
    print(f"[OK] result saved to: {OUTPUT_PATH}")

    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()