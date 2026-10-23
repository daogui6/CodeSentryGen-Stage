from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement

from normalizer import pep503_normalize


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    with path.open("r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if line:
                rows.append(json.loads(line))

    return rows


def find_sample(
    rows: list[dict[str, Any]],
    sample_id: str,
) -> dict[str, Any] | None:
    for row in rows:
        if str(row.get("sample_id", "")) == sample_id:
            return row

    return None


def parse_manifest_constraints(
    requirements_text: str,
    distribution: str,
) -> dict[str, Any]:
    normalized_distribution = pep503_normalize(distribution)

    matched_requirements: list[dict[str, Any]] = []
    invalid_lines: list[str] = []

    for raw_line in requirements_text.splitlines():
        line = raw_line.strip().lstrip("\ufeff")

        if not line:
            continue

        if line.startswith("#"):
            continue

        if line.startswith("-"):
            continue

        line = line.split("#", 1)[0].strip()

        if not line:
            continue

        try:
            requirement = Requirement(line)
        except InvalidRequirement:
            invalid_lines.append(raw_line)
            continue

        if pep503_normalize(requirement.name) != normalized_distribution:
            continue

        matched_requirements.append(
            {
                "name": requirement.name,
                "normalized_name": pep503_normalize(
                    requirement.name
                ),
                "specifier": str(requirement.specifier),
                "extras": sorted(requirement.extras),
                "marker": (
                    str(requirement.marker)
                    if requirement.marker is not None
                    else ""
                ),
                "url": requirement.url or "",
                "original_text": raw_line,
            }
        )

    if not matched_requirements:
        return {
            "status": "not_declared",
            "constraint_kind": "not_declared",
            "specifier": "",
            "matched_requirements": [],
            "invalid_lines": invalid_lines,
        }

    has_url = any(
        item["url"]
        for item in matched_requirements
    )

    if has_url:
        return {
            "status": "unsupported_direct_url",
            "constraint_kind": "direct_url",
            "specifier": "",
            "matched_requirements": matched_requirements,
            "invalid_lines": invalid_lines,
        }

    has_marker = any(
        item["marker"]
        for item in matched_requirements
    )

    specifiers = [
        item["specifier"]
        for item in matched_requirements
        if item["specifier"]
    ]

    combined_specifier = ",".join(specifiers)

    if has_marker:
        return {
            "status": "conditional",
            "constraint_kind": "environment_marker",
            "specifier": combined_specifier,
            "matched_requirements": matched_requirements,
            "invalid_lines": invalid_lines,
        }

    if not combined_specifier:
        return {
            "status": "resolved",
            "constraint_kind": "unconstrained",
            "specifier": "",
            "matched_requirements": matched_requirements,
            "invalid_lines": invalid_lines,
        }

    return {
        "status": "resolved",
        "constraint_kind": "version_specifier",
        "specifier": combined_specifier,
        "matched_requirements": matched_requirements,
        "invalid_lines": invalid_lines,
    }


def resolve_manifest_constraints(
    sample: dict[str, Any],
    distribution: str,
) -> dict[str, Any]:
    sample_id = str(sample.get("sample_id", ""))
    requirements_text = str(
        sample.get("requirements_text", "") or ""
    )

    constraint = parse_manifest_constraints(
        requirements_text=requirements_text,
        distribution=distribution,
    )

    return {
        "schema_version": "avcs_manifest_constraints_v0.1",
        "sample_id": sample_id,
        "distribution": distribution,
        "normalized_distribution": pep503_normalize(
            distribution
        ),
        "requirements_text": requirements_text,
        "status": constraint["status"],
        "constraint_kind": constraint["constraint_kind"],
        "specifier": constraint["specifier"],
        "matched_requirements": constraint[
            "matched_requirements"
        ],
        "invalid_lines": constraint["invalid_lines"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Resolve AVCS manifest version constraints "
            "from sample requirements_text."
        )
    )

    parser.add_argument(
        "--samples",
        type=Path,
        required=True,
    )

    parser.add_argument(
        "--sample-id",
        required=True,
    )

    parser.add_argument(
        "--distribution",
        required=True,
    )

    parser.add_argument(
        "--out",
        type=Path,
        required=True,
    )

    args = parser.parse_args()

    samples = read_jsonl(args.samples)

    sample = find_sample(
        samples,
        args.sample_id,
    )

    if sample is None:
        raise SystemExit(
            f"[FAIL] sample not found: {args.sample_id}"
        )

    result = resolve_manifest_constraints(
        sample=sample,
        distribution=args.distribution,
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

    print(f"[OK] sample id: {result['sample_id']}")
    print(f"[OK] distribution: {result['distribution']}")
    print(f"[OK] status: {result['status']}")
    print(
        f"[OK] constraint kind: "
        f"{result['constraint_kind']}"
    )
    print(
        f"[OK] manifest specifier: "
        f"{result['specifier'] or '(unconstrained)'}"
    )
    print(f"[OK] result saved to: {args.out}")


if __name__ == "__main__":
    main()