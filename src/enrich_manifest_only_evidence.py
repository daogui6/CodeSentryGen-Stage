import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any

from normalizer import pep503_normalize


ROOT = Path(__file__).resolve().parents[1]

DEFAULT_INPUT_PATH = (
    ROOT
    / "output"
    / "auto_qwen37_100_reachability_v2_enriched.jsonl"
)

DEFAULT_EVIDENCE_PATH = (
    ROOT
    / "output"
    / "auto_qwen37_100_manifest_only_dependency_recheck.csv"
)

DEFAULT_OUTPUT_PATH = (
    ROOT
    / "output"
    / "auto_qwen37_100_manifest_evidence_enriched.jsonl"
)

DEFAULT_SUMMARY_PATH = (
    ROOT
    / "output"
    / "auto_qwen37_100_manifest_evidence_summary.md"
)


LABEL_POLICY: dict[str, dict[str, Any]] = {
    "direct_import_backed": {
        "risk_candidate": False,
        "status": "resolved",
        "severity": "none",
        "evidence_level": "strong",
        "review_priority": "none",
        "reason": (
            "The manifest dependency has direct import evidence. "
            "The original mismatch was caused by incomplete "
            "import-to-distribution mapping."
        ),
    },
    "transitive_dependency_backed": {
        "risk_candidate": True,
        "status": "weak",
        "severity": "low",
        "evidence_level": "strong",
        "review_priority": "low",
        "reason": (
            "The package is not directly imported, but a required "
            "dependency path from a directly used distribution "
            "supports the manifest declaration."
        ),
    },
    "optional_extra_dependency": {
        "risk_candidate": True,
        "status": "weak",
        "severity": "low",
        "evidence_level": "moderate",
        "review_priority": "medium",
        "reason": (
            "The package is supported by an optional extra "
            "dependency path, which is valid only when the "
            "corresponding extra is selected."
        ),
    },
    "conditional_dependency_backed": {
        "risk_candidate": True,
        "status": "weak",
        "severity": "low",
        "evidence_level": "moderate",
        "review_priority": "medium",
        "reason": (
            "The package is supported by a conditional dependency "
            "path whose applicability depends on environment markers."
        ),
    },
    "no_dependency_evidence": {
        "risk_candidate": True,
        "status": "probable",
        "severity": "medium",
        "evidence_level": "none",
        "review_priority": "high",
        "reason": (
            "No direct import, required dependency, optional extra, "
            "or conditional dependency evidence was found."
        ),
    },
}

def read_jsonl(path: Path) -> list[dict[str, Any]]:
    """读取 JSONL 依赖记录。"""
    if not path.exists():
        raise FileNotFoundError(
            f"Input JSONL not found: {path}"
        )

    records: list[dict[str, Any]] = []

    with path.open(
        "r",
        encoding="utf-8",
    ) as file:
        for line_number, raw_line in enumerate(
            file,
            start=1,
        ):
            line = raw_line.strip()

            if not line:
                continue

            try:
                records.append(
                    json.loads(line)
                )
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON at "
                    f"{path}:{line_number}: {exc}"
                ) from exc

    return records


def write_jsonl(
    records: list[dict[str, Any]],
    path: Path,
) -> None:
    """写出补充证据后的 JSONL。"""
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with path.open(
        "w",
        encoding="utf-8",
    ) as file:
        for record in records:
            file.write(
                json.dumps(
                    record,
                    ensure_ascii=False,
                )
                + "\n"
            )


def make_key(
    sample_id: str,
    package: str,
) -> tuple[str, str]:
    """
    使用 sample_id + 规范化 package 唯一定位记录。
    """
    return (
        sample_id.strip(),
        pep503_normalize(package.strip()),
    )


def read_evidence_csv(
    path: Path,
) -> tuple[
    dict[tuple[str, str], dict[str, str]],
    list[str],
]:
    """
    读取自动分类 CSV，建立：

        (sample_id, package) -> evidence row

    同时返回 CSV 的原始字段名。
    """
    if not path.exists():
        raise FileNotFoundError(
            f"Evidence CSV not found: {path}"
        )

    index: dict[
        tuple[str, str],
        dict[str, str],
    ] = {}

    with path.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as file:
        reader = csv.DictReader(file)

        fieldnames = reader.fieldnames or []

        for row_number, row in enumerate(
            reader,
            start=2,
        ):
            sample_id = row.get(
                "sample_id",
                "",
            ).strip()

            package = row.get(
                "package",
                "",
            ).strip()

            label = row.get(
                "dependency_label",
                "",
            ).strip()

            if not sample_id or not package:
                raise ValueError(
                    "Evidence row is missing sample_id "
                    f"or package at line {row_number}"
                )

            if label not in LABEL_POLICY:
                raise ValueError(
                    f"Unsupported dependency_label "
                    f"at line {row_number}: {label}"
                )

            key = make_key(
                sample_id,
                package,
            )

            if key in index:
                previous_label = index[key].get(
                    "dependency_label",
                    "",
                )

                if previous_label != label:
                    raise ValueError(
                        "Conflicting labels for "
                        f"{sample_id} / {package}: "
                        f"{previous_label} vs {label}"
                    )

            index[key] = row

    return index, fieldnames


def build_evidence_object(
    row: dict[str, str],
    policy: dict[str, Any],
) -> dict[str, Any]:
    """
    将 CSV 分类结果整理成结构化证据对象。
    """
    return {
        "label": row.get(
            "dependency_label",
            "",
        ),
        "risk_candidate": policy[
            "risk_candidate"
        ],
        "recommended_status": policy[
            "status"
        ],
        "recommended_severity": policy[
            "severity"
        ],
        "recommended_evidence_level": policy[
            "evidence_level"
        ],
        "recommended_review_priority": policy[
            "review_priority"
        ],
        "matched_by": row.get(
            "matched_by",
            "",
        ),
        "matched_import_paths": row.get(
            "matched_import_paths",
            "",
        ),
        "matched_wheel_prefixes": row.get(
            "matched_wheel_prefixes",
            "",
        ),
        "direct_distributions": row.get(
            "direct_distributions",
            "",
        ),
        "dependency_evidence": row.get(
            "dependency_evidence",
            "",
        ),
        "resolver_status": row.get(
            "resolver_status",
            "",
        ),
        "resolver_error": row.get(
            "resolver_error",
            "",
        ),
        "reason": policy[
            "reason"
        ],
        "source": (
            "manifest_only_dependency_recheck"
        ),
    }


def write_summary(
    path: Path,
    input_path: Path,
    evidence_path: Path,
    output_path: Path,
    total_records: int,
    manifest_records: int,
    enriched_records: int,
    label_counts: Counter[str],
    unmatched_keys: list[tuple[str, str]],
) -> None:
    """写出 Markdown 汇总报告。"""
    lines = [
        "# Manifest-only Evidence Enrichment Summary",
        "",
        f"- Input records: `{input_path}`",
        f"- Evidence CSV: `{evidence_path}`",
        f"- Output records: `{output_path}`",
        "",
        "## Counts",
        "",
        f"- total dependency records: {total_records}",
        f"- manifest dependency records: {manifest_records}",
        f"- enriched manifest records: {enriched_records}",
        f"- unmatched evidence rows: {len(unmatched_keys)}",
        "",
        "## Evidence label distribution",
        "",
    ]

    for label, count in sorted(
        label_counts.items()
    ):
        lines.append(
            f"- `{label}`: {count}"
        )

    if unmatched_keys:
        lines.extend(
            [
                "",
                "## Unmatched evidence rows",
                "",
            ]
        )

        for sample_id, package in unmatched_keys:
            lines.append(
                f"- `{sample_id}` / `{package}`"
            )

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Enrich dependency records with "
            "manifest-only evidence labels."
        )
    )

    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT_PATH,
        help="Input reachability-enriched JSONL",
    )

    parser.add_argument(
        "--evidence",
        type=Path,
        default=DEFAULT_EVIDENCE_PATH,
        help="Manifest-only dependency evidence CSV",
    )

    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUTPUT_PATH,
        help="Output enriched JSONL",
    )

    parser.add_argument(
        "--summary",
        type=Path,
        default=DEFAULT_SUMMARY_PATH,
        help="Output Markdown summary",
    )

    args = parser.parse_args()

    records = read_jsonl(
        args.input
    )

    evidence_index, _ = read_evidence_csv(
        args.evidence
    )

    output_records: list[
        dict[str, Any]
    ] = []

    matched_keys: set[
        tuple[str, str]
    ] = set()

    label_counts: Counter[str] = Counter()

    manifest_records = 0
    enriched_records = 0

    for original_record in records:
        record = dict(
            original_record
        )

        source_type = str(
            record.get(
                "source_type",
                "",
            )
        )

        if source_type in {
            "manifest",
            "requirements",
        }:
            manifest_records += 1

            sample_id = str(
                record.get(
                    "sample_id",
                    "",
                )
            )

            package = str(
                record.get(
                    "package",
                    "",
                )
            )

            key = make_key(
                sample_id,
                package,
            )

            evidence_row = evidence_index.get(
                key
            )

            if evidence_row is not None:
                label = evidence_row[
                    "dependency_label"
                ]

                policy = LABEL_POLICY[
                    label
                ]

                record[
                    "manifest_only_evidence_label"
                ] = label

                record[
                    "manifest_only_risk_candidate"
                ] = policy[
                    "risk_candidate"
                ]

                record[
                    "manifest_only_evidence_level"
                ] = policy[
                    "evidence_level"
                ]

                record[
                    "manifest_only_review_priority"
                ] = policy[
                    "review_priority"
                ]

                record[
                    "manifest_only_evidence"
                ] = build_evidence_object(
                    evidence_row,
                    policy,
                )

                matched_keys.add(
                    key
                )

                label_counts[
                    label
                ] += 1

                enriched_records += 1

        output_records.append(
            record
        )

    unmatched_keys = sorted(
        set(evidence_index)
        - matched_keys
    )

    write_jsonl(
        output_records,
        args.out,
    )

    write_summary(
        path=args.summary,
        input_path=args.input,
        evidence_path=args.evidence,
        output_path=args.out,
        total_records=len(records),
        manifest_records=manifest_records,
        enriched_records=enriched_records,
        label_counts=label_counts,
        unmatched_keys=unmatched_keys,
    )

    print(
        "============================================================"
    )
    print(
        "Manifest-only evidence enrichment"
    )
    print(
        "============================================================"
    )
    print(
        f"total_records = {len(records)}"
    )
    print(
        f"manifest_records = {manifest_records}"
    )
    print(
        f"enriched_records = {enriched_records}"
    )

    for label, count in sorted(
        label_counts.items()
    ):
        print(
            f"{label} = {count}"
        )

    print(
        f"unmatched_evidence_rows = "
        f"{len(unmatched_keys)}"
    )
    print(
        f"output = "
        f"{args.out.relative_to(ROOT)}"
    )
    print(
        f"summary = "
        f"{args.summary.relative_to(ROOT)}"
    )
    print(
        "============================================================"
    )

    if unmatched_keys:
        print(
            "[ERROR] Some evidence rows were not "
            "matched to dependency records:"
        )

        for sample_id, package in unmatched_keys:
            print(
                f"  - {sample_id} | {package}"
            )

        raise SystemExit(1)


if __name__ == "__main__":
    main()