from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


def normalize_name(value: Any) -> str:
    """
    对 distribution/package 名做轻量规范化。

    例如：
    PyYAML -> pyyaml
    python_dateutil -> python-dateutil
    google.api.client -> google-api-client
    """
    if value is None:
        return ""

    text = str(value).strip().lower()

    return re.sub(
        r"[-_.]+",
        "-",
        text,
    )


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(
            f"missing file: {path}"
        )

    return json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(
            f"missing file: {path}"
        )

    rows: list[dict[str, Any]] = []

    with path.open(
        "r",
        encoding="utf-8",
    ) as f:
        for line_no, line in enumerate(
            f,
            start=1,
        ):
            line = line.strip()

            if not line:
                continue

            try:
                rows.append(
                    json.loads(line)
                )
            except json.JSONDecodeError as e:
                raise ValueError(
                    f"{path} line {line_no} "
                    f"is invalid json: {e}"
                ) from e

    return rows


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
    ) as f:
        for row in rows:
            f.write(
                json.dumps(
                    row,
                    ensure_ascii=False,
                )
                + "\n"
            )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Attach standalone AVCS trigger evidence "
            "to matching dependency records."
        )
    )

    parser.add_argument(
        "--input",
        type=Path,
        required=True,
        help="Input dependency records JSONL.",
    )

    parser.add_argument(
        "--trigger-evidence",
        type=Path,
        required=True,
        help="Standalone AVCS trigger evidence JSON.",
    )

    parser.add_argument(
        "--out",
        type=Path,
        required=True,
        help="Output enriched dependency records JSONL.",
    )

    args = parser.parse_args()

    records = read_jsonl(
        args.input
    )

    trigger_evidence = read_json(
        args.trigger_evidence
    )

    evidence_source = (
        trigger_evidence.get(
            "evidence_source",
            {},
        )
    )

    target_sample_id = (
        evidence_source.get(
            "sample_id"
        )
    )

    target_distribution = (
        trigger_evidence.get(
            "distribution"
        )
    )

    if not target_sample_id:
        raise ValueError(
            "trigger evidence is missing "
            "evidence_source.sample_id"
        )

    if not target_distribution:
        raise ValueError(
            "trigger evidence is missing "
            "distribution"
        )

    target_package = normalize_name(
        target_distribution
    )

    matched_count = 0
    output_rows: list[dict[str, Any]] = []

    for record in records:
        output_record = dict(
            record
        )

        record_sample_id = (
            record.get(
                "sample_id"
            )
        )

        record_package = normalize_name(
            record.get(
                "package"
            )
            or record.get(
                "raw_name"
            )
        )

        matched = (
            record_sample_id
            == target_sample_id
            and record_package
            == target_package
        )

        if matched:
            existing = record.get(
                "trigger_evidence"
            )

            # 不允许静默覆盖另一份不同的 Trigger Evidence。
            if (
                existing is not None
                and existing
                != trigger_evidence
            ):
                raise ValueError(
                    "matching dependency record already "
                    "contains different trigger evidence"
                )

            output_record[
                "trigger_evidence"
            ] = trigger_evidence

            matched_count += 1

        output_rows.append(
            output_record
        )

    if matched_count == 0:
        raise ValueError(
            "no dependency record matched "
            f"sample_id={target_sample_id!r}, "
            f"distribution={target_distribution!r}"
        )

    write_jsonl(
        args.out,
        output_rows,
    )

    print(
        "[OK] AVCS trigger evidence attached"
    )
    print(
        f"[OK] input records: {len(records)}"
    )
    print(
        f"[OK] matched records: {matched_count}"
    )
    print(
        f"[OK] sample: {target_sample_id}"
    )
    print(
        f"[OK] distribution: {target_distribution}"
    )
    print(
        f"[OK] saved: {args.out}"
    )


if __name__ == "__main__":
    main()