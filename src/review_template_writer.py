from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict, List


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []

    if not path.exists():
        return rows

    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))

    return rows


def write_manual_review_template(
    benchmark_jsonl_path: Path,
    review_csv_path: Path,
) -> None:
    records = load_jsonl(benchmark_jsonl_path)
    review_csv_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "sample_id",
        "prompt_id",
        "package",
        "raw_name",
        "status",
        "risk_type",
        "severity",
        "install_reachability",
        "registry_exists_now",
        "registry_status_code",
        "auto_label",
        "manual_label",
        "review_reason",
        "reviewer",
        "review_status",
        "evidence_url",
    ]

    with review_csv_path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for row in records:
            writer.writerow(
                {
                    "sample_id": row.get("sample_id"),
                    "prompt_id": row.get("prompt_id"),
                    "package": row.get("package"),
                    "raw_name": row.get("raw_name"),
                    "status": row.get("status"),
                    "risk_type": row.get("risk_type"),
                    "severity": row.get("severity"),
                    "install_reachability": row.get("install_reachability"),
                    "registry_exists_now": row.get("registry_exists_now"),
                    "registry_status_code": row.get("registry_status_code"),
                    "auto_label": row.get("auto_label"),

                    # These fields should be filled manually later.
                    "manual_label": "",
                    "review_reason": "",
                    "reviewer": "",
                    "review_status": "unreviewed",

                    "evidence_url": row.get("registry_query_url"),
                }
            )