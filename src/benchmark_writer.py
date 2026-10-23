from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional


def _safe_get(d: Dict[str, Any], key: str, default: Any = None) -> Any:
    value = d.get(key, default)
    return default if value is None else value


def _build_risk_index(risk_rows: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """
    Build an index for risk cards.
    Key format: sample_id::package
    """
    index = {}
    for card in risk_rows:
        sample_id = card.get("sample_id", "")
        package = card.get("package", "")
        key = f"{sample_id}::{package}"
        index[key] = card
    return index


def convert_to_benchmark_records(
    all_rows: List[Dict[str, Any]],
    risk_rows: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Convert pilot detection results into GenDepRiskBench-style records.

    Current version:
    - one record per dependency entity
    - risk fields are filled when the dependency has a risk card
    - normal dependencies are also preserved as negative / normal samples
    """
    risk_index = _build_risk_index(risk_rows)
    records: List[Dict[str, Any]] = []

    for row in all_rows:
        sample_id = row.get("sample_id", "")
        package = row.get("package", "")
        risk_card = risk_index.get(f"{sample_id}::{package}")

        if row.get("false_positive_filtered") or row.get("local_module_filtered"):
            continue

        pypi = row.get("pypi", {}) or {}
        location = row.get("location", {}) or {}

        is_risk = risk_card is not None

        record = {
            # Basic sample identity
            "sample_id": sample_id,
            "prompt_id": row.get("prompt_id"),
            "language": "python",
            "ecosystem": "pypi",
            "model": row.get("model"),

            # Time fields
            "generation_time": row.get("generation_time"),
            "audit_time": pypi.get("audit_time"),

            # Dependency entity
            "raw_name": row.get("raw_name"),
            "package": package,
            "source_type": row.get("source_type"),
            "location": {
                "file": location.get("file"),
                "line": location.get("line"),
            },

            # Current pilot detection result
            "status": row.get("status"),
            "risk_type": risk_card.get("type") if is_risk else None,
            "severity": risk_card.get("severity") if is_risk else None,
            "confidence": risk_card.get("confidence") if is_risk else None,

            # Reachability / evidence
            "install_reachability": row.get("install_reachability"),
            "evidence_level": risk_card.get("evidence_level") if is_risk else "current_registry_evidence",
            "time_view": risk_card.get("time_view") if is_risk else "as_of_audit_current_pypi",

            # Registry evidence
            "registry_exists_now": pypi.get("exists_now"),
            "registry_query_url": pypi.get("query_url"),
            "first_release_time": pypi.get("first_release_time"),
            "latest_version": pypi.get("latest_version"),
            "registry_status_code": pypi.get("status_code"),
            "registry_error": pypi.get("error"),

            # Filtering and labeling
            "false_positive_filtered": row.get("false_positive_filtered", False),
            "local_module_filtered": row.get("local_module_filtered", False),

            # Label fields for future manual annotation
            "auto_label": "risk" if is_risk else "normal_or_unconfirmed",
            "manual_label": None,
            "label_source": "auto_pilot",
            "review_status": "unreviewed",

            # Repair, only for risks
            "repair": risk_card.get("repair") if is_risk else None,
        }

        records.append(record)

    return records


def write_benchmark_jsonl(
    output_path: Path,
    all_rows: List[Dict[str, Any]],
    risk_rows: List[Dict[str, Any]],
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    records = convert_to_benchmark_records(all_rows, risk_rows)

    with output_path.open("w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")