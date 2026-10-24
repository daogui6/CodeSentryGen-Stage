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
    - only an explicitly formal, eligible card receives auto_label=risk
    - missing or inconsistent card authority fails closed to auxiliary review
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

        has_card = risk_card is not None
        declared_channel = (
            str(risk_card.get("channel") or "")
            if has_card
            else ""
        )
        is_formal_risk = bool(
            has_card
            and declared_channel == "formal"
            and risk_card.get("formal_eligible") is True
        )
        risk_channel = (
            "formal"
            if is_formal_risk
            else ("auxiliary" if has_card else "none")
        )

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
            "risk_type": risk_card.get("type") if has_card else None,
            "risk_subtype": risk_card.get("subtype") if has_card else None,
            "severity": risk_card.get("severity") if has_card else None,
            "confidence": risk_card.get("confidence") if has_card else None,
            "risk_channel": risk_channel,
            "formal_eligible": is_formal_risk,
            "claim_strength": (
                risk_card.get("claim_strength") if has_card else None
            ),

            # Reachability / evidence
            "install_reachability": row.get("install_reachability"),
            "evidence_level": risk_card.get("evidence_level") if has_card else "current_registry_evidence",
            "time_view": risk_card.get("time_view") if has_card else "as_of_audit_current_pypi",

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
            "auto_label": (
                "risk"
                if is_formal_risk
                else (
                    "auxiliary_review"
                    if has_card
                    else "normal_or_unconfirmed"
                )
            ),
            "manual_label": None,
            "label_source": "auto_pilot",
            "review_status": "unreviewed",

            # Repair, only for risks
            "repair": risk_card.get("repair") if has_card else None,
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
