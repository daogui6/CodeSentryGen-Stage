from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from time_view_contract_v1 import validate_time_view_contract


ROOT = Path(__file__).resolve().parents[1]
SEMANTICS_PATH = ROOT / "config/core_risk_semantics_v2_1_repair_v1.json"

FORMAL_MAIN_RISK_TYPES = {
    "temporal_package_hallucination",
    "api_induced_vulnerable_dependency",
    "temporal_drift",
}

AUXILIARY_RISK_TYPES = {
    "dependency_declaration_mismatch",
    "temporal_uncertainty_review",
    "manifest_vulnerable_dependency",
    "lockfile_vulnerable_dependency",
}

ALL_RISK_TYPES = FORMAL_MAIN_RISK_TYPES | AUXILIARY_RISK_TYPES

AVCS_FORMAL_RISK_VIEW_IDS = {
    "api_induced_vulnerable_dependency": "as_of_tg",
    "temporal_drift": "as_of_audit",
}


def avcs_formal_risk_view_eligible(
    risk_type: str,
    evaluation_time_view: dict[str, Any] | None,
) -> bool:
    """Authorize an AVCS formal card for its risk-specific time view.

    This deliberately separates formal scientific validity from membership
    in the generation-time denominator.  Temporal drift is formal only in an
    audit-time view; it must never be relabeled as an ``as_of_tg`` positive.
    """
    expected_view = AVCS_FORMAL_RISK_VIEW_IDS.get(str(risk_type or ""))
    if expected_view is None:
        return False
    contract = validate_time_view_contract(
        evaluation_time_view,
        allow_legacy=True,
    )
    expected_channel = (
        "generation_time"
        if expected_view == "as_of_tg"
        else "audit_time"
    )
    return (
        contract.get("view_id") == expected_view
        and contract.get("view_specific_metric_channel") == expected_channel
        and contract.get("retrospective_only") is False
    )


def load_semantics() -> dict[str, Any]:
    value = json.loads(SEMANTICS_PATH.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Risk semantics contract must be an object")
    expected = set(value.get("formal_main_risk_types", []))
    if expected != FORMAL_MAIN_RISK_TYPES:
        raise ValueError(
            "Risk semantics formal taxonomy drifted: "
            f"{sorted(expected)}"
        )
    configured_views = value.get("avcs_formal_risk_time_views")
    expected_views = {
        risk_type: {
            "view_id": view_id,
            "metric_channel": (
                "generation_time"
                if view_id == "as_of_tg"
                else "audit_time"
            ),
        }
        for risk_type, view_id in AVCS_FORMAL_RISK_VIEW_IDS.items()
    }
    if configured_views != expected_views:
        raise ValueError(
            "Risk semantics AVCS time-view mapping drifted: "
            f"{configured_views!r}"
        )
    return value


def pep503_normalize(value: Any) -> str:
    return re.sub(r"[-_.]+", "-", str(value or "").strip().lower())


def canonical_file(value: Any) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    normalized = text.replace("\\", "/")
    root = str(ROOT.resolve()).replace("\\", "/")
    if normalized.lower().startswith(root.lower() + "/"):
        normalized = normalized[len(root) + 1 :]
    return normalized


def canonical_location(value: Any) -> dict[str, Any]:
    raw = value if isinstance(value, dict) else {}
    line = raw.get("line")
    column = raw.get("column")
    result = {
        "file": canonical_file(raw.get("file")),
        "line": int(line) if isinstance(line, int) else None,
        "column": int(column) if isinstance(column, int) else None,
        "entity": (
            str(raw.get("entity"))
            if raw.get("entity") is not None
            else None
        ),
        "source_type": (
            str(raw.get("source_type"))
            if raw.get("source_type") is not None
            else None
        ),
    }
    return result


def risk_package(card: dict[str, Any]) -> str:
    introduced = (
        card.get("introduced_by")
        if isinstance(card.get("introduced_by"), dict)
        else {}
    )
    return str(
        card.get("distribution")
        or card.get("package")
        or introduced.get("package")
        or introduced.get("entity")
        or ""
    ).strip()


def temporal_evidence(card: dict[str, Any]) -> dict[str, Any]:
    evidence = card.get("evidence")
    if not isinstance(evidence, dict):
        return {}
    rows = evidence.get("temporal")
    if isinstance(rows, list) and rows and isinstance(rows[0], dict):
        return rows[0]
    if isinstance(rows, dict):
        return rows
    return {}


def time_view(card: dict[str, Any]) -> dict[str, Any]:
    temporal = temporal_evidence(card)
    evaluation_contract = None
    if card.get("evaluation_time_view") is not None:
        evaluation_contract = validate_time_view_contract(
            card.get("evaluation_time_view"),
            allow_legacy=True,
        )
    uncertainty = (
        card.get("generation_time_uncertainty_seconds")
        if card.get("generation_time_uncertainty_seconds") is not None
        else temporal.get("generation_time_uncertainty_seconds")
    )
    if uncertainty is not None:
        uncertainty = float(uncertainty)
    result = {
        "generation_time": (
            card.get("generation_time")
            or temporal.get("generation_time")
        ),
        "generation_time_uncertainty_seconds": uncertainty,
        "audit_time": temporal.get("audit_time"),
        "knowledge_time": card.get("knowledge_time"),
        "vulnerability_published_at": card.get(
            "vulnerability_published_at"
        ),
        "temporal_classification": (
            card.get("temporal_classification")
            or temporal.get("temporal_status")
        ),
    }
    if evaluation_contract is not None:
        result["evaluation_contract"] = evaluation_contract
    return result


def canonical_risk_identity_payload(
    *,
    sample_id: str,
    risk_type: str,
    package: str,
    location: dict[str, Any],
    time_view_value: dict[str, Any],
) -> dict[str, Any]:
    evaluation_contract = (
        time_view_value.get("evaluation_contract")
        if isinstance(
            time_view_value.get("evaluation_contract"), dict
        )
        else {}
    )
    time_payload = {
        "generation_time": time_view_value.get("generation_time"),
        "generation_time_uncertainty_seconds": (
            time_view_value.get(
                "generation_time_uncertainty_seconds"
            )
        ),
        "audit_time": time_view_value.get("audit_time"),
        "knowledge_time": time_view_value.get("knowledge_time"),
        "temporal_classification": time_view_value.get(
            "temporal_classification"
        ),
    }
    if evaluation_contract:
        time_payload["evaluation_contract"] = {
            "view_id": evaluation_contract.get("view_id"),
            "target_generation_time": evaluation_contract.get(
                "target_generation_time"
            ),
            "evidence_cutoff": evaluation_contract.get(
                "evidence_cutoff"
            ),
            "evidence_snapshot_sha256": evaluation_contract.get(
                "evidence_snapshot_sha256"
            ),
            "view_specific_metric_channel": evaluation_contract.get(
                "view_specific_metric_channel"
            ),
            "formal_generation_metric_eligible": (
                evaluation_contract.get(
                    "formal_generation_metric_eligible"
                )
            ),
            "retrospective_only": evaluation_contract.get(
                "retrospective_only"
            ),
        }
    return {
        "sample_id": sample_id,
        "risk_type": risk_type,
        "normalized_package": pep503_normalize(package),
        "location": {
            "file": location.get("file"),
            "line": location.get("line"),
            "column": location.get("column"),
        },
        "time_view": time_payload,
    }


def risk_identity_sha256(
    *,
    sample_id: str,
    risk_type: str,
    package: str,
    location: dict[str, Any],
    time_view_value: dict[str, Any],
) -> str:
    payload = canonical_risk_identity_payload(
        sample_id=sample_id,
        risk_type=risk_type,
        package=package,
        location=location,
        time_view_value=time_view_value,
    )
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _unique_values(values: list[Any]) -> list[Any]:
    by_json: dict[str, Any] = {}
    for value in values:
        by_json[_canonical_json(value)] = copy.deepcopy(value)
    return [
        by_json[key]
        for key in sorted(by_json)
    ]


def _aggregate_scalar_values(
    values: list[Any],
) -> tuple[Any, str]:
    unique = _unique_values(values)
    if not unique:
        return None, "empty"
    if len(unique) == 1:
        return unique[0], "single_value"
    return {
        "aggregation": "multiple_values",
        "values": unique,
    }, "multiple_values"


def _merge_compatible_dict(
    left: dict[str, Any],
    right: dict[str, Any],
) -> tuple[dict[str, Any] | None, bool]:
    result = copy.deepcopy(left)
    for key, right_value in right.items():
        if key not in result:
            result[key] = copy.deepcopy(right_value)
            continue
        left_value = result[key]
        if (
            isinstance(left_value, dict)
            and isinstance(right_value, dict)
        ):
            merged, compatible = _merge_compatible_dict(
                left_value,
                right_value,
            )
            if not compatible or merged is None:
                return None, False
            result[key] = merged
            continue
        if _canonical_json(left_value) != _canonical_json(
            right_value
        ):
            return None, False
    return result, True


def _aggregate_repairs(
    repairs: list[dict[str, Any]],
) -> tuple[dict[str, Any], str]:
    unique = _unique_values(repairs)
    if not unique:
        return {}, "empty"
    if len(unique) == 1:
        return copy.deepcopy(unique[0]), "identical"

    merged = copy.deepcopy(unique[0])
    for repair in unique[1:]:
        candidate, compatible = _merge_compatible_dict(
            merged,
            repair,
        )
        if not compatible or candidate is None:
            return {
                "status": "review_required",
                "reason": "conflicting_source_repairs",
                "alternatives": unique,
            }, "conflict_review_required"
        merged = candidate
    return merged, "compatible_merged"


_EVIDENCE_REF_SCALAR_KEYS = {
    "package_kb",
    "release_history_view",
    "api_history_adapter",
    "api_constraints",
    "manifest_constraints",
}


def _collect_evidence_refs(value: Any) -> list[str]:
    refs: set[str] = set()

    def visit(current: Any, key: str = "") -> None:
        lowered = key.lower()
        is_ref_key = (
            lowered.endswith("_ref")
            or lowered.endswith("_refs")
            or lowered in _EVIDENCE_REF_SCALAR_KEYS
        )
        if is_ref_key:
            if isinstance(current, str) and current.strip():
                refs.add(current.strip())
            elif isinstance(current, list):
                for item in current:
                    if isinstance(item, str) and item.strip():
                        refs.add(item.strip())

        if isinstance(current, dict):
            for child_key, child_value in current.items():
                visit(child_value, str(child_key))
        elif isinstance(current, list):
            for item in current:
                visit(item, key)

    visit(value)
    return sorted(refs)


def _unique_source_cards(
    source_cards: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    unique = _unique_values(source_cards)
    return sorted(
        unique,
        key=lambda row: (
            str(row.get("risk_id") or ""),
            _canonical_json(row),
        ),
    )


def _source_risk_ids(
    source_cards: list[dict[str, Any]],
) -> list[str]:
    return sorted(
        {
            str(row.get("risk_id"))
            for row in source_cards
            if row.get("risk_id") is not None
            and str(row.get("risk_id")).strip()
        }
    )


def _vulnerability_instances(
    source_cards: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for source in source_cards:
        vulnerability_id = str(
            source.get("vulnerability_id") or ""
        ).strip()
        if vulnerability_id:
            grouped.setdefault(vulnerability_id, []).append(
                source
            )

    result: list[dict[str, Any]] = []
    for vulnerability_id in sorted(grouped):
        rows = grouped[vulnerability_id]
        severity, _ = _aggregate_scalar_values(
            [copy.deepcopy(row.get("severity")) for row in rows]
        )
        repair, repair_status = _aggregate_repairs(
            [
                copy.deepcopy(row.get("repair"))
                for row in rows
                if isinstance(row.get("repair"), dict)
            ]
        )
        evidence_refs: set[str] = set()
        published_values: list[Any] = []
        source_ids: set[str] = set()
        for row in rows:
            evidence_refs.update(
                _collect_evidence_refs(row.get("evidence"))
            )
            published_values.append(
                row.get("vulnerability_published_at")
            )
            if row.get("risk_id") is not None:
                source_ids.add(str(row.get("risk_id")))

        published_at, published_status = (
            _aggregate_scalar_values(published_values)
        )
        result.append(
            {
                "vulnerability_id": vulnerability_id,
                "published_at": published_at,
                "published_at_status": published_status,
                "severity": severity,
                "evidence_refs": sorted(evidence_refs),
                "repair": repair,
                "repair_status": repair_status,
                "source_risk_ids": sorted(source_ids),
            }
        )
    return result


def _identity_level_time_view(
    value: Any,
) -> dict[str, Any]:
    view = value if isinstance(value, dict) else {}
    evaluation_contract = (
        view.get("evaluation_contract")
        if isinstance(view.get("evaluation_contract"), dict)
        else {}
    )
    result = {
        "generation_time": view.get("generation_time"),
        "generation_time_uncertainty_seconds": view.get(
            "generation_time_uncertainty_seconds"
        ),
        "audit_time": view.get("audit_time"),
        "knowledge_time": view.get("knowledge_time"),
        "temporal_classification": view.get(
            "temporal_classification"
        ),
    }
    if evaluation_contract:
        result["evaluation_contract"] = {
            "view_id": evaluation_contract.get("view_id"),
            "target_generation_time": evaluation_contract.get(
                "target_generation_time"
            ),
            "evidence_cutoff": evaluation_contract.get(
                "evidence_cutoff"
            ),
            "evidence_snapshot_sha256": evaluation_contract.get(
                "evidence_snapshot_sha256"
            ),
            "view_specific_metric_channel": evaluation_contract.get(
                "view_specific_metric_channel"
            ),
            "formal_generation_metric_eligible": (
                evaluation_contract.get(
                    "formal_generation_metric_eligible"
                )
            ),
            "retrospective_only": evaluation_contract.get(
                "retrospective_only"
            ),
        }
    return result


def _aggregate_normalized_group(
    cards: list[dict[str, Any]],
) -> dict[str, Any]:
    if not cards:
        raise ValueError("Risk Card aggregation requires cards")

    identity = str(cards[0].get("risk_identity") or "")
    for card in cards:
        if str(card.get("risk_identity") or "") != identity:
            raise ValueError(
                "Risk Card aggregation received mixed identities"
            )

    core_fields = (
        "schema_version",
        "risk_id",
        "risk_identity",
        "sample_id",
        "type",
        "channel",
        "formal_positive",
        "package",
        "introduced_by",
        "pipeline_origin",
        "coverage",
        "scientific_boundary",
    )
    baseline = cards[0]
    for card in cards[1:]:
        for field in core_fields:
            if _canonical_json(card.get(field)) != _canonical_json(
                baseline.get(field)
            ):
                raise ValueError(
                    "Risk Card aggregation semantic conflict for "
                    f"{field}: identity={identity}"
                )
        if _canonical_json(
            _identity_level_time_view(card.get("time_view"))
        ) != _canonical_json(
            _identity_level_time_view(
                baseline.get("time_view")
            )
        ):
            raise ValueError(
                "Risk Card aggregation semantic conflict for "
                f"identity-level time_view: identity={identity}"
            )

    source_cards: list[dict[str, Any]] = []
    for card in cards:
        existing = card.get("source_cards")
        if isinstance(existing, list) and existing:
            source_cards.extend(
                copy.deepcopy(row)
                for row in existing
                if isinstance(row, dict)
            )
        elif isinstance(card.get("source_card"), dict):
            source_cards.append(
                copy.deepcopy(card["source_card"])
            )
    source_cards = _unique_source_cards(source_cards)
    if not source_cards:
        raise ValueError(
            "Risk Card aggregation lost all source cards"
        )

    representative_source = source_cards[0]
    representative = min(
        cards,
        key=_canonical_json,
    )
    result = copy.deepcopy(representative)

    publication_values = _unique_values(
        [
            source.get("vulnerability_published_at")
            for source in source_cards
        ]
    )
    if isinstance(result.get("time_view"), dict):
        result["time_view"]["vulnerability_published_at"] = (
            publication_values[0]
            if len(publication_values) == 1
            else None
        )

    source_ids = _source_risk_ids(source_cards)
    result["source_risk_ids"] = source_ids
    result["source_cards"] = source_cards
    result["source_risk_id"] = (
        str(representative_source.get("risk_id"))
        if representative_source.get("risk_id") is not None
        else None
    )
    result["source_card"] = copy.deepcopy(
        representative_source
    )

    result["vulnerability_instances"] = (
        _vulnerability_instances(source_cards)
    )

    evidence_refs: set[str] = set()
    for source in source_cards:
        evidence_refs.update(
            _collect_evidence_refs(source.get("evidence"))
        )
    result["evidence_refs"] = sorted(evidence_refs)

    severity, severity_status = _aggregate_scalar_values(
        [
            copy.deepcopy(source.get("severity"))
            for source in source_cards
        ]
    )
    result["severity"] = severity

    aggregated_repair, repair_status = _aggregate_repairs(
        [
            copy.deepcopy(source.get("repair"))
            for source in source_cards
            if isinstance(source.get("repair"), dict)
        ]
    )
    result["repair"] = aggregated_repair

    evidence = (
        copy.deepcopy(representative_source.get("evidence"))
        if isinstance(representative_source.get("evidence"), dict)
        else {}
    )
    vulnerability_refs = sorted(
        {
            ref
            for source in source_cards
            for ref in (
                (
                    source.get("evidence")
                    if isinstance(source.get("evidence"), dict)
                    else {}
                ).get("vulnerability_source_refs", [])
                or []
            )
            if isinstance(ref, str) and ref.strip()
        }
    )
    if vulnerability_refs:
        evidence["vulnerability_source_refs"] = (
            vulnerability_refs
        )
    result["evidence"] = evidence

    result["aggregation"] = {
        "status": (
            "single_source"
            if len(source_cards) == 1
            else "aggregated"
        ),
        "source_card_count": len(source_cards),
        "vulnerability_count": len(
            result["vulnerability_instances"]
        ),
        "severity_status": severity_status,
        "repair_status": repair_status,
        "input_order_independent": True,
    }
    return result


def resolve_type(
    card: dict[str, Any],
    *,
    aliases: dict[str, str] | None = None,
) -> tuple[str, str]:
    internal_type = str(card.get("type", "") or "").strip()
    resolved = (
        str((aliases or {}).get(internal_type, "") or "").strip()
        or internal_type
    )
    if resolved not in ALL_RISK_TYPES:
        raise ValueError(
            f"Risk type is outside v2.1 taxonomy: {resolved}"
        )
    return internal_type, resolved


def normalize_risk_card(
    card: dict[str, Any],
    *,
    pipeline_origin: str,
    aliases: dict[str, str] | None = None,
    generation_time_uncertainty_seconds: float | None = None,
) -> dict[str, Any]:
    if pipeline_origin not in {"THO", "AVCS"}:
        raise ValueError(f"Unsupported pipeline origin: {pipeline_origin}")

    internal_type, resolved_type = resolve_type(
        card,
        aliases=aliases,
    )
    explicit_channel = str(card.get("channel", "") or "").strip()
    explicit_formal = card.get("formal_eligible")

    if explicit_channel:
        if explicit_channel not in {"formal", "auxiliary"}:
            raise ValueError(
                f"Invalid Risk Card channel: {explicit_channel}"
            )
        channel = explicit_channel
    elif (
        resolved_type in FORMAL_MAIN_RISK_TYPES
        and explicit_formal is not False
    ):
        channel = "formal"
    else:
        channel = "auxiliary"

    formal_positive = (
        channel == "formal"
        and resolved_type in FORMAL_MAIN_RISK_TYPES
        and explicit_formal is not False
    )

    package_name = risk_package(card)
    if not package_name:
        raise ValueError("Risk Card package identity is missing")

    introduced = canonical_location(card.get("introduced_by"))
    view = time_view(card)
    if (
        view.get("generation_time_uncertainty_seconds") is None
        and generation_time_uncertainty_seconds is not None
    ):
        resolved_uncertainty = float(
            generation_time_uncertainty_seconds
        )
        if resolved_uncertainty < 0:
            raise ValueError(
                "generation-time uncertainty must be >= 0"
            )
        view["generation_time_uncertainty_seconds"] = (
            resolved_uncertainty
        )
    sample_id = str(card.get("sample_id", "") or "").strip()
    if not sample_id:
        raise ValueError("Risk Card sample_id is missing")

    identity = risk_identity_sha256(
        sample_id=sample_id,
        risk_type=resolved_type,
        package=package_name,
        location=introduced,
        time_view_value=view,
    )

    evidence = (
        copy.deepcopy(card.get("evidence"))
        if isinstance(card.get("evidence"), dict)
        else {}
    )
    unknowns = (
        copy.deepcopy(card.get("unknowns"))
        if isinstance(card.get("unknowns"), dict)
        else {}
    )
    repair = (
        copy.deepcopy(card.get("repair"))
        if isinstance(card.get("repair"), dict)
        else {}
    )
    coverage = (
        copy.deepcopy(card.get("coverage"))
        if isinstance(card.get("coverage"), dict)
        else None
    )

    result = {
        "schema_version": "risk_card_v2.1",
        "risk_id": f"risk_{identity[:20]}",
        "risk_identity": identity,
        "source_risk_id": (
            str(card.get("risk_id"))
            if card.get("risk_id") is not None
            else None
        ),
        "sample_id": sample_id,
        "type": resolved_type,
        "internal_type": internal_type,
        "channel": channel,
        "formal_positive": formal_positive,
        "status": card.get("status"),
        "severity": copy.deepcopy(card.get("severity")),
        "package": {
            "ecosystem": str(card.get("ecosystem") or "pypi"),
            "name": package_name,
            "normalized_name": pep503_normalize(package_name),
        },
        "introduced_by": introduced,
        "time_view": view,
        "pipeline_origin": pipeline_origin,
        "evidence": evidence,
        "unknowns": unknowns,
        "coverage": coverage,
        "repair": repair,
        "scientific_boundary": {
            "unknown_is_not_false": True,
            "temporal_unknown_is_not_positive": True,
            "install_reachability_is_not_install_time": True,
            "trigger_match_is_not_exploit_proof": True,
            "auxiliary_findings_excluded_from_main_metrics": True,
        },
        "source_card": copy.deepcopy(card),
        "source_risk_ids": [],
        "source_cards": [copy.deepcopy(card)],
        "vulnerability_instances": [],
        "evidence_refs": [],
        "aggregation": {},
    }
    result = _aggregate_normalized_group([result])
    validate_risk_card(result)
    return result


def validate_risk_card(card: dict[str, Any]) -> None:
    required = {
        "schema_version",
        "risk_id",
        "risk_identity",
        "source_risk_id",
        "sample_id",
        "type",
        "internal_type",
        "channel",
        "formal_positive",
        "status",
        "severity",
        "package",
        "introduced_by",
        "time_view",
        "pipeline_origin",
        "evidence",
        "unknowns",
        "coverage",
        "repair",
        "scientific_boundary",
        "source_card",
        "source_risk_ids",
        "source_cards",
        "vulnerability_instances",
        "evidence_refs",
        "aggregation",
    }
    missing = required - set(card)
    if missing:
        raise ValueError(
            f"Unified Risk Card missing fields: {sorted(missing)}"
        )
    if card.get("schema_version") != "risk_card_v2.1":
        raise ValueError("Unified Risk Card schema_version mismatch")
    if card.get("type") not in ALL_RISK_TYPES:
        raise ValueError(
            f"Unified Risk Card type invalid: {card.get('type')}"
        )
    if card.get("channel") not in {"formal", "auxiliary"}:
        raise ValueError("Unified Risk Card channel invalid")
    if card.get("pipeline_origin") not in {"THO", "AVCS"}:
        raise ValueError("Unified Risk Card pipeline_origin invalid")
    coverage = card.get("coverage")
    if coverage is not None and not isinstance(coverage, dict):
        raise ValueError("Unified Risk Card coverage must be object or null")
    if isinstance(coverage, dict):
        required_coverage_fields = {
            "schema_version",
            "support_status",
            "coverage_outcome",
            "main_metric_eligible",
            "formal_positive",
            "blocking_unknown_reasons",
            "coverage_annotations",
            "avcs_package_scope",
            "package_kb_scope",
            "observed_call_coverage",
            "manifest_coverage",
            "vulnerability_coverage",
            "trigger_coverage",
            "time_analysis",
            "scientific_boundary",
        }
        missing_coverage = (
            required_coverage_fields - set(coverage)
        )
        if missing_coverage:
            raise ValueError(
                "Unified Risk Card coverage missing fields: "
                f"{sorted(missing_coverage)}"
            )
        if coverage.get("schema_version") != (
            "avcs_final_output_coverage_v1"
        ):
            raise ValueError(
                "Unified Risk Card coverage schema invalid"
            )
        if not isinstance(
            coverage.get("main_metric_eligible"), bool
        ):
            raise ValueError(
                "Unified Risk Card coverage eligibility must be bool"
            )
        if not isinstance(coverage.get("formal_positive"), bool):
            raise ValueError(
                "Unified Risk Card coverage formal_positive must be bool"
            )
        boundary = coverage.get("scientific_boundary")
        if not isinstance(boundary, dict) or any(
            boundary.get(field) is not True
            for field in (
                "coverage_is_explanatory_not_additional_risk_evidence",
                "unknown_is_not_false",
                "selected_scope_is_not_package_wide",
                "trigger_match_is_not_exploit_proof",
            )
        ):
            raise ValueError(
                "Unified Risk Card coverage scientific boundary invalid"
            )
    if (
        card.get("pipeline_origin") == "AVCS"
        and card.get("formal_positive") is True
    ):
        if not isinstance(coverage, dict):
            raise ValueError(
                "Formal AVCS Risk Card must carry coverage"
            )
        if coverage.get("schema_version") != (
            "avcs_final_output_coverage_v1"
        ):
            raise ValueError(
                "Formal AVCS Risk Card coverage schema invalid"
            )
        generation_metric = coverage.get("generation_metric")
        if not isinstance(generation_metric, dict) or (
            generation_metric.get("channel") != "generation_time"
            or generation_metric.get("outcome")
            != coverage.get("coverage_outcome")
            or generation_metric.get("eligible")
            is not coverage.get("main_metric_eligible")
            or generation_metric.get("formal_positive")
            is not coverage.get("formal_positive")
        ):
            raise ValueError(
                "Formal AVCS Risk Card generation metric is inconsistent"
            )
        if card.get("type") == "temporal_drift":
            audit_metric = coverage.get("audit_drift_metric")
            if not isinstance(audit_metric, dict):
                raise ValueError(
                    "Formal temporal_drift Risk Card requires audit metric"
                )
            if (
                audit_metric.get("channel") != "audit_time"
                or audit_metric.get("outcome") != "formal_positive"
                or audit_metric.get("eligible") is not True
                or audit_metric.get("formal_positive") is not True
            ):
                raise ValueError(
                    "Formal temporal_drift Risk Card audit metric invalid"
                )
            if (
                coverage.get("main_metric_eligible") is not False
                or coverage.get("formal_positive") is not False
            ):
                raise ValueError(
                    "temporal_drift cannot enter generation-time denominator"
                )
        else:
            if coverage.get("coverage_outcome") != "formal_positive":
                raise ValueError(
                    "Formal AVCS Risk Card coverage outcome must be "
                    "formal_positive"
                )
            if coverage.get("main_metric_eligible") is not True:
                raise ValueError(
                    "Formal AVCS Risk Card coverage must be metric eligible"
                )
            if coverage.get("formal_positive") is not True:
                raise ValueError(
                    "Formal AVCS Risk Card generation metric must be positive"
                )
    identity = str(card.get("risk_identity") or "")
    if not re.fullmatch(r"[0-9a-f]{64}", identity):
        raise ValueError("Unified Risk Card risk_identity is not SHA-256")
    if card.get("risk_id") != f"risk_{identity[:20]}":
        raise ValueError("Unified Risk Card risk_id does not match identity")
    package = card.get("package")
    if not isinstance(package, dict):
        raise ValueError("Unified Risk Card package must be object")
    if not str(package.get("normalized_name") or ""):
        raise ValueError("Unified Risk Card normalized package missing")
    introduced = card.get("introduced_by")
    if not isinstance(introduced, dict):
        raise ValueError("Unified Risk Card introduced_by must be object")
    view = card.get("time_view")
    if not isinstance(view, dict):
        raise ValueError("Unified Risk Card time_view must be object")
    evaluation_contract = view.get("evaluation_contract")
    if evaluation_contract is not None:
        validated_evaluation_contract = validate_time_view_contract(
            evaluation_contract,
            allow_legacy=True,
        )
        if (
            card.get("pipeline_origin") == "AVCS"
            and card.get("formal_positive") is True
            and not avcs_formal_risk_view_eligible(
                str(card.get("type") or ""),
                validated_evaluation_contract,
            )
        ):
            raise ValueError(
                "Formal AVCS Risk Card uses an unauthorized risk/time view"
            )
    formal_positive = card.get("formal_positive")
    if not isinstance(formal_positive, bool):
        raise ValueError("Unified Risk Card formal_positive must be bool")
    if formal_positive and card.get("channel") != "formal":
        raise ValueError("Formal positive cannot be auxiliary")
    if (
        card.get("type") == "temporal_uncertainty_review"
        and formal_positive
    ):
        raise ValueError("temporal_unknown review cannot be formal positive")
    if (
        card.get("type") not in FORMAL_MAIN_RISK_TYPES
        and card.get("channel") == "formal"
    ):
        raise ValueError(
            "Auxiliary taxonomy item cannot use formal channel"
        )


    source_cards = card.get("source_cards")
    if (
        not isinstance(source_cards, list)
        or not source_cards
        or not all(
            isinstance(row, dict)
            for row in source_cards
        )
    ):
        raise ValueError(
            "Unified Risk Card source_cards must be a non-empty object list"
        )
    source_risk_ids = card.get("source_risk_ids")
    if (
        not isinstance(source_risk_ids, list)
        or source_risk_ids != sorted(set(source_risk_ids))
        or not all(
            isinstance(value, str)
            and value.strip()
            for value in source_risk_ids
        )
    ):
        raise ValueError(
            "Unified Risk Card source_risk_ids must be sorted unique strings"
        )
    source_risk_id = card.get("source_risk_id")
    if (
        source_risk_id is not None
        and str(source_risk_id) not in source_risk_ids
    ):
        raise ValueError(
            "Unified Risk Card representative source_risk_id is not aggregated"
        )
    if not any(
        _canonical_json(row)
        == _canonical_json(card.get("source_card"))
        for row in source_cards
    ):
        raise ValueError(
            "Unified Risk Card representative source_card is not aggregated"
        )

    vulnerability_instances = card.get(
        "vulnerability_instances"
    )
    if (
        not isinstance(vulnerability_instances, list)
        or not all(
            isinstance(row, dict)
            and str(row.get("vulnerability_id") or "").strip()
            for row in vulnerability_instances
        )
    ):
        raise ValueError(
            "Unified Risk Card vulnerability_instances invalid"
        )
    vulnerability_ids = [
        str(row["vulnerability_id"])
        for row in vulnerability_instances
    ]
    if vulnerability_ids != sorted(set(vulnerability_ids)):
        raise ValueError(
            "Unified Risk Card vulnerability_instances must be unique and sorted"
        )

    evidence_refs = card.get("evidence_refs")
    if (
        not isinstance(evidence_refs, list)
        or evidence_refs != sorted(set(evidence_refs))
        or not all(
            isinstance(value, str)
            and value.strip()
            for value in evidence_refs
        )
    ):
        raise ValueError(
            "Unified Risk Card evidence_refs must be sorted unique strings"
        )

    aggregation = card.get("aggregation")
    if not isinstance(aggregation, dict):
        raise ValueError(
            "Unified Risk Card aggregation must be object"
        )
    if aggregation.get("source_card_count") != len(
        source_cards
    ):
        raise ValueError(
            "Unified Risk Card source_card_count mismatch"
        )
    if aggregation.get("vulnerability_count") != len(
        vulnerability_instances
    ):
        raise ValueError(
            "Unified Risk Card vulnerability_count mismatch"
        )
    if aggregation.get("input_order_independent") is not True:
        raise ValueError(
            "Unified Risk Card aggregation must be input-order independent"
        )
    if aggregation.get("repair_status") == (
        "conflict_review_required"
    ):
        repair = card.get("repair")
        if (
            not isinstance(repair, dict)
            or repair.get("status") != "review_required"
            or repair.get("reason")
            != "conflicting_source_repairs"
        ):
            raise ValueError(
                "Conflicting Risk Card repairs must route to review"
            )


def deduplicate_cards(
    cards: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for card in cards:
        validate_risk_card(card)
        identity = str(card["risk_identity"])
        grouped.setdefault(identity, []).append(card)

    result: list[dict[str, Any]] = []
    for identity in sorted(grouped):
        aggregated = _aggregate_normalized_group(
            grouped[identity]
        )
        validate_risk_card(aggregated)
        result.append(aggregated)
    return result
