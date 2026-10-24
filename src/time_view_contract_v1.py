from __future__ import annotations

import copy
import re
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any


FORMAL_TIME_VIEW_IDS = frozenset({"as_of_tg", "as_of_audit", "oracle_now"})
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class TimeViewContractError(ValueError):
    """Raised when a named evaluation view could mix temporal authorities."""


def _parse_aware(value: str, *, field: str) -> datetime:
    text = str(value or "").strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise TimeViewContractError(f"{field} must be ISO-8601: {value!r}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise TimeViewContractError(f"{field} must be timezone-aware")
    return parsed.astimezone(timezone.utc)


def _utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _validate_namespace(view_id: str, output_namespace: str) -> str:
    namespace = str(output_namespace or "").strip().replace("\\", "/")
    path = PurePosixPath(namespace)
    if not namespace or path.is_absolute() or ".." in path.parts:
        raise TimeViewContractError("output namespace must be a safe relative path")
    if not path.parts or path.parts[0] != view_id:
        raise TimeViewContractError(
            f"output namespace must begin with {view_id!r}"
        )
    return path.as_posix()


def build_time_view_contract(
    *,
    view_id: str,
    generation_time: str,
    evidence_cutoff: str,
    evidence_snapshot_sha256: str,
    output_namespace: str,
) -> dict[str, Any]:
    """Build an explicit, non-overwriting three-view evaluation contract."""
    if view_id not in FORMAL_TIME_VIEW_IDS:
        raise TimeViewContractError(f"unsupported time view: {view_id!r}")

    generation = _parse_aware(generation_time, field="generation_time")
    evidence = _parse_aware(evidence_cutoff, field="evidence_cutoff")
    if evidence < generation:
        raise TimeViewContractError(
            "evidence_cutoff cannot precede the sample generation time"
        )
    if view_id == "as_of_tg" and evidence != generation:
        raise TimeViewContractError(
            "as_of_tg requires evidence_cutoff equal to generation_time"
        )
    if view_id in {"as_of_audit", "oracle_now"} and evidence == generation:
        raise TimeViewContractError(
            f"{view_id} requires a post-generation evidence cutoff"
        )

    snapshot_sha = str(evidence_snapshot_sha256 or "").strip().lower()
    if not _SHA256_RE.fullmatch(snapshot_sha):
        raise TimeViewContractError(
            "evidence_snapshot_sha256 must be exactly 64 lowercase hex characters"
        )
    namespace = _validate_namespace(view_id, output_namespace)
    retrospective = view_id == "oracle_now"

    return {
        "schema_version": "codesentry_gen_time_view_contract_v1",
        "view_id": view_id,
        "target_generation_time": _utc_text(generation),
        "release_state_cutoff": _utc_text(generation),
        "evidence_cutoff": _utc_text(evidence),
        "evidence_snapshot_sha256": snapshot_sha,
        "output_namespace": namespace,
        "retrospective_only": retrospective,
        "formal_generation_metric_eligible": view_id == "as_of_tg",
        "view_specific_metric_channel": (
            "generation_time"
            if view_id == "as_of_tg"
            else "audit_time"
            if view_id == "as_of_audit"
            else "oracle_retrospective"
        ),
        "may_overwrite_other_view": False,
        "oracle_may_enter_formal_denominator": False,
    }


def build_legacy_time_view_marker() -> dict[str, Any]:
    """Mark compatibility callers that predate explicit named views."""
    return {
        "schema_version": "codesentry_gen_time_view_contract_v1",
        "view_id": "legacy_implicit",
        "main_experiment_eligible": False,
        "reason": "explicit_named_view_snapshot_hash_and_namespace_required",
        "may_overwrite_other_view": False,
        "oracle_may_enter_formal_denominator": False,
    }


def validate_time_view_contract(
    value: dict[str, Any] | None,
    *,
    allow_legacy: bool = True,
) -> dict[str, Any]:
    """Validate a downstream time-view authority instead of trusting flags.

    The builder is the only authority for explicit-view eligibility.  This
    validator deliberately reconstructs that contract so a caller cannot
    toggle ``formal_generation_metric_eligible`` after construction.
    Missing contracts are projected to the legacy marker and therefore fail
    closed for all main-experiment metrics.
    """
    if value is None:
        if not allow_legacy:
            raise TimeViewContractError("explicit named time view is required")
        return build_legacy_time_view_marker()
    if not isinstance(value, dict):
        raise TimeViewContractError("time view contract must be an object")

    view_id = str(value.get("view_id") or "").strip()
    if view_id == "legacy_implicit":
        if not allow_legacy:
            raise TimeViewContractError("legacy implicit time view is forbidden")
        expected = build_legacy_time_view_marker()
    else:
        expected = build_time_view_contract(
            view_id=view_id,
            generation_time=str(value.get("target_generation_time") or ""),
            evidence_cutoff=str(value.get("evidence_cutoff") or ""),
            evidence_snapshot_sha256=str(
                value.get("evidence_snapshot_sha256") or ""
            ),
            output_namespace=str(value.get("output_namespace") or ""),
        )

    mismatches = [
        key
        for key, expected_value in expected.items()
        if value.get(key) != expected_value
    ]
    if mismatches:
        raise TimeViewContractError(
            "time view contract semantic fields drifted: "
            + ",".join(sorted(mismatches))
        )
    return copy.deepcopy(expected)


def formal_generation_metric_eligible(
    value: dict[str, Any] | None,
) -> bool:
    """Return True only for a fully validated ``as_of_tg`` contract."""
    contract = validate_time_view_contract(value, allow_legacy=True)
    return (
        contract.get("view_id") == "as_of_tg"
        and contract.get("formal_generation_metric_eligible") is True
        and contract.get("view_specific_metric_channel")
        == "generation_time"
    )


def validate_coverage_metric_authority(
    coverage: dict[str, Any],
) -> None:
    """Reject formal coverage that lacks an explicit named-view authority.

    Legacy summary flags are descriptive compatibility fields, not authority.
    A generation or audit observation may enter a formal denominator only when
    its metric object and exact named time-view contract agree.
    """
    if not isinstance(coverage, dict):
        raise TimeViewContractError("coverage metric authority must be an object")

    outcome = str(
        coverage.get("main_metric_outcome")
        or coverage.get("coverage_outcome")
        or ""
    )
    main_eligible = coverage.get("main_metric_eligible")
    formal_positive = coverage.get("formal_positive")
    generation_claim = (
        main_eligible is True
        or formal_positive is True
        or outcome in {"formal_positive", "formal_negative"}
    )

    audit_metric = coverage.get("audit_drift_metric")
    audit_claim = isinstance(audit_metric, dict) and (
        audit_metric.get("eligible") is True
        or audit_metric.get("formal_positive") is True
    )
    if not generation_claim and not audit_claim:
        return

    evaluation_time_view = coverage.get("evaluation_time_view")
    generation_metric = coverage.get("generation_metric")
    if not isinstance(evaluation_time_view, dict):
        raise TimeViewContractError(
            "coverage metric authority evaluation_time_view missing"
        )
    if not isinstance(generation_metric, dict):
        raise TimeViewContractError(
            "coverage metric authority generation_metric missing"
        )
    if not isinstance(audit_metric, dict):
        raise TimeViewContractError(
            "coverage metric authority audit_drift_metric missing"
        )

    validated_view = validate_time_view_contract(
        evaluation_time_view,
        allow_legacy=False,
    )
    if (
        generation_metric.get("channel") != "generation_time"
        or generation_metric.get("outcome") != outcome
        or generation_metric.get("eligible") is not main_eligible
        or generation_metric.get("formal_positive") is not formal_positive
    ):
        raise TimeViewContractError(
            "coverage metric authority generation_metric inconsistent"
        )
    if (
        audit_metric.get("channel") != "audit_time"
        or not isinstance(audit_metric.get("eligible"), bool)
        or not isinstance(audit_metric.get("formal_positive"), bool)
        or (
            audit_metric.get("outcome") == "formal_positive"
        )
        is not (audit_metric.get("formal_positive") is True)
    ):
        raise TimeViewContractError(
            "coverage metric authority audit_drift_metric inconsistent"
        )

    if generation_claim:
        if outcome not in {"formal_positive", "formal_negative"}:
            raise TimeViewContractError(
                "coverage metric authority generation outcome is not formal"
            )
        if (
            validated_view.get("view_id") != "as_of_tg"
            or not formal_generation_metric_eligible(validated_view)
            or generation_metric.get("eligible") is not True
        ):
            raise TimeViewContractError(
                "coverage metric authority generation view unauthorized"
            )

    if audit_claim:
        if (
            validated_view.get("view_id") != "as_of_audit"
            or validated_view.get("view_specific_metric_channel")
            != "audit_time"
            or validated_view.get("retrospective_only") is not False
            or audit_metric.get("outcome")
            not in {"formal_positive", "formal_negative"}
            or audit_metric.get("eligible") is not True
            or main_eligible is not False
            or formal_positive is not False
            or generation_metric.get("eligible") is not False
        ):
            raise TimeViewContractError(
                "coverage metric authority audit view unauthorized"
            )
