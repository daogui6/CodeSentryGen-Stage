from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


TIMELINE_CONTRACT_VERSION = "codesentry_gen_timeline_contract_v1"


def parse_aware_utc(value: Any) -> datetime | None:
    """Parse an explicitly timezone-aware timestamp and normalize to UTC.

    Naive timestamps are not repaired by assumption. Returning None keeps
    optional/unknown evidence unknown; required callers use require_aware_utc.
    """
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        result = datetime.fromisoformat(text)
    except ValueError:
        return None
    if result.tzinfo is None or result.utcoffset() is None:
        return None
    return result.astimezone(timezone.utc)


def require_aware_utc(
    value: Any,
    *,
    label: str,
) -> datetime:
    parsed = parse_aware_utc(value)
    if parsed is None:
        raise ValueError(
            f"{label} must be a timezone-aware ISO-8601 timestamp: "
            f"{value!r}"
        )
    return parsed


def utc_iso(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("utc_iso requires an aware datetime")
    return value.astimezone(timezone.utc).isoformat()


def require_not_after(
    earlier: datetime,
    later: datetime,
    *,
    earlier_label: str,
    later_label: str,
) -> None:
    if earlier > later:
        raise ValueError(
            "Timeline invariant violated: "
            f"{earlier_label}={utc_iso(earlier)} must be <= "
            f"{later_label}={utc_iso(later)}"
        )


def validate_generation_knowledge(
    *,
    generation_time: Any,
    knowledge_time: Any,
    label: str = "sample",
) -> dict[str, str]:
    generation = require_aware_utc(
        generation_time,
        label=f"{label}.generation_time",
    )
    knowledge = require_aware_utc(
        knowledge_time,
        label=f"{label}.knowledge_time",
    )
    require_not_after(
        generation,
        knowledge,
        earlier_label=f"{label}.generation_time",
        later_label=f"{label}.knowledge_time",
    )
    return {
        "generation_time": utc_iso(generation),
        "knowledge_time": utc_iso(knowledge),
    }


def vulnerability_knowledge_status_at_cutoff(
    *,
    published_at: Any,
    knowledge_time: Any,
) -> str:
    knowledge = require_aware_utc(
        knowledge_time,
        label="knowledge_time",
    )
    published = parse_aware_utc(published_at)
    if published is None:
        return "publication_time_unknown"
    if published > knowledge:
        return "not_yet_published"
    return "known_by_knowledge_time"


def validate_release_snapshot_timeline(
    manifest: dict[str, Any],
    *,
    artifacts: dict[str, dict[str, Any]] | None = None,
    label: str = "release_snapshot",
) -> dict[str, Any]:
    """Validate that a registry snapshot never claims knowledge from the future.

    Historical reconstruction is valid: an old snapshot_time can be evaluated
    using bytes acquired later. The prohibited direction is snapshot coverage
    later than the actual acquisition/audit time.
    """
    snapshot = require_aware_utc(
        manifest.get("snapshot_time"),
        label=f"{label}.snapshot_time",
    )
    created = require_aware_utc(
        manifest.get("created_at"),
        label=f"{label}.created_at",
    )
    require_not_after(
        snapshot,
        created,
        earlier_label=f"{label}.snapshot_time",
        later_label=f"{label}.created_at",
    )

    packages = manifest.get("packages")
    if not isinstance(packages, dict) or not packages:
        raise ValueError(
            f"{label}.packages must be a non-empty object"
        )

    checked_packages = 0
    for package, row in packages.items():
        if not isinstance(row, dict):
            raise ValueError(
                f"{label}.packages[{package!r}] must be an object"
            )
        row_time = require_aware_utc(
            row.get("time_view"),
            label=f"{label}.{package}.time_view",
        )
        if row_time != snapshot:
            raise ValueError(
                f"{label}.{package}.time_view must equal snapshot_time: "
                f"{utc_iso(row_time)} != {utc_iso(snapshot)}"
            )
        row_audit = require_aware_utc(
            row.get("audit_time"),
            label=f"{label}.{package}.audit_time",
        )
        require_not_after(
            snapshot,
            row_audit,
            earlier_label=f"{label}.snapshot_time",
            later_label=f"{label}.{package}.audit_time",
        )
        require_not_after(
            row_audit,
            created,
            earlier_label=f"{label}.{package}.audit_time",
            later_label=f"{label}.created_at",
        )

        if artifacts is not None:
            artifact = artifacts.get(str(package))
            if not isinstance(artifact, dict):
                raise ValueError(
                    f"{label}.{package} artifact missing for timeline check"
                )
            artifact_time = require_aware_utc(
                artifact.get("time_view"),
                label=f"{label}.{package}.artifact.time_view",
            )
            artifact_audit = require_aware_utc(
                artifact.get("audit_time"),
                label=f"{label}.{package}.artifact.audit_time",
            )
            if artifact_time != snapshot:
                raise ValueError(
                    f"{label}.{package} artifact time_view does not match "
                    "snapshot_time"
                )
            if artifact_audit != row_audit:
                raise ValueError(
                    f"{label}.{package} manifest/artifact audit_time mismatch"
                )
            require_not_after(
                snapshot,
                artifact_audit,
                earlier_label=f"{label}.snapshot_time",
                later_label=f"{label}.{package}.artifact.audit_time",
            )
        checked_packages += 1

    return {
        "timeline_contract_version": TIMELINE_CONTRACT_VERSION,
        "snapshot_time": utc_iso(snapshot),
        "created_at": utc_iso(created),
        "package_count": checked_packages,
        "future_snapshot_allowed": False,
        "historical_reconstruction_allowed": True,
    }


def validate_sample_generation_times(
    *,
    samples: list[dict[str, Any]],
    knowledge_time: Any,
    label: str = "formal_run",
) -> dict[str, Any]:
    knowledge = require_aware_utc(
        knowledge_time,
        label=f"{label}.knowledge_time",
    )
    checked = 0
    for row in samples:
        if not isinstance(row, dict):
            raise ValueError(
                f"{label} sample row must be an object"
            )
        sample_id = str(row.get("sample_id") or "").strip()
        if str(row.get("generation_error") or "").strip():
            continue
        generation = require_aware_utc(
            row.get("generation_time"),
            label=(
                f"{label}.sample[{sample_id or '?'}].generation_time"
            ),
        )
        require_not_after(
            generation,
            knowledge,
            earlier_label=(
                f"{label}.sample[{sample_id or '?'}].generation_time"
            ),
            later_label=f"{label}.knowledge_time",
        )
        checked += 1
    return {
        "timeline_contract_version": TIMELINE_CONTRACT_VERSION,
        "knowledge_time": utc_iso(knowledge),
        "checked_samples": checked,
    }
