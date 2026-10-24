from __future__ import annotations

import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "config/step9_protocol_registry_v1.json"
ACTIVE_POINTER_PATH = ROOT / "config/step9_active_protocol.json"

METHOD_STATUS_REPAIR = "repair_in_progress_not_frozen"
METHOD_STATUS_FROZEN = "frozen_before_fresh_generation"
TERMINAL_RUN_LIFECYCLE = "test100_scientific_closure_complete"

RUN_LIFECYCLE_STATES = frozenset(
    {
        METHOD_STATUS_REPAIR,
        METHOD_STATUS_FROZEN,
        "pilot20_generation_complete_release_snapshot_pending",
        "pilot_release_snapshot_complete_core_closure_pending",
        "pilot_core_freeze_closure_complete_analysis_pending",
        "pilot_analysis_complete_scientific_closure_pending",
        "pilot_scientific_closure_complete_test100_generation_authorized",
        "test100_generation_complete_snapshot_pending",
        "test_release_snapshot_complete_core_closure_pending",
        "test_core_freeze_closure_complete_analysis_pending",
        "test_analysis_complete_scientific_closure_pending",
        TERMINAL_RUN_LIFECYCLE,
    }
)

POST_GENERATION_RUN_LIFECYCLES = frozenset(
    state
    for state in RUN_LIFECYCLE_STATES
    if state
    not in {
        METHOD_STATUS_REPAIR,
        METHOD_STATUS_FROZEN,
    }
)


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return value


def resolve_repo_path(path: Path | str) -> Path:
    value = Path(path)
    if not value.is_absolute():
        value = ROOT / value
    return value.resolve()


def rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def _required_text(value: Any, *, field: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"Step9 {field} is empty")
    return text


def validate_protocol_registry() -> dict[str, Any]:
    registry = read_json(REGISTRY_PATH)
    pointer = read_json(ACTIVE_POINTER_PATH)

    if registry.get("schema_version") != (
        "codesentry_gen_step9_protocol_registry_v1"
    ):
        raise ValueError("Unexpected Step9 protocol registry schema")
    if registry.get("status") != "ACTIVE":
        raise ValueError("Step9 protocol registry is not ACTIVE")
    if pointer.get("schema_version") != (
        "codesentry_gen_step9_active_protocol_v1"
    ):
        raise ValueError("Unexpected Step9 active pointer schema")

    registry_id = _required_text(
        registry.get("active_protocol_id"),
        field="registry active_protocol_id",
    )
    pointer_id = _required_text(
        pointer.get("active_protocol_id"),
        field="pointer active_protocol_id",
    )
    registry_file = _required_text(
        registry.get("active_protocol_file"),
        field="registry active_protocol_file",
    )
    pointer_file = _required_text(
        pointer.get("protocol_file"),
        field="pointer protocol_file",
    )

    if registry_id != pointer_id:
        raise ValueError(
            "Step9 registry/pointer active protocol id mismatch"
        )
    if registry_file != pointer_file:
        raise ValueError(
            "Step9 registry/pointer active protocol file mismatch"
        )

    active_path = resolve_repo_path(pointer_file)
    if not active_path.exists() or not active_path.is_file():
        raise FileNotFoundError(
            f"Active Step9 protocol file missing: {active_path}"
        )
    active = read_json(active_path)

    if str(active.get("protocol_id") or "").strip() != pointer_id:
        raise ValueError(
            "Active Step9 protocol id does not match active pointer"
        )

    active_entry = registry.get("active_protocol")
    if not isinstance(active_entry, dict):
        raise ValueError("Step9 registry active_protocol entry missing")
    if active_entry.get("protocol_id") != pointer_id:
        raise ValueError("Step9 registry active_protocol id mismatch")
    if active_entry.get("file") != pointer_file:
        raise ValueError("Step9 registry active_protocol file mismatch")

    method_status = _required_text(
        active.get("status"),
        field="immutable protocol method status",
    )
    if method_status not in {
        METHOD_STATUS_REPAIR,
        METHOD_STATUS_FROZEN,
    }:
        raise ValueError(
            f"Unexpected Step9 immutable method status: {method_status!r}"
        )

    run_lifecycle = _required_text(
        pointer.get("lifecycle_status"),
        field="active run lifecycle_status",
    )
    if run_lifecycle not in RUN_LIFECYCLE_STATES:
        raise ValueError(
            f"Unexpected Step9 active run lifecycle: {run_lifecycle!r}"
        )

    registry_lifecycle = _required_text(
        registry.get("active_lifecycle_status"),
        field="registry active_lifecycle_status",
    )
    entry_lifecycle = _required_text(
        active_entry.get("lifecycle_status"),
        field="registry active_protocol.lifecycle_status",
    )
    if not (
        run_lifecycle == registry_lifecycle == entry_lifecycle
    ):
        raise ValueError(
            "Step9 pointer/registry active run lifecycle mismatch"
        )

    method_execution_allowed = active.get(
        "formal_execution_allowed"
    ) is True
    pointer_execution_allowed = pointer.get(
        "formal_execution_allowed"
    ) is True
    registry_execution_allowed = registry.get(
        "formal_execution_allowed"
    ) is True
    entry_execution_allowed = active_entry.get(
        "formal_execution_allowed"
    ) is True

    if not (
        pointer_execution_allowed
        == registry_execution_allowed
        == entry_execution_allowed
    ):
        raise ValueError(
            "Step9 pointer/registry live execution authority mismatch"
        )
    live_execution_allowed = pointer_execution_allowed

    if method_status == METHOD_STATUS_REPAIR:
        if run_lifecycle != METHOD_STATUS_REPAIR:
            raise ValueError(
                "Unfrozen Step9 method cannot have an advanced run lifecycle"
            )
        if method_execution_allowed or live_execution_allowed:
            raise ValueError(
                "Unfrozen Step9 method unexpectedly authorizes execution"
            )
    else:
        if not method_execution_allowed:
            raise ValueError(
                "Frozen Step9 method does not preserve method eligibility"
            )
        if run_lifecycle == METHOD_STATUS_REPAIR:
            raise ValueError(
                "Frozen Step9 method points to an unfrozen run lifecycle"
            )

    pointer_selection_started = (
        pointer.get("fresh_selection_started") is True
    )
    pointer_generation_started = (
        pointer.get("fresh_generation_started") is True
    )
    if "fresh_selection_started" in active_entry and (
        active_entry.get("fresh_selection_started") is True
    ) != pointer_selection_started:
        raise ValueError(
            "Step9 pointer/registry fresh-selection state mismatch"
        )
    if "fresh_generation_started" in active_entry and (
        active_entry.get("fresh_generation_started") is True
    ) != pointer_generation_started:
        raise ValueError(
            "Step9 pointer/registry fresh-generation state mismatch"
        )

    if run_lifecycle in POST_GENERATION_RUN_LIFECYCLES and not (
        pointer_selection_started and pointer_generation_started
    ):
        raise ValueError(
            "Post-generation Step9 lifecycle lacks started selection/generation"
        )

    if run_lifecycle == TERMINAL_RUN_LIFECYCLE:
        authority = pointer.get("execution_authority_model")
        if not isinstance(authority, dict):
            raise ValueError(
                "Terminal Step9 lifecycle lacks execution authority model"
            )
        if live_execution_allowed:
            raise ValueError(
                "Terminal Step9 lifecycle still authorizes formal execution"
            )
        if authority.get("direct_benchmark_execution_authority") is not False:
            raise ValueError(
                "Terminal Step9 lifecycle retains direct benchmark authority"
            )
        if authority.get("successor_benchmark_authorized") is not False:
            raise ValueError(
                "Terminal Step9 lifecycle authorizes an undeclared successor"
            )
        pointer_next = str(
            pointer.get("next_independent_gate") or ""
        ).strip()
        authority_next = str(
            authority.get("next_independent_gate") or ""
        ).strip()
        if (
            pointer_next != "none_test100_complete"
            or authority_next != pointer_next
        ):
            raise ValueError(
                "Terminal Step9 lifecycle has a nonterminal next gate"
            )

    historical = registry.get("historical_protocols")
    if not isinstance(historical, list):
        raise ValueError("Step9 historical protocol list missing")
    historical_ids: set[str] = set()
    for row in historical:
        if not isinstance(row, dict):
            raise ValueError("Invalid Step9 historical protocol entry")
        protocol_id = str(row.get("protocol_id") or "").strip()
        file_text = str(row.get("file") or "").strip()
        if not protocol_id or not file_text:
            raise ValueError(
                "Historical Step9 protocol identity/file missing"
            )
        if protocol_id in historical_ids:
            raise ValueError(
                f"Duplicate historical Step9 protocol id: {protocol_id}"
            )
        historical_ids.add(protocol_id)
        if protocol_id == pointer_id:
            raise ValueError(
                "Active Step9 protocol also appears as historical"
            )
        historical_path = resolve_repo_path(file_text)
        if not historical_path.exists():
            raise FileNotFoundError(
                f"Historical Step9 protocol missing: {historical_path}"
            )

    return {
        "registry": registry,
        "pointer": pointer,
        "active_path": active_path,
        "active_protocol": active,
        "active_entry": active_entry,
        "method_status": method_status,
        "run_lifecycle_status": run_lifecycle,
        "method_execution_allowed": method_execution_allowed,
        "live_execution_allowed": live_execution_allowed,
    }


def require_explicit_protocol(
    protocol_path: Path | None,
    *,
    operation: str,
) -> Path:
    if protocol_path is None:
        raise ValueError(
            f"{operation} requires an explicit --protocol/--step9-protocol; "
            "there is intentionally no historical default."
        )
    return resolve_repo_path(protocol_path)


def validate_explicit_protocol(
    protocol_path: Path | None,
    *,
    operation: str,
    require_active: bool,
    require_frozen: bool,
    require_formal_execution_allowed: bool,
) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    path = require_explicit_protocol(
        protocol_path,
        operation=operation,
    )
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(
            f"{operation} protocol file missing: {path}"
        )

    lineage = validate_protocol_registry()
    protocol = read_json(path)

    if require_active:
        if path != lineage["active_path"]:
            raise ValueError(
                f"{operation} requires the unique active Step9 protocol "
                f"{rel(lineage['active_path'])}; got {rel(path)}"
            )
        expected_id = lineage["pointer"]["active_protocol_id"]
        if protocol.get("protocol_id") != expected_id:
            raise ValueError(
                f"{operation} active protocol id mismatch"
            )

    if require_frozen and protocol.get("status") != METHOD_STATUS_FROZEN:
        raise ValueError(
            f"{operation} requires a frozen Step9 protocol; "
            f"current status={protocol.get('status')!r}"
        )

    if require_formal_execution_allowed:
        if protocol.get("formal_execution_allowed") is not True:
            raise ValueError(
                f"{operation} blocked: protocol method eligibility "
                "is not true"
            )
        if require_active and not lineage["live_execution_allowed"]:
            raise ValueError(
                f"{operation} blocked by active Step9 run lifecycle "
                f"{lineage['run_lifecycle_status']!r}"
            )

    return path, protocol, lineage


def require_active_frozen_protocol(
    protocol_path: Path | None,
    *,
    operation: str,
) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    return validate_explicit_protocol(
        protocol_path,
        operation=operation,
        require_active=True,
        require_frozen=True,
        require_formal_execution_allowed=True,
    )


def require_active_pre_generation_protocol(
    protocol_path: Path | None,
    *,
    operation: str,
) -> tuple[Path, dict[str, Any], dict[str, Any]]:
    return require_active_frozen_protocol(
        protocol_path,
        operation=operation,
    )
