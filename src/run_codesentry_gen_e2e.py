from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from freeze_hash_v1 import (
    canonical_sha256_file,
    hash_matches,
    verify_hash,
)
from step9_protocol_registry import (
    require_active_frozen_protocol,
)
from verify_core_freeze_closure_v1 import (
    verify_core_freeze_closure,
)
from build_step9_method_freeze_v1 import verify_step9_formal_freeze_binding
from generation_outcome_accounting_v1 import validate_manifest_self_consistency
from generation_outcome_integration_v1 import (
    accepted_rows_from_manifest,
    evaluate_split_statistical_eligibility,
    require_successor_method_revision_contract,
)
from scientific_contract_v1 import (
    build_avcs_coverage_review_findings,
    build_avcs_resume_input,
    build_e2e_run_contract,
    evaluate_scientific_contract,
    initialize_or_verify_e2e_resume_contract,
    project_avcs_final_output_coverage,
    verify_avcs_resume_contract,
    verify_sceg_base_resume,
)
from risk_semantics_v21 import (
    FORMAL_MAIN_RISK_TYPES,
    deduplicate_cards,
    load_semantics,
    normalize_risk_card,
    validate_risk_card,
)
from time_contract_v1 import (
    require_aware_utc,
    utc_iso,
    validate_sample_generation_times,
)
from time_view_contract_v1 import (
    FORMAL_TIME_VIEW_IDS,
    build_legacy_time_view_marker,
    build_time_view_contract,
    validate_coverage_metric_authority,
)


ROOT = Path(__file__).resolve().parents[1]
RISK_SEMANTICS = load_semantics()
PYTHON = sys.executable

DEFAULT_STEP8_FREEZE = ROOT / "output/step8_freeze_v0/step8_freeze_report.json"
DEFAULT_THRESHOLD_POLICY = ROOT / "config/step8_avcs_threshold_policy_v2_f10_exposure_prerequisite.json"
DEFAULT_AVCS_KB_DIR = ROOT / "data/avcs_package_kb"
DEFAULT_IMPORT_MAPPING = ROOT / "config/import_mapping.json"
DEFAULT_IDENTITY_POLICY = ROOT / "config/package_identity_policy_v1.json"
DEFAULT_STEP7_FREEZE = (
    ROOT
    / "output/step7_batch_review_v0/step7_freeze_v1/step7_freeze_report.json"
)
REQUIRED_SCRIPTS = [
    ROOT / "src/generate_code_from_prompts.py",
    ROOT / "src/run_pilot.py",
    ROOT / "src/enrich_temporal_status.py",
    ROOT / "src/enrich_reachability_v2.py",
    ROOT / "src/build_temporal_risk_cards.py",
    ROOT / "src/run_step8_unified_avcs.py",
    ROOT / "src/build_sceg_ir_v21.py",
    ROOT / "src/finalize_sceg_ir_v21.py",
    ROOT / "src/materialize_project_snapshots_v1.py",
    ROOT / "src/package_identity_v1.py",
    ROOT / "src/project_dependency_facts_v1.py",
]


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return value


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows

    with path.open("r", encoding="utf-8-sig") as handle:
        for line_no, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(
                    f"Expected object at {path}:{line_no}"
                )
            rows.append(value)
    return rows


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def rel(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def raw_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def resolve_requested_time_view_binding(
    *,
    time_view_id: str | None,
    snapshot_sha256: str | None,
    output_namespace: str | None,
    release_snapshot_manifest: Path | None,
) -> dict[str, str] | None:
    """Resolve an all-or-none E2E binding for a named evaluation view."""
    values = (time_view_id, snapshot_sha256, output_namespace)
    if all(value is None for value in values):
        return None
    if any(value is None for value in values):
        raise ValueError(
            "Named time view requires view ID, snapshot SHA-256, and "
            "output namespace together"
        )

    view_id = str(time_view_id or "").strip()
    snapshot = str(snapshot_sha256 or "").strip().lower()
    namespace = str(output_namespace or "").strip().replace("\\", "/")
    if view_id not in FORMAL_TIME_VIEW_IDS:
        raise ValueError(f"Unsupported named time view: {view_id!r}")
    if len(snapshot) != 64 or any(
        char not in "0123456789abcdef" for char in snapshot
    ):
        raise ValueError(
            "Named time-view snapshot SHA-256 must be 64 lowercase hex"
        )
    if not namespace or namespace.split("/", 1)[0] != view_id:
        raise ValueError(
            "Named time-view output namespace must begin with the view ID"
        )
    if release_snapshot_manifest is not None:
        if not release_snapshot_manifest.exists():
            raise FileNotFoundError(release_snapshot_manifest)
        actual_snapshot = raw_sha256(release_snapshot_manifest)
        if actual_snapshot != snapshot:
            raise ValueError(
                "Named time-view snapshot hash disagrees with the bound "
                "release snapshot manifest"
            )
    return {
        "view_id": view_id,
        "evidence_snapshot_sha256": snapshot,
        "output_namespace": namespace.rstrip("/"),
    }


def build_sample_time_view_contract(
    *,
    binding: dict[str, str],
    sample_id: str,
    generation_time: str,
    audit_knowledge_time: str | None,
) -> dict[str, Any]:
    view_id = binding["view_id"]
    if view_id == "as_of_tg":
        evidence_cutoff = generation_time
    else:
        if audit_knowledge_time is None:
            raise ValueError(
                f"{view_id} requires an explicit audit/oracle cutoff"
            )
        evidence_cutoff = audit_knowledge_time
    namespace = (
        binding["output_namespace"].rstrip("/")
        + "/samples/"
        + sample_id
    )
    return build_time_view_contract(
        view_id=view_id,
        generation_time=generation_time,
        evidence_cutoff=evidence_cutoff,
        evidence_snapshot_sha256=binding["evidence_snapshot_sha256"],
        output_namespace=namespace,
    )


def expected_prompt_count(
    prompts: Path,
    *,
    start: int,
    limit: int,
) -> int:
    rows = read_jsonl(prompts)
    if start < 1:
        raise ValueError("--start must be >= 1")
    rows = rows[start - 1:]
    if limit > 0:
        rows = rows[:limit]
    return len(rows)


def verify_hash_map(
    *,
    expected: dict[str, Any],
    label: str,
) -> None:
    if not expected:
        raise ValueError(f"{label} hash map is empty")

    for relative, expected_digest in expected.items():
        path = ROOT / str(relative)
        verify_hash(
            path,
            expected_digest,
            label=f"{label}:{relative}",
            legacy_eol_compatible=True,
        )


def verify_step8_frozen_files(
    freeze: dict[str, Any],
) -> list[str]:
    blockers: list[str] = []

    hashes = freeze.get("critical_file_sha256", {})

    if not isinstance(hashes, dict) or not hashes:
        return ["step8_freeze_critical_hashes_missing"]

    for relative, expected_digest in hashes.items():
        path = ROOT / str(relative)

        if not path.exists() or not path.is_file():
            blockers.append(f"step8_frozen_file_missing:{relative}")
            continue

        if not hash_matches(
            path,
            expected_digest,
            legacy_eol_compatible=True,
        ):
            blockers.append(f"step8_frozen_file_drift:{relative}")

    return blockers


def verify_step9_run_contract(
    *,
    run_purpose: str,
    prompts: Path,
    model: str,
    real_generation: bool,
    start: int,
    limit: int,
    out_dir: Path,
    protocol_path: Path | None,
    knowledge_time: str | None,
    generation_time_uncertainty_seconds: float | None,
    release_snapshot_manifest: Path | None = None,
    time_view_id: str | None = None,
    time_view_snapshot_sha256: str | None = None,
    time_view_output_namespace: str | None = None,
) -> dict[str, Any]:
    requested_time_view_binding = resolve_requested_time_view_binding(
        time_view_id=time_view_id,
        snapshot_sha256=time_view_snapshot_sha256,
        output_namespace=time_view_output_namespace,
        release_snapshot_manifest=release_snapshot_manifest,
    )
    if run_purpose == "integration_smoke":
        resolved_uncertainty = (
            float(generation_time_uncertainty_seconds)
            if generation_time_uncertainty_seconds is not None
            else float(
                RISK_SEMANTICS[
                    "generation_time_uncertainty"
                ]["integration_smoke_default_seconds"]
            )
        )
        if resolved_uncertainty < 0:
            raise ValueError(
                "generation-time uncertainty must be >= 0"
            )
        resolved_smoke_knowledge = None
        if knowledge_time is not None:
            resolved_smoke_knowledge = utc_iso(
                require_aware_utc(
                    knowledge_time,
                    label="integration_smoke.knowledge_time",
                )
            )
        return {
            "is_step9": False,
            "fresh_step9_benchmark_used": False,
            "step9_started": False,
            "step9_split": None,
            "knowledge_time": resolved_smoke_knowledge,
            "generation_time_uncertainty_seconds": resolved_uncertainty,
            "formal_main_risk_types": sorted(FORMAL_MAIN_RISK_TYPES),
            "formal_type_aliases": {},
            "avcs_coverage_acceptance": {},
            "named_time_view_binding": requested_time_view_binding,
        }

    if run_purpose not in {"step9_pilot", "step9_test"}:
        raise ValueError(f"Unsupported run purpose: {run_purpose}")

    protocol_path, protocol, protocol_lineage = (
        require_active_frozen_protocol(
            protocol_path,
            operation=f"E2E {run_purpose}",
        )
    )
    require_successor_method_revision_contract(protocol)
    selection_path = ROOT / protocol["planned_outputs"]["selection_manifest"]
    selection = read_json(selection_path)

    if protocol.get("status") != "frozen_before_fresh_generation":
        raise ValueError("Step9 protocol is not frozen")

    split_name = "pilot" if run_purpose == "step9_pilot" else "test"
    snapshot_key = (
        "pilot_release_snapshot_manifest"
        if split_name == "pilot"
        else "test_release_snapshot_manifest"
    )
    closure_key = (
        "pilot_core_freeze_closure"
        if split_name == "pilot"
        else "test_core_freeze_closure"
    )
    expected_snapshot_rel = str(
        protocol.get("planned_outputs", {}).get(snapshot_key) or ""
    ).strip()
    expected_core_closure_rel = str(
        protocol.get("planned_outputs", {}).get(closure_key) or ""
    ).strip()
    if not expected_snapshot_rel or not expected_core_closure_rel:
        raise ValueError(
            "Frozen v4 protocol does not declare split-specific "
            "post-generation evidence outputs"
        )

    time_views = protocol.get("evaluation_time_views")
    if not isinstance(time_views, dict):
        raise ValueError(
            "Step9 repaired runtime requires evaluation_time_views in the "
            "frozen protocol"
        )
    declared_named_views = time_views.get("named_view_contracts")
    if not isinstance(declared_named_views, dict):
        raise ValueError(
            "Formal Step9 protocol predates named time-view authority; "
            "a prospective protocol revision and Method Freeze are required"
        )
    if requested_time_view_binding is None:
        raise ValueError(
            "Formal Step9 requires an explicit protocol-bound named time view"
        )
    declared_view = declared_named_views.get(
        requested_time_view_binding["view_id"]
    )
    if not isinstance(declared_view, dict):
        raise ValueError(
            "Requested named time view is not declared by the frozen protocol"
        )
    if declared_view.get("output_namespace") != (
        requested_time_view_binding["output_namespace"]
    ):
        raise ValueError(
            "Named time-view output namespace differs from the frozen protocol"
        )
    if declared_view.get("snapshot_binding") != (
        "split_release_snapshot_manifest_sha256"
    ):
        raise ValueError(
            "Named time-view snapshot authority is not protocol-bound to the "
            "split release snapshot manifest"
        )
    if (
        requested_time_view_binding["view_id"] == "as_of_tg"
        and declared_view.get("formal_generation_metric_eligible") is not True
    ):
        raise ValueError(
            "Protocol does not authorize as_of_tg for the generation metric"
        )
    if (
        requested_time_view_binding["view_id"] != "as_of_tg"
        and declared_view.get("formal_generation_metric_eligible") is not False
    ):
        raise ValueError(
            "Audit/oracle protocol view cannot enter the generation metric"
        )
    knowledge_mode = str(
        time_views.get("audit_knowledge_time_mode") or ""
    ).strip()
    protocol_knowledge_time = str(
        time_views.get("audit_knowledge_time") or ""
    ).strip()
    resolved_snapshot_time: str | None = None
    if knowledge_mode == (
        "bound_release_snapshot_created_at_after_generation"
    ):
        if protocol_knowledge_time:
            raise ValueError(
                "Derived Step9 audit-knowledge mode must not also freeze "
                "a literal audit_knowledge_time"
            )
        if release_snapshot_manifest is None:
            raise ValueError(
                "Derived Step9 audit knowledge requires the post-generation "
                "frozen release snapshot manifest"
            )
        if release_snapshot_manifest.resolve() != (
            ROOT / expected_snapshot_rel
        ).resolve():
            raise ValueError(
                "Formal Step9 must use the split-specific release snapshot "
                "declared by the frozen protocol"
            )
        snapshot = read_json(release_snapshot_manifest)
        if snapshot.get("status") != "FROZEN":
            raise ValueError(
                "Step9 release snapshot manifest is not FROZEN"
            )
        snapshot_dt = require_aware_utc(
            snapshot.get("snapshot_time"),
            label="Step9 release_snapshot.snapshot_time",
        )
        frozen_knowledge_dt = require_aware_utc(
            snapshot.get("created_at"),
            label="Step9 release_snapshot.created_at",
        )
        if snapshot_dt > frozen_knowledge_dt:
            raise ValueError(
                "Release snapshot created_at precedes snapshot_time"
            )
        resolved_snapshot_time = utc_iso(snapshot_dt)
        resolved_knowledge_time = utc_iso(frozen_knowledge_dt)
        knowledge_source = "bound_release_snapshot.created_at"
    else:
        if not protocol_knowledge_time:
            raise ValueError(
                "Step9 repaired runtime requires either frozen "
                "audit_knowledge_time or the declared post-generation "
                "release-snapshot derivation mode"
            )
        frozen_knowledge_dt = require_aware_utc(
            protocol_knowledge_time,
            label="Step9 evaluation_time_views.audit_knowledge_time",
        )
        resolved_knowledge_time = utc_iso(frozen_knowledge_dt)
        knowledge_source = "frozen_protocol.audit_knowledge_time"

    if knowledge_time is not None:
        cli_knowledge_dt = require_aware_utc(
            knowledge_time,
            label="--knowledge-time",
        )
        if cli_knowledge_dt != frozen_knowledge_dt:
            raise ValueError(
                "--knowledge-time does not match the resolved frozen Step9 "
                "audit knowledge cutoff"
            )

    protocol_uncertainty = time_views.get(
        "generation_time_uncertainty_seconds"
    )
    if protocol_uncertainty is None:
        raise ValueError(
            "Step9 repaired runtime requires frozen "
            "evaluation_time_views.generation_time_uncertainty_seconds"
        )
    resolved_uncertainty = float(protocol_uncertainty)
    if resolved_uncertainty < 0:
        raise ValueError(
            "Frozen generation-time uncertainty must be >= 0"
        )
    if (
        generation_time_uncertainty_seconds is not None
        and float(generation_time_uncertainty_seconds)
        != resolved_uncertainty
    ):
        raise ValueError(
            "--generation-time-uncertainty-seconds does not match "
            "the frozen Step9 protocol"
        )

    if selection.get("status") != "FROZEN":
        raise ValueError("Step9 fresh selection is not frozen")

    if not hash_matches(
        protocol_path,
        selection.get("protocol_sha256", ""),
        legacy_eol_compatible=True,
    ):
        raise ValueError("Step9 protocol drifted after split freeze")

    audit_path = ROOT / protocol["leakage_audit"]["file"]

    if not audit_path.exists():
        raise ValueError("Step9 pre-generation leakage audit is missing")

    audit = read_json(audit_path)

    if audit.get("status") != "PASS":
        raise ValueError("Step9 pre-generation leakage audit is not PASS")

    if not hash_matches(
        audit_path,
        selection.get("leakage_audit_sha256", ""),
        legacy_eol_compatible=True,
    ):
        raise ValueError("Step9 leakage audit drifted after split freeze")

    selection_schema = str(selection.get("schema_version") or "")
    if selection_schema in {
        "step9_fresh_selection_manifest_v0.3",
        "step9_fresh_selection_manifest_v0.4",
    }:
        method_record = selection.get("method_freeze")
        if not isinstance(method_record, dict):
            raise ValueError(
                "Step9 selection does not bind the pre-generation method freeze"
            )
        method_rel = str(method_record.get("file") or "").strip()
        expected_method_rel = str(
            protocol.get("planned_outputs", {}).get("method_freeze")
            or ""
        ).strip()
        if not method_rel or method_rel != expected_method_rel:
            raise ValueError(
                "Step9 selection method freeze differs from frozen protocol"
            )
        method_path = ROOT / method_rel
        if not method_path.exists():
            raise ValueError("Step9 pre-generation method freeze is missing")
        if not hash_matches(
            method_path,
            method_record.get("sha256", ""),
            legacy_eol_compatible=True,
        ):
            raise ValueError(
                "Step9 pre-generation method freeze drifted after split freeze"
            )
        method = verify_step9_formal_freeze_binding(
            method_path,
            protocol_path=protocol_path,
            require_git_identity=True,
            require_environment_versions=True,
        )
        if method_record.get("method_closure_sha256") != method.get(
            "method_closure_sha256"
        ):
            raise ValueError(
                "Step9 method-freeze digest mismatch"
            )

        runtime_contract = selection.get("runtime_freeze_contract")
        if not isinstance(runtime_contract, dict):
            raise ValueError(
                "Step9 selection runtime freeze contract is missing"
            )
        if (
            runtime_contract.get("authority")
            != "pre_generation_repaired_method_freeze"
            or runtime_contract.get("method_freeze_file") != method_rel
            or runtime_contract.get("method_closure_sha256")
            != method.get("method_closure_sha256")
            or runtime_contract.get(
                "release_snapshot_intentionally_post_generation"
            )
            is not True
        ):
            raise ValueError(
                "Step9 selection runtime authority is not the "
                "pre-generation repaired method freeze"
            )
    else:
        runtime_hashes = selection.get("evaluation_runtime_sha256", {})
        if not isinstance(runtime_hashes, dict):
            raise ValueError("Step9 evaluation runtime hash set is invalid")
        verify_hash_map(
            expected=runtime_hashes,
            label="Step9 evaluation runtime",
        )

    expected_rel = protocol["splits"][split_name]["output"]
    expected_path = ROOT / expected_rel

    if prompts.resolve() != expected_path.resolve():
        raise ValueError(
            f"{run_purpose} must use frozen split {expected_rel}; got {rel(prompts)}"
        )

    manifest_split = selection[split_name]
    expected_sha = str(manifest_split.get("sha256", "")).strip()

    if not expected_sha or not hash_matches(
        prompts,
        expected_sha,
        legacy_eol_compatible=True,
    ):
        raise ValueError(
            f"{run_purpose} prompt split SHA256 does not match frozen manifest"
        )
    actual_sha = canonical_sha256_file(prompts)

    expected_model = str(
        protocol.get("model_generation", {}).get("model", "")
    ).strip()

    if expected_model and model != expected_model:
        raise ValueError(
            f"{run_purpose} model must be {expected_model}, got {model}"
        )

    if not real_generation:
        raise ValueError(
            f"{run_purpose} requires --real; mock generation is forbidden"
        )

    declared_size = int(protocol["splits"][split_name]["size"])

    if start != 1:
        raise ValueError(
            f"{run_purpose} must start at row 1 of the frozen split"
        )

    if limit not in {0, declared_size}:
        raise ValueError(
            f"{run_purpose} must run the full frozen split "
            f"(--limit {declared_size} or --limit 0), got {limit}"
        )

    planned_output = ROOT / protocol["planned_outputs"][
        "pilot_run" if split_name == "pilot" else "test_run"
    ]

    if out_dir.resolve() != planned_output.resolve():
        raise ValueError(
            f"{run_purpose} must write to frozen output directory "
            f"{rel(planned_output)}; got {rel(out_dir)}"
        )

    if run_purpose == "step9_test":
        if selection.get("test", {}).get(
            "generated_results_inspected"
        ) is not False:
            raise ValueError(
                "Frozen test split must be uninspected before formal test start"
            )

        closure_path = ROOT / protocol["planned_outputs"]["pilot_closure"]

        if not closure_path.exists():
            raise ValueError(
                "Step9 test is blocked until the pilot closure artifact exists"
            )

        closure = read_json(closure_path)

        if (
            closure.get("status") != "PASS"
            or closure.get("pilot_closed") is not True
        ):
            raise ValueError("Step9 pilot closure is not PASS")

        if closure.get("detection_semantics_changed") is not False:
            raise ValueError(
                "Pilot closure does not certify unchanged detection semantics"
            )

        if closure.get("thresholds_changed") is not False:
            raise ValueError(
                "Pilot closure does not certify unchanged frozen thresholds"
            )

    return {
        "is_step9": True,
        "fresh_step9_benchmark_used": True,
        "step9_started": True,
        "step9_split": split_name,
        "step9_protocol_file": rel(protocol_path),
        "step9_selection_file": rel(selection_path),
        "formal_main_risk_types": list(
            protocol.get("formal_main_risk_types", [])
        ),
        "formal_type_aliases": dict(
            protocol.get("formal_type_aliases", {})
        ),
        "package_identity": dict(
            protocol.get("package_identity", {})
        ),
        "active_protocol_registry_file": (
            "config/step9_protocol_registry_v1.json"
        ),
        "active_protocol_pointer_file": (
            "config/step9_active_protocol.json"
        ),
        "active_protocol_id": protocol_lineage["pointer"][
            "active_protocol_id"
        ],
        "step9_leakage_audit_file": rel(audit_path),
        "step9_split_sha256": actual_sha,
        "step9_full_split_required": True,
        "step9_real_generation_required": True,
        "knowledge_time": resolved_knowledge_time,
        "knowledge_time_source": knowledge_source,
        "release_snapshot_time": resolved_snapshot_time,
        "generation_time_uncertainty_seconds": resolved_uncertainty,
        "release_snapshot_manifest_file": expected_snapshot_rel,
        "core_freeze_closure_file": expected_core_closure_rel,
        "avcs_coverage_acceptance": copy.deepcopy(
            protocol.get("avcs_coverage_acceptance") or {}
        ),
        "named_time_view_binding": copy.deepcopy(
            requested_time_view_binding
        ),
    }

def verify_step9_generation_stage(
    *,
    protocol_path: Path,
    run_purpose: str,
    prompts: Path,
    out_dir: Path,
    model: str,
    release_snapshot_manifest: Path,
    resolved_knowledge_time: str,
) -> tuple[Path, dict[str, Any], list[dict[str, Any]]]:
    protocol = read_json(protocol_path)
    split_name = "pilot" if run_purpose == "step9_pilot" else "test"
    key = (
        "pilot_generation_stage_manifest"
        if split_name == "pilot"
        else "test_generation_stage_manifest"
    )
    stage_rel = str(
        protocol.get("planned_outputs", {}).get(key) or ""
    ).strip()
    if not stage_rel:
        raise ValueError(
            f"Frozen protocol does not declare {key}"
        )
    stage_path = ROOT / stage_rel
    if not stage_path.exists():
        raise FileNotFoundError(
            f"Frozen real-generation stage manifest missing: {stage_rel}"
        )
    stage = read_json(stage_path)
    if (
        stage.get("schema_version")
        != "step9_generation_stage_manifest_v1"
        or stage.get("status") != "PASS"
        or stage.get("split") != split_name
    ):
        raise ValueError("Invalid Step9 generation-stage manifest")

    verify_hash(
        protocol_path,
        stage.get("protocol_hash"),
        label="Step9 generation-stage protocol",
        legacy_eol_compatible=True,
    )

    selection_path = ROOT / protocol["planned_outputs"][
        "selection_manifest"
    ]
    if stage.get("selection_manifest_file") != rel(selection_path):
        raise ValueError(
            "Generation stage selection-manifest path mismatch"
        )
    verify_hash(
        selection_path,
        stage.get("selection_manifest_hash"),
        label="Step9 generation-stage selection",
        legacy_eol_compatible=True,
    )
    selection = read_json(selection_path)

    method_path = ROOT / protocol["planned_outputs"]["method_freeze"]
    if stage.get("method_freeze_file") != rel(method_path):
        raise ValueError("Generation stage method-freeze path mismatch")
    verify_hash(
        method_path,
        stage.get("method_freeze_hash"),
        label="Step9 generation-stage method freeze",
        legacy_eol_compatible=True,
    )
    method = verify_step9_formal_freeze_binding(
        method_path,
        protocol_path=protocol_path,
        require_git_identity=True,
        require_environment_versions=True,
    )
    if stage.get("method_closure_sha256") != method.get(
        "method_closure_sha256"
    ):
        raise ValueError(
            "Generation stage method-freeze digest mismatch"
        )

    expected_prompt_rel = protocol["splits"][split_name]["output"]
    if stage.get("prompt_file") != expected_prompt_rel:
        raise ValueError("Generation-stage prompt path mismatch")
    if prompts.resolve() != (ROOT / expected_prompt_rel).resolve():
        raise ValueError("Generation-stage prompt split mismatch")
    if stage.get("prompt_sha256") != canonical_sha256_file(prompts):
        raise ValueError("Generation-stage prompt split hash mismatch")

    model_cfg = protocol.get("model_generation")
    if not isinstance(model_cfg, dict):
        raise ValueError("Frozen protocol model_generation missing")
    expected_model = str(model_cfg.get("model") or "").strip()
    if not expected_model or model != expected_model:
        raise ValueError("Generation-stage model differs from protocol")
    if stage.get("model") != expected_model:
        raise ValueError("Generation-stage manifest model mismatch")
    expected_temperature = float(model_cfg.get("temperature"))
    expected_timeout = int(model_cfg.get("request_timeout_seconds"))
    expected_retries = int(model_cfg.get("retries"))
    if (
        float(stage.get("temperature")) != expected_temperature
        or int(stage.get("timeout_seconds")) != expected_timeout
        or int(stage.get("retries")) != expected_retries
    ):
        raise ValueError(
            "Generation-stage runtime parameters differ from frozen protocol"
        )

    generation_dir = out_dir / "generation"
    samples_path = generation_dir / "generated_samples.jsonl"
    if stage.get("generated_samples_file") != rel(samples_path):
        raise ValueError("Generation-stage samples path mismatch")
    if not samples_path.exists():
        raise FileNotFoundError(samples_path)
    if stage.get("generated_samples_sha256") != canonical_sha256_file(
        samples_path
    ):
        raise ValueError("Frozen generated-samples artifact drift")

    rows = read_jsonl(samples_path)
    declared_size = int(protocol["splits"][split_name]["size"])
    if (
        len(rows) > declared_size
        or int(stage.get("generated_sample_count", -1)) != len(rows)
        or int(stage.get("selected_count", -1)) != declared_size
        or int(stage.get("declared_size", -1)) != declared_size
    ):
        raise ValueError("Frozen generation-stage sample count mismatch")

    outcome_rel = str(
        stage.get("generation_outcome_manifest_file") or ""
    ).strip()
    if not outcome_rel:
        raise ValueError(
            "Frozen generation stage does not bind outcome manifest"
        )
    outcome_path = ROOT / outcome_rel
    if not outcome_path.is_file():
        raise FileNotFoundError(outcome_path)
    outcome = read_json(outcome_path)
    validate_manifest_self_consistency(outcome)
    if outcome.get("split") != split_name:
        raise ValueError("Frozen generation outcome split mismatch")
    if int(outcome.get("selected_count") or 0) != declared_size:
        raise ValueError("Frozen outcome selected count mismatch")
    if stage.get("stage_evidence_status") != outcome.get(
        "stage_evidence_status"
    ):
        raise ValueError("Frozen stage/outcome status mismatch")
    if stage.get("generation_outcome_manifest_content_sha256") != (
        outcome.get("manifest_content_sha256")
    ):
        raise ValueError("Frozen stage/outcome content binding mismatch")
    verify_hash(
        outcome_path,
        stage.get("generation_outcome_manifest_hash"),
        label="Step9 generation outcome manifest",
        legacy_eol_compatible=True,
    )
    eligibility = evaluate_split_statistical_eligibility(outcome)
    if stage.get("statistical_eligibility") != eligibility:
        raise ValueError(
            "Frozen generation-stage statistical eligibility mismatch"
        )
    if eligibility.get("eligible") is not True:
        raise ValueError(
            "Formal Step9 analysis is statistically NO-GO"
        )

    expected_prompt_ids = selection[split_name]["prompt_ids"]
    if list(outcome.get("selected_prompt_ids") or []) != expected_prompt_ids:
        raise ValueError(
            "Outcome manifest selected prompt order differs from selection"
        )
    observed_prompt_ids = [
        str(row.get("prompt_id") or "").strip() for row in rows
    ]
    observed_set = set(observed_prompt_ids)
    expected_observed_order = [
        prompt_id
        for prompt_id in expected_prompt_ids
        if prompt_id in observed_set
    ]
    if (
        observed_prompt_ids != expected_observed_order
        or len(observed_set) != len(observed_prompt_ids)
    ):
        raise ValueError(
            "Frozen generated rows violate selected relative prompt order"
        )
    accepted_rows = accepted_rows_from_manifest(
        generated_rows=rows,
        manifest=outcome,
    )

    time_views = protocol.get("evaluation_time_views")
    if not isinstance(time_views, dict):
        raise ValueError("Frozen protocol evaluation_time_views missing")
    uncertainty_raw = time_views.get(
        "generation_time_uncertainty_seconds"
    )
    if not isinstance(uncertainty_raw, (int, float)):
        raise ValueError(
            "Frozen protocol generation-time uncertainty is invalid"
        )
    frozen_uncertainty = float(uncertainty_raw)
    if stage.get("generation_time_uncertainty_seconds") != frozen_uncertainty:
        raise ValueError(
            "Generation-stage Δt differs from frozen protocol"
        )

    generation_times = []
    for row in accepted_rows:
        sample_id = str(row.get("sample_id") or "").strip()
        if str(row.get("model") or "").strip() != expected_model:
            raise ValueError(
                f"Frozen generation requested-model mismatch for {sample_id}"
            )
        if str(row.get("api_reported_model") or "").strip() != expected_model:
            raise ValueError(
                f"Frozen generation API-reported model mismatch for {sample_id}"
            )
        if float(row.get("generation_temperature")) != expected_temperature:
            raise ValueError(
                f"Frozen generation temperature mismatch for {sample_id}"
            )
        generated_at = require_aware_utc(
            row.get("generation_time"),
            label=(
                "Step9 generation-stage "
                f"{sample_id}.generation_time"
            ),
        )
        request_started = require_aware_utc(
            row.get("generation_request_started_at"),
            label=(
                "Step9 generation-stage "
                f"{sample_id}.generation_request_started_at"
            ),
        )
        response_completed = require_aware_utc(
            row.get("generation_response_completed_at"),
            label=(
                "Step9 generation-stage "
                f"{sample_id}.generation_response_completed_at"
            ),
        )
        if request_started > response_completed:
            raise ValueError(
                f"Frozen generation interval inverted for {sample_id}"
            )
        if generated_at != response_completed:
            raise ValueError(
                f"Frozen generation_time is not response completion for {sample_id}"
            )
        measured_seconds = (
            response_completed - request_started
        ).total_seconds()
        observed_seconds = row.get(
            "generation_observed_request_seconds"
        )
        if (
            not isinstance(observed_seconds, (int, float))
            or abs(float(observed_seconds) - measured_seconds) > 0.01
        ):
            raise ValueError(
                f"Frozen generation interval provenance mismatch for {sample_id}"
            )
        if measured_seconds > frozen_uncertainty:
            raise ValueError(
                f"Frozen generation exceeds protocol Δt for {sample_id}"
            )
        generation_times.append(generated_at)

    if not generation_times:
        raise ValueError(
            "Statistically eligible formal analysis has no accepted timestamps"
        )
    observed_min = utc_iso(min(generation_times))
    observed_max = utc_iso(max(generation_times))
    if (
        stage.get("generation_time_min") != observed_min
        or stage.get("generation_time_max") != observed_max
    ):
        raise ValueError("Generation-stage time range mismatch")

    code_dir = generation_dir / "code"
    req_dir = generation_dir / "requirements"
    for key_name, base_dir in (
        ("code_sidecar_sha256", code_dir),
        ("requirements_sidecar_sha256", req_dir),
    ):
        expected_map = stage.get(key_name)
        if (
            not isinstance(expected_map, dict)
            or len(expected_map) != len(accepted_rows)
        ):
            raise ValueError(
                f"Generation-stage {key_name} inventory mismatch"
            )
        for relative, digest in expected_map.items():
            target = ROOT / str(relative)
            if not target.exists() or not target.is_file():
                raise FileNotFoundError(target)
            if canonical_sha256_file(target) != str(digest):
                raise ValueError(
                    f"Frozen generation sidecar drift: {relative}"
                )
            if target.parent.resolve() != base_dir.resolve():
                raise ValueError(
                    f"Generation sidecar escaped expected directory: {relative}"
                )

    snapshot = read_json(release_snapshot_manifest)
    if snapshot.get("status") != "FROZEN":
        raise ValueError("Post-generation release snapshot is not FROZEN")
    snapshot_time = require_aware_utc(
        snapshot.get("snapshot_time"),
        label="Step9 release_snapshot.snapshot_time",
    )
    knowledge_dt = require_aware_utc(
        resolved_knowledge_time,
        label="Step9 resolved audit knowledge time",
    )
    finalized_at = require_aware_utc(
        stage.get("stage_finalized_at"),
        label="Step9 generation-stage stage_finalized_at",
    )
    if finalized_at > snapshot_time:
        raise ValueError(
            "Post-generation release snapshot predates split finalization"
        )
    if max(generation_times) > snapshot_time:
        raise ValueError(
            "Post-generation release snapshot does not cover every accepted "
            "generation_time"
        )
    if max(generation_times) > knowledge_dt:
        raise ValueError(
            "Resolved audit knowledge time precedes generated code"
        )

    return stage_path, outcome, accepted_rows


def run_cmd(cmd: list[str]) -> None:
    print("\n[RUN]", " ".join(cmd))
    result = subprocess.run(cmd, cwd=ROOT)
    if result.returncode != 0:
        raise RuntimeError(
            f"Command failed with exit code {result.returncode}: "
            + " ".join(cmd)
        )


def build_step8_avcs_command(
    *,
    code_path: Path | None,
    sample_id: str,
    samples_path: Path | None,
    sample_out: Path,
    knowledge_time: str | None,
    release_snapshot_manifest: Path | None,
    sceg_ir_path: Path | None,
    identity_policy_path: Path,
    project_root: Path | None = None,
    time_view_id: str | None = None,
    time_view_snapshot_sha256: str | None = None,
    time_view_output_namespace: str | None = None,
) -> list[str]:
    cmd = [
        PYTHON,
        "src/run_step8_unified_avcs.py",
        "--sample-id",
        sample_id,
        "--out-dir",
        str(sample_out),
        "--identity-policy",
        str(identity_policy_path),
    ]
    if code_path is not None:
        cmd.extend(["--code", str(code_path)])
    if samples_path is not None:
        cmd.extend(["--sample-records", str(samples_path)])
    if project_root is not None:
        cmd.extend(["--project-root", str(project_root)])
    if knowledge_time:
        cmd.extend(["--knowledge-time", knowledge_time])
    explicit_time_view_fields = (
        time_view_id,
        time_view_snapshot_sha256,
        time_view_output_namespace,
    )
    if any(value is not None for value in explicit_time_view_fields):
        if any(value is None for value in explicit_time_view_fields):
            raise ValueError(
                "Step8 named time-view command fields must be all-or-none"
            )
        cmd.extend(
            [
                "--time-view-id",
                str(time_view_id),
                "--time-view-snapshot-sha256",
                str(time_view_snapshot_sha256),
                "--time-view-output-namespace",
                str(time_view_output_namespace),
            ]
        )
    if sceg_ir_path is not None:
        cmd.extend(["--sceg-ir", str(sceg_ir_path)])
    if release_snapshot_manifest is not None:
        cmd.extend(
            [
                "--release-snapshot-manifest",
                str(release_snapshot_manifest),
            ]
        )
    return cmd


def formal_release_snapshot_binding_blockers(
    *,
    run_purpose: str,
    release_snapshot_manifest: Path | None,
    core_closure_report: dict[str, Any] | None,
) -> list[str]:
    if run_purpose not in {"step9_pilot", "step9_test"}:
        return []

    blockers: list[str] = []
    if release_snapshot_manifest is None:
        return [
            "release_snapshot_manifest_required_for_formal_step9"
        ]

    if (
        not release_snapshot_manifest.exists()
        or not release_snapshot_manifest.is_file()
    ):
        return [
            "formal_release_snapshot_manifest_missing:"
            + rel(release_snapshot_manifest)
        ]

    try:
        snapshot = read_json(release_snapshot_manifest)
        if snapshot.get("status") != "FROZEN":
            blockers.append(
                "formal_release_snapshot_manifest_not_frozen"
            )
        packages = snapshot.get("packages")
        if not isinstance(packages, dict) or not packages:
            blockers.append(
                "formal_release_snapshot_manifest_has_no_packages"
            )
    except Exception as exc:
        blockers.append(
            "formal_release_snapshot_manifest_invalid:"
            f"{type(exc).__name__}:{exc}"
        )

    if core_closure_report is None:
        blockers.append(
            "formal_release_snapshot_core_closure_not_verified"
        )
        return blockers

    expected_snapshot_text = str(
        core_closure_report.get("release_snapshot_manifest") or ""
    ).strip()
    expected_snapshot_hash = core_closure_report.get(
        "release_snapshot_manifest_hash"
    )
    if not expected_snapshot_text:
        blockers.append(
            "core_closure_release_snapshot_manifest_missing"
        )
    else:
        expected_snapshot = (
            ROOT / expected_snapshot_text
        ).resolve()
        if release_snapshot_manifest.resolve() != expected_snapshot:
            blockers.append(
                "formal_release_snapshot_path_not_bound_to_core_closure"
            )

    if not isinstance(expected_snapshot_hash, dict):
        blockers.append(
            "core_closure_release_snapshot_hash_missing"
        )
    else:
        try:
            verify_hash(
                release_snapshot_manifest,
                expected_snapshot_hash,
                label="formal release snapshot bound by core closure",
            )
        except Exception as exc:
            blockers.append(
                "formal_release_snapshot_hash_not_bound_to_"
                f"core_closure:{type(exc).__name__}:{exc}"
            )

    return blockers


def preflight(
    *,
    prompts: Path,
    step8_freeze: Path,
    core_freeze_closure: Path | None,
    release_snapshot_manifest: Path | None,
    real_generation: bool,
    run_purpose: str,
) -> dict[str, Any]:
    blockers: list[str] = []
    warnings: list[str] = []

    if not prompts.exists():
        blockers.append(f"prompts_missing:{rel(prompts)}")

    for path in REQUIRED_SCRIPTS:
        if not path.exists():
            blockers.append(f"required_script_missing:{rel(path)}")

    # Historical Step8 freeze remains provenance for the pre-repair system.
    # It is not the authoritative runtime gate once a repaired-core closure
    # is supplied, because the repaired core intentionally changed files that
    # Step8 v0 hash-bound.
    freeze: dict[str, Any] | None = None
    if not step8_freeze.exists():
        blockers.append(f"step8_freeze_missing:{rel(step8_freeze)}")
    else:
        freeze = read_json(step8_freeze)
        if freeze.get("freeze_status") != "PASS":
            blockers.append("step8_freeze_status_not_pass")
        if freeze.get("step8_frozen") is not True:
            blockers.append("step8_not_frozen")

    core_closure_status = "not_supplied"
    core_closure_report: dict[str, Any] | None = None
    if core_freeze_closure is not None:
        if not core_freeze_closure.exists():
            blockers.append(
                f"core_freeze_closure_missing:{rel(core_freeze_closure)}"
            )
            core_closure_status = "missing"
        else:
            try:
                core_closure_report = verify_core_freeze_closure(
                    core_freeze_closure,
                    require_git_identity=True,
                    require_environment_versions=True,
                )
                core_closure_status = "verified"
            except Exception as exc:
                blockers.append(
                    "core_freeze_closure_invalid:"
                    f"{type(exc).__name__}:{exc}"
                )
                core_closure_status = "invalid"
    elif run_purpose in {"step9_pilot", "step9_test"}:
        blockers.append(
            "core_freeze_closure_required_for_formal_step9"
        )
    else:
        warnings.append(
            "repaired core closure not supplied; using legacy Step8 freeze "
            "hash gate for integration-smoke compatibility"
        )
        if freeze is not None:
            blockers.extend(verify_step8_frozen_files(freeze))

    threshold: dict[str, Any] | None = None
    if not DEFAULT_THRESHOLD_POLICY.exists():
        blockers.append("threshold_policy_missing")
    else:
        threshold = read_json(DEFAULT_THRESHOLD_POLICY)
        if threshold.get("status") != "frozen":
            blockers.append("threshold_policy_not_frozen")

    if real_generation:
        local_config = ROOT / "config/local_api_config.json"
        has_env_key = bool(os.getenv("DASHSCOPE_API_KEY"))
        has_local_config = local_config.exists()
        if not (has_env_key or has_local_config):
            blockers.append("qwen_api_configuration_missing")

    blockers.extend(
        formal_release_snapshot_binding_blockers(
            run_purpose=run_purpose,
            release_snapshot_manifest=release_snapshot_manifest,
            core_closure_report=core_closure_report,
        )
    )

    if freeze is not None and freeze.get("step9_started") is True:
        warnings.append(
            "historical Step8 freeze says step9_started=true"
        )

    return {
        "status": "PASS" if not blockers else "BLOCKED",
        "blockers": blockers,
        "warnings": warnings,
        "historical_step8_freeze_file": rel(step8_freeze),
        "core_freeze_closure_file": (
            rel(core_freeze_closure)
            if core_freeze_closure is not None
            else None
        ),
        "core_freeze_closure_status": core_closure_status,
        "formal_release_snapshot_binding_status": (
            "verified"
            if (
                run_purpose in {"step9_pilot", "step9_test"}
                and release_snapshot_manifest is not None
                and not any(
                    blocker.startswith("formal_release_snapshot")
                    or blocker.startswith("core_closure_release_snapshot")
                    for blocker in blockers
                )
            )
            else (
                "not_required"
                if run_purpose == "integration_smoke"
                else "blocked"
            )
        ),
        "runtime_gate_source": (
            "repaired_core_freeze_closure"
            if core_freeze_closure is not None
            else "historical_step8_freeze_legacy_fallback"
        ),
        "threshold_policy_file": rel(DEFAULT_THRESHOLD_POLICY),
        "real_generation": real_generation,
    }


def split_formal_tho_findings(
    *,
    raw_path: Path,
    formal_path: Path,
    auxiliary_path: Path,
    formal_types: set[str],
    formal_type_aliases: dict[str, str] | None = None,
    generation_time_uncertainty_seconds: float | None = None,
) -> dict[str, int]:
    """Normalize THO cards to Risk Card v2.1 and route by channel."""
    formal: list[dict[str, Any]] = []
    auxiliary: list[dict[str, Any]] = []

    for card in read_jsonl(raw_path):
        normalized = normalize_risk_card(
            card,
            pipeline_origin="THO",
            aliases=formal_type_aliases,
            generation_time_uncertainty_seconds=(
                generation_time_uncertainty_seconds
            ),
        )
        if (
            normalized["channel"] == "formal"
            and normalized["type"] in formal_types
            and normalized["formal_positive"] is True
        ):
            formal.append(normalized)
        else:
            auxiliary.append(normalized)

    formal = deduplicate_cards(formal)
    auxiliary = deduplicate_cards(auxiliary)
    write_jsonl(formal_path, formal)
    write_jsonl(auxiliary_path, auxiliary)

    return {
        "raw": len(formal) + len(auxiliary),
        "formal": len(formal),
        "auxiliary": len(auxiliary),
    }


def merge_risk_cards(
    *,
    tho_path: Path,
    avcs_sample_dirs: list[Path],
    out_path: Path,
    avcs_auxiliary_path: Path | None = None,
    formal_types: set[str] | None = None,
    formal_type_aliases: dict[str, str] | None = None,
    generation_time_uncertainty_seconds: float | None = None,
) -> dict[str, Any]:
    effective_formal_types = set(
        formal_types or FORMAL_MAIN_RISK_TYPES
    )
    rows: list[dict[str, Any]] = []
    counts = {"tho": 0, "avcs": 0, "avcs_auxiliary": 0}
    avcs_auxiliary: list[dict[str, Any]] = []

    for card in read_jsonl(tho_path):
        if card.get("schema_version") == "risk_card_v2.1":
            normalized = copy.deepcopy(card)
            validate_risk_card(normalized)
        else:
            normalized = normalize_risk_card(
                card,
                pipeline_origin="THO",
                aliases=formal_type_aliases,
                generation_time_uncertainty_seconds=(
                    generation_time_uncertainty_seconds
                ),
            )

        if (
            normalized["channel"] != "formal"
            or normalized["type"] not in effective_formal_types
            or normalized["formal_positive"] is not True
        ):
            raise ValueError(
                "THO formal input contains an auxiliary/non-formal card: "
                f"{normalized['type']}"
            )
        rows.append(normalized)
        counts["tho"] += 1

    for sample_dir in avcs_sample_dirs:
        path = sample_dir / "risk_cards.jsonl"
        for card in read_jsonl(path):
            normalized = normalize_risk_card(
                card,
                pipeline_origin="AVCS",
                aliases=formal_type_aliases,
                generation_time_uncertainty_seconds=(
                    generation_time_uncertainty_seconds
                ),
            )
            if (
                normalized["channel"] != "formal"
                or normalized["type"] not in effective_formal_types
                or normalized["formal_positive"] is not True
            ):
                avcs_auxiliary.append(normalized)
                counts["avcs_auxiliary"] += 1
                continue

            rows.append(normalized)
            counts["avcs"] += 1

    rows = deduplicate_cards(rows)
    avcs_auxiliary = deduplicate_cards(avcs_auxiliary)
    write_jsonl(out_path, rows)
    if avcs_auxiliary_path is not None:
        write_jsonl(avcs_auxiliary_path, avcs_auxiliary)
    return {
        "total": len(rows),
        "tho": sum(
            row["pipeline_origin"] == "THO"
            for row in rows
        ),
        "avcs": sum(
            row["pipeline_origin"] == "AVCS"
            for row in rows
        ),
        "avcs_auxiliary": len(avcs_auxiliary),
    }


def summarize_avcs_coverage(
    avcs_sample_dirs: list[Path],
) -> dict[str, Any]:
    samples_with_supported_package = 0
    package_analyses_completed = 0
    time_complete_analyses = 0
    time_complete_with_risk_cards = 0
    time_complete_without_risk_cards = 0
    vulnerability_catalog_entries = 0
    vulnerabilities_with_published_at = 0
    unsupported_candidate_count = 0
    dependency_candidate_count = 0
    in_scope_candidate_count = 0
    out_of_scope_candidate_count = 0
    dependency_candidate_sample_count = 0
    in_scope_sample_count = 0
    out_of_scope_only_sample_count = 0
    release_snapshot_bound_analyses = 0
    release_snapshot_hashes: dict[str, str] = {}
    coverage_outcomes: list[dict[str, Any]] = []
    coverage_records: list[dict[str, Any]] = []
    coverage_outcome_counts: dict[str, int] = {}
    audit_drift_metric_outcome_counts: dict[str, int] = {}
    formal_metric_eligible_count = 0
    audit_drift_metric_eligible_count = 0
    syntax_unavailable_sample_count = 0
    analysis_support_state_counts: dict[str, int] = {}
    named_time_view_counts: dict[str, int] = {}

    for sample_dir in avcs_sample_dirs:
        manifest_path = sample_dir / "manifest.json"
        if not manifest_path.exists():
            raise FileNotFoundError(
                f"AVCS sample manifest missing: {manifest_path}"
            )
        manifest = read_json(manifest_path)
        coverage_path = sample_dir / "coverage_outcomes.jsonl"
        if not coverage_path.exists():
            raise FileNotFoundError(
                f"AVCS coverage outcomes missing: {coverage_path}"
            )
        sample_coverage = read_jsonl(coverage_path)
        for coverage_row in sample_coverage:
            if coverage_row.get("sample_id") != sample_dir.name:
                raise ValueError(
                    f"AVCS coverage sample mismatch: {coverage_path}"
                )
            copied_coverage = copy.deepcopy(coverage_row)
            validate_coverage_metric_authority(copied_coverage)
            evaluation_time_view = (
                copied_coverage.get("evaluation_time_view")
                if isinstance(
                    copied_coverage.get("evaluation_time_view"), dict
                )
                else {}
            )
            view_id = str(
                evaluation_time_view.get("view_id") or "missing"
            )
            named_time_view_counts[view_id] = (
                named_time_view_counts.get(view_id, 0) + 1
            )
            coverage_outcomes.append(copied_coverage)
            coverage_records.append(
                {
                    "sample_id": sample_dir.name,
                    "distribution": copied_coverage.get("distribution"),
                    "support_status": copied_coverage.get("support_status"),
                    "evaluation_time_view": copy.deepcopy(
                        evaluation_time_view
                    ),
                    "view_specific_metric_outcome": copy.deepcopy(
                        copied_coverage.get(
                            "view_specific_metric_outcome"
                        )
                    ),
                    "coverage": project_avcs_final_output_coverage(
                        copied_coverage
                    ),
                }
            )
            outcome = str(
                copied_coverage.get("main_metric_outcome") or ""
            )
            if outcome:
                coverage_outcome_counts[outcome] = (
                    coverage_outcome_counts.get(outcome, 0) + 1
                )
            if copied_coverage.get("main_metric_eligible") is True:
                formal_metric_eligible_count += 1
            audit_metric = copied_coverage.get("audit_drift_metric")
            if isinstance(audit_metric, dict):
                audit_outcome = str(
                    audit_metric.get("outcome") or ""
                )
                if audit_outcome:
                    audit_drift_metric_outcome_counts[audit_outcome] = (
                        audit_drift_metric_outcome_counts.get(
                            audit_outcome, 0
                        )
                        + 1
                    )
                if audit_metric.get("eligible") is True:
                    audit_drift_metric_eligible_count += 1

        sample_has_generation_metric_eligible = any(
            row.get("main_metric_eligible") is True
            for row in sample_coverage
        )
        sample_has_audit_drift_metric_eligible = any(
            isinstance(row.get("audit_drift_metric"), dict)
            and row["audit_drift_metric"].get("eligible") is True
            for row in sample_coverage
        )
        sample_has_metric_eligible = (
            sample_has_generation_metric_eligible
            or sample_has_audit_drift_metric_eligible
        )
        sample_has_syntax_unavailable = any(
            str(row.get("main_metric_outcome") or "")
            == "syntax_unavailable"
            for row in sample_coverage
        )
        sample_has_explicit_no_candidate = any(
            str(row.get("main_metric_outcome") or "")
            == "no_avcs_candidate"
            for row in sample_coverage
        )

        package_count = int(manifest.get("package_analysis_count", 0) or 0)
        package_analyses_completed += package_count
        if package_count > 0:
            samples_with_supported_package += 1

        unsupported = manifest.get(
            "unsupported_candidate_distributions", []
        )
        if isinstance(unsupported, list):
            unsupported_candidate_count += len(unsupported)

        dependency_set: set[str] | None = None
        in_scope_set: set[str] | None = None
        out_of_scope_set: set[str] | None = None
        dependency_candidates = manifest.get(
            "dependency_candidate_distributions"
        )
        in_scope_candidates = manifest.get(
            "in_curated_scope_candidate_distributions"
        )
        out_of_scope_candidates = manifest.get(
            "out_of_curated_scope_candidate_distributions"
        )
        if all(
            isinstance(value, list)
            for value in (
                dependency_candidates,
                in_scope_candidates,
                out_of_scope_candidates,
            )
        ):
            dependency_set = {
                str(value).strip().lower()
                for value in dependency_candidates
                if str(value).strip()
            }
            in_scope_set = {
                str(value).strip().lower()
                for value in in_scope_candidates
                if str(value).strip()
            }
            out_of_scope_set = {
                str(value).strip().lower()
                for value in out_of_scope_candidates
                if str(value).strip()
            }
            if in_scope_set & out_of_scope_set:
                raise ValueError(
                    f"AVCS curated scope overlap: {manifest_path}"
                )
            if dependency_set != (in_scope_set | out_of_scope_set):
                raise ValueError(
                    f"AVCS curated scope partition mismatch: {manifest_path}"
                )
            dependency_candidate_count += len(dependency_set)
            in_scope_candidate_count += len(in_scope_set)
            out_of_scope_candidate_count += len(out_of_scope_set)
            if dependency_set:
                dependency_candidate_sample_count += 1
            if in_scope_set:
                in_scope_sample_count += 1
            elif out_of_scope_set:
                out_of_scope_only_sample_count += 1

        packages = manifest.get("packages", [])
        if not isinstance(packages, list):
            raise ValueError(
                f"AVCS packages summary is invalid: {manifest_path}"
            )
        if len(packages) != package_count:
            raise ValueError(
                f"AVCS package_analysis_count mismatch: {manifest_path}"
            )

        for row in packages:
            if not isinstance(row, dict):
                continue
            coverage = row.get("coverage")
            if not isinstance(coverage, dict):
                raise ValueError(
                    f"AVCS package coverage missing: {manifest_path}"
                )
            validate_coverage_metric_authority(coverage)
            outcome = str(
                coverage.get("main_metric_outcome") or ""
            )
            if outcome not in {
                "formal_positive",
                "formal_negative",
                "auxiliary_only",
                "unknown_review",
                "syntax_unavailable",
            }:
                raise ValueError(
                    f"Invalid AVCS package coverage outcome: {outcome!r}"
                )
            if (
                outcome == "formal_negative"
                and coverage.get("main_metric_eligible") is not True
            ):
                raise ValueError(
                    "Formal negative package is not metric-eligible"
                )
            if (
                outcome == "unknown_review"
                and not coverage.get("blocking_unknown_reasons")
            ):
                raise ValueError(
                    "Unknown/review package has no explicit reason"
                )
            if outcome == "syntax_unavailable":
                if coverage.get("main_metric_eligible") is not False:
                    raise ValueError(
                        "Syntax-unavailable package must be non-metric"
                    )
                if coverage.get("formal_positive") is not False:
                    raise ValueError(
                        "Syntax-unavailable package cannot be formal positive"
                    )
                blockers = coverage.get("blocking_unknown_reasons")
                if (
                    not isinstance(blockers, list)
                    or "syntax_unavailable" not in blockers
                ):
                    raise ValueError(
                        "Syntax-unavailable package has no explicit support reason"
                    )
            generation_metric = coverage.get("generation_metric")
            if isinstance(generation_metric, dict) and (
                generation_metric.get("channel") != "generation_time"
                or generation_metric.get("outcome") != outcome
                or generation_metric.get("eligible")
                is not coverage.get("main_metric_eligible")
                or generation_metric.get("formal_positive")
                is not coverage.get("formal_positive")
            ):
                raise ValueError(
                    "Generation metric disagrees with legacy coverage fields"
                )
            audit_metric = coverage.get("audit_drift_metric")
            if isinstance(audit_metric, dict):
                if audit_metric.get("channel") != "audit_time":
                    raise ValueError(
                        "Audit-drift metric has the wrong channel"
                    )
                if not isinstance(audit_metric.get("eligible"), bool):
                    raise ValueError(
                        "Audit-drift metric eligibility must be boolean"
                    )
                if not isinstance(
                    audit_metric.get("formal_positive"), bool
                ):
                    raise ValueError(
                        "Audit-drift metric formal_positive must be boolean"
                    )
                if (
                    audit_metric.get("formal_positive") is True
                    and (
                        audit_metric.get("outcome") != "formal_positive"
                        or audit_metric.get("eligible") is not True
                        or coverage.get("main_metric_eligible") is not False
                        or coverage.get("formal_positive") is not False
                    )
                ):
                    raise ValueError(
                        "Audit-drift positive entered the generation metric"
                    )
                if (
                    (
                        audit_metric.get("outcome")
                        == "formal_positive"
                    )
                    is not (
                        audit_metric.get("formal_positive") is True
                    )
                ):
                    raise ValueError(
                        "Audit-drift outcome and positive flag disagree"
                    )
                if audit_metric.get("eligible") is True:
                    evaluation_time_view = coverage.get(
                        "evaluation_time_view"
                    )
                    if not isinstance(evaluation_time_view, dict) or (
                        evaluation_time_view.get("view_id")
                        != "as_of_audit"
                        or evaluation_time_view.get(
                            "view_specific_metric_channel"
                        )
                        != "audit_time"
                        or evaluation_time_view.get("retrospective_only")
                        is not False
                        or audit_metric.get("outcome")
                        not in {"formal_positive", "formal_negative"}
                    ):
                        raise ValueError(
                            "Audit-drift metric uses an unauthorized view"
                        )

            if row.get("knowledge_complete_to_requested_time") is True:
                time_complete_analyses += 1
                if int(row.get("risk_card_count", 0) or 0) > 0:
                    time_complete_with_risk_cards += 1
                else:
                    time_complete_without_risk_cards += 1
            if row.get("source_release_snapshot_manifest_bound") is True:
                release_snapshot_bound_analyses += 1
            vulnerability_catalog_entries += int(
                row.get("vulnerability_catalog_count", 0) or 0
            )
            vulnerabilities_with_published_at += int(
                row.get("vulnerability_published_at_count", 0) or 0
            )
            distribution = str(
                row.get("normalized_distribution")
                or row.get("distribution")
                or ""
            ).strip()
            digest = str(
                row.get("source_release_history_sha256", "")
            ).strip()
            if distribution and digest:
                previous = release_snapshot_hashes.get(distribution)
                if previous is not None and previous != digest:
                    raise ValueError(
                        "Multiple release snapshot hashes observed for "
                        f"{distribution}"
                    )
                release_snapshot_hashes[distribution] = digest

        if sample_has_metric_eligible:
            analysis_support_state = "metric_eligible"
        elif sample_has_syntax_unavailable:
            analysis_support_state = "syntax_unavailable"
            syntax_unavailable_sample_count += 1
        elif sample_has_explicit_no_candidate:
            analysis_support_state = "no_avcs_candidate"
        elif (
            dependency_set is not None
            and not dependency_set
        ):
            analysis_support_state = "no_avcs_candidate"
        elif (
            in_scope_set is not None
            and out_of_scope_set is not None
            and not in_scope_set
            and bool(out_of_scope_set)
        ):
            analysis_support_state = "out_of_curated_scope"
        else:
            analysis_support_state = "insufficient_method_coverage"
        analysis_support_state_counts[analysis_support_state] = (
            analysis_support_state_counts.get(
                analysis_support_state, 0
            )
            + 1
        )

    return {
        "samples_invoked": len(avcs_sample_dirs),
        "samples_with_supported_package": (
            samples_with_supported_package
        ),
        "samples_without_supported_package": (
            len(avcs_sample_dirs) - samples_with_supported_package
        ),
        "package_analyses_completed": package_analyses_completed,
        "time_complete_analyses": time_complete_analyses,
        "time_incomplete_analyses": (
            package_analyses_completed - time_complete_analyses
        ),
        "time_complete_with_risk_cards": (
            time_complete_with_risk_cards
        ),
        "time_complete_without_risk_cards": (
            time_complete_without_risk_cards
        ),
        "unsupported_candidate_count": unsupported_candidate_count,
        "dependency_candidate_count": dependency_candidate_count,
        "in_scope_candidate_count": in_scope_candidate_count,
        "out_of_scope_candidate_count": out_of_scope_candidate_count,
        "dependency_candidate_sample_count": dependency_candidate_sample_count,
        "in_scope_sample_count": in_scope_sample_count,
        "out_of_scope_only_sample_count": out_of_scope_only_sample_count,
        "release_snapshot_bound_analyses": (
            release_snapshot_bound_analyses
        ),
        "vulnerability_catalog_entries": vulnerability_catalog_entries,
        "vulnerabilities_with_published_at": (
            vulnerabilities_with_published_at
        ),
        "vulnerability_publication_time_coverage": (
            vulnerabilities_with_published_at
            / vulnerability_catalog_entries
            if vulnerability_catalog_entries
            else None
        ),
        "release_snapshot_hashes": release_snapshot_hashes,
        "coverage_outcome_counts": dict(
            sorted(coverage_outcome_counts.items())
        ),
        "audit_drift_metric_outcome_counts": dict(
            sorted(audit_drift_metric_outcome_counts.items())
        ),
        "formal_metric_eligible_count": formal_metric_eligible_count,
        "audit_drift_metric_eligible_count": (
            audit_drift_metric_eligible_count
        ),
        "authorized_metric_eligible_count": (
            formal_metric_eligible_count
            + audit_drift_metric_eligible_count
        ),
        "metric_eligible_count": formal_metric_eligible_count,
        "curated_scope_candidate_count": in_scope_candidate_count,
        "insufficient_method_coverage_count": (
            analysis_support_state_counts.get(
                "insufficient_method_coverage", 0
            )
        ),
        "formal_negative_count": coverage_outcome_counts.get(
            "formal_negative", 0
        ),
        "formal_positive_count": coverage_outcome_counts.get(
            "formal_positive", 0
        ),
        "unknown_review_count": coverage_outcome_counts.get(
            "unknown_review", 0
        ),
        "auxiliary_only_count": coverage_outcome_counts.get(
            "auxiliary_only", 0
        ),
        "unsupported_in_scope_count": coverage_outcome_counts.get(
            "unsupported_in_scope", 0
        ),
        "out_of_curated_scope_count": coverage_outcome_counts.get(
            "out_of_curated_scope", 0
        ),
        "syntax_unavailable_count": coverage_outcome_counts.get(
            "syntax_unavailable", 0
        ),
        "syntax_unavailable_sample_count": (
            syntax_unavailable_sample_count
        ),
        "analysis_support_state_counts": dict(
            sorted(analysis_support_state_counts.items())
        ),
        "named_time_view_counts": dict(
            sorted(named_time_view_counts.items())
        ),
        "coverage_outcomes": coverage_outcomes,
        "coverage_records": coverage_records,
        "run_level_coverage_contract": {
            "schema_version": "avcs_run_level_coverage_contract_v1",
            "records_include_supported_unknown_unsupported_and_not_applicable": True,
            "records_include_curated_package_scope": True,
            "record_coverage_schema": "avcs_final_output_coverage_v1",
            "package_identity_candidate_is_not_avcs_scope_membership": True,
            "selected_scope_is_not_package_wide": True,
            "unknown_is_not_false": True,
            "syntax_unavailable_is_not_negative": True,
            "syntax_unavailable_is_not_metric_eligible": True,
            "generation_metric_requires_as_of_tg": True,
            "audit_drift_metric_requires_as_of_audit": True,
        },
        "scientific_interpretation": {
            "time_complete_without_risk_cards_is_valid_negative_outcome": True,
            "zero_risk_cards_does_not_imply_method_not_executed": True,
            "time_incomplete_analysis_is_not_counted_as_complete_negative": True,
            "absence_of_risk_card_is_not_formal_negative": True,
            "unsupported_or_unknown_is_excluded_from_formal_denominator": True,
            "out_of_curated_scope_is_excluded_from_formal_denominator": True,
            "metric_evaluability_is_reported_separately_from_scope_correctness": True,
            "auxiliary_only_is_excluded_from_main_metrics": True,
            "syntax_unavailable_is_excluded_from_main_metrics": True,
            "syntax_unavailable_is_not_negative": True,
            "audit_drift_metric_is_separate_from_generation_metric": True,
        },
    }


def export_sceg_bundle(
    *,
    sceg_path: Path,
    out_dir: Path,
) -> dict[str, int]:
    records = read_jsonl(sceg_path)

    nodes: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    for record in records:
        graph_id = record.get("graph_id")

        raw_nodes = record.get("nodes", {})
        if isinstance(raw_nodes, dict):
            for node_kind, node in raw_nodes.items():
                if not isinstance(node, dict):
                    continue
                nodes.append(
                    {
                        "graph_id": graph_id,
                        "node_kind": node_kind,
                        "node": node,
                    }
                )

        raw_evidence = record.get("evidence", {})
        if isinstance(raw_evidence, dict):
            for evidence_kind, payload in raw_evidence.items():
                if payload is None:
                    continue
                evidence.append(
                    {
                        "graph_id": graph_id,
                        "evidence_kind": evidence_kind,
                        "evidence": payload,
                    }
                )

        raw_edges = record.get("edges", [])
        if isinstance(raw_edges, list):
            for edge in raw_edges:
                if not isinstance(edge, dict):
                    continue
                copied = copy.deepcopy(edge)
                copied["graph_id"] = graph_id
                edges.append(copied)

    write_jsonl(out_dir / "nodes.jsonl", nodes)
    write_jsonl(out_dir / "evidence.jsonl", evidence)
    write_jsonl(out_dir / "edges.jsonl", edges)

    return {
        "sceg_record_count": len(records),
        "node_record_count": len(nodes),
        "evidence_record_count": len(evidence),
        "edge_count": len(edges),
    }


def build_summary_markdown(manifest: dict[str, Any]) -> str:
    counts = manifest["counts"]
    lines = [
        "# CodeSentry-Gen E2E Run Summary",
        "",
        f"- status: **{manifest['status']}**",
        (
            "- integration_process_status: "
            f"**{manifest['integration_process_status']}**"
        ),
        (
            "- scientific_contract_status: "
            f"**{manifest['scientific_contract_status']}**"
        ),
        (
            "- formal_output_checker_executed: "
            f"{manifest['formal_output_checker_executed']}"
        ),
        f"- prompts: {counts['prompt_rows_selected']}",
        f"- generated_success: {counts['generated_success']}",
        f"- generation_failed: {counts['generation_failed']}",
        f"- dependency_records: {counts['dependency_records']}",
        f"- THO_risk_cards: {counts['tho_risk_cards']}",
        f"- AVCS_samples_invoked: {counts['avcs_samples_invoked']}",
        (
            "- AVCS_samples_with_supported_package: "
            f"{counts['avcs_samples_with_supported_package']}"
        ),
        (
            "- AVCS_package_analyses_completed: "
            f"{counts['avcs_package_analyses_completed']}"
        ),
        (
            "- AVCS_time_complete_analyses: "
            f"{counts['avcs_time_complete_analyses']}"
        ),
        f"- AVCS_formal_risk_cards: {counts['avcs_formal_risk_cards']}",
        f"- AVCS_auxiliary_findings: {counts['avcs_auxiliary_findings']}",
        (
            "- AVCS_formal_negative_coverage: "
            f"{manifest['avcs_scientific_coverage'].get('formal_negative_count', 0)}"
        ),
        (
            "- AVCS_unknown_review_coverage: "
            f"{manifest['avcs_scientific_coverage'].get('unknown_review_count', 0)}"
        ),
        f"- unified_risk_cards: {counts['unified_risk_cards']}",
        f"- SCEG_records: {counts['sceg_records']}",
        f"- SCEG_edges: {counts['sceg_edges']}",
        "",
        "## Scientific boundary",
        "",
        "- Step8 freeze is required before this orchestrator can execute.",
        (
            "- Process completion and scientific-contract PASS are reported "
            "separately; formal runs require both."
        ),
        (
            "- Fresh prevalence may contain zero positives for a formal risk; "
            "route reachability is checked by a controlled gate instead."
        ),
        "- THO and AVCS Risk Cards remain distinguishable by pipeline_origin.",
        "- AVCS runner invocation is reported separately from supported-package analysis.",
        "- Conventional manifest/lock AVCS findings stay auxiliary to the three formal risks.",
        "- Trigger evidence remains secondary inside AVCS.",
        "- Absence of a Risk Card is never interpreted as a formal negative without an explicit metric-eligible coverage outcome.",
        "- Unsupported, unknown/review, and auxiliary-only AVCS outcomes are excluded from the main formal denominator.",
        "- SCEG 2.1 is built before THO/AVCS and is consumed by both paths.",
        "- Missing repository context is recorded as uncertainty; import-only observations do not prove an external package identity.",
        "- Manifest/lock/CI install evidence may independently establish external dependency intent.",
        "- Risk derivation is location-aware; package-only fallback is allowed only when a Risk Card has no source location.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Guarded end-to-end CodeSentry-Gen orchestrator: prompts -> code "
            "generation -> SCEG 2.1 -> THO/AVCS -> unified Risk Cards."
        )
    )
    parser.add_argument("--prompts", required=True, type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--limit", type=int, default=5)
    parser.add_argument("--start", type=int, default=1)
    parser.add_argument("--real", action="store_true")
    parser.add_argument("--model", default="qwen-plus")
    parser.add_argument(
        "--run-purpose",
        choices=["integration_smoke", "step9_pilot", "step9_test"],
        default="integration_smoke",
        help=(
            "Declare whether this run is an integration smoke or a frozen "
            "fresh Step9 pilot/test run."
        ),
    )
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--retries", type=int, default=1)
    parser.add_argument(
        "--step8-freeze",
        type=Path,
        default=DEFAULT_STEP8_FREEZE,
        help=(
            "Historical Step8 freeze provenance / legacy integration-smoke "
            "gate. Repaired formal runs must use --core-freeze-closure."
        ),
    )
    parser.add_argument(
        "--core-freeze-closure",
        type=Path,
        default=None,
        help=(
            "Canonical repaired-core closure. A candidate closure may gate "
            "integration_smoke; formal Step9 requires the frozen closure "
            "declared by the active Step9 protocol."
        ),
    )
    parser.add_argument(
        "--dataset-label",
        default="codesentry_gen_e2e_smoke",
    )
    parser.add_argument(
        "--step9-protocol",
        type=Path,
        default=None,
        help=(
            "Explicit frozen active Step9 protocol. Required for "
            "step9_pilot/step9_test; there is intentionally no historical "
            "default. Integration smoke does not require it."
        ),
    )
    parser.add_argument(
        "--release-snapshot-manifest",
        type=Path,
        default=None,
        help=(
            "Optional FROZEN AVCS release snapshot manifest. This is "
            "append-only runtime evidence and does not modify historical "
            "Step8/Step9 artifacts."
        ),
    )
    parser.add_argument(
        "--knowledge-time",
        default=None,
        help=(
            "Explicit vulnerability/advisory knowledge cutoff for AVCS. "
            "For repaired formal Step9 this is normally derived from the "
            "split-specific post-generation release snapshot; if supplied "
            "manually, it must equal that frozen derived cutoff."
        ),
    )
    parser.add_argument(
        "--time-view-id",
        choices=sorted(FORMAL_TIME_VIEW_IDS),
        default=None,
        help=(
            "Named evaluation view. Formal runs require a prospective "
            "protocol declaration; omitted integration runs are legacy and "
            "cannot enter the generation-time denominator."
        ),
    )
    parser.add_argument(
        "--time-view-snapshot-sha256",
        default=None,
        help="Raw SHA-256 of the frozen evidence snapshot manifest.",
    )
    parser.add_argument(
        "--time-view-output-namespace",
        default=None,
        help=(
            "View-prefixed, non-overwriting namespace root; each sample is "
            "bound below this root."
        ),
    )
    parser.add_argument(
        "--generation-time-uncertainty-seconds",
        type=float,
        default=None,
        help=(
            "Explicit generation-time uncertainty Δt in seconds. Integration "
            "smoke defaults to the repair-line semantics contract; formal "
            "runs require the frozen protocol to declare the value."
        ),
    )
    parser.add_argument(
        "--controlled-generation-time",
        default=None,
        help=(
            "Timezone-aware generation time for deterministic mock integration "
            "fixtures. Allowed only for integration_smoke without --real."
        ),
    )
    parser.add_argument(
        "--mock-profile",
        choices=[
            "requests_default",
            "f15_prefreeze_aiohttp",
            "r5_r7_syntax_invalid_manifest",
        ],
        default="requests_default",
        help=(
            "Deterministic mock fixture profile. Non-default profiles are "
            "allowed only for integration_smoke without --real."
        ),
    )
    parser.add_argument(
        "--preflight-only",
        action="store_true",
        help="Check integration prerequisites without creating outputs.",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help=(
            "Resume an interrupted E2E run. Existing generated samples are "
            "reused, completed AVCS sample outputs are skipped, and downstream "
            "derived outputs may be regenerated deterministically."
        ),
    )
    parser.add_argument(
        "--reuse-frozen-generation",
        action="store_true",
        help=(
            "Formal Step9 analysis-only mode. Reuse the separately frozen "
            "real-generation stage after post-generation Registry evidence "
            "and the bound core closure are available; never recall the model."
        ),
    )
    args = parser.parse_args()

    prompts = args.prompts
    if not prompts.is_absolute():
        prompts = ROOT / prompts

    out_dir = args.out_dir
    if not out_dir.is_absolute():
        out_dir = ROOT / out_dir

    freeze_path = args.step8_freeze
    if not freeze_path.is_absolute():
        freeze_path = ROOT / freeze_path

    core_freeze_closure = args.core_freeze_closure
    if (
        core_freeze_closure is not None
        and not core_freeze_closure.is_absolute()
    ):
        core_freeze_closure = ROOT / core_freeze_closure

    step9_protocol_path = args.step9_protocol
    if (
        step9_protocol_path is not None
        and not step9_protocol_path.is_absolute()
    ):
        step9_protocol_path = ROOT / step9_protocol_path

    release_snapshot_manifest = args.release_snapshot_manifest
    if (
        release_snapshot_manifest is not None
        and not release_snapshot_manifest.is_absolute()
    ):
        release_snapshot_manifest = ROOT / release_snapshot_manifest

    if args.run_purpose in {"step9_pilot", "step9_test"}:
        if step9_protocol_path is None:
            raise ValueError(
                "Formal Step9 requires an explicit --step9-protocol"
            )
        raw_protocol = read_json(step9_protocol_path)
        split_name = (
            "pilot" if args.run_purpose == "step9_pilot" else "test"
        )
        snapshot_key = (
            "pilot_release_snapshot_manifest"
            if split_name == "pilot"
            else "test_release_snapshot_manifest"
        )
        closure_key = (
            "pilot_core_freeze_closure"
            if split_name == "pilot"
            else "test_core_freeze_closure"
        )
        planned = raw_protocol.get("planned_outputs")
        if not isinstance(planned, dict):
            raise ValueError("Formal Step9 protocol planned_outputs missing")
        expected_snapshot = ROOT / str(planned.get(snapshot_key) or "")
        expected_closure = ROOT / str(planned.get(closure_key) or "")
        if not str(planned.get(snapshot_key) or "").strip():
            raise ValueError(
                f"Formal Step9 protocol missing {snapshot_key}"
            )
        if not str(planned.get(closure_key) or "").strip():
            raise ValueError(
                f"Formal Step9 protocol missing {closure_key}"
            )
        if release_snapshot_manifest is None:
            release_snapshot_manifest = expected_snapshot
        if core_freeze_closure is None:
            core_freeze_closure = expected_closure

    controlled_generation_time: str | None = None
    if args.controlled_generation_time is not None:
        if args.run_purpose != "integration_smoke" or args.real:
            raise ValueError(
                "--controlled-generation-time is restricted to mock "
                "integration_smoke runs"
            )
        controlled_generation_time = utc_iso(
            require_aware_utc(
                args.controlled_generation_time,
                label="integration_smoke.controlled_generation_time",
            )
        )
    if (
        args.mock_profile != "requests_default"
        and (args.run_purpose != "integration_smoke" or args.real)
    ):
        raise ValueError(
            "Non-default --mock-profile is restricted to mock "
            "integration_smoke runs"
        )

    if args.reuse_frozen_generation and args.run_purpose == "integration_smoke":
        raise ValueError(
            "--reuse-frozen-generation is restricted to formal Step9"
        )
    if (
        args.run_purpose in {"step9_pilot", "step9_test"}
        and not args.reuse_frozen_generation
    ):
        raise ValueError(
            "Formal repaired Step9 must use the staged generation/evidence "
            "workflow; monolithic generate-and-analyze execution is forbidden"
        )

    step9_contract = verify_step9_run_contract(
        run_purpose=args.run_purpose,
        prompts=prompts,
        model=args.model,
        real_generation=args.real,
        start=args.start,
        limit=args.limit,
        out_dir=out_dir,
        protocol_path=step9_protocol_path,
        knowledge_time=args.knowledge_time,
        generation_time_uncertainty_seconds=(
            args.generation_time_uncertainty_seconds
        ),
        release_snapshot_manifest=release_snapshot_manifest,
        time_view_id=args.time_view_id,
        time_view_snapshot_sha256=args.time_view_snapshot_sha256,
        time_view_output_namespace=args.time_view_output_namespace,
    )

    if step9_contract["is_step9"]:
        expected_core_closure = ROOT / str(
            step9_contract["core_freeze_closure_file"]
        )
        if (
            core_freeze_closure is not None
            and core_freeze_closure.resolve()
            != expected_core_closure.resolve()
        ):
            raise ValueError(
                "Formal Step9 must use the core freeze closure declared by "
                "the frozen protocol."
            )

    generation_stage_manifest: Path | None = None
    generation_outcome_manifest_value: dict[str, Any] | None = None
    staged_accepted_rows: list[dict[str, Any]] | None = None
    if step9_contract["is_step9"]:
        if release_snapshot_manifest is None:
            raise ValueError(
                "Formal staged analysis requires the post-generation release snapshot"
            )
        (
            generation_stage_manifest,
            generation_outcome_manifest_value,
            staged_accepted_rows,
        ) = verify_step9_generation_stage(
            protocol_path=step9_protocol_path,
            run_purpose=args.run_purpose,
            prompts=prompts,
            out_dir=out_dir,
            model=args.model,
            release_snapshot_manifest=release_snapshot_manifest,
            resolved_knowledge_time=step9_contract["knowledge_time"],
        )

    check = preflight(
        prompts=prompts,
        step8_freeze=freeze_path,
        core_freeze_closure=core_freeze_closure,
        release_snapshot_manifest=release_snapshot_manifest,
        real_generation=args.real,
        run_purpose=args.run_purpose,
    )
    expected_selected_count = expected_prompt_count(
        prompts,
        start=args.start,
        limit=args.limit,
    )

    print("CODESENTRY-GEN E2E PREFLIGHT", check["status"])
    if check["blockers"]:
        print("blockers =")
        for blocker in check["blockers"]:
            print(" -", blocker)
    if check["warnings"]:
        print("warnings =")
        for warning in check["warnings"]:
            print(" -", warning)

    if args.preflight_only:
        return

    if check["status"] != "PASS":
        raise SystemExit(
            "E2E execution blocked until preflight passes. "
            "Do not bypass the Step8 freeze gate."
        )

    if (
        out_dir.exists()
        and not args.resume
        and not args.reuse_frozen_generation
    ):
        raise FileExistsError(
            f"Refusing overwrite: {out_dir}. Use a new run directory "
            "or pass --resume for an interrupted run."
        )
    if (
        (args.resume or args.reuse_frozen_generation)
        and not out_dir.exists()
    ):
        raise FileNotFoundError(
            "Existing run directory required for resume/staged analysis: "
            f"{out_dir}"
        )
    out_dir.mkdir(
        parents=True,
        exist_ok=(args.resume or args.reuse_frozen_generation),
    )

    current_run_contract = build_e2e_run_contract(
        prompts=prompts,
        run_purpose=args.run_purpose,
        model=args.model if args.real else "mock_generation_v0",
        real_generation=args.real,
        start=args.start,
        limit=args.limit,
        timeout=args.timeout,
        retries=args.retries,
        dataset_label=args.dataset_label,
        knowledge_time=step9_contract.get("knowledge_time"),
        uncertainty_seconds=step9_contract[
            "generation_time_uncertainty_seconds"
        ],
        release_snapshot_manifest=release_snapshot_manifest,
        step8_freeze=freeze_path,
        step9_protocol=(
            step9_protocol_path
            if step9_contract["is_step9"]
            else None
        ),
        core_freeze_closure=core_freeze_closure,
        generation_stage_manifest=generation_stage_manifest,
        reuse_frozen_generation=args.reuse_frozen_generation,
        controlled_generation_time=controlled_generation_time,
        mock_profile=(args.mock_profile if not args.real else None),
        evaluation_time_view_binding=step9_contract.get(
            "named_time_view_binding"
        ),
    )
    run_contract_path = initialize_or_verify_e2e_resume_contract(
        out_dir=out_dir,
        current=current_run_contract,
        resume=args.resume,
    )

    generation_dir = out_dir / "generation"
    tho_dir = out_dir / "tho"
    registry_cache_dir = tho_dir / "registry_cache"
    registry_snapshot_dir = tho_dir / "registry_snapshot"
    avcs_dir = out_dir / "avcs"
    cards_dir = out_dir / "risk_cards"
    sceg_dir = out_dir / "sceg"
    summary_dir = out_dir / "summary"

    for path in [
        generation_dir,
        tho_dir,
        avcs_dir,
        cards_dir,
        sceg_dir,
        summary_dir,
    ]:
        path.mkdir(
            parents=True,
            exist_ok=(args.resume or args.reuse_frozen_generation),
        )

    samples_path = generation_dir / "generated_samples.jsonl"
    code_dir = generation_dir / "code"
    requirements_dir = generation_dir / "requirements"
    project_snapshots_dir = generation_dir / "project_snapshots"

    analysis_samples_path = samples_path
    if step9_contract["is_step9"]:
        if (
            generation_outcome_manifest_value is None
            or staged_accepted_rows is None
        ):
            raise ValueError(
                "Formal Step9 accepted analysis population is unresolved"
            )
        analysis_samples_path = (
            generation_dir / "accepted_complete_samples.jsonl"
        )
        if analysis_samples_path.exists():
            if read_jsonl(analysis_samples_path) != staged_accepted_rows:
                raise ValueError(
                    "Accepted-complete analysis sample artifact drift"
                )
        else:
            write_jsonl(analysis_samples_path, staged_accepted_rows)
    downstream_samples_path = analysis_samples_path

    generation_cmd = [
        PYTHON,
        "src/generate_code_from_prompts.py",
        "--prompts",
        str(prompts),
        "--out",
        str(samples_path),
        "--code-dir",
        str(code_dir),
        "--requirements-dir",
        str(requirements_dir),
        "--limit",
        str(args.limit),
        "--start",
        str(args.start),
        "--model",
        args.model,
        "--timeout",
        str(args.timeout),
        "--retries",
        str(args.retries),
    ]
    if args.reuse_frozen_generation:
        if not samples_path.exists() or not code_dir.exists() or not requirements_dir.exists():
            raise FileNotFoundError(
                "Frozen generation artifacts are incomplete"
            )
        print(
            "\n[REUSE] frozen real generation stage; model API will not be called"
        )
    else:
        if args.real:
            generation_cmd.append("--real")
        else:
            generation_cmd.extend(["--mock-profile", args.mock_profile])
            if controlled_generation_time is not None:
                generation_cmd.extend(
                    [
                        "--generation-time-override",
                        controlled_generation_time,
                    ]
                )
        if args.resume:
            generation_cmd.append("--resume")
        run_cmd(generation_cmd)

    snapshot_cmd = [
        PYTHON,
        "src/materialize_project_snapshots_v1.py",
        "--samples",
        str(downstream_samples_path),
        "--code-dir",
        str(code_dir),
        "--requirements-dir",
        str(requirements_dir),
        "--out-dir",
        str(project_snapshots_dir),
    ]
    if args.resume and project_snapshots_dir.exists():
        snapshot_cmd.append("--verify")
    run_cmd(snapshot_cmd)

    dependency_records = tho_dir / "dependency_records.jsonl"
    stage1_cards = tho_dir / "stage1_risk_cards.jsonl"
    sceg_base_ir = sceg_dir / "sceg_v2_1_base.json"
    sceg_dependency_projection = (
        tho_dir / "dependency_records_from_sceg_v2_1.jsonl"
    )
    reuse_authoritative_preanalysis = (
        args.resume and sceg_base_ir.exists()
    )

    pilot_cmd = [
        PYTHON,
        "src/run_pilot.py",
        "--samples",
        str(downstream_samples_path),
        "--out",
        str(dependency_records),
        "--risk-out",
        str(stage1_cards),
        "--summary-out",
        str(tho_dir / "stage1_summary.md"),
        "--benchmark-out",
        str(tho_dir / "stage1_benchmark.jsonl"),
        "--benchmark-summary-out",
        str(tho_dir / "stage1_benchmark_summary.md"),
        "--review-template-out",
        str(tho_dir / "stage1_review_template.csv"),
        "--registry-cache-dir",
        str(registry_cache_dir),
        "--registry-snapshot-dir",
        str(registry_snapshot_dir),
        "--registry-run-id",
        out_dir.name,
        "--identity-policy",
        str(DEFAULT_IDENTITY_POLICY),
        "--project-snapshots-dir",
        str(project_snapshots_dir),
    ]

    if reuse_authoritative_preanalysis:
        if not dependency_records.exists():
            raise ValueError(
                "Resume refused: authoritative SCEG exists but its "
                "pre-analysis dependency records are missing. Registry "
                "acquisition will not be re-run after the canonical SCEG "
                "boundary."
            )
        print(
            "[RESUME] reusing frozen pre-analysis dependency/registry "
            "evidence; run_pilot registry acquisition not re-executed"
        )
    else:
        run_cmd(pilot_cmd)

    if reuse_authoritative_preanalysis:
        verify_sceg_base_resume(
            base_ir_path=sceg_base_ir,
            projection_path=sceg_dependency_projection,
            samples_path=downstream_samples_path,
            dependency_records_path=dependency_records,
            code_dir=code_dir,
            mapping_path=DEFAULT_IMPORT_MAPPING,
            dataset_label=args.dataset_label,
            identity_policy_path=DEFAULT_IDENTITY_POLICY,
            project_snapshots_dir=project_snapshots_dir,
        )
        print("[RESUME] verified and reused SCEG 2.1 base IR")
    else:
        run_cmd(
            [
                PYTHON,
                "src/build_sceg_ir_v21.py",
                "--samples",
                str(downstream_samples_path),
                "--dependency-records",
                str(dependency_records),
                "--code-dir",
                str(code_dir),
                "--dataset-label",
                args.dataset_label,
                "--identity-policy",
                str(DEFAULT_IDENTITY_POLICY),
                "--project-snapshots-dir",
                str(project_snapshots_dir),
                "--out",
                str(sceg_base_ir),
                "--dependency-projection-out",
                str(sceg_dependency_projection),
            ]
        )

    temporal_path = tho_dir / "temporal_enriched.jsonl"
    run_cmd(
        [
            PYTHON,
            "src/enrich_temporal_status.py",
            "--input",
            str(sceg_dependency_projection),
            "--output",
            str(temporal_path),
            "--summary",
            str(tho_dir / "temporal_summary.md"),
            "--uncertainty-seconds",
            str(
                step9_contract[
                    "generation_time_uncertainty_seconds"
                ]
            ),
        ]
    )

    reachability_path = tho_dir / "reachability_enriched.jsonl"
    run_cmd(
        [
            PYTHON,
            "src/enrich_reachability_v2.py",
            "--input",
            str(temporal_path),
            "--output",
            str(reachability_path),
            "--summary",
            str(tho_dir / "reachability_summary.md"),
            "--sceg-ir",
            str(sceg_base_ir),
            "--identity-policy",
            str(DEFAULT_IDENTITY_POLICY),
        ]
    )

    tho_cards_path = cards_dir / "tho_risk_cards.jsonl"
    tho_auxiliary_path = cards_dir / "tho_auxiliary_findings.jsonl"

    formal_types = {
        str(value).strip()
        for value in step9_contract.get("formal_main_risk_types", [])
        if str(value).strip()
    }

    effective_formal_types = set(
        formal_types or FORMAL_MAIN_RISK_TYPES
    )
    effective_aliases = dict(
        step9_contract.get("formal_type_aliases", {}) or {}
    )

    raw_tho_cards_path = cards_dir / "tho_findings_raw.jsonl"
    run_cmd(
        [
            PYTHON,
            "src/build_temporal_risk_cards.py",
            "--input",
            str(reachability_path),
            "--output",
            str(raw_tho_cards_path),
            "--summary",
            str(tho_dir / "tho_findings_raw_summary.md"),
        ]
    )
    tho_split_counts = split_formal_tho_findings(
        raw_path=raw_tho_cards_path,
        formal_path=tho_cards_path,
        auxiliary_path=tho_auxiliary_path,
        formal_types=effective_formal_types,
        formal_type_aliases=effective_aliases,
        generation_time_uncertainty_seconds=step9_contract.get(
            "generation_time_uncertainty_seconds"
        ),
    )

    selected_generation_rows = read_jsonl(samples_path)
    samples = read_jsonl(downstream_samples_path)
    if step9_contract.get("knowledge_time") is not None:
        validate_sample_generation_times(
            samples=samples,
            knowledge_time=step9_contract["knowledge_time"],
            label=(
                "formal_step9"
                if step9_contract["is_step9"]
                else "integration_smoke"
            ),
        )
    avcs_sample_dirs: list[Path] = []
    avcs_failures: list[dict[str, str]] = []

    for row in samples:
        sample_id = str(row.get("sample_id", "")).strip()
        if not sample_id:
            continue
        if str(row.get("generation_error", "")).strip():
            avcs_failures.append(
                {
                    "sample_id": sample_id,
                    "reason": "generation_error",
                }
            )
            continue

        named_time_view_binding = step9_contract.get(
            "named_time_view_binding"
        )
        sample_evaluation_time_view: dict[str, Any] = (
            build_legacy_time_view_marker()
        )
        sample_avcs_knowledge_time = step9_contract.get("knowledge_time")
        if isinstance(named_time_view_binding, dict):
            sample_generation_time = str(
                row.get("generation_time") or ""
            ).strip()
            if not sample_generation_time:
                raise ValueError(
                    "Named time view requires generation_time for "
                    + sample_id
                )
            sample_evaluation_time_view = build_sample_time_view_contract(
                binding=named_time_view_binding,
                sample_id=sample_id,
                generation_time=sample_generation_time,
                audit_knowledge_time=step9_contract.get("knowledge_time"),
            )
            if named_time_view_binding.get("view_id") == "as_of_tg":
                sample_avcs_knowledge_time = sample_generation_time

        # F-04: canonical SCEG has already been constructed and verified.
        # Post-extraction AVCS must not require the raw generated code or
        # generated-sample JSONL again.  Those artifacts remain provenance
        # of SCEG construction, not parallel analysis facts.
        sample_out = avcs_dir / "samples" / sample_id
        if args.resume and (sample_out / "manifest.json").exists():
            current_avcs_resume_input = build_avcs_resume_input(
                sample_id=sample_id,
                code_path=None,
                sample_records_path=None,
                sceg_ir_path=sceg_base_ir,
                release_snapshot_manifest_path=(
                    release_snapshot_manifest
                ),
                kb_dir=DEFAULT_AVCS_KB_DIR,
                threshold_policy_path=DEFAULT_THRESHOLD_POLICY,
                freeze_report_path=DEFAULT_STEP7_FREEZE,
                mapping_path=DEFAULT_IMPORT_MAPPING,
                time_view=None,
                knowledge_time=sample_avcs_knowledge_time,
                identity_policy_path=DEFAULT_IDENTITY_POLICY,
                # Formal AVCS consumes the canonical SCEG.  Project snapshot
                # provenance is already hash-bound inside SCEG source_inputs,
                # so the AVCS resume contract must not introduce a second
                # direct project-source dependency.
                project_snapshot_manifest_path=None,
                evaluation_time_view=sample_evaluation_time_view,
            )
            verify_avcs_resume_contract(
                sample_out=sample_out,
                current_input=current_avcs_resume_input,
            )
            print(
                f"[RESUME] verified and reused AVCS sample: {sample_id}"
            )
            avcs_sample_dirs.append(sample_out)
            continue

        if sample_out.exists():
            raise FileExistsError(
                f"Incomplete AVCS sample output already exists: {sample_out}. "
                "Preserve it for debugging and resume with a new E2E run "
                "directory for that failed attempt."
            )

        run_cmd(
            build_step8_avcs_command(
                code_path=None,
                sample_id=sample_id,
                samples_path=None,
                sample_out=sample_out,
                knowledge_time=sample_avcs_knowledge_time,
                release_snapshot_manifest=release_snapshot_manifest,
                sceg_ir_path=sceg_base_ir,
                identity_policy_path=DEFAULT_IDENTITY_POLICY,
                project_root=None,
                time_view_id=(
                    str(named_time_view_binding["view_id"])
                    if isinstance(named_time_view_binding, dict)
                    else None
                ),
                time_view_snapshot_sha256=(
                    str(
                        named_time_view_binding[
                            "evidence_snapshot_sha256"
                        ]
                    )
                    if isinstance(named_time_view_binding, dict)
                    else None
                ),
                time_view_output_namespace=(
                    str(
                        sample_evaluation_time_view["output_namespace"]
                    )
                    if isinstance(named_time_view_binding, dict)
                    else None
                ),
            )
        )
        avcs_sample_dirs.append(sample_out)

    unified_cards_path = cards_dir / "unified_risk_cards.jsonl"
    avcs_auxiliary_path = cards_dir / "avcs_auxiliary_findings.jsonl"
    card_counts = merge_risk_cards(
        tho_path=tho_cards_path,
        avcs_sample_dirs=avcs_sample_dirs,
        out_path=unified_cards_path,
        avcs_auxiliary_path=avcs_auxiliary_path,
        formal_types=effective_formal_types,
        formal_type_aliases=effective_aliases,
        generation_time_uncertainty_seconds=step9_contract.get(
            "generation_time_uncertainty_seconds"
        ),
    )

    if effective_formal_types:
        invalid_unified_types = sorted(
            {
                str(card.get("type", "") or "").strip()
                for card in read_jsonl(unified_cards_path)
                if str(card.get("type", "") or "").strip()
                not in effective_formal_types
            }
        )
        if invalid_unified_types:
            raise RuntimeError(
                "Formal Step9 unified Risk Cards contain types outside the "
                f"frozen taxonomy: {invalid_unified_types}"
            )

    sceg_analyzed_ir = sceg_dir / "sceg_v2_1_analyzed.json"
    if args.resume and sceg_analyzed_ir.exists():
        raise ValueError(
            "Resume refused: analyzed SCEG output already exists. "
            "This run reached finalization; validate it with the output "
            "checker instead of mutating/re-finalizing the same run directory."
        )
    run_cmd(
        [
            PYTHON,
            "src/finalize_sceg_ir_v21.py",
            "--base-ir",
            str(sceg_base_ir),
            "--tho-records",
            str(reachability_path),
            "--avcs-dir",
            str(avcs_dir),
            "--risk-cards",
            str(unified_cards_path),
            "--out",
            str(sceg_analyzed_ir),
        ]
    )
    sceg_value = read_json(sceg_analyzed_ir)
    sceg_counts = {
        "sceg_record_count": 1,
        "node_record_count": len(sceg_value.get("nodes", [])),
        "evidence_record_count": len(sceg_value.get("evidence", [])),
        "edge_count": len(sceg_value.get("edges", [])),
    }

    if any(
        str(row.get("generation_error", "")).strip()
        for row in samples
    ):
        raise ValueError(
            "Accepted-complete analysis population contains generation error"
        )
    generated_success = len(samples)
    generation_failed = expected_selected_count - generated_success

    selected_sample_ids = [
        str(row.get("sample_id", "")).strip()
        for row in selected_generation_rows
        if str(row.get("sample_id", "")).strip()
    ]
    unique_sample_count = len(set(selected_sample_ids))
    analysis_sample_ids = [
        str(row.get("sample_id", "")).strip()
        for row in samples
        if str(row.get("sample_id", "")).strip()
    ]
    analysis_unique_sample_count = len(set(analysis_sample_ids))

    if generation_outcome_manifest_value is not None:
        if generated_success != int(
            generation_outcome_manifest_value.get(
                "accepted_complete_count"
            )
            or 0
        ):
            raise ValueError(
                "Accepted analysis count differs from outcome manifest"
            )
        if generation_failed != int(
            generation_outcome_manifest_value.get("terminal_count") or 0
        ):
            raise ValueError(
                "Generation terminal count differs from selected attrition"
            )
    avcs_coverage = summarize_avcs_coverage(avcs_sample_dirs)
    avcs_coverage_rows = avcs_coverage.pop("coverage_outcomes")
    avcs_coverage_path = (
        cards_dir / "avcs_coverage_outcomes.jsonl"
    )
    write_jsonl(avcs_coverage_path, avcs_coverage_rows)
    avcs_coverage["coverage_outcomes_file"] = rel(
        avcs_coverage_path
    )
    avcs_coverage_review_rows = build_avcs_coverage_review_findings(
        avcs_coverage_rows
    )
    avcs_coverage_review_path = (
        cards_dir / "avcs_coverage_review_findings.jsonl"
    )
    write_jsonl(
        avcs_coverage_review_path,
        avcs_coverage_review_rows,
    )
    avcs_coverage["coverage_review_findings_file"] = rel(
        avcs_coverage_review_path
    )
    avcs_coverage["coverage_review_finding_count"] = len(
        avcs_coverage_review_rows
    )

    if generation_outcome_manifest_value is not None:
        process_pass = (
            expected_selected_count > 0
            and int(
                generation_outcome_manifest_value.get(
                    "selected_count"
                )
                or 0
            )
            == expected_selected_count
            and bool(
                generation_outcome_manifest_value.get(
                    "all_selected_accounted"
                )
            )
            and bool(
                generation_outcome_manifest_value.get(
                    "all_selected_finalized"
                )
            )
            and int(
                generation_outcome_manifest_value.get(
                    "unresolved_count"
                )
                or 0
            )
            == 0
            and unique_sample_count == len(selected_sample_ids)
            and analysis_unique_sample_count == generated_success
            and len(avcs_failures) == 0
            and len(avcs_sample_dirs) == generated_success
        )
    else:
        process_pass = (
            expected_selected_count > 0
            and len(samples) == expected_selected_count
            and unique_sample_count == expected_selected_count
            and generation_failed == 0
            and len(avcs_failures) == 0
            and len(avcs_sample_dirs) == generated_success
            and generated_success == expected_selected_count
        )

    scientific_report_path = (
        summary_dir / "scientific_contract_v1.json"
    )
    formal_output_checker_executed = False
    if step9_contract["is_step9"]:
        run_cmd(
            [
                PYTHON,
                "src/check_codesentry_gen_e2e_output.py",
                "--run-dir",
                str(out_dir),
                "--expected-samples",
                str(expected_selected_count),
                "--report",
                str(scientific_report_path),
                "--strict",
            ]
        )
        formal_output_checker_executed = True
        scientific_report = read_json(scientific_report_path)
    else:
        scientific_report = evaluate_scientific_contract(
            run_dir=out_dir,
            expected_samples=expected_selected_count,
            require_avcs_method=True,
        )
        write_json(scientific_report_path, scientific_report)

    scientific_pass = scientific_report.get("status") == "PASS"
    overall_pass = process_pass and scientific_pass
    if overall_pass:
        overall_status = "PASS"
    elif process_pass:
        overall_status = "PROCESS_PASS_SCIENTIFIC_FAIL"
    else:
        overall_status = "PARTIAL"

    coverage_acceptance = step9_contract.get(
        "avcs_coverage_acceptance"
    )
    if not isinstance(coverage_acceptance, dict):
        coverage_acceptance = {}
    formal_coverage_rule = coverage_acceptance.get("formal_step9")
    if not isinstance(formal_coverage_rule, dict):
        formal_coverage_rule = {}
    candidate_requires_metric_eligible = (
        formal_coverage_rule.get(
            "candidate_sample_requires_metric_eligible_outcome"
        )
        is True
    )
    syntax_unavailable_authorized = (
        formal_coverage_rule.get(
            "in_scope_syntax_unavailable_is_valid_non_metric_outcome"
        )
        is True
    )

    manifest = {
        "schema_version": "codesentry_gen_e2e_run_v0.4",
        "status": overall_status,
        "integration_process_status": (
            "PASS" if process_pass else "FAIL"
        ),
        "scientific_contract_status": (
            "PASS" if scientific_pass else "FAIL"
        ),
        "formal_output_checker_executed": (
            formal_output_checker_executed
        ),
        "scientific_contract_report": rel(
            scientific_report_path
        ),
        "generation_quality": copy.deepcopy(
            scientific_report.get("generation_quality") or {}
        ),
        "run_contract_file": rel(run_contract_path),
        "run_contract_digest": current_run_contract["digest"],
        "historical_step8_freeze_file": rel(freeze_path),
        "core_freeze_closure_file": (
            rel(core_freeze_closure)
            if core_freeze_closure is not None
            else None
        ),
        "runtime_gate_source": check.get("runtime_gate_source"),
        "formal_release_snapshot_binding_status": check.get(
            "formal_release_snapshot_binding_status"
        ),
        "threshold_policy_file": rel(DEFAULT_THRESHOLD_POLICY),
        "fresh_step9_benchmark_used": step9_contract[
            "fresh_step9_benchmark_used"
        ],
        "step9_started": step9_contract["step9_started"],
        "run_purpose": args.run_purpose,
        "step9_split": step9_contract.get("step9_split"),
        "avcs_knowledge_time": step9_contract.get("knowledge_time"),
        "avcs_knowledge_time_source": step9_contract.get(
            "knowledge_time_source"
        ),
        "evaluation_time_view_binding": copy.deepcopy(
            step9_contract.get("named_time_view_binding")
        ),
        "formal_release_snapshot_time": step9_contract.get(
            "release_snapshot_time"
        ),
        "generation_time_uncertainty_seconds": step9_contract.get(
            "generation_time_uncertainty_seconds"
        ),
        "risk_semantics_contract": rel(
            ROOT / "config/core_risk_semantics_v2_1_repair_v1.json"
        ),
        "step9_protocol_file": step9_contract.get(
            "step9_protocol_file"
        ),
        "active_protocol_registry_file": step9_contract.get(
            "active_protocol_registry_file"
        ),
        "active_protocol_pointer_file": step9_contract.get(
            "active_protocol_pointer_file"
        ),
        "active_protocol_id": step9_contract.get(
            "active_protocol_id"
        ),
        "step9_selection_file": step9_contract.get(
            "step9_selection_file"
        ),
        "step9_leakage_audit_file": step9_contract.get(
            "step9_leakage_audit_file"
        ),
        "step9_split_sha256": step9_contract.get(
            "step9_split_sha256"
        ),
        "mode": "real" if args.real else "mock",
        "resume": args.resume,
        "reuse_frozen_generation": args.reuse_frozen_generation,
        "generation_stage_manifest_file": (
            rel(generation_stage_manifest)
            if generation_stage_manifest is not None
            else None
        ),
        "generation_stage_manifest_sha256": (
            canonical_sha256_file(generation_stage_manifest)
            if generation_stage_manifest is not None
            else None
        ),
        "generation_outcome_manifest_file": (
            rel(generation_dir / "generation_outcome_manifest.json")
            if generation_outcome_manifest_value is not None
            else None
        ),
        "generation_outcome_manifest_content_sha256": (
            generation_outcome_manifest_value.get(
                "manifest_content_sha256"
            )
            if generation_outcome_manifest_value is not None
            else None
        ),
        "statistical_eligibility": (
            evaluate_split_statistical_eligibility(
                generation_outcome_manifest_value
            )
            if generation_outcome_manifest_value is not None
            else None
        ),
        "analysis_population_file": rel(downstream_samples_path),
        "analysis_population_count": generated_success,
        "model": args.model if args.real else "mock_generation_v0",
        "inputs": {
            "prompts": rel(prompts),
            "prompts_sha256": canonical_sha256_file(prompts),
            "identity_policy_file": rel(DEFAULT_IDENTITY_POLICY),
            "identity_policy_sha256": canonical_sha256_file(
                DEFAULT_IDENTITY_POLICY
            ),
            "project_snapshots_dir": rel(project_snapshots_dir),
            "start": args.start,
            "limit": args.limit,
            "controlled_generation_time": controlled_generation_time,
            "mock_profile": (
                args.mock_profile if not args.real else None
            ),
            "release_snapshot_manifest": (
                rel(release_snapshot_manifest)
                if release_snapshot_manifest is not None
                else None
            ),
            "release_snapshot_manifest_sha256": (
                canonical_sha256_file(release_snapshot_manifest)
                if release_snapshot_manifest is not None
                else None
            ),
            "generation_stage_manifest": (
                rel(generation_stage_manifest)
                if generation_stage_manifest is not None
                else None
            ),
            "reuse_frozen_generation": args.reuse_frozen_generation,
            "evaluation_time_view_binding": copy.deepcopy(
                step9_contract.get("named_time_view_binding")
            ),
        },
        "outputs": {
            "generated_samples": rel(samples_path),
            "accepted_complete_samples": rel(downstream_samples_path),
            "dependency_records": rel(dependency_records),
            "sceg_dependency_projection": rel(
                sceg_dependency_projection
            ),
            "temporal_enriched": rel(temporal_path),
            "reachability_enriched": rel(reachability_path),
            "registry_cache_dir": rel(registry_cache_dir),
            "registry_snapshot_dir": rel(registry_snapshot_dir),
            "tho_risk_cards": rel(tho_cards_path),
            "tho_auxiliary_findings": rel(tho_auxiliary_path),
            "avcs_auxiliary_findings": rel(avcs_auxiliary_path),
            "avcs_coverage_outcomes": rel(avcs_coverage_path),
            "avcs_coverage_review_findings": rel(
                avcs_coverage_review_path
            ),
            "avcs_dir": rel(avcs_dir),
            "unified_risk_cards": rel(unified_cards_path),
            "sceg_base_ir": rel(sceg_base_ir),
            "sceg_analyzed_ir": rel(sceg_analyzed_ir),
            "sceg_nodes": rel(sceg_dir / "nodes.jsonl"),
            "sceg_evidence": rel(sceg_dir / "evidence.jsonl"),
            "sceg_edges": rel(sceg_dir / "edges.jsonl"),
        },
        "avcs_scientific_coverage": {
            **avcs_coverage,
            "formal_cards_emitted": card_counts["avcs"],
            "auxiliary_findings_emitted": card_counts["avcs_auxiliary"],
            "fresh_prevalence_zero_positive_is_allowed": True,
            "runner_invocation_is_not_method_path_validation": True,
        },
        "counts": {
            "prompt_rows_requested": expected_selected_count,
            "prompt_rows_selected": expected_selected_count,
            "unique_sample_ids": unique_sample_count,
            "analysis_population_count": generated_success,
            "analysis_unique_sample_ids": analysis_unique_sample_count,
            "generated_success": generated_success,
            "generation_failed": generation_failed,
            "syntax_parseable": int(
                (scientific_report.get("generation_quality") or {}).get(
                    "syntax_parseable_count", 0
                )
            ),
            "syntax_invalid": int(
                (scientific_report.get("generation_quality") or {}).get(
                    "syntax_invalid_count", 0
                )
            ),
            "syntax_decode_error": int(
                (scientific_report.get("generation_quality") or {}).get(
                    "decode_error_count", 0
                )
            ),
            "dependency_records": len(read_jsonl(dependency_records)),
            "tho_raw_findings": tho_split_counts["raw"],
            "tho_auxiliary_findings": tho_split_counts["auxiliary"],
            "tho_risk_cards": card_counts["tho"],
            "avcs_samples_invoked": avcs_coverage["samples_invoked"],
            "avcs_samples_with_supported_package": avcs_coverage[
                "samples_with_supported_package"
            ],
            "avcs_package_analyses_completed": avcs_coverage[
                "package_analyses_completed"
            ],
            "avcs_time_complete_analyses": avcs_coverage[
                "time_complete_analyses"
            ],
            "avcs_time_incomplete_analyses": avcs_coverage[
                "time_incomplete_analyses"
            ],
            "avcs_failed_or_skipped": len(avcs_failures),
            "avcs_formal_risk_cards": card_counts["avcs"],
            "avcs_auxiliary_findings": card_counts["avcs_auxiliary"],
            "avcs_coverage_review_findings": len(
                avcs_coverage_review_rows
            ),
            "unified_risk_cards": card_counts["total"],
            "sceg_records": sceg_counts["sceg_record_count"],
            "sceg_nodes": sceg_counts["node_record_count"],
            "sceg_evidence": sceg_counts["evidence_record_count"],
            "sceg_edges": sceg_counts["edge_count"],
        },
        "avcs_failures_or_skips": avcs_failures,
        "scientific_boundary": {
            "historical_step8_freeze_retained_as_provenance": True,
            "historical_step8_freeze_is_not_formal_runtime_authority": (
                step9_contract["is_step9"]
            ),
            "formal_runtime_authority_is_repaired_core_closure": (
                step9_contract["is_step9"]
            ),
            "fresh_step9_benchmark_used": step9_contract[
                "fresh_step9_benchmark_used"
            ],
            "trigger_evidence_is_secondary": True,
            "unknown_is_not_false": True,
            "registry_evidence_is_run_scoped": True,
            "registry_query_errors_are_not_cached": True,
            "registry_positive_cache_ttl_seconds": 86400,
            "registry_negative_cache_ttl_seconds": 21600,
            "registry_snapshot_preserves_raw_response_and_hash": True,
            "sceg_schema_version": "2.1",
            "sceg_is_shared_pre_analysis_ir": True,
            "tho_consumes_sceg_dependency_projection": True,
            "avcs_consumes_sceg_api_nodes": True,
            "legacy_sceg_v0_posthoc_export_used": False,
            "risk_links_require_location_aware_identity": True,
            "e2e_smoke_is_not_step9": (
                args.run_purpose == "integration_smoke"
            ),
            "step9_run_uses_frozen_split": (
                step9_contract["is_step9"]
            ),
            "formal_step9_uses_staged_real_generation": (
                step9_contract["is_step9"]
                and args.reuse_frozen_generation
            ),
            "formal_step9_generation_api_not_recalled_during_analysis": (
                step9_contract["is_step9"]
                and args.reuse_frozen_generation
            ),
            "selected_population_generation_ledger_preserved": (
                generation_outcome_manifest_value is not None
            ),
            "downstream_analysis_population_is_accepted_complete_only": (
                generation_outcome_manifest_value is not None
            ),
            "terminal_generation_outcomes_excluded_from_dependency_denominator": (
                generation_outcome_manifest_value is not None
            ),
            "terminal_generation_outcomes_are_not_negative": True,
            "terminal_generation_outcomes_are_not_dependency_unknown": True,
            "formal_release_snapshot_acquired_after_generation": (
                step9_contract["is_step9"]
                and args.reuse_frozen_generation
            ),
            "formal_audit_knowledge_time_derived_from_bound_snapshot": (
                step9_contract.get("knowledge_time_source")
                == "bound_release_snapshot.created_at"
            ),
            "formal_step9_requires_explicit_protocol": True,
            "formal_step9_requires_unique_active_protocol": True,
            "package_identity_service_shared_across_tho_sceg_avcs": True,
            "legacy_step9_import_overlay_not_runtime_semantics": True,
            "project_snapshot_used_for_local_module_and_reachability": True,
            "reachability_contract_is_r0_to_r4": True,
            "r5_install_script_execution_not_implemented": True,
            "formal_main_risk_taxonomy_enforced": True,
            "unified_risk_card_schema": "risk_card_v2.1",
            "risk_identity_includes_location_and_time_view": True,
            "temporal_unknown_excluded_from_formal_positive": True,
            "install_reachability_does_not_imply_t_install": True,
            "step9_package_identity_policy": (
                step9_contract.get("package_identity", {})
                if step9_contract["is_step9"]
                else {}
            ),
            "auxiliary_findings_excluded_from_main_metrics": True,
            "resume_reuses_generation_without_recalling_api": True,
            "resume_requires_run_contract_digest_match": True,
            "resume_requires_avcs_input_digest_match": True,
            "resume_requires_avcs_required_output_hash_match": True,
            "integration_process_pass_separate_from_scientific_pass": True,
            "scientific_pass_requires_python_parse": False,
            "scientific_pass_requires_complete_parse_accounting": True,
            "syntax_invalid_generation_is_reportable_not_global_failure": True,
            "syntax_invalid_samples_remain_in_real_generation_population": True,
            "silent_syntax_filtering_forbidden": True,
            "scientific_pass_requires_nonempty_dependency_analysis": True,
            "scientific_pass_requires_nonempty_avcs_method_coverage": True,
            "formal_step9_avcs_coverage_acceptance_is_protocol_bound": True,
            "named_time_view_is_protocol_bound_for_formal_runs": True,
            "legacy_time_view_is_excluded_from_generation_metrics": True,
            "audit_and_oracle_views_are_separate_metric_channels": True,
            "formal_step9_candidate_sample_requires_metric_eligible_outcome": (
                candidate_requires_metric_eligible
            ),
            "formal_step9_non_metric_outcomes_are_protocol_bound": True,
            "formal_step9_syntax_unavailable_requires_protocol_authorization": True,
            "formal_step9_syntax_unavailable_authorized": (
                syntax_unavailable_authorized
            ),
            "formal_step9_no_avcs_candidate_is_explicit_not_applicable": True,
            "scientific_pass_requires_risk_card_schema": True,
            "scientific_pass_requires_sceg_referential_integrity": True,
            "scientific_pass_requires_time_invariants": True,
            "formal_run_executes_parameterized_output_checker": (
                step9_contract["is_step9"]
            ),
            "pass_requires_zero_generation_or_avcs_skips": True,
            "pass_requires_requested_prompt_count_and_unique_sample_ids": True,
        },
    }
    write_json(summary_dir / "run_manifest.json", manifest)
    (summary_dir / "e2e_summary.md").write_text(
        build_summary_markdown(manifest),
        encoding="utf-8",
        newline="\n",
    )

    print(
        "\nCODESENTRY-GEN E2E "
        + overall_status
    )
    print(
        "integration_process_status =",
        "PASS" if process_pass else "FAIL",
    )
    print(
        "scientific_contract_status =",
        "PASS" if scientific_pass else "FAIL",
    )
    for key, value in manifest["counts"].items():
        print(f"{key} = {value}")
    print(
        "fresh_step9_benchmark_used =",
        step9_contract["fresh_step9_benchmark_used"],
    )
    print("step9_started =", step9_contract["step9_started"])
    print("run_purpose =", args.run_purpose)
    print("saved =", rel(out_dir))

    if not process_pass:
        raise SystemExit(
            "E2E integration process FAIL. Inspect generation/AVCS skips; "
            "do not treat this run as PASS."
        )
    if step9_contract["is_step9"] and not scientific_pass:
        raise SystemExit(
            "Formal E2E scientific contract FAIL. The output checker report "
            "is authoritative; do not treat this run as formal PASS."
        )
    if not scientific_pass:
        print(
            "[WARN] Integration process completed, but scientific contract "
            "did not pass. This run is diagnostic only."
        )


if __name__ == "__main__":
    main()
