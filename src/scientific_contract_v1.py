from __future__ import annotations

import ast
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import jsonschema

from build_core_freeze_closure_v1 import (
    collect_python_closure, package_kb_runtime_refs, runtime_extension_versions,
)
from build_temporal_risk_cards import (
    build_repair,
    classify_risk,
    get_install_time_evidence,
    get_reachability,
)
from materialize_project_snapshots_v1 import verify_snapshot_index
from generation_outcome_accounting_v1 import validate_manifest_self_consistency
from generation_outcome_integration_v1 import (
    accepted_rows_from_manifest,
    evaluate_split_statistical_eligibility,
    require_successor_method_revision_contract,
)
from freeze_hash_v1 import (
    hash_record,
    verify_hash,
)
from risk_semantics_v21 import (
    FORMAL_MAIN_RISK_TYPES,
    avcs_formal_risk_view_eligible,
    deduplicate_cards,
    normalize_risk_card,
    pep503_normalize,
    validate_risk_card,
)
from sceg_ir_v21 import (
    build_base_ir,
    project_dependency_records,
    verify_ir,
)
from time_view_contract_v1 import validate_coverage_metric_authority


ROOT = Path(__file__).resolve().parents[1]

AVCS_RUNTIME_FILES = [
    "src/run_step8_unified_avcs.py",
    "src/avcs_curated_scope_v1.py",
    "src/resolve_api_version_constraints.py",
    "src/resolve_avcs_manifest_constraints.py",
    "src/run_avcs_trigger_matcher.py",
    "src/extract_api_calls.py",
    "src/normalizer.py",
    "src/sceg_ir_v21.py",
    "src/freeze_hash_v1.py",
    "src/scientific_contract_v1.py",
    "src/time_view_contract_v1.py",
    "src/check_codesentry_gen_e2e_output.py",
    "src/build_core_freeze_closure_v1.py",
    "src/step9_protocol_registry.py",
    "src/package_identity_v1.py",
    "src/project_dependency_facts_v1.py",
    "requirements-workflow-parser.txt",
    "src/materialize_project_snapshots_v1.py",
    "config/import_mapping.json",
    "config/package_identity_mapping_v1.json",
    "config/package_identity_policy_v1.json",
    "config/avcs_curated_scope_v1.json",
    "config/time_view_contract_v1.json",
    "config/step8_avcs_threshold_policy_v2_f10_exposure_prerequisite.json",
    "output/step7_batch_review_v0/step7_freeze_v1/step7_freeze_report.json",
]

E2E_RUNTIME_FILES = [
    "src/run_codesentry_gen_e2e.py",
    "src/build_step9_method_freeze_v1.py",
    "src/run_step9_generation_stage.py",
    "src/generation_outcome_accounting_v1.py",
    "src/generation_outcome_integration_v1.py",
    "src/build_step9_generation_recovery_assessment.py",
    "src/build_step9_generation_checkpoint_evidence.py",
    "src/build_step9_post_generation_evidence.py",
    "src/prepare_step9_fresh_benchmark.py",
    "src/check_step9_fresh_selection.py",
    "src/close_step9_fresh_pilot.py",
    "src/generate_code_from_prompts.py",
    "src/run_pilot.py",
    "src/build_sceg_ir_v21.py",
    "src/enrich_temporal_status.py",
    "src/enrich_reachability_v2.py",
    "src/build_temporal_risk_cards.py",
    "src/run_step8_unified_avcs.py",
    "src/avcs_curated_scope_v1.py",
    "src/finalize_sceg_ir_v21.py",
    "src/risk_semantics_v21.py",
    "src/sceg_ir_v21.py",
    "src/freeze_hash_v1.py",
    "src/scientific_contract_v1.py",
    "src/time_view_contract_v1.py",
    "src/build_core_freeze_closure_v1.py",
    "src/verify_core_freeze_closure_v1.py",
    "src/step9_protocol_registry.py",
    "src/package_identity_v1.py",
    "src/project_dependency_facts_v1.py",
    "requirements-workflow-parser.txt",
    "src/materialize_project_snapshots_v1.py",
    "config/package_identity_mapping_v1.json",
    "config/package_identity_policy_v1.json",
    "config/avcs_curated_scope_v1.json",
    "config/core_risk_semantics_v2_1_repair_v1.json",
    "config/time_view_contract_v1.json",
    "config/step9_protocol_registry_v1.json",
    "config/step9_active_protocol.json",
    "config/step9_fresh_benchmark_protocol_v4_repair_draft.json",
    "config/step9_fresh_benchmark_protocol_v4_final.json",
    "config/step9_fresh_benchmark_protocol_v4_final_r2.json",
    "config/step9_fresh_benchmark_protocol_v4_final_r3_repair.json",
    "config/step9_fresh_benchmark_protocol_v4_final_r3.json",
    "config/step9_v4_final_freeze_request.json",
    "config/step9_v4_final_r2_freeze_request.json",
    "config/step9_v4_final_r3_freeze_request.json",
    "schemas/risk_card_schema_v2_1.json",
    "schemas/sceg_schema_v2_1.json",
]


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return value


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        raise FileNotFoundError(path)
    with path.open("r", encoding="utf-8-sig") as handle:
        for line_no, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"Expected object at {path}:{line_no}")
            rows.append(value)
    return rows


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def canonical_json_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def parse_time(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        result = datetime.fromisoformat(text)
    except ValueError:
        return None
    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)
    return result.astimezone(timezone.utc)


def _hash_file_set(paths: list[Path]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for path in sorted(paths, key=rel):
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(path)
        result[rel(path)] = hash_record(path)
    return result


def avcs_runtime_file_set(kb_dir: Path) -> list[Path]:
    paths: set[Path] = {ROOT / value for value in AVCS_RUNTIME_FILES}
    paths.update(collect_python_closure([path for path in paths if path.suffix == ".py"]))
    kb_paths = sorted(kb_dir.glob("*_package_kb_v0.json"))
    if not kb_paths:
        raise ValueError(f"No Package KBs found under {kb_dir}")
    for kb_path in kb_paths:
        paths.add(kb_path)
        kb = read_json(kb_path)
        paths.update(package_kb_runtime_refs(kb_path, kb))
    return sorted(paths, key=rel)


def build_avcs_resume_input(
    *,
    sample_id: str,
    code_path: Path | None,
    sample_records_path: Path | None,
    sceg_ir_path: Path | None,
    release_snapshot_manifest_path: Path | None,
    kb_dir: Path,
    threshold_policy_path: Path,
    freeze_report_path: Path,
    mapping_path: Path,
    time_view: str | None,
    knowledge_time: str | None,
    identity_policy_path: Path | None = None,
    curated_scope_path: Path | None = None,
    project_snapshot_manifest_path: Path | None = None,
    evaluation_time_view: dict[str, Any] | None = None,
) -> dict[str, Any]:
    canonical_sceg_mode = sceg_ir_path is not None
    primary_files: dict[str, dict[str, Any] | None] = {
        # F-04: once canonical SCEG exists, raw generated code and the
        # generated-sample JSONL are validation-only/pre-construction inputs.
        # They must not remain part of AVCS scientific resume identity.
        "code": (
            hash_record(code_path)
            if code_path is not None and not canonical_sceg_mode
            else None
        ),
        "sample_records": (
            hash_record(sample_records_path)
            if sample_records_path is not None and not canonical_sceg_mode
            else None
        ),
        "sceg_ir": (
            hash_record(sceg_ir_path)
            if sceg_ir_path is not None
            else None
        ),
        "release_snapshot_manifest": (
            hash_record(release_snapshot_manifest_path)
            if release_snapshot_manifest_path is not None
            else None
        ),
        "threshold_policy": hash_record(threshold_policy_path),
        "step7_freeze_report": hash_record(freeze_report_path),
        "mapping": hash_record(mapping_path),
        "identity_policy": (
            hash_record(identity_policy_path)
            if identity_policy_path is not None
            else None
        ),
        "curated_scope": (
            hash_record(curated_scope_path)
            if curated_scope_path is not None
            else hash_record(ROOT / "config/avcs_curated_scope_v1.json")
        ),
        "project_snapshot_manifest": (
            hash_record(project_snapshot_manifest_path)
            if project_snapshot_manifest_path is not None
            else None
        ),
    }
    runtime_files = _hash_file_set(avcs_runtime_file_set(kb_dir))
    payload = {
        "schema_version": "avcs_resume_input_v1",
        "sample_id": sample_id,
        "time_view": time_view,
        "knowledge_time": knowledge_time,
        "evaluation_time_view": evaluation_time_view,
        "canonical_input_mode": (
            "sceg_ir" if canonical_sceg_mode else "legacy_external_sources"
        ),
        "validation_only_external_files_excluded": canonical_sceg_mode,
        "primary_files": primary_files,
        "runtime_files": runtime_files,
        "runtime_extensions": runtime_extension_versions(ROOT),
    }
    payload["digest"] = canonical_json_sha256(payload)
    return payload


def project_avcs_final_output_coverage(
    row: dict[str, Any],
) -> dict[str, Any]:
    """Independently project a coverage row into final-output semantics."""
    return {
        "schema_version": "avcs_final_output_coverage_v1",
        "support_status": row.get("support_status"),
        "coverage_outcome": row.get("main_metric_outcome"),
        "main_metric_eligible": row.get("main_metric_eligible"),
        "formal_positive": row.get("formal_positive"),
        "generation_metric": (
            json.loads(json.dumps(row.get("generation_metric")))
            if row.get("generation_metric") is not None
            else None
        ),
        "audit_drift_metric": (
            json.loads(json.dumps(row.get("audit_drift_metric")))
            if row.get("audit_drift_metric") is not None
            else None
        ),
        "evaluation_time_view": (
            json.loads(json.dumps(row.get("evaluation_time_view")))
            if row.get("evaluation_time_view") is not None
            else None
        ),
        "view_specific_metric_outcome": (
            json.loads(
                json.dumps(row.get("view_specific_metric_outcome"))
            )
            if row.get("view_specific_metric_outcome") is not None
            else None
        ),
        "syntax_parse_status": row.get("syntax_parse_status"),
        "analysis_support": (
            json.loads(json.dumps(row.get("analysis_support")))
            if row.get("analysis_support") is not None
            else None
        ),
        "blocking_unknown_reasons": list(
            row.get("blocking_unknown_reasons") or []
        ),
        "coverage_annotations": list(
            row.get("coverage_annotations") or []
        ),
        "avcs_package_scope": (
            json.loads(json.dumps(row.get("avcs_package_scope")))
            if row.get("avcs_package_scope") is not None
            else None
        ),
        "package_kb_scope": (
            json.loads(json.dumps(row.get("package_kb_scope")))
            if row.get("package_kb_scope") is not None
            else None
        ),
        "observed_call_coverage": (
            json.loads(json.dumps(row.get("observed_call_coverage")))
            if row.get("observed_call_coverage") is not None
            else None
        ),
        "manifest_coverage": (
            json.loads(json.dumps(row.get("manifest_coverage")))
            if row.get("manifest_coverage") is not None
            else None
        ),
        "vulnerability_coverage": (
            json.loads(json.dumps(row.get("vulnerability_coverage")))
            if row.get("vulnerability_coverage") is not None
            else None
        ),
        "trigger_coverage": (
            json.loads(json.dumps(row.get("trigger_coverage")))
            if row.get("trigger_coverage") is not None
            else None
        ),
        "time_analysis": (
            json.loads(json.dumps(row.get("time_analysis")))
            if row.get("time_analysis") is not None
            else None
        ),
        "scientific_boundary": {
            "coverage_is_explanatory_not_additional_risk_evidence": True,
            "unknown_is_not_false": True,
            "syntax_unavailable_is_not_negative": True,
            "syntax_unavailable_is_not_metric_eligible": True,
            "selected_scope_is_not_package_wide": True,
            "trigger_match_is_not_exploit_proof": True,
            "non_generation_view_is_not_main_metric_eligible": True,
            "audit_drift_metric_is_separate_from_generation_metric": True,
        },
    }


def build_avcs_coverage_review_findings(
    coverage_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Materialize non-formal AVCS coverage states as auxiliary findings.

    These records explain why absence of a formal Risk Card is not necessarily
    a negative result. They are deliberately separate from the three formal
    Risk Card types and are never metric-eligible by themselves.
    """
    findings: list[dict[str, Any]] = []
    for row in coverage_rows:
        if not isinstance(row, dict):
            continue
        outcome = str(row.get("main_metric_outcome") or "").strip()
        if outcome in {"formal_positive", "formal_negative"}:
            continue
        if not outcome:
            continue

        findings.append(
            {
                "schema_version": "avcs_coverage_review_finding_v1",
                "finding_kind": "avcs_coverage_review",
                "channel": "auxiliary_coverage",
                "sample_id": row.get("sample_id"),
                "distribution": row.get("distribution"),
                "support_status": row.get("support_status"),
                "coverage_outcome": outcome,
                "main_metric_eligible": False,
                "evaluation_time_view": json.loads(
                    json.dumps(row.get("evaluation_time_view"))
                ),
                "view_specific_metric_outcome": json.loads(
                    json.dumps(row.get("view_specific_metric_outcome"))
                ),
                "syntax_parse_status": row.get("syntax_parse_status"),
                "analysis_support": (
                    json.loads(json.dumps(row.get("analysis_support")))
                    if row.get("analysis_support") is not None
                    else None
                ),
                "blocking_unknown_reasons": list(
                    row.get("blocking_unknown_reasons") or []
                ),
                "coverage_annotations": list(
                    row.get("coverage_annotations") or []
                ),
                "avcs_package_scope": row.get("avcs_package_scope"),
                "package_kb_scope": row.get("package_kb_scope"),
                "observed_call_coverage": row.get(
                    "observed_call_coverage"
                ),
                "manifest_coverage": row.get("manifest_coverage"),
                "vulnerability_coverage": row.get(
                    "vulnerability_coverage"
                ),
                "trigger_coverage": row.get("trigger_coverage"),
                "time_analysis": row.get("time_analysis"),
                "coverage": project_avcs_final_output_coverage(row),
                "scientific_boundary": {
                    "formal_risk_type": None,
                    "excluded_from_formal_risk_metrics": True,
                    "absence_of_risk_card_is_not_negative_by_itself": True,
                },
            }
        )

    findings.sort(
        key=lambda row: (
            str(row.get("sample_id") or ""),
            str(row.get("distribution") or ""),
            str(row.get("coverage_outcome") or ""),
        )
    )
    return findings


def verify_avcs_coverage_review_findings(
    *,
    avcs_dir: Path,
    findings_path: Path,
) -> list[str]:
    """Require an exact auxiliary projection of non-formal coverage outcomes."""
    source_rows: list[dict[str, Any]] = []
    sample_root = avcs_dir / "samples"
    if sample_root.exists():
        for sample_dir in sorted(
            path for path in sample_root.iterdir() if path.is_dir()
        ):
            coverage_path = sample_dir / "coverage_outcomes.jsonl"
            if not coverage_path.exists():
                return [
                    f"coverage_outcomes_missing:{rel(coverage_path)}"
                ]
            source_rows.extend(read_jsonl(coverage_path))

    expected = build_avcs_coverage_review_findings(source_rows)
    if not findings_path.exists():
        return [
            f"coverage_review_findings_missing:{rel(findings_path)}"
        ]

    actual = read_jsonl(findings_path)
    if actual != expected:
        return [
            "coverage_review_findings_mismatch:"
            f"expected={len(expected)} actual={len(actual)}"
        ]
    return []


def build_avcs_output_contract(
    *,
    sample_out: Path,
    package_names: list[str],
    coverage_outcomes_path: Path | None = None,
) -> dict[str, Any]:
    required: dict[str, dict[str, Any]] = {}
    risk_cards = sample_out / "risk_cards.jsonl"
    required[rel(risk_cards)] = hash_record(risk_cards)
    if coverage_outcomes_path is not None:
        required[rel(coverage_outcomes_path)] = hash_record(
            coverage_outcomes_path
        )
    for name in sorted(set(package_names)):
        analysis = sample_out / "packages" / name / "analysis.json"
        required[rel(analysis)] = hash_record(analysis)
    return {
        "schema_version": "avcs_resume_outputs_v1",
        "required_outputs": required,
        "digest": canonical_json_sha256(required),
    }


def verify_avcs_resume_contract(
    *,
    sample_out: Path,
    current_input: dict[str, Any],
) -> dict[str, Any]:
    manifest_path = sample_out / "manifest.json"
    if not manifest_path.exists():
        raise ValueError(
            f"AVCS resume manifest missing: {manifest_path}"
        )
    manifest = read_json(manifest_path)
    if manifest.get("schema_version") != "step8_unified_avcs_run_v0.3":
        raise ValueError(
            "AVCS resume manifest schema is not v0.3"
        )

    contract = manifest.get("resume_contract")
    if not isinstance(contract, dict):
        raise ValueError("AVCS resume_contract missing")

    frozen_input = contract.get("input")
    if not isinstance(frozen_input, dict):
        raise ValueError("AVCS resume input contract missing")

    expected_digest = str(frozen_input.get("digest") or "")
    actual_digest = str(current_input.get("digest") or "")
    if not expected_digest or expected_digest != actual_digest:
        raise ValueError(
            "AVCS resume input digest mismatch: "
            f"expected={expected_digest} actual={actual_digest}"
        )

    outputs = contract.get("outputs")
    if not isinstance(outputs, dict):
        raise ValueError("AVCS resume output contract missing")
    required = outputs.get("required_outputs")
    if not isinstance(required, dict) or not required:
        # A zero-package analysis still must have risk_cards.jsonl.
        raise ValueError("AVCS resume required outputs missing")

    for relative, expected in required.items():
        verify_hash(
            ROOT / relative,
            expected,
            label=f"AVCS resume output:{relative}",
        )

    observed_digest = canonical_json_sha256(required)
    if observed_digest != outputs.get("digest"):
        raise ValueError("AVCS resume output digest metadata drift")

    return manifest


def build_e2e_run_contract(
    *,
    prompts: Path,
    run_purpose: str,
    model: str,
    real_generation: bool,
    start: int,
    limit: int,
    timeout: int,
    retries: int,
    dataset_label: str,
    knowledge_time: str | None,
    uncertainty_seconds: float,
    release_snapshot_manifest: Path | None,
    step8_freeze: Path,
    step9_protocol: Path | None,
    core_freeze_closure: Path | None = None,
    generation_stage_manifest: Path | None = None,
    reuse_frozen_generation: bool = False,
    controlled_generation_time: str | None = None,
    mock_profile: str | None = None,
    evaluation_time_view_binding: dict[str, Any] | None = None,
) -> dict[str, Any]:
    runtime_paths = [ROOT / value for value in E2E_RUNTIME_FILES]
    runtime_paths = sorted(set(runtime_paths).union(collect_python_closure(
        [path for path in runtime_paths if path.suffix == ".py"]
    )), key=rel)
    payload = {
        "schema_version": "codesentry_gen_e2e_resume_contract_v1",
        "inputs": {
            "prompts": {
                "path": rel(prompts),
                "hash": hash_record(prompts),
            },
            "run_purpose": run_purpose,
            "model": model,
            "real_generation": bool(real_generation),
            "start": start,
            "limit": limit,
            "timeout": timeout,
            "retries": retries,
            "dataset_label": dataset_label,
            "knowledge_time": knowledge_time,
            "generation_time_uncertainty_seconds": (
                float(uncertainty_seconds)
            ),
            "controlled_generation_time": controlled_generation_time,
            "mock_profile": mock_profile,
            "evaluation_time_view_binding": json.loads(
                json.dumps(evaluation_time_view_binding)
            ),
            "release_snapshot_manifest": (
                {
                    "path": rel(release_snapshot_manifest),
                    "hash": hash_record(release_snapshot_manifest),
                }
                if release_snapshot_manifest is not None
                else None
            ),
            "step8_freeze": {
                "path": rel(step8_freeze),
                "hash": hash_record(step8_freeze),
            },
            "core_freeze_closure": (
                {
                    "path": rel(core_freeze_closure),
                    "hash": hash_record(core_freeze_closure),
                }
                if core_freeze_closure is not None
                else None
            ),
            "step9_protocol": (
                {
                    "path": rel(step9_protocol),
                    "hash": hash_record(step9_protocol),
                }
                if step9_protocol is not None
                else None
            ),
            "generation_stage_manifest": (
                {
                    "path": rel(generation_stage_manifest),
                    "hash": hash_record(generation_stage_manifest),
                }
                if generation_stage_manifest is not None
                else None
            ),
            "reuse_frozen_generation": bool(reuse_frozen_generation),
        },
        "runtime_files": _hash_file_set(runtime_paths),
        "runtime_extensions": runtime_extension_versions(ROOT),
    }
    payload["digest"] = canonical_json_sha256(payload)
    return payload


def initialize_or_verify_e2e_resume_contract(
    *,
    out_dir: Path,
    current: dict[str, Any],
    resume: bool,
) -> Path:
    path = out_dir / "run_contract.json"
    if resume:
        if not path.exists():
            raise ValueError(
                "Resume refused: run_contract.json is missing"
            )
        frozen = read_json(path)
        if frozen.get("schema_version") != (
            "codesentry_gen_e2e_resume_contract_v1"
        ):
            raise ValueError(
                "Resume refused: run contract schema mismatch"
            )
        if frozen.get("digest") != current.get("digest"):
            raise ValueError(
                "Resume refused: E2E run input/runtime digest changed"
            )
        return path

    if path.exists():
        raise FileExistsError(
            f"Refusing overwrite of E2E run contract: {path}"
        )
    write_json(path, current)
    return path


def sceg_resume_semantic_payload(
    ir: dict[str, Any],
) -> dict[str, Any]:
    """Canonical SCEG semantics used to decide whether a base IR is reusable.

    Construction timestamps are intentionally excluded. Scientific inputs,
    contracts, Sample/time context, nodes, evidence, edges and source bindings
    remain part of the digest.
    """
    verify_ir(ir)
    payload = json.loads(
        json.dumps(ir, ensure_ascii=False)
    )
    payload.pop("created_at", None)
    payload.pop("finalized_at", None)

    source_inputs = payload.get("source_inputs")
    if isinstance(source_inputs, dict):
        dependency_input = source_inputs.get("dependency_records")
        if isinstance(dependency_input, dict):
            # The raw dependency JSONL hash includes cache/network transport
            # metadata. The scientific hash is preserved and remains part of
            # resume identity.
            dependency_input.pop("sha256", None)

    return payload


def sceg_resume_semantic_digest(ir: dict[str, Any]) -> str:
    return canonical_json_sha256(
        sceg_resume_semantic_payload(ir)
    )


def _tho_fact_identity(value: dict[str, Any]) -> tuple[
    str, str, str | None, int | None, str | None
]:
    location = (
        value.get("location")
        if isinstance(value.get("location"), dict)
        else {}
    )
    line = location.get("line")
    return (
        str(value.get("sample_id") or "").strip(),
        pep503_normalize(
            value.get("package")
            or value.get("normalized_distribution")
            or ""
        ),
        (
            str(location.get("file")).replace("\\", "/")
            if location.get("file") is not None
            else None
        ),
        int(line) if isinstance(line, int) else None,
        (
            str(value.get("source_type"))
            if value.get("source_type") is not None
            else None
        ),
    )


def _tho_card_identity(value: dict[str, Any]) -> tuple[
    str, str, str | None, int | None, str | None
]:
    introduced = (
        value.get("introduced_by")
        if isinstance(value.get("introduced_by"), dict)
        else {}
    )
    package = value.get("package")
    if isinstance(package, dict):
        package_value = (
            package.get("normalized_name")
            or package.get("name")
        )
    else:
        package_value = package
    line = introduced.get("line")
    return (
        str(value.get("sample_id") or "").strip(),
        pep503_normalize(package_value or ""),
        (
            str(introduced.get("file")).replace("\\", "/")
            if introduced.get("file") is not None
            else None
        ),
        int(line) if isinstance(line, int) else None,
        (
            str(introduced.get("source_type"))
            if introduced.get("source_type") is not None
            else None
        ),
    )


def validate_tho_formal_cards_against_records(
    *,
    cards: list[dict[str, Any]],
    reachability_records: list[dict[str, Any]],
) -> list[str]:
    """Re-derive THO decisions and compare them with emitted formal cards."""
    errors: list[str] = []
    record_index: dict[
        tuple[str, str, str | None, int | None, str | None],
        list[dict[str, Any]],
    ] = {}
    for row in reachability_records:
        record_index.setdefault(
            _tho_fact_identity(row), []
        ).append(row)

    observed_card_keys: set[
        tuple[str, str, str | None, int | None, str | None]
    ] = set()

    for card in cards:
        if card.get("pipeline_origin") != "THO":
            errors.append(
                "tho_card_pipeline_origin_mismatch:"
                + str(card.get("risk_id") or "")
            )
            continue
        if card.get("channel") != "formal":
            errors.append(
                "tho_risk_card_not_formal:"
                + str(card.get("risk_id") or "")
            )
            continue

        key = _tho_card_identity(card)
        matches = record_index.get(key, [])
        if len(matches) != 1:
            errors.append(
                "tho_card_fact_match_count:"
                f"{key}:{len(matches)}"
            )
            continue
        if key in observed_card_keys:
            errors.append(
                "duplicate_tho_formal_card_for_fact:"
                + str(key)
            )
            continue
        observed_card_keys.add(key)

        record = matches[0]
        decision = classify_risk(record)
        if (
            not isinstance(decision, dict)
            or decision.get("risk_type")
            != "temporal_package_hallucination"
            or decision.get("formal_eligible") is False
        ):
            errors.append(
                "tho_card_not_supported_by_fact:"
                f"{key}:temporal_status="
                f"{record.get('temporal_status_v2')!r}"
            )
            continue

        source_card = (
            card.get("source_card")
            if isinstance(card.get("source_card"), dict)
            else {}
        )
        checks = {
            "type": (
                card.get("type"),
                decision.get("risk_type"),
            ),
            "status": (
                card.get("status"),
                decision.get("status"),
            ),
            "severity": (
                card.get("severity"),
                decision.get("severity"),
            ),
            "subtype": (
                source_card.get("subtype"),
                decision.get("subtype"),
            ),
            "temporal_classification": (
                (
                    card.get("time_view")
                    if isinstance(card.get("time_view"), dict)
                    else {}
                ).get("temporal_classification"),
                (
                    record.get("temporal_status_v2")
                    or record.get("status")
                ),
            ),
        }
        for field, (actual, expected) in checks.items():
            if actual != expected:
                errors.append(
                    "tho_card_fact_semantic_mismatch:"
                    f"{key}:{field}:{actual!r}!={expected!r}"
                )

        raw_location = (
            source_card.get("introduced_by")
            if isinstance(source_card.get("introduced_by"), dict)
            else {}
        )
        record_location = (
            record.get("location")
            if isinstance(record.get("location"), dict)
            else {}
        )
        location_checks = {
            "file": (
                raw_location.get("file"),
                record_location.get("file"),
            ),
            "line": (
                raw_location.get("line"),
                record_location.get("line"),
            ),
            "entity": (
                raw_location.get("entity"),
                record.get("package"),
            ),
            "raw_name": (
                raw_location.get("raw_name"),
                record.get("raw_name"),
            ),
            "source_type": (
                raw_location.get("source_type"),
                record.get("source_type"),
            ),
        }
        for field, (actual, expected) in location_checks.items():
            if actual != expected:
                errors.append(
                    "tho_card_location_mismatch:"
                    f"{key}:{field}:{actual!r}!={expected!r}"
                )

        reachability = (
            source_card.get("install_reachability")
            if isinstance(
                source_card.get("install_reachability"), dict
            )
            else {}
        )
        expected_reachability = get_reachability(record)
        if reachability.get("level") != expected_reachability:
            errors.append(
                "tho_card_reachability_mismatch:"
                f"{key}:{reachability.get('level')!r}!="
                f"{expected_reachability!r}"
            )

        evidence = (
            source_card.get("evidence")
            if isinstance(source_card.get("evidence"), dict)
            else {}
        )
        structural_rows = evidence.get("structural")
        structural = (
            structural_rows[0]
            if isinstance(structural_rows, list)
            and structural_rows
            and isinstance(structural_rows[0], dict)
            else {}
        )
        expected_structural = {
            "kind": record.get("source_type"),
            "file": record_location.get("file"),
            "line": record_location.get("line"),
            "raw_name": record.get("raw_name"),
            "package": record.get("package"),
        }
        if structural != expected_structural:
            errors.append(
                "tho_card_structural_evidence_mismatch:"
                f"{key}"
            )

        temporal_rows = evidence.get("temporal")
        temporal = (
            temporal_rows[0]
            if isinstance(temporal_rows, list)
            and temporal_rows
            and isinstance(temporal_rows[0], dict)
            else {}
        )
        pypi = (
            record.get("pypi")
            if isinstance(record.get("pypi"), dict)
            else {}
        )
        expected_temporal = {
            "generation_time": record.get("generation_time"),
            "generation_time_uncertainty_seconds": record.get(
                "generation_time_uncertainty_seconds"
            ),
            "first_release_time": pypi.get("first_release_time"),
            "audit_time": pypi.get("audit_time"),
            "temporal_status": (
                record.get("temporal_status_v2")
                or record.get("status")
            ),
            "install_time_evidence": get_install_time_evidence(
                record
            ),
        }
        if canonical_json_sha256(temporal) != canonical_json_sha256(
            expected_temporal
        ):
            errors.append(
                "tho_card_temporal_evidence_mismatch:"
                f"{key}"
            )

        ecosystem_rows = evidence.get("ecosystem")
        ecosystem = (
            ecosystem_rows[0]
            if isinstance(ecosystem_rows, list)
            and ecosystem_rows
            and isinstance(ecosystem_rows[0], dict)
            else {}
        )
        expected_ecosystem = {
            "ecosystem": "pypi",
            "exists_now": pypi.get("exists_now"),
            "query_url": pypi.get("query_url"),
            "status_code": pypi.get("status_code"),
            "offline_pypi_exists": record.get(
                "offline_pypi_exists"
            ),
            "reference_false_positive": record.get(
                "reference_false_positive"
            ),
        }
        if ecosystem != expected_ecosystem:
            errors.append(
                "tho_card_ecosystem_evidence_mismatch:"
                f"{key}"
            )

        expected_repair = build_repair(record)
        source_repair = (
            source_card.get("repair")
            if isinstance(source_card.get("repair"), dict)
            else {}
        )
        if canonical_json_sha256(source_repair) != canonical_json_sha256(
            expected_repair
        ):
            errors.append(
                "tho_card_repair_mismatch:"
                f"{key}:source_card"
            )
        normalized_repair = (
            card.get("repair")
            if isinstance(card.get("repair"), dict)
            else {}
        )
        if canonical_json_sha256(normalized_repair) != (
            canonical_json_sha256(expected_repair)
        ):
            errors.append(
                "tho_card_repair_mismatch:"
                f"{key}:normalized"
            )

    expected_formal_keys: set[
        tuple[str, str, str | None, int | None, str | None]
    ] = set()
    for record in reachability_records:
        decision = classify_risk(record)
        if (
            isinstance(decision, dict)
            and decision.get("risk_type")
            == "temporal_package_hallucination"
            and decision.get("formal_eligible") is not False
        ):
            expected_formal_keys.add(
                _tho_fact_identity(record)
            )

    missing_cards = sorted(
        expected_formal_keys - observed_card_keys,
        key=str,
    )
    for key in missing_cards:
        errors.append(
            "tho_formal_fact_missing_risk_card:"
            + str(key)
        )
    return errors


def verify_sceg_base_resume(
    *,
    base_ir_path: Path,
    projection_path: Path,
    samples_path: Path,
    dependency_records_path: Path,
    code_dir: Path,
    mapping_path: Path,
    dataset_label: str,
    identity_policy_path: Path,
    project_snapshots_dir: Path,
) -> dict[str, Any]:
    if not base_ir_path.exists() or not projection_path.exists():
        raise ValueError(
            "SCEG resume refused: base IR or dependency projection missing"
        )

    frozen = read_json(base_ir_path)
    verify_ir(frozen)
    candidate = build_base_ir(
        samples_path=samples_path,
        dependency_records_path=dependency_records_path,
        code_dir=code_dir,
        mapping_path=mapping_path,
        dataset_label=dataset_label,
        identity_policy_path=identity_policy_path,
        project_snapshots_dir=project_snapshots_dir,
    )
    if (
        frozen.get("source_snapshot_id")
        != candidate.get("source_snapshot_id")
    ):
        raise ValueError(
            "SCEG resume refused: source snapshot changed"
        )
    if frozen.get("dataset_label") != dataset_label:
        raise ValueError(
            "SCEG resume refused: dataset label changed"
        )

    frozen_semantic_digest = sceg_resume_semantic_digest(frozen)
    candidate_semantic_digest = sceg_resume_semantic_digest(candidate)
    if frozen_semantic_digest != candidate_semantic_digest:
        raise ValueError(
            "SCEG resume refused: canonical semantic digest changed"
        )

    expected_projection = project_dependency_records(candidate)
    observed_projection = read_jsonl(projection_path)
    if canonical_json_sha256(expected_projection) != (
        canonical_json_sha256(observed_projection)
    ):
        raise ValueError(
            "SCEG resume refused: dependency projection drifted"
        )
    return frozen


def verify_e2e_run_contract_file(path: Path) -> list[str]:
    errors: list[str] = []
    if not path.exists():
        return ["run_contract_missing"]

    contract = read_json(path)
    if contract.get("schema_version") != (
        "codesentry_gen_e2e_resume_contract_v1"
    ):
        errors.append("run_contract_schema")

    expected_digest = str(contract.get("digest") or "")
    digest_payload = dict(contract)
    digest_payload.pop("digest", None)
    if canonical_json_sha256(digest_payload) != expected_digest:
        errors.append("run_contract_digest")

    runtime_files = contract.get("runtime_files")
    if not isinstance(runtime_files, dict) or not runtime_files:
        errors.append("run_contract_runtime_files")
    else:
        for relative, expected in runtime_files.items():
            try:
                verify_hash(
                    ROOT / relative,
                    expected,
                    label=f"E2E runtime:{relative}",
                )
            except Exception as exc:
                errors.append(
                    f"runtime:{relative}:{type(exc).__name__}"
                )

    inputs = contract.get("inputs")
    if not isinstance(inputs, dict):
        errors.append("run_contract_inputs")
        return errors

    for key in (
        "prompts",
        "release_snapshot_manifest",
        "step8_freeze",
        "core_freeze_closure",
        "step9_protocol",
    ):
        value = inputs.get(key)
        if value is None:
            continue
        if not isinstance(value, dict):
            errors.append(f"input:{key}:invalid")
            continue
        path_text = str(value.get("path") or "").strip()
        expected = value.get("hash")
        if not path_text or not isinstance(expected, dict):
            errors.append(f"input:{key}:hash_binding_missing")
            continue
        try:
            verify_hash(
                ROOT / path_text,
                expected,
                label=f"E2E input:{key}",
            )
        except Exception as exc:
            errors.append(
                f"input:{key}:{type(exc).__name__}"
            )

    return errors


def _verify_avcs_manifest_hash_closure(
    manifest: dict[str, Any],
) -> list[str]:
    errors: list[str] = []
    contract = manifest.get("resume_contract")
    if not isinstance(contract, dict):
        return ["resume_contract_missing"]

    frozen_input = contract.get("input")
    if not isinstance(frozen_input, dict):
        errors.append("resume_input_missing")
    else:
        expected = str(frozen_input.get("digest") or "")
        payload = dict(frozen_input)
        payload.pop("digest", None)
        if canonical_json_sha256(payload) != expected:
            errors.append("resume_input_digest")

        runtime_files = frozen_input.get("runtime_files")
        if not isinstance(runtime_files, dict) or not runtime_files:
            errors.append("resume_runtime_files_missing")
        else:
            for relative, hash_value in runtime_files.items():
                try:
                    verify_hash(
                        ROOT / relative,
                        hash_value,
                        label=f"AVCS runtime:{relative}",
                    )
                except Exception as exc:
                    errors.append(
                        f"runtime:{relative}:{type(exc).__name__}"
                    )

    outputs = contract.get("outputs")
    if not isinstance(outputs, dict):
        errors.append("resume_outputs_missing")
        return errors

    required = outputs.get("required_outputs")
    if not isinstance(required, dict) or not required:
        errors.append("resume_required_outputs_missing")
        return errors

    for relative, expected in required.items():
        try:
            verify_hash(
                ROOT / relative,
                expected,
                label=f"AVCS output:{relative}",
            )
        except Exception as exc:
            errors.append(
                f"output:{relative}:{type(exc).__name__}"
            )

    if canonical_json_sha256(required) != outputs.get("digest"):
        errors.append("resume_output_digest")
    return errors


def _gate(
    gates: dict[str, dict[str, Any]],
    name: str,
    passed: bool,
    detail: Any,
) -> None:
    gates[name] = {
        "status": "PASS" if passed else "FAIL",
        "detail": detail,
    }


def _schema_validate(instance: Any, schema_path: Path) -> None:
    schema = read_json(schema_path)
    jsonschema.validate(instance=instance, schema=schema)


def _observed_formal_risk_route_integrity(
    cards: list[dict[str, Any]],
) -> tuple[bool, dict[str, Any]]:
    expected_origin = {
        "temporal_package_hallucination": "THO",
        "api_induced_vulnerable_dependency": "AVCS",
        "temporal_drift": "AVCS",
    }
    observed_counts = {
        risk_type: 0
        for risk_type in sorted(FORMAL_MAIN_RISK_TYPES)
    }
    errors: list[str] = []

    for card in cards:
        if (
            card.get("channel") != "formal"
            or card.get("formal_positive") is not True
        ):
            continue
        risk_type = str(card.get("type") or "")
        origin = str(card.get("pipeline_origin") or "")
        if risk_type not in FORMAL_MAIN_RISK_TYPES:
            errors.append(
                "formal_card_type_outside_main_taxonomy:"
                f"{risk_type}"
            )
            continue
        observed_counts[risk_type] += 1
        if origin != expected_origin.get(risk_type):
            errors.append(
                "formal_card_pipeline_route_mismatch:"
                f"{risk_type}:{origin}:"
                f"expected={expected_origin.get(risk_type)}"
            )

    detail = {
        "mode": "current_run_observed_route_integrity",
        "zero_formal_positive_is_allowed": True,
        "observed_counts": observed_counts,
        "missing_types_are_not_run_failures": sorted(
            risk_type
            for risk_type, count in observed_counts.items()
            if count == 0
        ),
        "controlled_all_risk_capability_required_separately": True,
        "errors": errors,
    }
    return not errors, detail


def _expected_avcs_risk_type(
    *,
    actionability: str,
    temporal: str,
    manifest_kind: str,
) -> str | None:
    if actionability not in {
        "probable_manifest_exposure",
        "api_induced_vulnerable_dependency",
    }:
        return None
    if temporal == "temporal_drift":
        return "temporal_drift"
    if actionability == "api_induced_vulnerable_dependency":
        return "api_induced_vulnerable_dependency"
    return (
        "lockfile_vulnerable_dependency"
        if manifest_kind == "lockfile_exact_pin"
        else "manifest_vulnerable_dependency"
    )


def _repair_contains_expected(
    actual: Any,
    expected: Any,
) -> bool:
    if not isinstance(expected, dict):
        return actual == expected
    if not isinstance(actual, dict):
        return False
    return all(
        key in actual
        and _repair_contains_expected(actual[key], value)
        for key, value in expected.items()
    )



def _scientific_attribution_sort_key(
    row: dict[str, Any],
) -> tuple[Any, ...]:
    """Deterministic ordering for independently re-derived causal locations."""
    file_value = str(row.get("file") or "")
    line_value = row.get("line")
    column_value = row.get("column")
    return (
        1 if not file_value else 0,
        file_value,
        int(line_value) if isinstance(line_value, int) else 10**12,
        int(column_value) if isinstance(column_value, int) else 10**12,
        str(row.get("entity") or ""),
        str(row.get("source_type") or ""),
    )


def _scientific_api_attribution_candidates(
    api_constraints: dict[str, Any],
    distribution: str,
) -> list[dict[str, Any]]:
    normalized_distribution = pep503_normalize(distribution)
    matches = [
        row
        for row in api_constraints.get("distribution_constraints", [])
        if isinstance(row, dict)
        and pep503_normalize(
            row.get("normalized_distribution")
            or row.get("distribution")
            or ""
        )
        == normalized_distribution
    ]
    if len(matches) != 1:
        raise ValueError(
            "expected exactly one API distribution constraint for "
            f"{distribution}, got {len(matches)}"
        )

    candidates: list[dict[str, Any]] = []
    for row in matches[0].get("contributing_calls", []):
        if not isinstance(row, dict):
            continue
        location = (
            row.get("location")
            if isinstance(row.get("location"), dict)
            else {}
        )
        candidates.append(
            {
                "source_type": "api_call",
                "file": location.get("file"),
                "line": location.get("line"),
                "column": location.get("column"),
                "entity": row.get("api_symbol"),
                "call_text": row.get("call_text"),
                "matched_rule_ids": sorted(
                    {
                        str(value)
                        for value in row.get("matched_rule_ids", [])
                        if str(value).strip()
                    }
                ),
                "version_specifiers": list(
                    row.get("version_specifiers", [])
                ),
            }
        )

    candidates.sort(key=_scientific_attribution_sort_key)
    return candidates


def _scientific_dependency_attribution_candidates(
    manifest: dict[str, Any],
    distribution: str,
) -> list[dict[str, Any]]:
    kind = str(manifest.get("constraint_kind") or "")
    source = str(manifest.get("constraint_source") or "")

    fallback_file: Any = None
    if kind == "lockfile_exact_pin" or source == "lockfile":
        detail = (
            manifest.get("lockfile")
            if isinstance(manifest.get("lockfile"), dict)
            else {}
        )
        rows = [
            row
            for row in detail.get("matched_entries", [])
            if isinstance(row, dict)
        ]
        source_type = "lockfile"
        fallback_file = detail.get("source_path")
    else:
        rows = [
            row
            for row in manifest.get("matched_requirements", [])
            if isinstance(row, dict)
        ]
        source_type = "manifest"
        nested_manifest = (
            manifest.get("manifest")
            if isinstance(manifest.get("manifest"), dict)
            else {}
        )
        selected_files = [
            str(value)
            for value in nested_manifest.get(
                "selected_manifest_files", []
            )
            if str(value).strip()
        ]
        if len(selected_files) == 1:
            fallback_file = selected_files[0]

    candidates: list[dict[str, Any]] = []
    for row in rows:
        candidates.append(
            {
                "source_type": source_type,
                "file": (
                    row.get("file")
                    or row.get("source_path")
                    or fallback_file
                ),
                "line": row.get("line"),
                "column": row.get("column"),
                "entity": (
                    row.get("raw_name")
                    or row.get("name")
                    or row.get("normalized_name")
                    or distribution
                ),
                "specifier": (
                    row.get("specifier")
                    or (
                        f"=={row.get('exact_version')}"
                        if row.get("exact_version")
                        else ""
                    )
                ),
                "source_kind": row.get("source_kind"),
            }
        )

    if not candidates:
        candidates.append(
            {
                "source_type": source_type,
                "file": fallback_file,
                "line": None,
                "column": None,
                "entity": distribution,
                "specifier": manifest.get("specifier"),
                "source_kind": "constraint_summary_fallback",
            }
        )

    candidates.sort(key=_scientific_attribution_sort_key)
    return candidates


def _scientific_expected_avcs_attribution(
    *,
    actionability: str,
    distribution: str,
    api_constraints: dict[str, Any],
    manifest: dict[str, Any],
) -> tuple[
    dict[str, Any],
    str,
    str,
    list[dict[str, Any]],
]:
    """Re-derive AVCS attribution without trusting the emitted Risk Card."""
    if actionability == "api_induced_vulnerable_dependency":
        candidates = _scientific_api_attribution_candidates(
            api_constraints,
            distribution,
        )
        if not candidates:
            raise ValueError(
                "formal API-induced risk has no contributing API call"
            )
        basis = "api_constraint_contributing_call"
        evidence_key = "causal_api_calls"
    elif actionability == "probable_manifest_exposure":
        candidates = _scientific_dependency_attribution_candidates(
            manifest,
            distribution,
        )
        if not candidates:
            raise ValueError(
                "formal manifest/lock risk has no dependency declaration"
            )
        basis = (
            "lockfile_constraint_declaration"
            if candidates[0].get("source_type") == "lockfile"
            else "manifest_constraint_declaration"
        )
        evidence_key = "causal_dependency_declarations"
    else:
        raise ValueError(
            "unsupported formal AVCS actionability for causal attribution: "
            f"{actionability}"
        )

    primary = candidates[0]
    introduced_by = {
        "source_type": primary.get("source_type"),
        "file": primary.get("file"),
        "line": primary.get("line"),
        "column": primary.get("column"),
        "entity": primary.get("entity"),
    }
    return introduced_by, basis, evidence_key, candidates


def validate_avcs_formal_cards_against_analysis(
    *,
    avcs_dir: Path,
    unified_cards: list[dict[str, Any]],
) -> list[str]:
    """Cross-check emitted AVCS cards against runner analysis artifacts.

    This validates the current method's source-derived semantics, including
    F-13 causal attribution. Expected locations are independently re-derived
    from API-constraint and manifest/lock artifacts rather than trusting the
    emitted card or the first observed API-call order.
    """
    errors: list[str] = []
    raw_cards_by_source_id: dict[str, dict[str, Any]] = {}
    contexts: dict[
        tuple[str, str],
        dict[str, Any],
    ] = {}

    samples_root = avcs_dir / "samples"
    if not samples_root.exists():
        return errors

    for sample_dir in sorted(
        path for path in samples_root.iterdir()
        if path.is_dir()
    ):
        manifest_path = sample_dir / "manifest.json"
        if not manifest_path.exists():
            continue
        manifest = read_json(manifest_path)
        sample_id = str(
            manifest.get("sample_id") or sample_dir.name
        )
        raw_cards = read_jsonl(sample_dir / "risk_cards.jsonl")

        for raw_card in raw_cards:
            source_id = str(
                raw_card.get("risk_id") or ""
            ).strip()
            if not source_id:
                errors.append(
                    f"avcs_raw_card_missing_risk_id:{sample_id}"
                )
                continue
            if source_id in raw_cards_by_source_id:
                errors.append(
                    f"avcs_duplicate_source_risk_id:{source_id}"
                )
            raw_cards_by_source_id[source_id] = raw_card

        packages = manifest.get("packages")
        if not isinstance(packages, list):
            packages = []

        for package_summary in packages:
            if not isinstance(package_summary, dict):
                continue
            distribution = pep503_normalize(
                package_summary.get("normalized_distribution")
                or package_summary.get("distribution")
                or ""
            )
            if not distribution:
                continue

            analysis_path = (
                sample_dir
                / "packages"
                / distribution
                / "analysis.json"
            )
            if not analysis_path.exists():
                errors.append(
                    "avcs_analysis_missing:"
                    f"{sample_id}:{distribution}"
                )
                continue
            analysis = read_json(analysis_path)
            findings = {
                str(row.get("vulnerability_id") or ""): row
                for row in analysis.get("findings", [])
                if isinstance(row, dict)
                and str(row.get("vulnerability_id") or "")
            }

            kb_path_text = str(
                analysis.get("package_kb") or ""
            )
            kb: dict[str, Any] = {}
            if kb_path_text:
                kb_path = ROOT / kb_path_text
                if kb_path.exists():
                    kb = read_json(kb_path)
            vulnerabilities = {
                str(row.get("vulnerability_id") or ""): row
                for row in kb.get("vulnerability_catalog", [])
                if isinstance(row, dict)
                and str(row.get("vulnerability_id") or "")
            }

            api_constraints: dict[str, Any] = {}
            manifest_constraints: dict[str, Any] = {}
            artifacts = analysis.get("artifacts")
            if isinstance(artifacts, dict):
                api_constraints_text = str(
                    artifacts.get("api_constraints") or ""
                ).strip()
                if api_constraints_text:
                    api_constraints_path = ROOT / api_constraints_text
                    if api_constraints_path.exists():
                        api_constraints = read_json(
                            api_constraints_path
                        )

                manifest_constraints_text = str(
                    artifacts.get("manifest_constraints") or ""
                ).strip()
                if manifest_constraints_text:
                    manifest_constraints_path = (
                        ROOT / manifest_constraints_text
                    )
                    if manifest_constraints_path.exists():
                        manifest_constraints = read_json(
                            manifest_constraints_path
                        )

            package_coverage = package_summary.get("coverage")
            if not isinstance(package_coverage, dict):
                package_coverage = analysis.get("coverage")
            if not isinstance(package_coverage, dict):
                package_coverage = {}
            expected_coverage_row = {
                "support_status": "supported",
                **json.loads(json.dumps(package_coverage)),
            }

            contexts[(sample_id, distribution)] = {
                "analysis": analysis,
                "findings": findings,
                "vulnerabilities": vulnerabilities,
                "api_constraints": api_constraints,
                "manifest_constraints": manifest_constraints,
                "manifest_kind": str(
                    analysis.get(
                        "manifest_constraint_kind"
                    )
                    or ""
                ),
                "final_output_coverage": (
                    project_avcs_final_output_coverage(
                        expected_coverage_row
                    )
                ),
            }

        for card in raw_cards:
            card_sample_id = str(
                card.get("sample_id") or ""
            ).strip()
            distribution = pep503_normalize(
                card.get("distribution")
                or card.get("package")
                or ""
            )
            context = contexts.get(
                (card_sample_id, distribution)
            )
            source_id = str(
                card.get("risk_id") or ""
            ).strip()
            if context is None:
                errors.append(
                    "avcs_card_analysis_context_missing:"
                    f"{card_sample_id}:{distribution}:"
                    f"{source_id}"
                )
                continue

            analysis = context["analysis"]
            findings = context["findings"]
            vulnerabilities = context["vulnerabilities"]
            api_constraints = context["api_constraints"]
            manifest_constraints = context["manifest_constraints"]
            manifest_kind = context["manifest_kind"]
            expected_final_coverage = context[
                "final_output_coverage"
            ]

            vulnerability_id = str(
                card.get("vulnerability_id") or ""
            )
            finding = findings.get(vulnerability_id)
            if finding is None:
                errors.append(
                    "avcs_card_finding_missing:"
                    f"{card_sample_id}:{distribution}:"
                    f"{vulnerability_id}"
                )
                continue

            expected_type = _expected_avcs_risk_type(
                actionability=str(
                    finding.get("actionability") or ""
                ),
                temporal=str(
                    finding.get(
                        "temporal_classification"
                    )
                    or ""
                ),
                manifest_kind=manifest_kind,
            )
            checks = {
                "sample_id": (
                    card_sample_id,
                    sample_id,
                ),
                "distribution": (
                    distribution,
                    pep503_normalize(
                        analysis.get("normalized_distribution")
                        or analysis.get("distribution")
                        or ""
                    ),
                ),
                "type": (
                    card.get("type"),
                    expected_type,
                ),
                "temporal_classification": (
                    card.get(
                        "temporal_classification"
                    ),
                    finding.get(
                        "temporal_classification"
                    ),
                ),
                "generation_time": (
                    card.get("generation_time"),
                    finding.get("generation_time"),
                ),
                "knowledge_time": (
                    card.get("knowledge_time"),
                    finding.get("knowledge_time"),
                ),
                "actionability": (
                    card.get("actionability"),
                    finding.get("actionability"),
                ),
            }
            for field, (actual, expected) in checks.items():
                if actual != expected:
                    errors.append(
                        "avcs_card_fact_semantic_mismatch:"
                        f"{card_sample_id}:{distribution}:"
                        f"{vulnerability_id}:{field}:"
                        f"{actual!r}!={expected!r}"
                    )

            actual_coverage = card.get("coverage")
            if (
                not isinstance(actual_coverage, dict)
                or canonical_json_sha256(actual_coverage)
                != canonical_json_sha256(expected_final_coverage)
            ):
                errors.append(
                    "avcs_card_coverage_semantics_mismatch:"
                    f"{card_sample_id}:{distribution}:"
                    f"{vulnerability_id}"
                )

            vulnerability = vulnerabilities.get(
                vulnerability_id, {}
            )
            expected_severity = (
                vulnerability.get("severity", [])
                or "not_calibrated"
            )
            if card.get("severity") != expected_severity:
                errors.append(
                    "avcs_card_vulnerability_severity_mismatch:"
                    f"{card_sample_id}:{distribution}:"
                    f"{vulnerability_id}"
                )

            evidence = (
                card.get("evidence")
                if isinstance(card.get("evidence"), dict)
                else {}
            )
            if evidence.get(
                "vulnerability_source_refs", []
            ) != vulnerability.get("source_refs", []):
                errors.append(
                    "avcs_card_vulnerability_evidence_mismatch:"
                    f"{card_sample_id}:{distribution}:"
                    f"{vulnerability_id}"
                )

            if not _repair_contains_expected(
                card.get("repair"),
                finding.get("repair"),
            ):
                errors.append(
                    "avcs_card_repair_mismatch:"
                    f"{card_sample_id}:{distribution}:"
                    f"{vulnerability_id}"
                )

            introduced = (
                card.get("introduced_by")
                if isinstance(
                    card.get("introduced_by"), dict
                )
                else {}
            )
            try:
                (
                    expected_introduced,
                    expected_basis,
                    expected_evidence_key,
                    expected_candidates,
                ) = _scientific_expected_avcs_attribution(
                    actionability=str(
                        finding.get("actionability") or ""
                    ),
                    distribution=str(
                        analysis.get("distribution")
                        or distribution
                    ),
                    api_constraints=api_constraints,
                    manifest=manifest_constraints,
                )
            except ValueError as exc:
                errors.append(
                    "avcs_card_causal_attribution_unresolved:"
                    f"{card_sample_id}:{distribution}:"
                    f"{vulnerability_id}:{exc}"
                )
                continue

            for field, expected in (
                expected_introduced.items()
            ):
                if introduced.get(field) != expected:
                    errors.append(
                        "avcs_card_location_mismatch:"
                        f"{card_sample_id}:{distribution}:"
                        f"{vulnerability_id}:{field}:"
                        f"{introduced.get(field)!r}!="
                        f"{expected!r}"
                    )

            evidence = (
                card.get("evidence")
                if isinstance(card.get("evidence"), dict)
                else {}
            )
            attribution = (
                evidence.get("causal_attribution")
                if isinstance(
                    evidence.get("causal_attribution"), dict
                )
                else {}
            )
            if attribution.get("attribution_basis") != expected_basis:
                errors.append(
                    "avcs_card_attribution_basis_mismatch:"
                    f"{card_sample_id}:{distribution}:"
                    f"{vulnerability_id}:"
                    f"{attribution.get('attribution_basis')!r}!="
                    f"{expected_basis!r}"
                )

            primary_location = (
                attribution.get("primary_causal_location")
                if isinstance(
                    attribution.get("primary_causal_location"),
                    dict,
                )
                else {}
            )
            for field, expected in expected_introduced.items():
                if primary_location.get(field) != expected:
                    errors.append(
                        "avcs_card_primary_causal_location_mismatch:"
                        f"{card_sample_id}:{distribution}:"
                        f"{vulnerability_id}:{field}:"
                        f"{primary_location.get(field)!r}!="
                        f"{expected!r}"
                    )

            actual_candidates = attribution.get(
                expected_evidence_key
            )
            if (
                not isinstance(actual_candidates, list)
                or canonical_json_sha256(actual_candidates)
                != canonical_json_sha256(expected_candidates)
            ):
                errors.append(
                    "avcs_card_causal_source_set_mismatch:"
                    f"{card_sample_id}:{distribution}:"
                    f"{vulnerability_id}:{expected_evidence_key}"
                )

    for card in unified_cards:
        if card.get("pipeline_origin") != "AVCS":
            continue

        source_ids = (
            card.get("source_risk_ids")
            if isinstance(
                card.get("source_risk_ids"), list
            )
            else []
        )
        if not source_ids:
            representative = str(
                card.get("source_risk_id") or ""
            ).strip()
            if representative:
                source_ids = [representative]

        raw_sources: list[dict[str, Any]] = []
        missing_source = False
        for source_id in source_ids:
            raw_card = raw_cards_by_source_id.get(
                str(source_id)
            )
            if raw_card is None:
                errors.append(
                    "avcs_unified_source_card_missing:"
                    f"{source_id}"
                )
                missing_source = True
                continue
            raw_sources.append(raw_card)
        if missing_source or not raw_sources:
            continue

        actual_source_cards = (
            card.get("source_cards")
            if isinstance(card.get("source_cards"), list)
            else []
        )
        if {
            canonical_json_sha256(row)
            for row in actual_source_cards
            if isinstance(row, dict)
        } != {
            canonical_json_sha256(row)
            for row in raw_sources
        }:
            errors.append(
                "avcs_unified_source_cards_drift:"
                f"{card.get('risk_identity')}"
            )
            continue

        view = (
            card.get("time_view")
            if isinstance(card.get("time_view"), dict)
            else {}
        )
        uncertainty = view.get(
            "generation_time_uncertainty_seconds"
        )
        normalized_sources = [
            normalize_risk_card(
                raw_card,
                pipeline_origin="AVCS",
                generation_time_uncertainty_seconds=(
                    float(uncertainty)
                    if uncertainty is not None
                    else None
                ),
            )
            for raw_card in raw_sources
        ]
        expected_cards = deduplicate_cards(
            normalized_sources
        )
        if len(expected_cards) != 1:
            errors.append(
                "avcs_unified_aggregation_identity_split:"
                f"{card.get('risk_identity')}"
            )
            continue
        expected = expected_cards[0]
        if canonical_json_sha256(card) != (
            canonical_json_sha256(expected)
        ):
            errors.append(
                "avcs_unified_normalization_mismatch:"
                f"{card.get('risk_identity')}"
            )

    return errors


def _sceg_risk_link_check(ir: dict[str, Any]) -> tuple[bool, list[str]]:
    nodes = {
        str(row.get("node_id")): row
        for row in ir.get("nodes", [])
        if isinstance(row, dict)
    }
    incoming: dict[str, list[dict[str, Any]]] = {}
    for edge in ir.get("edges", []):
        if not isinstance(edge, dict):
            continue
        if edge.get("type") == "derives_risk":
            incoming.setdefault(str(edge.get("target")), []).append(edge)

    errors: list[str] = []
    for risk_id, risk in nodes.items():
        if risk.get("type") != "Risk":
            continue
        links = incoming.get(risk_id, [])
        if len(links) != 1:
            errors.append(
                f"{risk_id}:expected_one_derives_risk_got_{len(links)}"
            )
            continue
        source = nodes.get(str(links[0].get("source")))
        if source is None:
            errors.append(f"{risk_id}:source_missing")
            continue

        payload = risk.get("payload") or {}
        card = payload.get("risk_card")
        if not isinstance(card, dict):
            errors.append(f"{risk_id}:risk_card_missing")
            continue
        introduced = card.get("introduced_by")
        if not isinstance(introduced, dict):
            introduced = {}
        line = introduced.get("line")
        source_line = (source.get("location") or {}).get("line")
        if line is not None and source_line != line:
            errors.append(
                f"{risk_id}:location_line_mismatch:{line}!={source_line}"
            )

    return not errors, errors


def evaluate_avcs_method_coverage(
    *,
    avcs_dir: Path,
    expected_samples: int,
    require_avcs_method: bool = True,
    require_frozen_release_snapshot: bool = False,
    expected_release_snapshot: dict[str, Any] | None = None,
    coverage_acceptance_rule: dict[str, Any] | None = None,
    require_coverage_acceptance_rule: bool = False,
) -> tuple[bool, dict[str, Any]]:
    """Evaluate whether AVCS actually reached a scientifically usable path.

    A package analysis is not sufficient by itself. At least one package must
    have knowledge complete to the requested time when AVCS method coverage is
    required. A time-complete analysis with no formal-positive Risk Card is a
    valid negative method outcome and must not be forced positive.
    """
    sample_root = avcs_dir / "samples"
    avcs_dirs = (
        sorted(
            path
            for path in sample_root.iterdir()
            if path.is_dir()
        )
        if sample_root.exists()
        else []
    )

    errors: list[str] = []
    package_analysis_count = 0
    samples_with_supported_package = 0
    samples_without_supported_package = 0
    time_complete_analyses = 0
    time_incomplete_analyses = 0
    time_complete_formal_positive_analyses = 0
    time_complete_no_formal_positive_analyses = 0
    unsupported_candidate_count = 0
    dependency_candidate_count = 0
    in_scope_candidate_count = 0
    out_of_scope_candidate_count = 0
    dependency_candidate_sample_count = 0
    in_scope_sample_count = 0
    out_of_scope_only_sample_count = 0
    in_scope_non_metric_sample_count = 0
    package_outcomes: list[dict[str, Any]] = []
    sample_outcomes: list[dict[str, Any]] = []
    coverage_records: list[dict[str, Any]] = []
    coverage_outcome_counts: dict[str, int] = {}
    audit_drift_metric_outcome_counts: dict[str, int] = {}
    formal_metric_eligible_count = 0
    audit_drift_metric_eligible_count = 0
    formal_metric_eligible_sample_count = 0
    audit_drift_metric_eligible_sample_count = 0
    explicit_no_candidate_sample_count = 0
    insufficient_sample_count = 0
    syntax_unavailable_sample_count = 0
    analysis_support_state_counts: dict[str, int] = {}
    coverage_acceptance_errors: list[str] = []

    accepted_rule: dict[str, Any] | None = None
    accepted_rule_schema: str | None = None
    if coverage_acceptance_rule is not None:
        if not isinstance(coverage_acceptance_rule, dict):
            coverage_acceptance_errors.append(
                "coverage_acceptance_rule_invalid"
            )
        else:
            accepted_rule_schema = str(
                coverage_acceptance_rule.get("schema_version") or ""
            )
            if accepted_rule_schema not in {
                "avcs_coverage_acceptance_v1",
                "avcs_coverage_acceptance_v2",
            }:
                coverage_acceptance_errors.append(
                    "coverage_acceptance_rule_schema"
                )
            else:
                accepted_rule = coverage_acceptance_rule

        if accepted_rule is not None and accepted_rule_schema == (
            "avcs_coverage_acceptance_v1"
        ):
            required_boolean_fields = (
                "require_explicit_outcome_per_sample",
                "allow_no_avcs_candidate_samples",
                "candidate_sample_requires_metric_eligible_outcome",
            )
            for field in required_boolean_fields:
                if not isinstance(accepted_rule.get(field), bool):
                    coverage_acceptance_errors.append(
                        f"coverage_acceptance_rule_field:{field}"
                    )
            minimum = accepted_rule.get(
                "minimum_formal_metric_eligible_samples"
            )
            if not isinstance(minimum, int) or minimum < 1:
                coverage_acceptance_errors.append(
                    "coverage_acceptance_rule_field:"
                    "minimum_formal_metric_eligible_samples"
                )

        if accepted_rule is not None and accepted_rule_schema == (
            "avcs_coverage_acceptance_v2"
        ):
            required_boolean_fields = (
                "require_explicit_outcome_per_sample",
                "allow_no_dependency_candidate_samples",
                "allow_out_of_curated_scope_only_samples",
                "in_scope_missing_method_support_is_contract_failure",
                "in_scope_unknown_review_is_valid_non_metric_outcome",
                "metric_evaluability_is_measurement_not_correctness",
                "out_of_curated_scope_is_not_negative",
            )
            for field in required_boolean_fields:
                if accepted_rule.get(field) is not True:
                    coverage_acceptance_errors.append(
                        f"coverage_acceptance_rule_field:{field}"
                    )
    elif require_coverage_acceptance_rule:
        coverage_acceptance_errors.append(
            "formal_coverage_acceptance_rule_missing"
        )

    expected_snapshot_path: str | None = None
    expected_snapshot_sha256: str | None = None
    if expected_release_snapshot is not None:
        if not isinstance(expected_release_snapshot, dict):
            errors.append("expected_release_snapshot_invalid")
        else:
            expected_snapshot_path = str(
                expected_release_snapshot.get("path") or ""
            ).strip() or None
            expected_hash = expected_release_snapshot.get("hash")
            if isinstance(expected_hash, dict):
                expected_snapshot_sha256 = str(
                    expected_hash.get("sha256") or ""
                ).strip() or None
            if (
                require_frozen_release_snapshot
                and (
                    expected_snapshot_path is None
                    or expected_snapshot_sha256 is None
                )
            ):
                errors.append(
                    "formal_expected_release_snapshot_binding_incomplete"
                )
    elif require_frozen_release_snapshot:
        errors.append("formal_expected_release_snapshot_missing")

    if len(avcs_dirs) != expected_samples:
        errors.append(
            f"sample_dir_count:{len(avcs_dirs)}!={expected_samples}"
        )

    for sample_dir in avcs_dirs:
        manifest_path = sample_dir / "manifest.json"
        if not manifest_path.exists():
            errors.append(f"{sample_dir.name}:manifest_missing")
            continue
        manifest = read_json(manifest_path)

        coverage_path = sample_dir / "coverage_outcomes.jsonl"
        if not coverage_path.exists():
            errors.append(
                f"{sample_dir.name}:coverage_outcomes_missing"
            )
            coverage_rows: list[dict[str, Any]] = []
        else:
            raw_coverage_rows = read_jsonl(coverage_path)
            coverage_rows = []
            for coverage_row in raw_coverage_rows:
                if coverage_row.get("sample_id") != sample_dir.name:
                    errors.append(
                        f"{sample_dir.name}:coverage_sample_id_mismatch"
                    )
                    continue
                outcome = str(
                    coverage_row.get("main_metric_outcome") or ""
                )
                if not outcome:
                    errors.append(
                        f"{sample_dir.name}:coverage_outcome_missing"
                    )
                    continue
                try:
                    validate_coverage_metric_authority(coverage_row)
                except (TypeError, ValueError) as exc:
                    errors.append(
                        f"{sample_dir.name}:coverage_metric_authority:"
                        f"{exc}"
                    )
                    continue
                coverage_rows.append(coverage_row)
                coverage_outcome_counts[outcome] = (
                    coverage_outcome_counts.get(outcome, 0) + 1
                )
                if coverage_row.get("main_metric_eligible") is True:
                    formal_metric_eligible_count += 1
                audit_metric = coverage_row.get("audit_drift_metric")
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
                coverage_records.append(
                    {
                        "sample_id": sample_dir.name,
                        "distribution": coverage_row.get("distribution"),
                        "support_status": coverage_row.get("support_status"),
                        "coverage": project_avcs_final_output_coverage(
                            coverage_row
                        ),
                    }
                )

        for error in _verify_avcs_manifest_hash_closure(manifest):
            errors.append(
                f"{sample_dir.name}:hash_closure:{error}"
            )

        if manifest.get("schema_version") != "step8_unified_avcs_run_v0.3":
            errors.append(
                f"{sample_dir.name}:manifest_schema"
            )
        if manifest.get("sample_id") != sample_dir.name:
            errors.append(
                f"{sample_dir.name}:sample_id_mismatch"
            )
        if manifest.get("api_parse_status") in {
            None,
            "",
            "unknown",
            "error",
            "failed",
        }:
            errors.append(
                f"{sample_dir.name}:api_parse_status"
            )

        if require_frozen_release_snapshot:
            manifest_snapshot_path = str(
                manifest.get("release_snapshot_manifest_file") or ""
            ).strip()
            manifest_snapshot_sha = str(
                manifest.get("release_snapshot_manifest_sha256") or ""
            ).strip()
            if not manifest_snapshot_path or not manifest_snapshot_sha:
                errors.append(
                    f"{sample_dir.name}:formal_release_snapshot_missing"
                )
            if (
                expected_snapshot_path is not None
                and manifest_snapshot_path != expected_snapshot_path
            ):
                errors.append(
                    f"{sample_dir.name}:release_snapshot_path_mismatch"
                )
            if (
                expected_snapshot_sha256 is not None
                and manifest_snapshot_sha != expected_snapshot_sha256
            ):
                errors.append(
                    f"{sample_dir.name}:release_snapshot_hash_mismatch"
                )

        package_count = int(
            manifest.get("package_analysis_count", 0) or 0
        )
        packages = manifest.get("packages")
        if not isinstance(packages, list) or len(packages) != package_count:
            errors.append(
                f"{sample_dir.name}:package_count_mismatch"
            )
            continue

        package_analysis_count += package_count
        if package_count > 0:
            samples_with_supported_package += 1
        else:
            samples_without_supported_package += 1

        unsupported_candidates = manifest.get(
            "unsupported_candidate_distributions", []
        )
        if not isinstance(unsupported_candidates, list):
            unsupported_candidates = []
            errors.append(
                f"{sample_dir.name}:unsupported_candidate_list_invalid"
            )
        unsupported_candidate_count += len(unsupported_candidates)
        unsupported_rows = {
            str(row.get("distribution") or "").strip().lower()
            for row in coverage_rows
            if row.get("support_status")
            in {"unsupported", "unsupported_in_scope"}
        }
        for distribution in unsupported_candidates:
            normalized_unsupported = str(distribution).strip().lower()
            if normalized_unsupported not in unsupported_rows:
                errors.append(
                    f"{sample_dir.name}:{normalized_unsupported}:"
                    "unsupported_coverage_missing"
                )

        dependency_candidates = manifest.get(
            "dependency_candidate_distributions"
        )
        in_scope_candidates = manifest.get(
            "in_curated_scope_candidate_distributions"
        )
        out_of_scope_candidates = manifest.get(
            "out_of_curated_scope_candidate_distributions"
        )

        has_r5_scope_fields = all(
            isinstance(value, list)
            for value in (
                dependency_candidates,
                in_scope_candidates,
                out_of_scope_candidates,
            )
        )
        if accepted_rule_schema == "avcs_coverage_acceptance_v2":
            if not has_r5_scope_fields:
                errors.append(
                    f"{sample_dir.name}:r5_scope_manifest_fields_missing"
                )
                dependency_candidates = []
                in_scope_candidates = []
                out_of_scope_candidates = []
        if has_r5_scope_fields:
            dependency_set = {
                pep503_normalize(str(value))
                for value in dependency_candidates
                if str(value).strip()
            }
            in_scope_set = {
                pep503_normalize(str(value))
                for value in in_scope_candidates
                if str(value).strip()
            }
            out_of_scope_set = {
                pep503_normalize(str(value))
                for value in out_of_scope_candidates
                if str(value).strip()
            }
            if in_scope_set & out_of_scope_set:
                errors.append(
                    f"{sample_dir.name}:curated_scope_partition_overlap"
                )
            if dependency_set != (in_scope_set | out_of_scope_set):
                errors.append(
                    f"{sample_dir.name}:curated_scope_partition_incomplete"
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

            out_of_scope_rows = {
                pep503_normalize(str(row.get("distribution") or ""))
                for row in coverage_rows
                if row.get("support_status") == "out_of_curated_scope"
                and row.get("main_metric_outcome")
                == "out_of_curated_scope"
                and row.get("main_metric_eligible") is False
                and row.get("formal_positive") is False
            }
            if out_of_scope_rows != out_of_scope_set:
                errors.append(
                    f"{sample_dir.name}:out_of_scope_coverage_mismatch"
                )

            supported_rows = {
                pep503_normalize(str(row.get("distribution") or ""))
                for row in coverage_rows
                if row.get("support_status") == "supported"
            }
            if (supported_rows | unsupported_rows) != in_scope_set:
                errors.append(
                    f"{sample_dir.name}:in_scope_coverage_mismatch"
                )

        generation_formal_positive_packages: set[str] = set()
        audit_drift_formal_positive_packages: set[str] = set()
        risk_cards_path = sample_dir / "risk_cards.jsonl"
        if risk_cards_path.exists():
            for card in read_jsonl(risk_cards_path):
                risk_type = str(card.get("type") or "")
                if risk_type not in FORMAL_MAIN_RISK_TYPES:
                    continue
                if (
                    card.get("channel") != "formal"
                    or card.get("formal_eligible") is not True
                ):
                    continue
                package = str(
                    card.get("normalized_distribution")
                    or card.get("distribution")
                    or card.get("package")
                    or ""
                ).strip().lower()
                evaluation_time_view = card.get("evaluation_time_view")
                try:
                    authorized = avcs_formal_risk_view_eligible(
                        risk_type,
                        evaluation_time_view,
                    )
                except (TypeError, ValueError):
                    authorized = False
                if not authorized:
                    errors.append(
                        f"{sample_dir.name}:{package}:"
                        f"formal_card_time_view_unauthorized:{risk_type}"
                    )
                    continue
                if not package:
                    continue
                if risk_type == "api_induced_vulnerable_dependency":
                    generation_formal_positive_packages.add(package)
                elif risk_type == "temporal_drift":
                    audit_drift_formal_positive_packages.add(package)

        sample_package_outcomes: list[dict[str, Any]] = []
        for package in packages:
            if not isinstance(package, dict):
                errors.append(
                    f"{sample_dir.name}:package_summary_invalid"
                )
                continue

            distribution = str(
                package.get("normalized_distribution")
                or package.get("distribution")
                or ""
            ).strip().lower()
            coverage = package.get("coverage")
            if not isinstance(coverage, dict):
                errors.append(
                    f"{sample_dir.name}:{distribution}:coverage_missing"
                )
                coverage = {}
            coverage_outcome = str(
                coverage.get("main_metric_outcome") or ""
            )
            try:
                validate_coverage_metric_authority(coverage)
            except (TypeError, ValueError) as exc:
                errors.append(
                    f"{sample_dir.name}:{distribution}:"
                    f"coverage_metric_authority:{exc}"
                )
                continue
            if coverage_outcome not in {
                "formal_positive",
                "formal_negative",
                "auxiliary_only",
                "unknown_review",
                "syntax_unavailable",
            }:
                errors.append(
                    f"{sample_dir.name}:{distribution}:"
                    f"coverage_outcome_invalid:{coverage_outcome}"
                )
            blocking_reasons = coverage.get(
                "blocking_unknown_reasons", []
            )
            if not isinstance(blocking_reasons, list):
                errors.append(
                    f"{sample_dir.name}:{distribution}:"
                    "coverage_blockers_invalid"
                )
                blocking_reasons = []

            supported_coverage_rows = [
                row
                for row in coverage_rows
                if row.get("support_status") == "supported"
                and str(row.get("distribution") or "").strip().lower()
                == distribution
            ]
            if len(supported_coverage_rows) != 1:
                errors.append(
                    f"{sample_dir.name}:{distribution}:"
                    "supported_coverage_row_count"
                )

            analysis_text = str(
                package.get("analysis_file") or ""
            ).strip()
            if not analysis_text:
                errors.append(
                    f"{sample_dir.name}:analysis_file_missing"
                )
                continue
            analysis_path = ROOT / analysis_text
            if not analysis_path.exists():
                errors.append(
                    f"{sample_dir.name}:analysis_not_found:{analysis_text}"
                )

            snapshot_bound = (
                package.get("source_release_snapshot_manifest_bound")
                is True
            )
            if require_frozen_release_snapshot and not snapshot_bound:
                errors.append(
                    f"{sample_dir.name}:{distribution}:"
                    "release_snapshot_not_bound"
                )

            time_complete = (
                package.get("knowledge_complete_to_requested_time")
                is True
            )
            generation_formal_positive = (
                bool(distribution)
                and distribution in generation_formal_positive_packages
            )
            audit_drift_formal_positive = (
                bool(distribution)
                and distribution in audit_drift_formal_positive_packages
            )

            if (
                coverage.get("formal_positive")
                is not generation_formal_positive
            ):
                errors.append(
                    f"{sample_dir.name}:{distribution}:"
                    "coverage_formal_positive_mismatch"
                )
            generation_metric = coverage.get("generation_metric")
            if isinstance(generation_metric, dict) and (
                generation_metric.get("channel") != "generation_time"
                or generation_metric.get("outcome") != coverage_outcome
                or generation_metric.get("eligible")
                is not coverage.get("main_metric_eligible")
                or generation_metric.get("formal_positive")
                is not coverage.get("formal_positive")
            ):
                errors.append(
                    f"{sample_dir.name}:{distribution}:"
                    "generation_metric_inconsistent"
                )
            if (
                coverage_outcome == "formal_positive"
                and not generation_formal_positive
            ):
                errors.append(
                    f"{sample_dir.name}:{distribution}:"
                    "positive_outcome_without_formal_card"
                )
            audit_metric = coverage.get("audit_drift_metric")
            if audit_drift_formal_positive and not isinstance(
                audit_metric, dict
            ):
                errors.append(
                    f"{sample_dir.name}:{distribution}:"
                    "audit_drift_metric_missing"
                )
                audit_metric = {}
            if isinstance(audit_metric, dict):
                if audit_metric.get("channel") != "audit_time":
                    errors.append(
                        f"{sample_dir.name}:{distribution}:"
                        "audit_drift_metric_channel"
                    )
                if not isinstance(audit_metric.get("eligible"), bool):
                    errors.append(
                        f"{sample_dir.name}:{distribution}:"
                        "audit_drift_metric_eligibility"
                    )
                if not isinstance(
                    audit_metric.get("formal_positive"), bool
                ):
                    errors.append(
                        f"{sample_dir.name}:{distribution}:"
                        "audit_drift_metric_formal_positive_type"
                    )
                elif (
                    audit_metric.get("formal_positive")
                    is not audit_drift_formal_positive
                ):
                    errors.append(
                        f"{sample_dir.name}:{distribution}:"
                        "audit_drift_formal_positive_mismatch"
                    )
                audit_outcome = str(audit_metric.get("outcome") or "")
                if (
                    (audit_outcome == "formal_positive")
                    is not (
                        audit_metric.get("formal_positive") is True
                    )
                ):
                    errors.append(
                        f"{sample_dir.name}:{distribution}:"
                        "audit_drift_outcome_positive_mismatch"
                    )
                if audit_metric.get("eligible") is True:
                    evaluation_time_view = coverage.get(
                        "evaluation_time_view"
                    )
                    try:
                        audit_view_authorized = (
                            avcs_formal_risk_view_eligible(
                                "temporal_drift",
                                evaluation_time_view,
                            )
                        )
                    except (TypeError, ValueError):
                        audit_view_authorized = False
                    if (
                        not audit_view_authorized
                        or audit_outcome
                        not in {"formal_positive", "formal_negative"}
                    ):
                        errors.append(
                            f"{sample_dir.name}:{distribution}:"
                            "audit_drift_metric_unauthorized"
                        )
                if audit_drift_formal_positive and (
                    audit_metric.get("outcome") != "formal_positive"
                    or audit_metric.get("eligible") is not True
                    or coverage.get("main_metric_eligible") is not False
                    or coverage.get("formal_positive") is not False
                ):
                    errors.append(
                        f"{sample_dir.name}:{distribution}:"
                        "audit_drift_denominator_isolation"
                    )
            if coverage_outcome == "formal_negative":
                if not time_complete:
                    errors.append(
                        f"{sample_dir.name}:{distribution}:"
                        "formal_negative_time_incomplete"
                    )
                if blocking_reasons:
                    errors.append(
                        f"{sample_dir.name}:{distribution}:"
                        "formal_negative_has_unknown_blockers"
                    )
                if coverage.get("main_metric_eligible") is not True:
                    errors.append(
                        f"{sample_dir.name}:{distribution}:"
                        "formal_negative_not_metric_eligible"
                    )
            if (
                coverage_outcome
                in {
                    "unknown_review",
                    "auxiliary_only",
                    "syntax_unavailable",
                }
                and coverage.get("main_metric_eligible") is True
            ):
                errors.append(
                    f"{sample_dir.name}:{distribution}:"
                    "nonformal_coverage_marked_metric_eligible"
                )
            if (
                coverage_outcome == "unknown_review"
                and not blocking_reasons
            ):
                errors.append(
                    f"{sample_dir.name}:{distribution}:"
                    "unknown_review_without_reason"
                )
            if coverage_outcome == "syntax_unavailable":
                if "syntax_unavailable" not in blocking_reasons:
                    errors.append(
                        f"{sample_dir.name}:{distribution}:"
                        "syntax_unavailable_without_reason"
                    )
                if coverage.get("main_metric_eligible") is not False:
                    errors.append(
                        f"{sample_dir.name}:{distribution}:"
                        "syntax_unavailable_metric_eligible"
                    )
                if coverage.get("formal_positive") is not False:
                    errors.append(
                        f"{sample_dir.name}:{distribution}:"
                        "syntax_unavailable_formal_positive"
                    )

            if time_complete:
                time_complete_analyses += 1
                if generation_formal_positive:
                    time_complete_formal_positive_analyses += 1
                    time_outcome = "time_complete_formal_positive"
                else:
                    time_complete_no_formal_positive_analyses += 1
                    time_outcome = "time_complete_no_formal_positive"
            else:
                time_incomplete_analyses += 1
                time_outcome = "time_incomplete"

            row = {
                "sample_id": sample_dir.name,
                "distribution": distribution,
                "outcome": time_outcome,
                "knowledge_complete_to_requested_time": time_complete,
                "formal_positive": generation_formal_positive,
                "audit_drift_formal_positive": (
                    audit_drift_formal_positive
                ),
                "release_snapshot_bound": snapshot_bound,
                "coverage_outcome": coverage_outcome,
                "main_metric_eligible": (
                    coverage.get("main_metric_eligible") is True
                ),
                "blocking_unknown_reasons": list(blocking_reasons),
                "coverage": project_avcs_final_output_coverage(
                    {
                        "support_status": "supported",
                        **json.loads(json.dumps(coverage)),
                    }
                ),
            }
            package_outcomes.append(row)
            sample_package_outcomes.append(row)

        unsupported_count = len(unsupported_candidates)
        candidate_count = package_count + unsupported_count
        sample_eligible_count = sum(
            1
            for row in coverage_rows
            if row.get("main_metric_eligible") is True
        )
        sample_audit_drift_eligible_count = sum(
            1
            for row in coverage_rows
            if isinstance(row.get("audit_drift_metric"), dict)
            and row["audit_drift_metric"].get("eligible") is True
        )
        sample_authorized_metric_count = (
            sample_eligible_count
            + sample_audit_drift_eligible_count
        )
        no_candidate_rows = [
            row
            for row in coverage_rows
            if row.get("main_metric_outcome") == "no_avcs_candidate"
            and row.get("support_status") == "not_applicable"
        ]

        sample_has_syntax_unavailable = any(
            row.get("main_metric_outcome") == "syntax_unavailable"
            and row.get("main_metric_eligible") is False
            for row in coverage_rows
        )

        if accepted_rule_schema == "avcs_coverage_acceptance_v2":
            dependency_set = (
                {
                    pep503_normalize(str(value))
                    for value in dependency_candidates
                    if str(value).strip()
                }
                if isinstance(dependency_candidates, list)
                else set()
            )
            in_scope_set = (
                {
                    pep503_normalize(str(value))
                    for value in in_scope_candidates
                    if str(value).strip()
                }
                if isinstance(in_scope_candidates, list)
                else set()
            )
            out_of_scope_set = (
                {
                    pep503_normalize(str(value))
                    for value in out_of_scope_candidates
                    if str(value).strip()
                }
                if isinstance(out_of_scope_candidates, list)
                else set()
            )

            if not dependency_set:
                sample_scope_status = "no_dependency_candidate"
                sample_metric_status = "not_applicable"
                sample_method_outcome = "no_dependency_candidate"
                analysis_support_state = "no_avcs_candidate"
            elif not in_scope_set and out_of_scope_set:
                sample_scope_status = "out_of_curated_scope_only"
                sample_metric_status = "not_applicable"
                sample_method_outcome = "out_of_curated_scope_only"
                analysis_support_state = "out_of_curated_scope"
            else:
                sample_scope_status = "has_in_scope_candidate"
                if sample_authorized_metric_count > 0:
                    sample_metric_status = "metric_eligible"
                    sample_method_outcome = "formal_metric_eligible"
                    analysis_support_state = "metric_eligible"
                    if sample_eligible_count > 0:
                        formal_metric_eligible_sample_count += 1
                    if sample_audit_drift_eligible_count > 0:
                        audit_drift_metric_eligible_sample_count += 1
                else:
                    sample_metric_status = "non_metric"
                    sample_method_outcome = "in_scope_non_metric"
                    if sample_has_syntax_unavailable:
                        analysis_support_state = "syntax_unavailable"
                        syntax_unavailable_sample_count += 1
                    else:
                        analysis_support_state = (
                            "insufficient_method_coverage"
                        )
                        insufficient_sample_count += 1
                    in_scope_non_metric_sample_count += 1

            if (
                accepted_rule.get("require_explicit_outcome_per_sample")
                is True
                and not coverage_rows
            ):
                coverage_acceptance_errors.append(
                    f"{sample_dir.name}:explicit_coverage_outcome_missing"
                )
            if (
                sample_scope_status == "no_dependency_candidate"
                and accepted_rule.get(
                    "allow_no_dependency_candidate_samples"
                )
                is not True
            ):
                coverage_acceptance_errors.append(
                    f"{sample_dir.name}:no_dependency_candidate_not_allowed"
                )
            if (
                sample_scope_status == "out_of_curated_scope_only"
                and accepted_rule.get(
                    "allow_out_of_curated_scope_only_samples"
                )
                is not True
            ):
                coverage_acceptance_errors.append(
                    f"{sample_dir.name}:out_of_curated_scope_only_not_allowed"
                )
            if (
                unsupported_count > 0
                and accepted_rule.get(
                    "in_scope_missing_method_support_is_contract_failure"
                )
                is True
            ):
                coverage_acceptance_errors.append(
                    f"{sample_dir.name}:in_scope_package_missing_method_support"
                )
            if (
                sample_has_syntax_unavailable
                and accepted_rule.get(
                    "in_scope_syntax_unavailable_is_valid_non_metric_outcome"
                )
                is not True
            ):
                coverage_acceptance_errors.append(
                    f"{sample_dir.name}:syntax_unavailable_not_authorized_"
                    "by_frozen_protocol"
                )
        else:
            sample_scope_status = None
            sample_metric_status = None
            if candidate_count == 0 and len(no_candidate_rows) == 1:
                sample_method_outcome = "no_avcs_candidate"
                analysis_support_state = "no_avcs_candidate"
                explicit_no_candidate_sample_count += 1
            elif sample_eligible_count > 0:
                sample_method_outcome = "formal_metric_eligible"
                analysis_support_state = "metric_eligible"
                formal_metric_eligible_sample_count += 1
            elif sample_audit_drift_eligible_count > 0:
                sample_method_outcome = "audit_drift_metric_eligible"
                analysis_support_state = "metric_eligible"
                audit_drift_metric_eligible_sample_count += 1
            elif sample_has_syntax_unavailable:
                sample_method_outcome = "syntax_unavailable"
                analysis_support_state = "syntax_unavailable"
                syntax_unavailable_sample_count += 1
            else:
                sample_method_outcome = "insufficient_method_coverage"
                analysis_support_state = "insufficient_method_coverage"
                insufficient_sample_count += 1

            if accepted_rule is not None:
                if (
                    accepted_rule.get("require_explicit_outcome_per_sample")
                    is True
                    and not coverage_rows
                ):
                    coverage_acceptance_errors.append(
                        f"{sample_dir.name}:explicit_coverage_outcome_missing"
                    )
                if (
                    candidate_count == 0
                    and sample_method_outcome == "no_avcs_candidate"
                    and accepted_rule.get(
                        "allow_no_avcs_candidate_samples"
                    )
                    is not True
                ):
                    coverage_acceptance_errors.append(
                        f"{sample_dir.name}:no_avcs_candidate_not_allowed"
                    )
                if (
                    candidate_count > 0
                    and accepted_rule.get(
                        "candidate_sample_requires_metric_eligible_outcome"
                    )
                    is True
                    and sample_eligible_count == 0
                ):
                    coverage_acceptance_errors.append(
                        f"{sample_dir.name}:candidate_sample_has_no_"
                        "metric_eligible_outcome"
                    )

        analysis_support_state_counts[analysis_support_state] = (
            analysis_support_state_counts.get(analysis_support_state, 0) + 1
        )

        sample_outcomes.append(
            {
                "sample_id": sample_dir.name,
                "analysis_support_state": analysis_support_state,
                "supported_package_count": package_count,
                "unsupported_candidate_count": unsupported_count,
                "candidate_count": candidate_count,
                "dependency_candidate_count": (
                    len(dependency_set)
                    if accepted_rule_schema == "avcs_coverage_acceptance_v2"
                    else None
                ),
                "in_scope_candidate_count": (
                    len(in_scope_set)
                    if accepted_rule_schema == "avcs_coverage_acceptance_v2"
                    else None
                ),
                "out_of_scope_candidate_count": (
                    len(out_of_scope_set)
                    if accepted_rule_schema == "avcs_coverage_acceptance_v2"
                    else None
                ),
                "formal_metric_eligible_package_count": (
                    sample_eligible_count
                ),
                "audit_drift_metric_eligible_package_count": (
                    sample_audit_drift_eligible_count
                ),
                "authorized_metric_eligible_package_count": (
                    sample_authorized_metric_count
                ),
                "scope_status": sample_scope_status,
                "metric_status": sample_metric_status,
                "outcome": sample_method_outcome,
                "packages": sample_package_outcomes,
            }
        )

    if (
        accepted_rule is not None
        and accepted_rule_schema == "avcs_coverage_acceptance_v1"
    ):
        minimum = int(
            accepted_rule.get(
                "minimum_formal_metric_eligible_samples", 1
            )
        )
        if formal_metric_eligible_sample_count < minimum:
            coverage_acceptance_errors.append(
                "formal_metric_eligible_sample_count:"
                f"{formal_metric_eligible_sample_count}<{minimum}"
            )

    errors.extend(coverage_acceptance_errors)

    explicit_syntax_support_accounting_ok = (
        syntax_unavailable_sample_count > 0
        and syntax_unavailable_sample_count == len(avcs_dirs)
        and insufficient_sample_count == 0
    )
    legacy_method_coverage_ok = (
        package_analysis_count > 0
        and (
            time_complete_analyses > 0
            or explicit_syntax_support_accounting_ok
        )
    )
    acceptance_coverage_ok = (
        not coverage_acceptance_errors
        if accepted_rule is not None
        else legacy_method_coverage_ok
    )
    method_coverage_ok = acceptance_coverage_ok
    avcs_method_ok = (
        not errors
        and (
            method_coverage_ok
            if require_avcs_method
            else True
        )
    )
    return avcs_method_ok, {
        "errors": errors,
        "samples_invoked": len(avcs_dirs),
        "samples_with_supported_package": samples_with_supported_package,
        "samples_without_supported_package": samples_without_supported_package,
        "package_analyses": package_analysis_count,
        "time_complete_analyses": time_complete_analyses,
        "time_incomplete_analyses": time_incomplete_analyses,
        "time_complete_formal_positive_analyses": (
            time_complete_formal_positive_analyses
        ),
        "time_complete_no_formal_positive_analyses": (
            time_complete_no_formal_positive_analyses
        ),
        "unsupported_candidate_count": unsupported_candidate_count,
        "dependency_candidate_count": dependency_candidate_count,
        "in_scope_candidate_count": in_scope_candidate_count,
        "out_of_scope_candidate_count": out_of_scope_candidate_count,
        "dependency_candidate_sample_count": dependency_candidate_sample_count,
        "in_scope_sample_count": in_scope_sample_count,
        "out_of_scope_only_sample_count": out_of_scope_only_sample_count,
        "in_scope_non_metric_sample_count": in_scope_non_metric_sample_count,
        "require_nonempty_method": require_avcs_method,
        "require_frozen_release_snapshot": (
            require_frozen_release_snapshot
        ),
        "expected_release_snapshot_path": expected_snapshot_path,
        "expected_release_snapshot_sha256": expected_snapshot_sha256,
        "method_coverage_requires_time_complete_analysis": (
            accepted_rule is None
            and not explicit_syntax_support_accounting_ok
        ),
        "explicit_syntax_support_accounting_can_close_nonmetric_coverage": (
            explicit_syntax_support_accounting_ok
        ),
        "syntax_support_accounting_does_not_create_metric_eligibility": True,
        "zero_formal_positive_is_allowed": True,
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
        "formal_metric_eligible_sample_count": (
            formal_metric_eligible_sample_count
        ),
        "audit_drift_metric_eligible_sample_count": (
            audit_drift_metric_eligible_sample_count
        ),
        "explicit_no_candidate_sample_count": (
            explicit_no_candidate_sample_count
        ),
        "insufficient_sample_count": insufficient_sample_count,
        "insufficient_method_coverage_count": insufficient_sample_count,
        "syntax_unavailable_sample_count": syntax_unavailable_sample_count,
        "analysis_support_state_counts": analysis_support_state_counts,
        "curated_scope_candidate_count": in_scope_candidate_count,
        "metric_eligible_count": formal_metric_eligible_count,
        "coverage_acceptance_rule_required": (
            require_coverage_acceptance_rule
        ),
        "coverage_acceptance_rule": accepted_rule,
        "coverage_acceptance_errors": coverage_acceptance_errors,
        "formal_negative_count": coverage_outcome_counts.get(
            "formal_negative", 0
        ),
        "formal_positive_coverage_count": coverage_outcome_counts.get(
            "formal_positive", 0
        ),
        "unknown_review_count": coverage_outcome_counts.get(
            "unknown_review", 0
        ),
        "auxiliary_only_count": coverage_outcome_counts.get(
            "auxiliary_only", 0
        ),
        "unsupported_coverage_count": coverage_outcome_counts.get(
            "unsupported", 0
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
        "coverage_contract": {
            "absence_of_risk_card_is_not_negative_by_itself": True,
            "formal_negative_requires_time_complete_no_blockers": True,
            "unknown_review_excluded_from_main_denominator": True,
            "syntax_unavailable_excluded_from_main_denominator": True,
            "syntax_unavailable_is_not_negative": True,
            "syntax_unavailable_requires_protocol_authorization_in_formal_v2": (
                accepted_rule_schema == "avcs_coverage_acceptance_v2"
            ),
            "unsupported_excluded_from_main_denominator": True,
            "unsupported_in_scope_excluded_from_main_denominator": True,
            "out_of_curated_scope_excluded_from_main_denominator": True,
            "metric_evaluability_is_measurement_not_correctness": (
                accepted_rule_schema == "avcs_coverage_acceptance_v2"
            ),
            "auxiliary_only_excluded_from_main_metrics": True,
            "audit_drift_metric_is_separate_from_generation_metric": True,
        },
        "sample_outcomes": sample_outcomes,
        "package_outcomes": package_outcomes,
        "coverage_records": coverage_records,
        "run_level_coverage_contract": {
            "schema_version": "avcs_run_level_coverage_contract_v1",
            "records_include_supported_unknown_unsupported_and_not_applicable": True,
            "records_include_curated_package_scope": True,
            "record_coverage_schema": "avcs_final_output_coverage_v1",
            "package_identity_candidate_is_not_avcs_scope_membership": True,
            "selected_scope_is_not_package_wide": True,
            "unknown_is_not_false": True,
            "syntax_unavailable_is_not_false": True,
            "generation_metric_requires_as_of_tg": True,
            "audit_drift_metric_requires_as_of_audit": True,
        },
    }




def verify_generation_sidecar_integrity(
    *,
    generation_dir: Path,
    samples: list[dict[str, Any]],
) -> list[str]:
    """Verify immutable generated JSONL/sidecar binding.

    Syntax validity is deliberately not part of this check. Missing, mutated,
    or undecodable sidecars are integrity failures and remain fail-closed.
    """
    errors: list[str] = []
    for row in samples:
        sample_id = str(row.get("sample_id") or "").strip()
        if not sample_id:
            errors.append("blank_sample_id")
            continue

        code_path = generation_dir / "code" / f"{sample_id}.py"
        req_path = (
            generation_dir
            / "requirements"
            / f"{sample_id}_requirements.txt"
        )

        if not code_path.exists():
            errors.append(f"{sample_id}:code_missing")
        else:
            try:
                observed_code = code_path.read_text(
                    encoding="utf-8-sig"
                ).strip()
            except UnicodeDecodeError as exc:
                errors.append(
                    f"{sample_id}:code_decode_error:{exc}"
                )
            else:
                expected_code = str(
                    row.get("generated_code") or ""
                ).strip()
                if observed_code != expected_code:
                    errors.append(
                        f"{sample_id}:code_jsonl_mismatch"
                    )

        if not req_path.exists():
            errors.append(f"{sample_id}:requirements_missing")
        else:
            try:
                observed_requirements = req_path.read_text(
                    encoding="utf-8-sig"
                ).strip()
            except UnicodeDecodeError as exc:
                errors.append(
                    f"{sample_id}:requirements_decode_error:{exc}"
                )
            else:
                expected_requirements = str(
                    row.get("requirements_text") or ""
                ).strip()
                if observed_requirements != expected_requirements:
                    errors.append(
                        f"{sample_id}:requirements_jsonl_mismatch"
                    )
    return errors

def build_generation_parse_accounting(
    *,
    generation_dir: Path,
    sample_ids: list[str],
    expected_samples: int,
) -> tuple[dict[str, Any], list[str]]:
    """Account for syntax support without treating syntax-invalid output as deletion.

    R5-r7 separates immutable generation integrity from Python parseability.
    Every selected sample must receive exactly one parse/support status. A
    syntax-invalid model response remains part of the Real LLM Generation
    population; missing bytes or incomplete accounting remain fatal.
    """
    records: list[dict[str, Any]] = []
    fatal_errors: list[str] = []
    status_counts = {
        "parseable": 0,
        "syntax_invalid": 0,
        "decode_error": 0,
        "integrity_failure": 0,
    }

    if len(sample_ids) != expected_samples:
        fatal_errors.append(
            f"sample_count:{len(sample_ids)}!={expected_samples}"
        )
    if len(set(sample_ids)) != len(sample_ids):
        fatal_errors.append("duplicate_sample_id")
    if any(not sample_id for sample_id in sample_ids):
        fatal_errors.append("blank_sample_id")

    for sample_id in sample_ids:
        code_path = generation_dir / "code" / f"{sample_id}.py"
        diagnostic: dict[str, Any] | None = None
        content_sha256: str | None = None

        if not code_path.exists():
            status = "integrity_failure"
            diagnostic = {
                "error_type": "MissingGeneratedSidecar",
                "message": "generated code sidecar is missing",
            }
            fatal_errors.append(f"{sample_id}:code_missing")
        else:
            raw_bytes = code_path.read_bytes()
            content_sha256 = hashlib.sha256(raw_bytes).hexdigest()
            try:
                source = raw_bytes.decode("utf-8-sig")
            except UnicodeDecodeError as exc:
                status = "decode_error"
                diagnostic = {
                    "error_type": type(exc).__name__,
                    "message": str(exc),
                    "start": exc.start,
                    "end": exc.end,
                }
            else:
                try:
                    ast.parse(source, filename=str(code_path))
                except SyntaxError as exc:
                    status = "syntax_invalid"
                    diagnostic = {
                        "error_type": type(exc).__name__,
                        "message": str(exc.msg),
                        "line": exc.lineno,
                        "offset": exc.offset,
                        "end_line": getattr(exc, "end_lineno", None),
                        "end_offset": getattr(exc, "end_offset", None),
                    }
                else:
                    status = "parseable"

        status_counts[status] += 1
        records.append(
            {
                "sample_id": sample_id,
                "syntax_parse_status": status,
                "content_sha256": content_sha256,
                "parse_diagnostic": diagnostic,
            }
        )

    accounted_ids = [
        str(row.get("sample_id") or "")
        for row in records
    ]
    if accounted_ids != sample_ids:
        fatal_errors.append("parse_accounting_sample_order_or_identity_mismatch")
    if len(records) != expected_samples:
        fatal_errors.append(
            f"parse_accounting_count:{len(records)}!={expected_samples}"
        )

    accounted_total = sum(status_counts.values())
    if accounted_total != len(records):
        fatal_errors.append(
            f"parse_status_count_mismatch:{accounted_total}!={len(records)}"
        )

    generated_response_count = len(records)
    parseable_count = status_counts["parseable"]
    syntax_invalid_count = status_counts["syntax_invalid"]
    decode_error_count = status_counts["decode_error"]
    integrity_failure_count = status_counts["integrity_failure"]
    denominator = generated_response_count or 1

    return (
        {
            "schema_version": "generated_code_parse_accounting_v1",
            "generated_response_count": generated_response_count,
            "syntax_parseable_count": parseable_count,
            "syntax_parseable_rate": parseable_count / denominator,
            "syntax_invalid_count": syntax_invalid_count,
            "syntax_invalid_rate": syntax_invalid_count / denominator,
            "decode_error_count": decode_error_count,
            "integrity_failure_count": integrity_failure_count,
            "all_samples_accounted": (
                generated_response_count == expected_samples
                and accounted_ids == sample_ids
            ),
            "syntax_invalid_is_reportable_not_global_failure": True,
            "decode_error_is_explicitly_accounted": True,
            "silent_drop_forbidden": True,
            "records": records,
        },
        fatal_errors,
    )

def evaluate_scientific_contract(
    *,
    run_dir: Path,
    expected_samples: int,
    require_avcs_method: bool = True,
) -> dict[str, Any]:
    run_dir = run_dir.resolve()
    generation = run_dir / "generation"
    tho = run_dir / "tho"
    cards = run_dir / "risk_cards"
    sceg = run_dir / "sceg"
    avcs = run_dir / "avcs"

    gates: dict[str, dict[str, Any]] = {}

    selected_samples = read_jsonl(
        generation / "generated_samples.jsonl"
    )
    selected_sample_ids = [
        str(row.get("sample_id") or "").strip()
        for row in selected_samples
    ]
    outcome_path = generation / "generation_outcome_manifest.json"
    outcome_manifest: dict[str, Any] | None = None
    statistical_eligibility: dict[str, Any] | None = None

    if outcome_path.is_file():
        try:
            outcome_manifest = read_json(outcome_path)
            validate_manifest_self_consistency(outcome_manifest)
            samples = accepted_rows_from_manifest(
                generated_rows=selected_samples,
                manifest=outcome_manifest,
            )
            statistical_eligibility = (
                evaluate_split_statistical_eligibility(
                    outcome_manifest
                )
            )
            sample_ids = list(
                outcome_manifest.get("accepted_sample_ids") or []
            )
            analysis_expected_samples = len(sample_ids)
            generation_ok = (
                int(outcome_manifest.get("selected_count") or 0)
                == expected_samples
                and bool(outcome_manifest.get("all_selected_accounted"))
                and bool(outcome_manifest.get("all_selected_finalized"))
                and int(outcome_manifest.get("unresolved_count") or 0) == 0
                and outcome_manifest.get("stage_evidence_status")
                in {
                    "FINALIZED_ALL_ACCEPTED",
                    "FINALIZED_WITH_TERMINALS",
                }
                and len(selected_sample_ids) <= expected_samples
                and len(set(selected_sample_ids))
                == len(selected_sample_ids)
                and all(selected_sample_ids)
                and len(samples) == analysis_expected_samples
            )
            generation_detail: Any = {
                "selected_expected": expected_samples,
                "selected_rows_present": len(selected_samples),
                "selected_count": outcome_manifest.get("selected_count"),
                "accepted_complete_count": outcome_manifest.get(
                    "accepted_complete_count"
                ),
                "terminal_count": outcome_manifest.get("terminal_count"),
                "unresolved_count": outcome_manifest.get(
                    "unresolved_count"
                ),
                "stage_evidence_status": outcome_manifest.get(
                    "stage_evidence_status"
                ),
                "analysis_population_count": analysis_expected_samples,
                "outcome_manifest": rel(outcome_path),
                "statistical_eligibility": statistical_eligibility,
                "terminal_is_not_dependency_negative": True,
                "terminal_is_not_dependency_unknown": True,
            }
        except Exception as exc:
            samples = []
            sample_ids = []
            analysis_expected_samples = 0
            generation_ok = False
            generation_detail = {
                "selected_expected": expected_samples,
                "selected_rows_present": len(selected_samples),
                "outcome_manifest": rel(outcome_path),
                "error": f"{type(exc).__name__}:{exc}",
            }
    else:
        samples = selected_samples
        sample_ids = selected_sample_ids
        analysis_expected_samples = expected_samples
        generation_ok = (
            len(samples) == expected_samples
            and len(set(sample_ids)) == expected_samples
            and all(sample_ids)
            and all(
                not str(row.get("generation_error") or "").strip()
                for row in samples
            )
        )
        generation_detail = {
            "expected": expected_samples,
            "actual": len(samples),
            "unique": len(set(sample_ids)),
            "legacy_all_accepted_generation_contract": True,
        }

    _gate(
        gates,
        (
            "generation_identity_and_outcome_accounting"
            if outcome_manifest is not None
            else "generation_identity_and_success"
        ),
        generation_ok,
        generation_detail,
    )

    sidecar_errors = verify_generation_sidecar_integrity(
        generation_dir=generation,
        samples=samples,
    )
    _gate(
        gates,
        "generation_sidecar_integrity",
        not sidecar_errors,
        sidecar_errors,
    )

    parse_accounting, parse_accounting_errors = (
        build_generation_parse_accounting(
            generation_dir=generation,
            sample_ids=sample_ids,
            expected_samples=analysis_expected_samples,
        )
    )
    _gate(
        gates,
        "generated_code_parse_accounting",
        not parse_accounting_errors,
        {
            **parse_accounting,
            "fatal_errors": parse_accounting_errors,
        },
    )

    dep = read_jsonl(tho / "dependency_records.jsonl")
    projected = read_jsonl(
        tho / "dependency_records_from_sceg_v2_1.jsonl"
    )
    temporal = read_jsonl(tho / "temporal_enriched.jsonl")
    reachability = read_jsonl(tho / "reachability_enriched.jsonl")
    dependency_ok = (
        len(dep) > 0
        and len(projected) == len(dep)
        and len(temporal) == len(dep)
        and len(reachability) == len(dep)
    )
    _gate(
        gates,
        "dependency_analysis_nonempty_and_closed",
        dependency_ok,
        {
            "dependency_records": len(dep),
            "projected": len(projected),
            "temporal": len(temporal),
            "reachability": len(reachability),
        },
    )

    analysis_population_set = set(sample_ids)
    dependency_population_errors = sorted(
        {
            str(row.get("sample_id") or "").strip()
            for row in dep
            if str(row.get("sample_id") or "").strip()
            not in analysis_population_set
        }
    )
    _gate(
        gates,
        "dependency_analysis_population_binding",
        not dependency_population_errors,
        {
            "analysis_population_count": len(sample_ids),
            "unexpected_dependency_sample_ids": dependency_population_errors,
            "terminal_generation_outcomes_excluded": (
                outcome_manifest is not None
            ),
        },
    )

    identity_errors: list[str] = []
    for row in dep:
        identity = row.get("package_identity")
        sample_id = str(row.get("sample_id") or "")
        package = str(row.get("package") or "")
        if not isinstance(identity, dict):
            identity_errors.append(f"{sample_id}/{package}:missing")
            continue
        if identity.get("schema_version") != (
            "codesentry_gen_package_identity_record_v1"
        ):
            identity_errors.append(
                f"{sample_id}/{package}:schema"
            )
        if identity.get("policy_version") != "package_identity_v1":
            identity_errors.append(
                f"{sample_id}/{package}:policy"
            )
        normalized = str(
            identity.get("normalized_distribution") or ""
        ).strip()
        if normalized and normalized != package:
            identity_errors.append(
                f"{sample_id}/{package}:distribution_mismatch:{normalized}"
            )
        status = str(identity.get("identity_status") or "")
        if status in {
            "stdlib",
            "local_module",
            "excluded_false_positive",
            "private_unknown",
        } and row.get("pypi") is not None:
            identity_errors.append(
                f"{sample_id}/{package}:excluded_identity_has_registry_query"
            )
    _gate(
        gates,
        "package_identity_consistency",
        not identity_errors,
        identity_errors,
    )

    snapshot_errors: list[str] = []
    snapshot_dir = generation / "project_snapshots"
    try:
        snapshot_index = verify_snapshot_index(snapshot_dir)
        if snapshot_index.get("sample_count") != analysis_expected_samples:
            snapshot_errors.append(
                "snapshot_sample_count:"
                f"{snapshot_index.get('sample_count')}!="
                f"{analysis_expected_samples}"
            )
    except Exception as exc:
        snapshot_errors.append(
            f"{type(exc).__name__}:{exc}"
        )
    _gate(
        gates,
        "project_snapshot_integrity",
        not snapshot_errors,
        snapshot_errors,
    )

    reachability_errors: list[str] = []
    allowed_reachability = {
        "mention_only",
        "import_only",
        "manifest_declared",
        "lockfile_resolved",
        "ci_installable",
    }
    for row in reachability:
        level = str(
            row.get("install_reachability_v2")
            or row.get("install_reachability")
            or ""
        ).strip()
        if level not in allowed_reachability:
            reachability_errors.append(
                f"{row.get('sample_id')}/{row.get('package')}:level:{level}"
            )
        if row.get("reachability_policy_version") != (
            "codesentry_gen_reachability_r0_r4_v1"
        ):
            reachability_errors.append(
                f"{row.get('sample_id')}/{row.get('package')}:policy"
            )
        evidence = row.get("reachability_v2_evidence")
        if not isinstance(evidence, dict):
            reachability_errors.append(
                f"{row.get('sample_id')}/{row.get('package')}:evidence_missing"
            )
    _gate(
        gates,
        "reachability_r0_r4_contract",
        not reachability_errors,
        reachability_errors,
    )

    time_errors: list[str] = []
    for row in temporal:
        tg = parse_time(row.get("generation_time"))
        pypi = row.get("pypi")
        ta = (
            parse_time(pypi.get("audit_time"))
            if isinstance(pypi, dict)
            else None
        )
        if tg is not None and ta is not None and ta < tg:
            time_errors.append(
                f"{row.get('sample_id')}/{row.get('package')}:audit_before_generation"
            )
        if row.get("generation_time_uncertainty_seconds") is None:
            time_errors.append(
                f"{row.get('sample_id')}/{row.get('package')}:uncertainty_missing"
            )
    _gate(
        gates,
        "time_invariants",
        not time_errors,
        time_errors,
    )

    risk_schema = ROOT / "schemas/risk_card_schema_v2_1.json"
    risk_errors: list[str] = []
    for filename in [
        "tho_risk_cards.jsonl",
        "tho_auxiliary_findings.jsonl",
        "avcs_auxiliary_findings.jsonl",
        "unified_risk_cards.jsonl",
    ]:
        path = cards / filename
        rows = read_jsonl(path)
        for index, row in enumerate(rows):
            try:
                validate_risk_card(row)
                _schema_validate(row, risk_schema)
            except Exception as exc:
                risk_errors.append(
                    f"{filename}:{index}:{type(exc).__name__}:{exc}"
                )
    tho_formal_cards = read_jsonl(
        cards / "tho_risk_cards.jsonl"
    )
    risk_errors.extend(
        validate_tho_formal_cards_against_records(
            cards=tho_formal_cards,
            reachability_records=reachability,
        )
    )
    unified_cards = read_jsonl(
        cards / "unified_risk_cards.jsonl"
    )
    risk_errors.extend(
        validate_avcs_formal_cards_against_analysis(
            avcs_dir=avcs,
            unified_cards=unified_cards,
        )
    )
    _gate(
        gates,
        "risk_card_schema_and_semantics",
        not risk_errors,
        risk_errors,
    )

    base_ir = read_json(sceg / "sceg_v2_1_base.json")
    analyzed_ir = read_json(sceg / "sceg_v2_1_analyzed.json")
    sceg_errors: list[str] = []
    try:
        verify_ir(base_ir)
        verify_ir(analyzed_ir)
        _schema_validate(
            analyzed_ir,
            ROOT / "schemas/sceg_schema_v2_1.json",
        )
        if (
            base_ir.get("source_snapshot_id")
            != analyzed_ir.get("source_snapshot_id")
        ):
            sceg_errors.append("source_snapshot_id_changed")
    except Exception as exc:
        sceg_errors.append(f"{type(exc).__name__}:{exc}")

    link_ok, link_errors = _sceg_risk_link_check(analyzed_ir)
    sceg_errors.extend(link_errors)
    _gate(
        gates,
        "sceg_schema_referential_integrity",
        not sceg_errors and link_ok,
        sceg_errors,
    )

    run_contract_value: dict[str, Any] = {}
    run_contract_path = run_dir / "run_contract.json"
    if run_contract_path.exists():
        try:
            run_contract_value = read_json(run_contract_path)
        except Exception:
            run_contract_value = {}

    run_inputs = run_contract_value.get("inputs")
    if not isinstance(run_inputs, dict):
        run_inputs = {}
    run_purpose = str(run_inputs.get("run_purpose") or "")
    formal_step9_run = run_purpose in {"step9_pilot", "step9_test"}
    expected_release_snapshot = run_inputs.get(
        "release_snapshot_manifest"
    )
    if not isinstance(expected_release_snapshot, dict):
        expected_release_snapshot = None

    coverage_acceptance_rule: dict[str, Any] | None = None
    coverage_protocol_errors: list[str] = []
    if formal_step9_run:
        protocol_binding = run_inputs.get("step9_protocol")
        if not isinstance(protocol_binding, dict):
            coverage_protocol_errors.append(
                "formal_step9_protocol_binding_missing"
            )
        else:
            protocol_path_text = str(
                protocol_binding.get("path") or ""
            ).strip()
            if not protocol_path_text:
                coverage_protocol_errors.append(
                    "formal_step9_protocol_path_missing"
                )
            else:
                try:
                    protocol_value = read_json(
                        ROOT / protocol_path_text
                    )
                    require_successor_method_revision_contract(
                        protocol_value
                    )
                    acceptance = protocol_value.get(
                        "avcs_coverage_acceptance"
                    )
                    if not isinstance(acceptance, dict):
                        coverage_protocol_errors.append(
                            "formal_avcs_coverage_acceptance_missing"
                        )
                    else:
                        formal_rule = acceptance.get("formal_step9")
                        if isinstance(formal_rule, dict):
                            coverage_acceptance_rule = formal_rule
                        else:
                            coverage_protocol_errors.append(
                                "formal_avcs_coverage_rule_missing"
                            )
                except Exception as exc:
                    coverage_protocol_errors.append(
                        "formal_step9_protocol_load_failed:"
                        f"{type(exc).__name__}:{exc}"
                    )

    avcs_method_ok, avcs_coverage_detail = (
        evaluate_avcs_method_coverage(
            avcs_dir=avcs,
            expected_samples=analysis_expected_samples,
            require_avcs_method=require_avcs_method,
            require_frozen_release_snapshot=formal_step9_run,
            expected_release_snapshot=expected_release_snapshot,
            coverage_acceptance_rule=coverage_acceptance_rule,
            require_coverage_acceptance_rule=formal_step9_run,
        )
    )
    if coverage_protocol_errors:
        avcs_method_ok = False
        avcs_coverage_detail["errors"].extend(
            coverage_protocol_errors
        )
        avcs_coverage_detail[
            "coverage_protocol_errors"
        ] = coverage_protocol_errors
    _gate(
        gates,
        "avcs_method_coverage_and_outputs",
        avcs_method_ok,
        avcs_coverage_detail,
    )

    coverage_review_path = (
        run_dir / "risk_cards" / "avcs_coverage_review_findings.jsonl"
    )
    coverage_review_errors = verify_avcs_coverage_review_findings(
        avcs_dir=avcs,
        findings_path=coverage_review_path,
    )
    _gate(
        gates,
        "avcs_coverage_review_output",
        not coverage_review_errors,
        {
            "errors": coverage_review_errors,
            "file": rel(coverage_review_path),
            "nonformal_coverage_is_explicit": True,
            "formal_risk_taxonomy_unchanged": True,
        },
    )

    run_contract_errors = verify_e2e_run_contract_file(
        run_dir / "run_contract.json"
    )
    _gate(
        gates,
        "run_input_runtime_hash_closure",
        not run_contract_errors,
        run_contract_errors,
    )

    route_ok, route_detail = (
        _observed_formal_risk_route_integrity(
            unified_cards
        )
    )
    _gate(
        gates,
        "formal_risk_routing_reachability",
        route_ok,
        route_detail,
    )

    passed = all(
        row.get("status") == "PASS"
        for row in gates.values()
    )
    return {
        "schema_version": "codesentry_gen_scientific_contract_v1",
        "status": "PASS" if passed else "FAIL",
        "run_dir": rel(run_dir),
        "expected_samples": expected_samples,
        "selected_population_count": expected_samples,
        "analysis_population_count": analysis_expected_samples,
        "generation_outcome_manifest": (
            rel(outcome_path) if outcome_manifest is not None else None
        ),
        "statistical_eligibility": statistical_eligibility,
        "require_avcs_method": require_avcs_method,
        "generation_quality": parse_accounting,
        "gates": gates,
    }
