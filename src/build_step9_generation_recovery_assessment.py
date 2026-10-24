from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from freeze_hash_v1 import canonical_sha256_file, hash_record
from generate_code_from_prompts import (
    fsync_directory,
    generation_request_contract,
)
from generation_crash_recovery import assess_partial_generation_artifacts
from generation_outcome_integration_v1 import (
    build_manifest_from_recovery,
    derive_journal_backed_local_reconstruction_ids,
    derive_selective_recovery_authority,
    derive_successor_recovery_action,
    evaluate_split_statistical_eligibility,
    require_successor_method_revision_contract,
)
from step9_protocol_registry import require_active_frozen_protocol


ROOT = Path(__file__).resolve().parents[1]


def read_jsonl_if_exists(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8-sig") as handle:
        for line_no, raw in enumerate(handle, 1):
            text = raw.strip()
            if not text:
                continue
            try:
                value = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"{path}:{line_no}: malformed JSON: {exc.msg}"
                ) from exc
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_no}: expected object")
            rows.append(value)
    return rows


def raw_sha256_or_none(path: Path) -> str | None:
    if not path.is_file():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def sidecar_hashes(directory: Path, pattern: str) -> dict[str, str]:
    if not directory.is_dir():
        return {}
    result: dict[str, str] = {}
    for path in sorted(directory.glob(pattern)):
        if path.is_file():
            result[rel(path)] = canonical_sha256_file(path)
    return result


def atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    if path.exists():
        raise FileExistsError(f"Refusing overwrite: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
        text=True,
    )
    temp_path = Path(temp_name)
    try:
        with os.fdopen(
            descriptor,
            "w",
            encoding="utf-8",
            newline="\n",
        ) as handle:
            handle.write(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        fsync_directory(path.parent)
    except Exception:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass
        raise


def expected_request_contract_from_protocol(
    protocol: dict[str, Any],
) -> tuple[dict[str, Any], int, int]:
    model_cfg = protocol.get("model_generation")
    if not isinstance(model_cfg, dict):
        raise ValueError("Frozen protocol model_generation missing")

    model = str(model_cfg.get("model") or "").strip()
    endpoint = str(model_cfg.get("provider_endpoint") or "").strip()
    if not model or not endpoint:
        raise ValueError("Frozen generation model/endpoint missing")

    timeout = int(model_cfg.get("request_timeout_seconds"))
    transport_mode = str(
        model_cfg.get("transport_mode") or "non_streaming_json"
    ).strip()
    connect_timeout = int(
        model_cfg.get("connect_timeout_seconds") or timeout
    )
    read_timeout = int(
        model_cfg.get("stream_read_timeout_seconds") or timeout
    )
    request_deadline = int(
        model_cfg.get("request_deadline_seconds") or timeout
    )
    max_tokens_raw = model_cfg.get("max_tokens")
    max_tokens = (
        int(max_tokens_raw) if max_tokens_raw is not None else None
    )
    enable_thinking = model_cfg.get("enable_thinking")
    thinking_mode = (
        "provider_default"
        if enable_thinking is None
        else ("enabled" if enable_thinking else "disabled")
    )
    reasoning_effort = str(
        model_cfg.get("reasoning_effort") or ""
    ).strip() or None
    response_format = str(
        model_cfg.get("response_format") or "text"
    ).strip()
    retries = int(model_cfg.get("retries") or 0)
    max_resume_rounds = int(
        model_cfg.get("max_resume_rounds") or 0
    )
    max_total_attempts = int(
        model_cfg.get("max_total_attempts_per_prompt")
        or ((max_resume_rounds + 1) * (retries + 1))
    )

    contract = generation_request_contract(
        model=model,
        provider_endpoint=endpoint,
        temperature=float(model_cfg.get("temperature")),
        reasoning_effort=reasoning_effort,
        thinking_mode=thinking_mode,
        response_format=response_format,
        stream=transport_mode == "streaming_sse",
        connect_timeout=connect_timeout,
        read_timeout=read_timeout,
        request_deadline=request_deadline,
        max_tokens=max_tokens,
    )
    return contract, max_total_attempts, max_resume_rounds


def build_recovery_assessment(
    *,
    protocol_path: Path,
    split: str,
    output_path: Path,
) -> dict[str, Any]:
    protocol_path, protocol, _ = require_active_frozen_protocol(
        protocol_path,
        operation=f"Step9 {split} generation crash recovery assessment",
    )
    if split not in {"pilot", "test"}:
        raise ValueError("split must be pilot or test")
    require_successor_method_revision_contract(protocol)

    split_cfg = protocol["splits"][split]
    prompts = ROOT / split_cfg["output"]
    prompt_rows = read_jsonl_if_exists(prompts)
    declared_size = int(split_cfg["size"])
    if len(prompt_rows) != declared_size:
        raise ValueError(
            "Selected prompt row count does not match frozen split size: "
            f"{len(prompt_rows)} != {declared_size}"
        )

    out_dir = ROOT / protocol["planned_outputs"][
        "pilot_run" if split == "pilot" else "test_run"
    ]
    generation_dir = out_dir / "generation"
    samples_path = generation_dir / "generated_samples.jsonl"
    attempts_path = generation_dir / "generation_attempts.jsonl"
    intents_path = generation_dir / "generation_attempt_intents.jsonl"
    accepted_journal_dir = generation_dir / "accepted_response_journal"
    code_dir = generation_dir / "code"
    requirements_dir = generation_dir / "requirements"
    checkpoint_path = generation_dir / "generation_checkpoint_manifest.json"

    expected_contract, max_total_attempts, max_resume_rounds = (
        expected_request_contract_from_protocol(protocol)
    )
    attempt_intent_rows = read_jsonl_if_exists(intents_path)
    attempt_rows = read_jsonl_if_exists(attempts_path)
    generated_rows = read_jsonl_if_exists(samples_path)
    assessment = assess_partial_generation_artifacts(
        prompt_rows=prompt_rows,
        attempt_intent_rows=attempt_intent_rows,
        attempt_rows=attempt_rows,
        generated_rows=generated_rows,
        accepted_journal_dir=accepted_journal_dir,
        expected_request_contract=expected_contract,
        expected_max_total_attempts=max_total_attempts,
        expected_max_resume_rounds=max_resume_rounds,
        code_dir=code_dir,
        requirements_dir=requirements_dir,
    )

    method_path = ROOT / protocol["planned_outputs"]["method_freeze"]
    if not method_path.is_file():
        raise FileNotFoundError(method_path)
    method = json.loads(method_path.read_text(encoding="utf-8-sig"))
    if not isinstance(method, dict):
        raise ValueError("Method-freeze artifact must be an object")
    method_closure_sha256 = str(
        method.get("method_closure_sha256") or ""
    ).strip()
    if not method_closure_sha256:
        raise ValueError(
            "Method-freeze artifact lacks method_closure_sha256"
        )
    selection_path = ROOT / protocol["planned_outputs"]["selection_manifest"]
    local_reconstruction_ids = (
        derive_journal_backed_local_reconstruction_ids(
            recovery_assessment=assessment,
            generated_rows=generated_rows,
            attempt_rows=attempt_rows,
            code_dir=code_dir,
            requirements_dir=requirements_dir,
        )
    )
    selective_authority = derive_selective_recovery_authority(
        recovery_assessment=assessment,
        max_resume_rounds=max_resume_rounds,
    )

    outcome_projection: dict[str, Any] | None = None
    eligibility_projection: dict[str, Any] | None = None
    projection_status = "LOCAL_RECONSTRUCTION_REQUIRED"
    if not local_reconstruction_ids:
        outcome_projection = build_manifest_from_recovery(
            split=split,
            protocol_id=str(protocol.get("protocol_id") or ""),
            selection_manifest_hash=hash_record(selection_path)["sha256"],
            method_closure_sha256=method_closure_sha256,
            request_contract_sha256=str(
                assessment.get("request_contract_sha256") or ""
            ),
            selected_records=prompt_rows,
            generated_rows=generated_rows,
            attempt_rows=attempt_rows,
            recovery_assessment=assessment,
            attempts_ref=rel(attempts_path),
            accepted_journal_dir_ref=rel(accepted_journal_dir),
            generated_samples_ref=rel(samples_path),
            code_dir_ref=rel(code_dir),
            requirements_dir_ref=rel(requirements_dir),
        )
        eligibility_projection = evaluate_split_statistical_eligibility(
            outcome_projection
        )
        projection_status = str(
            outcome_projection.get("stage_evidence_status") or ""
        )

    successor_recovery_action = derive_successor_recovery_action(
        local_reconstruction_ids=local_reconstruction_ids,
        selective_authority=selective_authority,
        outcome_projection=outcome_projection,
    )

    classifier_schema_version = assessment.get("schema_version")
    manifest = {
        **assessment,
        "schema_version": "step9_generation_recovery_assessment_v1",
        "classifier_schema_version": classifier_schema_version,
        "status": "RECOVERY_EVIDENCE_CLASSIFIED",
        "split": split,
        "protocol_file": rel(protocol_path),
        "protocol_hash": hash_record(protocol_path),
        "method_freeze_file": rel(method_path),
        "method_freeze_hash": (
            hash_record(method_path) if method_path.is_file() else None
        ),
        "prompt_file": rel(prompts),
        "prompt_raw_sha256": raw_sha256_or_none(prompts),
        "generated_samples_file": rel(samples_path),
        "generated_samples_raw_sha256": raw_sha256_or_none(samples_path),
        "attempt_ledger_file": rel(attempts_path),
        "attempt_ledger_raw_sha256": raw_sha256_or_none(attempts_path),
        "attempt_intent_ledger_file": rel(intents_path),
        "attempt_intent_ledger_raw_sha256": raw_sha256_or_none(intents_path),
        "checkpoint_file": rel(checkpoint_path),
        "checkpoint_raw_sha256": raw_sha256_or_none(checkpoint_path),
        "code_sidecar_sha256": sidecar_hashes(code_dir, "*.py"),
        "requirements_sidecar_sha256": sidecar_hashes(
            requirements_dir,
            "*_requirements.txt",
        ),
        "accepted_response_journal_sha256": sidecar_hashes(
            accepted_journal_dir,
            "*.accepted.json",
        ),
        "generation_outcome_projection": outcome_projection,
        "generation_outcome_projection_status": projection_status,
        "statistical_eligibility_projection": eligibility_projection,
        "journal_backed_local_reconstruction_ids": (
            local_reconstruction_ids
        ),
        "successor_selective_recovery_authority": selective_authority,
        "successor_recovery_action": successor_recovery_action,
        "scientific_boundary": {
            **dict(assessment.get("scientific_boundary") or {}),
            "recovery_projection_calls_provider": False,
            "frozen_classifier_is_unchanged": True,
            "terminal_or_ambiguous_samples_never_recalled": True,
            "journal_backed_accepted_reconstruction_is_local_only": True,
            "journal_backed_accepted_is_not_complete_until_materialized": True,
            "independently_safe_nonfinal_samples_may_continue": True,
            "mixed_terminal_and_nonfinal_is_not_stage_wide_terminal": True,
            "generation_outcome_projection_is_not_dependency_risk_analysis": True,
        },
    }
    atomic_write_json(output_path, manifest)
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Read-only forensic classification of an interrupted formal "
            "generation stage. This command never calls the provider and "
            "never repairs generation artifacts."
        )
    )
    parser.add_argument("--protocol", required=True, type=Path)
    parser.add_argument("--split", required=True, choices=["pilot", "test"])
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    manifest = build_recovery_assessment(
        protocol_path=args.protocol,
        split=args.split,
        output_path=args.out,
    )
    print("STEP9 GENERATION RECOVERY ASSESSMENT COMPLETE")
    print("stage_recovery_status =", manifest["stage_recovery_status"])
    print(
        "provider_recall_authorized =",
        manifest["provider_recall_authorized"],
    )
    print(
        "successor_recovery_action =",
        manifest["successor_recovery_action"],
    )
    print(
        "successor_selective_recall_ids =",
        manifest["successor_selective_recovery_authority"][
            "provider_recall_sample_ids"
        ],
    )
    print(
        "journal_backed_local_reconstruction_ids =",
        manifest["journal_backed_local_reconstruction_ids"],
    )
    print(
        "ambiguous_in_flight_count =",
        len(manifest["ids_by_state"]["AMBIGUOUS_IN_FLIGHT"]),
    )
    print(
        "generation_outcome_projection_status =",
        manifest["generation_outcome_projection_status"],
    )
    eligibility = manifest["statistical_eligibility_projection"]
    print(
        "statistical_eligibility_projection =",
        eligibility.get("status") if isinstance(eligibility, dict) else None,
    )
    print("saved =", args.out)


if __name__ == "__main__":
    main()
