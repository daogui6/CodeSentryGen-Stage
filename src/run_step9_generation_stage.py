from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from build_step9_method_freeze_v1 import verify_step9_formal_freeze_binding
from freeze_hash_v1 import canonical_sha256_file, hash_record
from generate_code_from_prompts import (
    fsync_directory,
    generation_request_contract,
    validate_selected_prompt_rows,
)
from generation_crash_recovery import assess_partial_generation_artifacts
from generation_reliability_validation import validate_generation_artifacts
from generation_outcome_integration_v1 import (
    accepted_rows_from_manifest,
    build_manifest_from_generation,
    build_manifest_from_recovery,
    evaluate_split_statistical_eligibility,
    require_successor_method_revision_contract,
)
from step9_protocol_registry import require_active_frozen_protocol
from time_contract_v1 import require_aware_utc, utc_iso


ROOT = Path(__file__).resolve().parents[1]


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return value


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8-sig") as handle:
        for line_no, raw in enumerate(handle, 1):
            text = raw.strip()
            if not text:
                continue
            value = json.loads(text)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_no}: expected object")
            rows.append(value)
    return rows


def write_json(path: Path, value: dict[str, Any]) -> None:
    if path.exists():
        raise FileExistsError(f"Refusing overwrite: {path}")
    _atomic_write_json(path, value)


def write_checkpoint_json(path: Path, value: dict[str, Any]) -> None:
    _atomic_write_json(path, value)


def _atomic_write_json(path: Path, value: dict[str, Any]) -> None:
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


def materialize_empty_generated_samples_artifact(path: Path) -> None:
    """Durably persist a zero-row JSONL artifact without overwriting evidence."""

    if path.exists():
        raise FileExistsError(
            f"Refusing to overwrite generated-samples artifact: {path}"
        )
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


def raw_sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_sha256_file_from_value(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def sidecar_hashes(directory: Path, pattern: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for path in sorted(directory.glob(pattern)):
        if path.is_file():
            result[rel(path)] = canonical_sha256_file(path)
    return result


def sidecar_hashes_for_sample_ids(
    directory: Path,
    *,
    sample_ids: list[str],
    suffix: str,
) -> dict[str, str]:
    result: dict[str, str] = {}
    for sample_id in sample_ids:
        path = directory / f"{sample_id}{suffix}"
        if not path.is_file():
            raise FileNotFoundError(path)
        result[rel(path)] = canonical_sha256_file(path)
    return result


def append_generation_adapter_cli(
    cmd: list[str],
    *,
    enable_thinking: bool | None,
    response_format: str,
    reasoning_effort: str | None,
) -> list[str]:
    """Append protocol-bound provider adapter flags deterministically."""
    result = list(cmd)
    if enable_thinking is not None:
        result.extend(
            [
                "--thinking-mode",
                "enabled" if enable_thinking else "disabled",
            ]
        )
    if response_format != "text":
        result.extend(["--response-format", response_format])
    if reasoning_effort is not None:
        result.extend(["--reasoning-effort", reasoning_effort])
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run only the real LLM generation stage for a frozen fresh Step9 "
            "split. Temporal Registry evidence is intentionally acquired later."
        )
    )
    parser.add_argument("--protocol", required=True, type=Path)
    parser.add_argument("--split", required=True, choices=["pilot", "test"])
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--retries", type=int, default=1)
    parser.add_argument(
        "--resume",
        action="store_true",
        help=(
            "Resume only from byte-bound checkpoint evidence or a byte-bound "
            "crash-recovery assessment. Successful samples are never "
            "regenerated."
        ),
    )
    parser.add_argument(
        "--resume-evidence-manifest",
        type=Path,
        default=None,
        help=(
            "Persisted checkpoint evidence manifest for the legacy "
            "checkpointed transport-pending resume path."
        ),
    )
    parser.add_argument(
        "--recovery-assessment-manifest",
        type=Path,
        default=None,
        help=(
            "Read-only crash-recovery assessment manifest. This path can "
            "authorize either bounded provider recall for RESUME_ELIGIBLE or "
            "local-only reconstruction for COMPLETE_SEALABLE."
        ),
    )
    args = parser.parse_args()
    supplied_resume_authorities = sum(
        value is not None
        for value in (
            args.resume_evidence_manifest,
            args.recovery_assessment_manifest,
        )
    )
    if args.resume and supplied_resume_authorities != 1:
        raise ValueError(
            "--resume requires exactly one of --resume-evidence-manifest "
            "or --recovery-assessment-manifest"
        )
    if not args.resume and supplied_resume_authorities:
        raise ValueError(
            "resume authority manifests are only valid with --resume"
        )
    return args


def _run_generation_stage(args: argparse.Namespace) -> None:
    protocol_path, protocol, _ = require_active_frozen_protocol(
        args.protocol,
        operation=f"Step9 {args.split} generation stage",
    )
    require_successor_method_revision_contract(protocol)

    subprocess.run(
        [
            sys.executable,
            str(ROOT / "src/check_step9_fresh_selection.py"),
            "--protocol",
            str(protocol_path),
        ],
        cwd=ROOT,
        check=True,
    )

    method_path = ROOT / str(
        protocol["planned_outputs"]["method_freeze"]
    )
    method = verify_step9_formal_freeze_binding(
        method_path,
        protocol_path=protocol_path,
        require_git_identity=True,
        require_environment_versions=True,
    )

    split_cfg = protocol["splits"][args.split]
    prompts = ROOT / split_cfg["output"]
    declared_size = int(split_cfg["size"])
    prompt_rows = read_jsonl(prompts)
    if len(prompt_rows) != declared_size:
        raise ValueError(
            "Selected prompt row count does not match frozen split size: "
            f"{len(prompt_rows)} != {declared_size}"
        )
    # Repeat the identity check locally even though the selection checker ran:
    # generation filenames and resume identity must be one-to-one before the
    # first paid provider request.
    validate_selected_prompt_rows(prompt_rows, start=1)
    out_dir = ROOT / protocol["planned_outputs"][
        "pilot_run" if args.split == "pilot" else "test_run"
    ]
    generation_dir = out_dir / "generation"
    samples_path = generation_dir / "generated_samples.jsonl"
    code_dir = generation_dir / "code"
    requirements_dir = generation_dir / "requirements"
    manifest_path = ROOT / protocol["planned_outputs"][
        "pilot_generation_stage_manifest"
        if args.split == "pilot"
        else "test_generation_stage_manifest"
    ]
    checkpoint_path = generation_dir / "generation_checkpoint_manifest.json"
    outcome_manifest_path = generation_dir / "generation_outcome_manifest.json"
    attempts_path = generation_dir / "generation_attempts.jsonl"
    attempt_intents_path = (
        generation_dir / "generation_attempt_intents.jsonl"
    )
    accepted_journal_dir = generation_dir / "accepted_response_journal"
    recovery_local_finalization = False
    selective_recovery_resume = False
    local_reconstruction_resume = False
    selective_recall_ids: list[str] = []
    local_reconstruction_ids: list[str] = []

    if args.resume:
        if not generation_dir.is_dir():
            raise FileNotFoundError(
                f"Resume generation directory missing: {generation_dir}"
            )
        if args.resume_evidence_manifest is not None:
            if not samples_path.is_file():
                raise FileNotFoundError(
                    f"Resume generated_samples missing: {samples_path}"
                )
            if not attempts_path.is_file():
                raise FileNotFoundError(
                    f"Resume attempt ledger missing: {attempts_path}"
                )
            if not checkpoint_path.is_file():
                raise FileNotFoundError(
                    f"Resume checkpoint manifest missing: {checkpoint_path}"
                )
            if not accepted_journal_dir.is_dir():
                raise FileNotFoundError(
                    "Resume accepted-response journal directory missing: "
                    f"{accepted_journal_dir}"
                )
        if manifest_path.exists():
            raise FileExistsError(
                "Cannot resume an already completed generation stage"
            )
    elif out_dir.exists():
        raise FileExistsError(
            f"Fresh Step9 {args.split} output already exists: {out_dir}"
        )
    if manifest_path.exists():
        raise FileExistsError(
            f"Generation-stage manifest already exists: {manifest_path}"
        )

    if args.split == "pilot":
        test_dir = ROOT / protocol["planned_outputs"]["test_run"]
        if test_dir.exists():
            raise ValueError(
                "Formal test output exists before pilot generation/closure"
            )
    else:
        pilot_closure_path = ROOT / protocol["planned_outputs"][
            "pilot_closure"
        ]
        if not pilot_closure_path.exists():
            raise FileNotFoundError(
                "Test generation is blocked until pilot closure exists"
            )
        pilot_closure = read_json(pilot_closure_path)
        if (
            pilot_closure.get("status") != "PASS"
            or pilot_closure.get("pilot_closed") is not True
            or pilot_closure.get("step9_test_authorized") is not True
        ):
            raise ValueError(
                "Pilot closure does not authorize formal test generation"
            )

    model_cfg = protocol.get("model_generation")
    if not isinstance(model_cfg, dict):
        raise ValueError("Frozen protocol model_generation missing")
    model = str(model_cfg.get("model") or "").strip()
    if not model:
        raise ValueError("Frozen protocol generation model is empty")
    if model_cfg.get("real_api") is not True:
        raise ValueError("Formal Step9 generation requires real_api=true")
    provider = str(model_cfg.get("provider") or "").strip()
    provider_region = str(model_cfg.get("provider_region") or "").strip()
    provider_endpoint = str(model_cfg.get("provider_endpoint") or "").strip()
    if not provider or not provider_region or not provider_endpoint:
        raise ValueError(
            "Formal Step9 requires protocol-bound provider, region, and endpoint"
        )
    if not provider_endpoint.startswith("https://"):
        raise ValueError("Formal Step9 provider endpoint must use HTTPS")
    if model_cfg.get("local_provider_endpoint_override_allowed") is not False:
        raise ValueError(
            "Formal Step9 must forbid local provider-endpoint overrides"
        )
    expected_temperature = float(model_cfg.get("temperature"))
    expected_timeout = int(model_cfg.get("request_timeout_seconds"))
    expected_retries = int(model_cfg.get("retries"))
    expected_transport_mode = str(
        model_cfg.get("transport_mode") or "non_streaming_json"
    ).strip()
    expected_connect_timeout = int(
        model_cfg.get("connect_timeout_seconds")
        or expected_timeout
    )
    expected_read_timeout = int(
        model_cfg.get("stream_read_timeout_seconds")
        or expected_timeout
    )
    expected_request_deadline = int(
        model_cfg.get("request_deadline_seconds")
        or expected_timeout
    )
    expected_max_tokens_raw = model_cfg.get("max_tokens")
    expected_max_resume_rounds = int(
        model_cfg.get("max_resume_rounds") or 0
    )
    expected_max_total_attempts = int(
        model_cfg.get("max_total_attempts_per_prompt")
        or (expected_retries + 1)
    )
    expected_max_tokens = (
        int(expected_max_tokens_raw)
        if expected_max_tokens_raw is not None
        else None
    )
    retry_backoff_raw = model_cfg.get("retry_backoff_seconds")
    if retry_backoff_raw is None:
        expected_retry_backoff = [2.0] * expected_retries
    elif (
        isinstance(retry_backoff_raw, list)
        and all(isinstance(x, (int, float)) for x in retry_backoff_raw)
    ):
        expected_retry_backoff = [float(x) for x in retry_backoff_raw]
    else:
        raise ValueError("Frozen retry_backoff_seconds must be a numeric list")
    if len(expected_retry_backoff) != expected_retries:
        raise ValueError(
            "Frozen retry_backoff_seconds length must equal retries"
        )
    expected_reasoning_effort = str(
        model_cfg.get("reasoning_effort") or ""
    ).strip() or None
    expected_enable_thinking_raw = model_cfg.get("enable_thinking")
    if expected_enable_thinking_raw is None:
        expected_enable_thinking = None
    elif isinstance(expected_enable_thinking_raw, bool):
        expected_enable_thinking = expected_enable_thinking_raw
    else:
        raise ValueError("Frozen enable_thinking must be boolean or null")
    expected_response_format = str(
        model_cfg.get("response_format") or "text"
    ).strip()
    if expected_response_format not in {"text", "json_object"}:
        raise ValueError(
            "Frozen response_format must be text or json_object"
        )
    adapter_revision = str(
        model_cfg.get("generation_adapter_contract_revision") or ""
    ).strip()

    if model == "deepseek-v4-flash-0731":
        if expected_enable_thinking is False:
            if expected_reasoning_effort is not None:
                raise ValueError(
                    "Non-thinking DeepSeek generation must omit "
                    "reasoning_effort"
                )
        elif expected_reasoning_effort not in {"low", "high", "max"}:
            raise ValueError(
                "Thinking/default DeepSeek generation requires frozen "
                "reasoning_effort in {low, high, max}"
            )

    if adapter_revision in {
        "r5_r10_nonthinking_json_adapter_v1",
        "generation_reliability_state_machine_v2",
    }:
        if expected_enable_thinking is not False:
            raise ValueError(
                "Non-thinking JSON generation adapter requires "
                "enable_thinking=false"
            )
        if expected_reasoning_effort is not None:
            raise ValueError(
                "Non-thinking JSON generation adapter forbids "
                "reasoning_effort"
            )
        if expected_response_format != "json_object":
            raise ValueError(
                "Non-thinking JSON generation adapter requires json_object "
                "output"
            )
        if expected_transport_mode != "streaming_sse":
            raise ValueError(
                "Non-thinking JSON generation adapter requires "
                "streaming_sse"
            )
    if args.timeout != expected_timeout:
        raise ValueError(
            f"--timeout must match frozen protocol: {expected_timeout}"
        )
    if args.retries != expected_retries:
        raise ValueError(
            f"--retries must match frozen protocol: {expected_retries}"
        )
    if expected_transport_mode == "streaming_sse":
        if model_cfg.get("stream") is not True:
            raise ValueError(
                "streaming_sse transport requires frozen stream=true"
            )
        if expected_connect_timeout <= 0 or expected_read_timeout <= 0:
            raise ValueError("Frozen streaming timeouts must be positive")
        if expected_request_deadline <= 0:
            raise ValueError("Frozen request deadline must be positive")
        if expected_timeout != expected_request_deadline:
            raise ValueError(
                "Streaming request_timeout_seconds must equal the frozen "
                "wall-clock request_deadline_seconds"
            )
        if (
            expected_connect_timeout + expected_read_timeout
            > expected_request_deadline
        ):
            raise ValueError(
                "Frozen connect + initial read timeout can exceed the total "
                "request deadline"
            )
        if expected_max_tokens is None or expected_max_tokens <= 0:
            raise ValueError(
                "Streaming generation contract requires frozen max_tokens"
            )
        if expected_max_resume_rounds < 0:
            raise ValueError("max_resume_rounds must be non-negative")
        if expected_max_total_attempts < expected_retries + 1:
            raise ValueError(
                "max_total_attempts_per_prompt is below one invocation budget"
            )
        expected_total_from_rounds = (
            (expected_max_resume_rounds + 1)
            * (expected_retries + 1)
        )
        if expected_max_total_attempts != expected_total_from_rounds:
            raise ValueError(
                "max_total_attempts_per_prompt must exactly equal "
                "(max_resume_rounds + 1) * (retries + 1)"
            )

    time_views = protocol.get("evaluation_time_views")
    if not isinstance(time_views, dict):
        raise ValueError("Frozen protocol evaluation_time_views missing")
    uncertainty_raw = time_views.get(
        "generation_time_uncertainty_seconds"
    )
    if not isinstance(uncertainty_raw, (int, float)):
        raise ValueError(
            "Frozen protocol generation-time uncertainty must be numeric"
        )
    uncertainty_seconds = float(uncertainty_raw)
    if uncertainty_seconds < 0:
        raise ValueError(
            "Frozen generation-time uncertainty must be non-negative"
        )
    if (
        expected_transport_mode == "streaming_sse"
        and expected_request_deadline > uncertainty_seconds
    ):
        raise ValueError(
            "Frozen request deadline exceeds generation-time uncertainty Δt"
        )

    expected_thinking_mode = (
        "provider_default"
        if expected_enable_thinking is None
        else ("enabled" if expected_enable_thinking else "disabled")
    )
    expected_request_contract = generation_request_contract(
        model=model,
        provider_endpoint=provider_endpoint,
        temperature=expected_temperature,
        reasoning_effort=expected_reasoning_effort,
        thinking_mode=expected_thinking_mode,
        response_format=expected_response_format,
        stream=(expected_transport_mode == "streaming_sse"),
        connect_timeout=expected_connect_timeout,
        read_timeout=expected_read_timeout,
        request_deadline=expected_request_deadline,
        max_tokens=expected_max_tokens,
    )

    if args.resume and args.resume_evidence_manifest is not None:
        prior_checkpoint = read_json(checkpoint_path)
        if prior_checkpoint.get("status") != "INCOMPLETE_TRANSPORT_PENDING":
            raise ValueError(
                "Resume requires INCOMPLETE_TRANSPORT_PENDING checkpoint"
            )
        if prior_checkpoint.get("terminal_failure_ids"):
            raise ValueError(
                "Resume is forbidden when terminal generation failures exist"
            )
        if prior_checkpoint.get("retry_budget_exhausted_ids"):
            raise ValueError(
                "Resume is forbidden after total attempt budget exhaustion"
            )
        if (
            prior_checkpoint.get("protocol_file") != rel(protocol_path)
            or prior_checkpoint.get("prompt_sha256")
            != canonical_sha256_file(prompts)
            or prior_checkpoint.get("method_closure_sha256")
            != method.get("method_closure_sha256")
        ):
            raise ValueError("Resume checkpoint binding mismatch")

        prior_resume_round = int(
            prior_checkpoint.get("resume_round", 0)
        )
        if prior_resume_round >= expected_max_resume_rounds:
            raise ValueError(
                "Frozen maximum resume rounds already exhausted"
            )

        evidence_path = args.resume_evidence_manifest.resolve()
        if not evidence_path.is_file():
            raise FileNotFoundError(
                f"Resume evidence manifest missing: {evidence_path}"
            )
        resume_evidence = read_json(evidence_path)
        if (
            resume_evidence.get("schema_version")
            != "step9_generation_checkpoint_evidence_v1"
            or resume_evidence.get("status")
            != "CHECKPOINT_BYTES_VERIFIED"
        ):
            raise ValueError("Resume evidence manifest lifecycle invalid")
        if resume_evidence.get("protocol_file") != rel(protocol_path):
            raise ValueError("Resume evidence protocol mismatch")
        if (
            resume_evidence.get("request_contract_sha256")
            != prior_checkpoint.get("request_contract_sha256")
        ):
            raise ValueError("Resume evidence request-contract mismatch")
        observed_intent_raw_sha256 = (
            raw_sha256_file(attempt_intents_path)
            if attempt_intents_path.is_file()
            else None
        )
        if (
            resume_evidence.get("checkpoint_raw_sha256")
            != raw_sha256_file(checkpoint_path)
            or resume_evidence.get("generated_samples_raw_sha256")
            != raw_sha256_file(samples_path)
            or resume_evidence.get("attempt_ledger_raw_sha256")
            != raw_sha256_file(attempts_path)
            or resume_evidence.get("attempt_intent_ledger_raw_sha256")
            != observed_intent_raw_sha256
        ):
            raise ValueError(
                "Resume evidence raw-byte binding mismatch"
            )

        observed_code_hashes = sidecar_hashes(code_dir, "*.py")
        observed_req_hashes = sidecar_hashes(
            requirements_dir,
            "*_requirements.txt",
        )
        observed_journal_hashes = sidecar_hashes(
            accepted_journal_dir,
            "*.accepted.json",
        )
        if (
            observed_code_hashes
            != prior_checkpoint.get("code_sidecar_sha256")
            or observed_req_hashes
            != prior_checkpoint.get("requirements_sidecar_sha256")
            or observed_code_hashes
            != resume_evidence.get("code_sidecar_sha256")
            or observed_req_hashes
            != resume_evidence.get("requirements_sidecar_sha256")
            or observed_journal_hashes
            != prior_checkpoint.get("accepted_response_journal_sha256")
            or observed_journal_hashes
            != resume_evidence.get("accepted_response_journal_sha256")
        ):
            raise ValueError(
                "Resume sidecar/journal hash binding mismatch"
            )

        current_rows = read_jsonl(samples_path)
        current_success_ids = [
            str(row.get("sample_id") or "").strip()
            for row in current_rows
            if not str(row.get("generation_error") or "").strip()
        ]
        current_pending_ids = [
            str(row.get("sample_id") or "").strip()
            for row in current_rows
            if str(row.get("generation_error") or "").strip()
            and row.get("generation_failure_recovery_class")
            == "transport_pending"
        ]
        if (
            current_success_ids
            != prior_checkpoint.get("successful_sample_ids")
            or current_pending_ids
            != prior_checkpoint.get("transport_pending_ids")
            or current_success_ids
            != resume_evidence.get("successful_sample_ids")
            or current_pending_ids
            != resume_evidence.get("transport_pending_ids")
        ):
            raise ValueError(
                "Resume sample-identity checkpoint mismatch"
            )

        prior_attempts = read_jsonl(attempts_path)
        prior_attempt_counts: dict[str, int] = {}
        for attempt in prior_attempts:
            sample_id = str(attempt.get("sample_id") or "").strip()
            if sample_id:
                prior_attempt_counts[sample_id] = (
                    prior_attempt_counts.get(sample_id, 0) + 1
                )
        for sample_id in current_pending_ids:
            count = prior_attempt_counts.get(sample_id, 0)
            if count >= expected_max_total_attempts:
                raise ValueError(
                    "Resume total-attempt budget already exhausted for "
                    f"{sample_id}: {count}"
                )
        validate_generation_artifacts(
            prompt_rows=prompt_rows,
            generated_rows=current_rows,
            attempt_rows=prior_attempts,
            attempt_intent_rows=(
                read_jsonl(attempt_intents_path)
                if attempt_intents_path.is_file()
                else None
            ),
            code_dir=code_dir,
            requirements_dir=requirements_dir,
            accepted_journal_dir=accepted_journal_dir,
            expected_request_contract=expected_request_contract,
            expected_retries_per_invocation=expected_retries,
            expected_max_resume_rounds=expected_max_resume_rounds,
            expected_max_total_attempts=expected_max_total_attempts,
        )
        recovery_assessment = None
    elif args.resume:
        prior_checkpoint = None
        resume_evidence = None
        assessment_path = args.recovery_assessment_manifest.resolve()
        if not assessment_path.is_file():
            raise FileNotFoundError(
                f"Recovery assessment manifest missing: {assessment_path}"
            )
        recovery_assessment = read_json(assessment_path)
        if (
            recovery_assessment.get("schema_version")
            != "step9_generation_recovery_assessment_v1"
            or recovery_assessment.get("status")
            != "RECOVERY_EVIDENCE_CLASSIFIED"
        ):
            raise ValueError("Recovery assessment lifecycle invalid")
        if recovery_assessment.get("split") != args.split:
            raise ValueError("Recovery assessment split mismatch")
        if recovery_assessment.get("protocol_file") != rel(protocol_path):
            raise ValueError("Recovery assessment protocol mismatch")
        if (
            recovery_assessment.get("protocol_hash")
            != hash_record(protocol_path)
            or recovery_assessment.get("method_freeze_file")
            != rel(method_path)
            or recovery_assessment.get("method_freeze_hash")
            != hash_record(method_path)
        ):
            raise ValueError(
                "Recovery assessment protocol/method byte binding mismatch"
            )
        if (
            recovery_assessment.get("request_contract_sha256")
            != canonical_sha256_file_from_value(expected_request_contract)
        ):
            raise ValueError(
                "Recovery assessment request-contract mismatch"
            )
        successor_action = str(
            recovery_assessment.get("successor_recovery_action") or ""
        ).strip()
        selective_authority = recovery_assessment.get(
            "successor_selective_recovery_authority"
        )
        if not isinstance(selective_authority, dict):
            raise ValueError(
                "Recovery assessment lacks successor selective authority"
            )
        selective_recall_ids = [
            str(value).strip()
            for value in (
                selective_authority.get("provider_recall_sample_ids") or []
            )
            if str(value).strip()
        ]
        local_reconstruction_ids = [
            str(value).strip()
            for value in (
                recovery_assessment.get(
                    "journal_backed_local_reconstruction_ids"
                )
                or []
            )
            if str(value).strip()
        ]
        selective_recovery_resume = successor_action in {
            "SELECTIVE_RESUME",
            "LOCAL_RECONSTRUCT_AND_SELECTIVE_RESUME",
        }
        local_reconstruction_resume = successor_action in {
            "LOCAL_RECONSTRUCT",
            "LOCAL_RECONSTRUCT_AND_SELECTIVE_RESUME",
        }
        recovery_local_finalization = (
            successor_action == "LOCAL_FINALIZE"
        )
        if successor_action == "HARD_STOP_UNRESOLVED":
            raise ValueError(
                "Recovery assessment has unresolved state with no safe "
                "continuation budget"
            )
        if successor_action not in {
            "SELECTIVE_RESUME",
            "LOCAL_RECONSTRUCT",
            "LOCAL_RECONSTRUCT_AND_SELECTIVE_RESUME",
            "LOCAL_FINALIZE",
        }:
            raise ValueError(
                "Unknown successor recovery action: "
                f"{successor_action!r}"
            )

        states = recovery_assessment.get("sample_recovery_state")
        if not isinstance(states, dict):
            raise ValueError("Recovery assessment sample states missing")
        allowed_recall_states = {
            "PROVEN_NOT_STARTED",
            "PROVEN_RETRYABLE_PRECOMMIT_FAILURE",
        }
        invalid_recall_ids = sorted(
            sample_id
            for sample_id in selective_recall_ids
            if str(states.get(sample_id) or "").strip()
            not in allowed_recall_states
        )
        if invalid_recall_ids:
            raise ValueError(
                "Selective recovery attempted to recall terminal/unsafe "
                "samples: " + ", ".join(invalid_recall_ids)
            )
        invalid_local_ids = sorted(
            sample_id
            for sample_id in local_reconstruction_ids
            if str(states.get(sample_id) or "").strip()
            != "PROVEN_ACCEPTED"
        )
        if invalid_local_ids:
            raise ValueError(
                "Local reconstruction includes non-accepted samples: "
                + ", ".join(invalid_local_ids)
            )
        overlap = sorted(
            set(selective_recall_ids) & set(local_reconstruction_ids)
        )
        if overlap:
            raise ValueError(
                "Provider-recall and local-reconstruction sets overlap: "
                + ", ".join(overlap)
            )
        if selective_recovery_resume:
            if (
                selective_authority.get("selective_resume_authorized")
                is not True
                or not selective_recall_ids
            ):
                raise ValueError(
                    "Selective resume lacks sample-level recall authority"
                )
        elif selective_recall_ids:
            raise ValueError(
                "Non-selective recovery cannot carry provider recall IDs"
            )
        if local_reconstruction_resume:
            if not local_reconstruction_ids:
                raise ValueError(
                    "Local reconstruction action has no journal-backed IDs"
                )
        elif local_reconstruction_ids:
            raise ValueError(
                "Non-reconstruction action cannot carry local-only IDs"
            )
        if recovery_local_finalization:
            projected = recovery_assessment.get(
                "generation_outcome_projection"
            )
            if not isinstance(projected, dict):
                raise ValueError(
                    "Local-finalize assessment lacks outcome projection"
                )
            if projected.get("stage_evidence_status") not in {
                "FINALIZED_ALL_ACCEPTED",
                "FINALIZED_WITH_TERMINALS",
            }:
                raise ValueError(
                    "Local-finalize projection is not durably finalized"
                )

        def current_raw_sha256(path: Path) -> str | None:
            return raw_sha256_file(path) if path.is_file() else None

        if (
            recovery_assessment.get("generated_samples_raw_sha256")
            != current_raw_sha256(samples_path)
            or recovery_assessment.get("attempt_ledger_raw_sha256")
            != current_raw_sha256(attempts_path)
            or recovery_assessment.get("attempt_intent_ledger_raw_sha256")
            != current_raw_sha256(attempt_intents_path)
            or recovery_assessment.get("checkpoint_raw_sha256")
            != current_raw_sha256(checkpoint_path)
            or recovery_assessment.get("code_sidecar_sha256")
            != sidecar_hashes(code_dir, "*.py")
            or recovery_assessment.get("requirements_sidecar_sha256")
            != sidecar_hashes(requirements_dir, "*_requirements.txt")
            or recovery_assessment.get("accepted_response_journal_sha256")
            != sidecar_hashes(accepted_journal_dir, "*.accepted.json")
        ):
            raise ValueError(
                "Recovery assessment no longer matches current artifact bytes"
            )

        prior_resume_round = int(
            recovery_assessment.get("current_resume_round", 0)
        )
        next_resume_round = selective_authority.get("next_resume_round")
        if selective_recovery_resume:
            if next_resume_round != prior_resume_round + 1:
                raise ValueError(
                    "Selective recovery next resume round is inconsistent"
                )
            if prior_resume_round >= expected_max_resume_rounds:
                raise ValueError(
                    "Frozen maximum resume rounds already exhausted"
                )
        accepted_journal_dir.mkdir(parents=True, exist_ok=True)
    else:
        prior_resume_round = 0
        resume_evidence = None
        recovery_assessment = None
        generation_dir.mkdir(parents=True, exist_ok=False)
        code_dir.mkdir(parents=True, exist_ok=False)
        requirements_dir.mkdir(parents=True, exist_ok=False)
        prior_checkpoint = None

    cmd = [
        sys.executable,
        str(ROOT / "src/generate_code_from_prompts.py"),
        "--prompts",
        str(prompts),
        "--out",
        str(samples_path),
        "--code-dir",
        str(code_dir),
        "--requirements-dir",
        str(requirements_dir),
        "--limit",
        str(declared_size),
        "--start",
        "1",
        "--model",
        model,
        "--timeout",
        str(args.timeout),
        "--retries",
        str(args.retries),
        "--temperature",
        str(expected_temperature),
        "--base-url",
        provider_endpoint,
        "--attempt-ledger",
        str(attempts_path),
        "--attempt-intent-ledger",
        str(attempt_intents_path),
        "--accepted-journal-dir",
        str(accepted_journal_dir),
        "--resume-round",
        str(
            max(
                1,
                prior_resume_round
                + (1 if selective_recovery_resume else 0),
            )
            if args.resume
            else 0
        ),
        "--real",
    ]
    if expected_transport_mode == "streaming_sse":
        cmd.extend(
            [
                "--stream",
                "--connect-timeout",
                str(expected_connect_timeout),
                "--read-timeout",
                str(expected_read_timeout),
                "--request-deadline",
                str(expected_request_deadline),
                "--max-tokens",
                str(expected_max_tokens),
                "--retry-backoff-seconds",
                ",".join(
                    str(value) for value in expected_retry_backoff
                ),
            ]
        )
    if args.resume:
        cmd.append("--resume")
    if selective_recovery_resume:
        for sample_id in selective_recall_ids:
            cmd.extend(["--resume-eligible-sample-id", sample_id])
    if local_reconstruction_resume:
        for sample_id in local_reconstruction_ids:
            cmd.extend(["--resume-local-only-sample-id", sample_id])
    cmd = append_generation_adapter_cli(
        cmd,
        enable_thinking=expected_enable_thinking,
        response_format=expected_response_format,
        reasoning_effort=expected_reasoning_effort,
    )
    if recovery_local_finalization:
        print(
            "[LOCAL FINALIZE] recovery outcome already final; provider call forbidden"
        )
    else:
        subprocess.run(cmd, cwd=ROOT, check=True)

    rows = read_jsonl(samples_path) if samples_path.is_file() else []
    if (
        recovery_local_finalization
        or selective_recovery_resume
        or local_reconstruction_resume
    ):
        if len(rows) > declared_size:
            raise ValueError(
                "Recovered generated row count exceeds frozen split size"
            )
    elif len(rows) != declared_size:
        raise ValueError(
            f"Generated row count mismatch: {len(rows)} != {declared_size}"
        )

    success_rows = [
        row
        for row in rows
        if not str(row.get("generation_error") or "").strip()
    ]
    transport_pending_rows = [
        row
        for row in rows
        if str(row.get("generation_error") or "").strip()
        and row.get("generation_failure_recovery_class")
        == "transport_pending"
    ]
    all_attempt_rows = (
        read_jsonl(attempts_path)
        if attempts_path.is_file()
        else []
    )
    all_attempt_intent_rows = (
        read_jsonl(attempt_intents_path)
        if attempt_intents_path.is_file()
        else []
    )
    if not recovery_local_finalization:
        if not attempts_path.is_file():
            raise FileNotFoundError(attempts_path)
        if not attempt_intents_path.is_file():
            raise FileNotFoundError(attempt_intents_path)
    if (
        recovery_local_finalization
        or selective_recovery_resume
        or local_reconstruction_resume
    ):
        reliability_validation = {
            "request_contract_sha256": (
                canonical_sha256_file_from_value(
                    expected_request_contract
                )
            ),
            "validation_source": (
                "post_recovery_reclassification"
                if (
                    selective_recovery_resume
                    or local_reconstruction_resume
                )
                else "byte_bound_recovery_assessment"
            ),
        }
    else:
        reliability_validation = validate_generation_artifacts(
            prompt_rows=prompt_rows,
            generated_rows=rows,
            attempt_rows=all_attempt_rows,
            attempt_intent_rows=all_attempt_intent_rows,
            code_dir=code_dir,
            requirements_dir=requirements_dir,
            accepted_journal_dir=accepted_journal_dir,
            expected_request_contract=expected_request_contract,
            expected_retries_per_invocation=expected_retries,
            expected_max_resume_rounds=expected_max_resume_rounds,
            expected_max_total_attempts=expected_max_total_attempts,
        )
    attempt_counts: dict[str, int] = {}
    for attempt in all_attempt_rows:
        sample_id = str(attempt.get("sample_id") or "").strip()
        if sample_id:
            attempt_counts[sample_id] = (
                attempt_counts.get(sample_id, 0) + 1
            )
    over_budget_ids = sorted(
        sample_id
        for sample_id, count in attempt_counts.items()
        if count > expected_max_total_attempts
    )
    if over_budget_ids:
        raise ValueError(
            "Generation exceeded frozen total-attempt budget: "
            + ", ".join(over_budget_ids)
        )
    retry_budget_exhausted_ids = sorted(
        str(row.get("sample_id") or "").strip()
        for row in transport_pending_rows
        if attempt_counts.get(
            str(row.get("sample_id") or "").strip(), 0
        )
        >= expected_max_total_attempts
    )

    selection_path = ROOT / protocol["planned_outputs"][
        "selection_manifest"
    ]
    post_recovery_assessment = None
    if recovery_local_finalization:
        outcome_manifest = build_manifest_from_recovery(
            split=args.split,
            protocol_id=str(protocol.get("protocol_id") or ""),
            selection_manifest_hash=hash_record(selection_path)["sha256"],
            method_closure_sha256=str(
                method.get("method_closure_sha256") or ""
            ),
            request_contract_sha256=reliability_validation[
                "request_contract_sha256"
            ],
            selected_records=prompt_rows,
            generated_rows=rows,
            attempt_rows=all_attempt_rows,
            recovery_assessment=recovery_assessment,
            attempts_ref=rel(attempts_path),
            accepted_journal_dir_ref=rel(accepted_journal_dir),
            generated_samples_ref=rel(samples_path),
            code_dir_ref=rel(code_dir),
            requirements_dir_ref=rel(requirements_dir),
        )
        if outcome_manifest != recovery_assessment.get(
            "generation_outcome_projection"
        ):
            raise ValueError(
                "Local recovery outcome projection drifted after assessment"
            )
    elif selective_recovery_resume or local_reconstruction_resume:
        post_recovery_assessment = assess_partial_generation_artifacts(
            prompt_rows=prompt_rows,
            attempt_intent_rows=all_attempt_intent_rows,
            attempt_rows=all_attempt_rows,
            generated_rows=rows,
            accepted_journal_dir=accepted_journal_dir,
            expected_request_contract=expected_request_contract,
            expected_max_total_attempts=expected_max_total_attempts,
            expected_max_resume_rounds=expected_max_resume_rounds,
            code_dir=code_dir,
            requirements_dir=requirements_dir,
        )
        outcome_manifest = build_manifest_from_recovery(
            split=args.split,
            protocol_id=str(protocol.get("protocol_id") or ""),
            selection_manifest_hash=hash_record(selection_path)["sha256"],
            method_closure_sha256=str(
                method.get("method_closure_sha256") or ""
            ),
            request_contract_sha256=reliability_validation[
                "request_contract_sha256"
            ],
            selected_records=prompt_rows,
            generated_rows=rows,
            attempt_rows=all_attempt_rows,
            recovery_assessment=post_recovery_assessment,
            attempts_ref=rel(attempts_path),
            accepted_journal_dir_ref=rel(accepted_journal_dir),
            generated_samples_ref=rel(samples_path),
            code_dir_ref=rel(code_dir),
            requirements_dir_ref=rel(requirements_dir),
        )
    else:
        outcome_manifest = build_manifest_from_generation(
            split=args.split,
            protocol_id=str(protocol.get("protocol_id") or ""),
            selection_manifest_hash=hash_record(selection_path)["sha256"],
            method_closure_sha256=str(
                method.get("method_closure_sha256") or ""
            ),
            request_contract_sha256=reliability_validation[
                "request_contract_sha256"
            ],
            selected_records=prompt_rows,
            generated_rows=rows,
            attempt_rows=all_attempt_rows,
            retry_budget_exhausted_ids=retry_budget_exhausted_ids,
            attempts_ref=rel(attempts_path),
            accepted_journal_dir_ref=rel(accepted_journal_dir),
            generated_samples_ref=rel(samples_path),
            code_dir_ref=rel(code_dir),
            requirements_dir_ref=rel(requirements_dir),
        )

    retry_budget_exhausted_ids = [
        str(row.get("sample_id") or "")
        for row in outcome_manifest.get("outcome_records", [])
        if row.get("final_outcome")
        == "TERMINAL_RETRY_BUDGET_EXHAUSTED"
    ]
    success_rows = accepted_rows_from_manifest(
        generated_rows=rows,
        manifest=outcome_manifest,
    )
    outcome_status = str(
        outcome_manifest.get("stage_evidence_status") or ""
    )
    eligibility = evaluate_split_statistical_eligibility(
        outcome_manifest
    )

    generated_samples_zero_row_materialized = False
    if not samples_path.is_file():
        if rows:
            raise ValueError(
                "Generated rows exist but generated_samples artifact is missing"
            )
        if outcome_status != "FINALIZED_WITH_TERMINALS":
            raise FileNotFoundError(
                "Final generation stage lacks generated_samples artifact: "
                f"{samples_path}"
            )
        materialize_empty_generated_samples_artifact(samples_path)
        generated_samples_zero_row_materialized = True

    unresolved_sample_ids = list(
        outcome_manifest.get("unresolved_sample_ids") or []
    )
    unresolved_transport_ids = [
        str(row.get("sample_id") or "").strip()
        for row in transport_pending_rows
        if str(row.get("sample_id") or "").strip()
        in set(unresolved_sample_ids)
    ]

    prior_sequence = (
        int(prior_checkpoint.get("checkpoint_sequence", 0))
        if isinstance(prior_checkpoint, dict)
        else 0
    )
    checkpoint = {
        "schema_version": "step9_generation_checkpoint_manifest_v1",
        "status": (
            "COMPLETE"
            if outcome_status == "FINALIZED_ALL_ACCEPTED"
            else (
                "FINALIZED_WITH_TERMINALS"
                if outcome_status == "FINALIZED_WITH_TERMINALS"
                else (
                    (
                        "INCOMPLETE_TRANSPORT_PENDING"
                        if set(unresolved_sample_ids)
                        == set(unresolved_transport_ids)
                        else "INCOMPLETE_RECOVERY_PENDING"
                    )
                    if outcome_status == "UNRESOLVED_RECOVERY_PENDING"
                    else "EVIDENCE_INVALID"
                )
            )
        ),
        "split": args.split,
        "protocol_file": rel(protocol_path),
        "protocol_hash": hash_record(protocol_path),
        "selection_manifest_file": rel(
            ROOT / protocol["planned_outputs"]["selection_manifest"]
        ),
        "selection_manifest_hash": hash_record(
            ROOT / protocol["planned_outputs"]["selection_manifest"]
        ),
        "method_freeze_file": rel(method_path),
        "method_freeze_hash": hash_record(method_path),
        "method_closure_sha256": method.get("method_closure_sha256"),
        "prompt_file": rel(prompts),
        "prompt_sha256": canonical_sha256_file(prompts),
        "declared_size": declared_size,
        "successful_sample_count": len(success_rows),
        "successful_sample_ids": [
            str(row.get("sample_id") or "").strip()
            for row in success_rows
        ],
        "transport_pending_ids": unresolved_transport_ids,
        "unresolved_sample_ids": unresolved_sample_ids,
        "selective_recovery_resume": selective_recovery_resume,
        "selective_recall_sample_ids": selective_recall_ids,
        "local_reconstruction_resume": local_reconstruction_resume,
        "local_reconstruction_sample_ids": local_reconstruction_ids,
        "terminal_failure_ids": list(
            outcome_manifest.get("terminal_sample_ids") or []
        ),
        "retry_budget_exhausted_ids": retry_budget_exhausted_ids,
        "generation_outcome_stage_status": outcome_status,
        "generation_outcome_manifest_file": (
            rel(outcome_manifest_path)
            if outcome_status
            in {"FINALIZED_ALL_ACCEPTED", "FINALIZED_WITH_TERMINALS"}
            else None
        ),
        "generation_outcome_manifest_content_sha256": (
            outcome_manifest.get("manifest_content_sha256")
            if outcome_status
            in {"FINALIZED_ALL_ACCEPTED", "FINALIZED_WITH_TERMINALS"}
            else None
        ),
        "accepted_complete_count": outcome_manifest.get(
            "accepted_complete_count"
        ),
        "terminal_count": outcome_manifest.get("terminal_count"),
        "unresolved_count": outcome_manifest.get("unresolved_count"),
        "attempt_count_by_sample": attempt_counts,
        "max_resume_rounds": expected_max_resume_rounds,
        "max_total_attempts_per_prompt": expected_max_total_attempts,
        "resume_round": (
            prior_resume_round
            if (
                recovery_local_finalization
                or (local_reconstruction_resume and not selective_recovery_resume)
            )
            else (prior_resume_round + 1 if args.resume else 0)
        ),
        "resume_evidence_manifest": (
            rel(args.resume_evidence_manifest)
            if args.resume_evidence_manifest is not None
            else None
        ),
        "generated_samples_file": rel(samples_path),
        "generated_samples_sha256": (
            canonical_sha256_file(samples_path)
            if samples_path.is_file()
            else None
        ),
        "generated_samples_zero_row_materialized": (
            generated_samples_zero_row_materialized
        ),
        "attempt_ledger_file": rel(attempts_path),
        "attempt_ledger_sha256": (
            canonical_sha256_file(attempts_path)
            if attempts_path.is_file()
            else None
        ),
        "attempt_intent_ledger_file": rel(attempt_intents_path),
        "attempt_intent_ledger_sha256": (
            canonical_sha256_file(attempt_intents_path)
            if attempt_intents_path.is_file()
            else None
        ),
        "code_sidecar_sha256": sidecar_hashes(code_dir, "*.py"),
        "requirements_sidecar_sha256": sidecar_hashes(
            requirements_dir,
            "*_requirements.txt",
        ),
        "accepted_response_journal_sha256": sidecar_hashes(
            accepted_journal_dir,
            "*.accepted.json",
        ),
        "request_contract_sha256": reliability_validation[
            "request_contract_sha256"
        ],
        "model": model,
        "provider_endpoint": provider_endpoint,
        "temperature": expected_temperature,
        "reasoning_effort": expected_reasoning_effort,
        "enable_thinking": expected_enable_thinking,
        "response_format": expected_response_format,
        "generation_adapter_contract_revision": adapter_revision or None,
        "transport_mode": expected_transport_mode,
        "connect_timeout_seconds": expected_connect_timeout,
        "stream_read_timeout_seconds": expected_read_timeout,
        "request_deadline_seconds": expected_request_deadline,
        "max_tokens": expected_max_tokens,
        "retries": expected_retries,
        "retry_backoff_seconds": expected_retry_backoff,
        "checkpoint_sequence": prior_sequence + 1,
        "resumed_from_checkpoint": bool(args.resume),
        "scientific_boundary": {
            "successful_samples_must_never_be_regenerated": True,
            "provider_attempt_armed_before_network_call": True,
            "armed_attempt_without_durable_outcome_is_ambiguous": True,
            "ambiguous_in_flight_provider_recall_forbidden": True,
            "accepted_response_committed_before_output_row": True,
            "accepted_response_journal_bound_to_prompt_and_request": True,
            "only_transport_pending_samples_are_resume_eligible": True,
            "terminal_model_output_failures_are_not_auto_retried": True,
            "checkpoint_must_be_persisted_before_resume": True,
            "release_snapshot_acquired_before_complete_generation": False,
            "recovery_local_finalization": (
                recovery_local_finalization
            ),
            "local_recovery_finalization_provider_call_forbidden": True,
            "terminal_sample_provider_recall_forbidden": True,
            "generation_outcome_projection_recomputed_before_sealing": (
                recovery_local_finalization
                or selective_recovery_resume
                or local_reconstruction_resume
            ),
        },
    }
    write_checkpoint_json(checkpoint_path, checkpoint)

    if outcome_status == "EVIDENCE_INVALID":
        raise ValueError(
            "Generation outcome accounting is evidence-invalid: "
            + "; ".join(
                str(value)
                for value in outcome_manifest.get(
                    "validation_errors", []
                )
            )
        )
    if outcome_status == "UNRESOLVED_RECOVERY_PENDING":
        raise ValueError(
            "Generation checkpoint incomplete with unresolved samples: "
            + ", ".join(
                str(value)
                for value in outcome_manifest.get(
                    "unresolved_sample_ids", []
                )
            )
        )
    if outcome_status not in {
        "FINALIZED_ALL_ACCEPTED",
        "FINALIZED_WITH_TERMINALS",
    }:
        raise ValueError(
            f"Unexpected generation outcome stage status: {outcome_status!r}"
        )
    write_json(outcome_manifest_path, outcome_manifest)
    stage_finalized_at = datetime.now(timezone.utc).isoformat()

    generation_times = []
    for row in success_rows:
        sample_id = str(row.get("sample_id") or "").strip()
        if str(row.get("model") or "").strip() != model:
            raise ValueError(f"Requested model mismatch for {sample_id}")
        if str(row.get("api_reported_model") or "").strip() != model:
            raise ValueError(f"API-reported model mismatch for {sample_id}")
        if float(row.get("generation_temperature")) != expected_temperature:
            raise ValueError(
                f"Generation temperature mismatch for {sample_id}"
            )
        if str(
            row.get("generation_reasoning_effort") or ""
        ).strip() != str(expected_reasoning_effort or ""):
            raise ValueError(
                f"Generation reasoning_effort mismatch for {sample_id}"
            )
        if row.get("generation_enable_thinking") != expected_enable_thinking:
            raise ValueError(
                f"Generation enable_thinking mismatch for {sample_id}"
            )
        if str(
            row.get("generation_response_format") or "text"
        ).strip() != expected_response_format:
            raise ValueError(
                f"Generation response_format mismatch for {sample_id}"
            )
        if str(row.get("generation_transport_mode") or "").strip() != (
            expected_transport_mode
        ):
            raise ValueError(
                f"Generation transport mismatch for {sample_id}"
            )
        if row.get("generation_max_tokens") != expected_max_tokens:
            raise ValueError(
                f"Generation max_tokens mismatch for {sample_id}"
            )
        if str(row.get("generation_provider_endpoint") or "").strip() != (
            provider_endpoint
        ):
            raise ValueError(
                f"Generation provider endpoint mismatch for {sample_id}"
            )
        if row.get("generation_provider_endpoint_source") != "explicit_argument":
            raise ValueError(
                f"Generation endpoint was not explicitly protocol-bound for {sample_id}"
            )
        generated_at = require_aware_utc(
            row.get("generation_time"),
            label=f"generation_stage.{sample_id}.generation_time",
        )
        request_started = require_aware_utc(
            row.get("generation_request_started_at"),
            label=(
                f"generation_stage.{sample_id}."
                "generation_request_started_at"
            ),
        )
        response_completed = require_aware_utc(
            row.get("generation_response_completed_at"),
            label=(
                f"generation_stage.{sample_id}."
                "generation_response_completed_at"
            ),
        )
        if request_started > response_completed:
            raise ValueError(
                f"Generation request interval inverted for {sample_id}"
            )
        if generated_at != response_completed:
            raise ValueError(
                f"generation_time is not response completion for {sample_id}"
            )
        observed_seconds = row.get(
            "generation_observed_request_seconds"
        )
        if not isinstance(observed_seconds, (int, float)):
            raise ValueError(
                f"Observed generation interval missing for {sample_id}"
            )
        measured_seconds = (
            response_completed - request_started
        ).total_seconds()
        if abs(float(observed_seconds) - measured_seconds) > 0.01:
            raise ValueError(
                f"Observed generation interval mismatch for {sample_id}"
            )
        if measured_seconds > uncertainty_seconds:
            raise ValueError(
                f"Generation interval exceeds frozen Δt for {sample_id}: "
                f"{measured_seconds} > {uncertainty_seconds}"
            )
        generation_times.append(generated_at)

    accepted_sample_ids = [
        str(value).strip()
        for value in (outcome_manifest.get("accepted_sample_ids") or [])
        if str(value).strip()
    ]
    accepted_count = int(
        outcome_manifest.get("accepted_complete_count") or 0
    )
    if len(accepted_sample_ids) != accepted_count:
        raise ValueError("Accepted sample identity count mismatch")
    code_hashes = sidecar_hashes_for_sample_ids(
        code_dir,
        sample_ids=accepted_sample_ids,
        suffix=".py",
    )
    requirement_hashes = sidecar_hashes_for_sample_ids(
        requirements_dir,
        sample_ids=accepted_sample_ids,
        suffix="_requirements.txt",
    )
    accepted_journal_hashes = sidecar_hashes_for_sample_ids(
        accepted_journal_dir,
        sample_ids=accepted_sample_ids,
        suffix=".accepted.json",
    )

    manifest = {
        "schema_version": "step9_generation_stage_manifest_v1",
        "status": "PASS",
        "split": args.split,
        "protocol_file": rel(protocol_path),
        "protocol_hash": hash_record(protocol_path),
        "selection_manifest_file": rel(selection_path),
        "selection_manifest_hash": hash_record(selection_path),
        "method_freeze_file": rel(method_path),
        "method_freeze_hash": hash_record(method_path),
        "method_closure_sha256": method.get("method_closure_sha256"),
        "prompt_file": rel(prompts),
        "prompt_sha256": canonical_sha256_file(prompts),
        "declared_size": declared_size,
        "generated_sample_count": len(rows),
        "selected_count": declared_size,
        "accepted_complete_count": accepted_count,
        "terminal_count": int(outcome_manifest.get("terminal_count") or 0),
        "unresolved_count": int(
            outcome_manifest.get("unresolved_count") or 0
        ),
        "stage_evidence_status": outcome_status,
        "generation_outcome_manifest_file": rel(outcome_manifest_path),
        "generation_outcome_manifest_hash": hash_record(
            outcome_manifest_path
        ),
        "generation_outcome_manifest_content_sha256": (
            outcome_manifest.get("manifest_content_sha256")
        ),
        "statistical_eligibility": eligibility,
        "stage_finalized_at": stage_finalized_at,
        "model": model,
        "provider": provider,
        "provider_region": provider_region,
        "provider_endpoint": provider_endpoint,
        "temperature": expected_temperature,
        "reasoning_effort": expected_reasoning_effort,
        "enable_thinking": expected_enable_thinking,
        "response_format": expected_response_format,
        "generation_adapter_contract_revision": adapter_revision or None,
        "timeout_seconds": expected_timeout,
        "retries": expected_retries,
        "transport_mode": expected_transport_mode,
        "connect_timeout_seconds": expected_connect_timeout,
        "stream_read_timeout_seconds": expected_read_timeout,
        "request_deadline_seconds": expected_request_deadline,
        "max_tokens": expected_max_tokens,
        "retry_backoff_seconds": expected_retry_backoff,
        "max_resume_rounds": expected_max_resume_rounds,
        "max_total_attempts_per_prompt": expected_max_total_attempts,
        "resume_round": checkpoint["resume_round"],
        "attempt_count_by_sample": attempt_counts,
        "generation_checkpoint_manifest_file": rel(checkpoint_path),
        "generation_checkpoint_manifest_hash": hash_record(checkpoint_path),
        "attempt_ledger_file": rel(attempts_path),
        "attempt_ledger_hash": (
            hash_record(attempts_path)
            if attempts_path.is_file()
            else None
        ),
        "attempt_intent_ledger_file": rel(attempt_intents_path),
        "attempt_intent_ledger_hash": (
            hash_record(attempt_intents_path)
            if attempt_intents_path.is_file()
            else None
        ),
        "recovery_assessment_manifest": (
            rel(args.recovery_assessment_manifest)
            if args.recovery_assessment_manifest is not None
            else None
        ),
        "recovery_assessment_stage_status": (
            recovery_assessment.get("stage_recovery_status")
            if recovery_assessment is not None
            else None
        ),
        "recovery_assessment_raw_sha256": (
            raw_sha256_file(args.recovery_assessment_manifest)
            if args.recovery_assessment_manifest is not None
            else None
        ),
        "resume_used": bool(args.resume),
        "recovered_after_retry_count": sum(
            1
            for row in rows
            if row.get("generation_recovered_after_retry") is True
        ),
        "generation_time_min": (
            utc_iso(min(generation_times))
            if generation_times
            else None
        ),
        "generation_time_max": (
            utc_iso(max(generation_times))
            if generation_times
            else None
        ),
        "generation_time_uncertainty_seconds": uncertainty_seconds,
        "generation_time_uncertainty_semantics": (
            "pre-frozen conservative upper bound on the successful real "
            "request interval ending at generation_time"
        ),
        "generated_samples_file": rel(samples_path),
        "generated_samples_sha256": canonical_sha256_file(samples_path),
        "generated_samples_zero_row_materialized": (
            generated_samples_zero_row_materialized
        ),
        "code_sidecar_sha256": code_hashes,
        "requirements_sidecar_sha256": requirement_hashes,
        "accepted_response_journal_sha256": accepted_journal_hashes,
        "request_contract_sha256": reliability_validation[
            "request_contract_sha256"
        ],
        "scientific_boundary": {
            "real_generation": True,
            "generation_provider_endpoint_protocol_bound": True,
            "generation_reasoning_effort_protocol_bound": (
                expected_reasoning_effort is not None
            ),
            "generation_thinking_mode_protocol_bound": (
                expected_enable_thinking is not None
            ),
            "generation_response_format_protocol_bound": True,
            "local_provider_endpoint_override_used": False,
            "generation_time_source": "runtime_completion_clock",
            "generation_request_interval_recorded": True,
            "observed_request_interval_must_fit_frozen_delta_t": True,
            "generation_time_override_used": False,
            "method_freeze_verified_before_generation": True,
            "release_snapshot_acquired_before_generation": False,
            "registry_temporal_evidence_must_be_acquired_after_generation": True,
            "generated_results_not_used_to_change_method_or_selection": True,
            "streaming_transport_protocol_bound": (
                expected_transport_mode == "streaming_sse"
            ),
            "durable_checkpoint_protocol_bound": True,
            "successful_samples_never_regenerated_on_resume": True,
            "resume_only_classifier_proven_nonfinal_samples": True,
            "selective_resume_sample_allowlist_enforced": True,
            "journal_backed_local_reconstruction_allowlist_enforced": True,
            "journal_backed_local_reconstruction_provider_call_forbidden": True,
            "terminal_or_ambiguous_samples_never_recalled": True,
            "terminal_only_zero_row_artifact_is_empty_jsonl": True,
            "resume_requires_byte_bound_authority_evidence": True,
            "resume_rounds_bounded": True,
            "total_attempts_per_prompt_bounded": True,
            "attempt_ledger_state_machine_validated": True,
            "attempt_intent_precedes_provider_call": True,
            "ambiguous_in_flight_fail_closed_for_that_sample": True,
            "mixed_terminal_and_nonfinal_does_not_suppress_safe_recall": True,
            "crash_recovery_assessment_byte_bound_when_used": (
                recovery_assessment is not None
            ),
            "accepted_project_sidecar_journal_closure_validated": True,
            "terminal_artifact_shape_does_not_define_analysis_population": True,
            "generation_outcome_accounting_byte_bound": True,
            "terminal_generation_outcomes_are_final_not_negative": True,
            "terminal_generation_outcomes_are_not_dependency_unknown": True,
            "analysis_population_is_accepted_complete_only": True,
            "stage_finalization_is_separate_from_all_accepted_success": True,
            "statistical_eligibility_does_not_change_generation_outcome": True,
        },
    }
    write_json(manifest_path, manifest)

    print("STEP9 REAL GENERATION STAGE PASS")
    print("split =", args.split)
    print("selected_samples =", declared_size)
    print("generated_rows_present =", len(rows))
    print("accepted_complete =", manifest["accepted_complete_count"])
    print("terminal_count =", manifest["terminal_count"])
    print("stage_evidence_status =", manifest["stage_evidence_status"])
    print("statistical_eligibility =", eligibility["status"])
    print("generation_time_min =", manifest["generation_time_min"])
    print("generation_time_max =", manifest["generation_time_max"])
    print("saved =", rel(manifest_path))


@contextmanager
def generation_stage_execution_lock(root: Path):
    """Serialize this checkout's stage preflight, resume and evidence writes.

    The OS releases the lease on process exit/crash. Its persistent temporary
    marker is neither scientific evidence nor a new execution authority.
    Separate CI runners still rely on the existing workflow/authority guards.
    """
    key = hashlib.sha256(os.path.normcase(str(root.resolve())).encode("utf-8")).hexdigest()
    lock_dir = Path(tempfile.gettempdir()) / "codesentry-generation-stage-locks"
    lock_dir.mkdir(parents=True, exist_ok=True)
    with (lock_dir / (key + ".lock")).open("a+b") as handle:
        if os.name == "nt":
            import msvcrt
            if handle.seek(0, os.SEEK_END) == 0:
                handle.write(b"\0")
                handle.flush()
            handle.seek(0)
            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise RuntimeError("Generation stage execution already active in this checkout") from exc
            try:
                yield
            finally:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        elif os.name == "posix":
            import fcntl
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise RuntimeError("Generation stage execution already active in this checkout") from exc
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        else:
            raise RuntimeError("Generation stage execution lock unavailable on this platform")


def main() -> None:
    args = parse_args()
    # Acquire before all authority/checkpoint reads, not just the subprocess;
    # otherwise a queued child could execute stale preflight/retry authority.
    with generation_stage_execution_lock(ROOT):
        _run_generation_stage(args)


if __name__ == "__main__":
    main()
