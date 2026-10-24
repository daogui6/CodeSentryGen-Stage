from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return value


def raw_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_jsonl(path: Path) -> list[dict[str, Any]]:
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


def atomic_write_json(path: Path, value: dict[str, Any]) -> None:
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
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        try:
            parent_fd = os.open(str(path.parent), flags)
        except OSError:
            parent_fd = None
        if parent_fd is not None:
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
    except Exception:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass
        raise


def build_checkpoint_evidence(
    *,
    checkpoint_path: Path,
    output_path: Path,
    root: Path | None = None,
) -> dict[str, Any]:
    checkpoint = read_json(checkpoint_path)
    if checkpoint.get("status") != "INCOMPLETE_TRANSPORT_PENDING":
        raise ValueError(
            "Checkpoint evidence can only be built for "
            "INCOMPLETE_TRANSPORT_PENDING state"
        )
    if checkpoint.get("terminal_failure_ids"):
        raise ValueError(
            "Checkpoint evidence cannot authorize terminal failures"
        )
    if checkpoint.get("retry_budget_exhausted_ids"):
        raise ValueError(
            "Checkpoint evidence cannot authorize exhausted retry budget"
        )

    resolution_root = (
        root.resolve() if root is not None else Path.cwd().resolve()
    )
    generated_samples = Path(str(checkpoint["generated_samples_file"]))
    attempt_ledger = Path(str(checkpoint["attempt_ledger_file"]))
    attempt_intent_value = checkpoint.get("attempt_intent_ledger_file")
    attempt_intent_ledger = (
        Path(str(attempt_intent_value))
        if attempt_intent_value is not None
        else None
    )
    if not generated_samples.is_absolute():
        generated_samples = resolution_root / generated_samples
    if not attempt_ledger.is_absolute():
        attempt_ledger = resolution_root / attempt_ledger
    if (
        attempt_intent_ledger is not None
        and not attempt_intent_ledger.is_absolute()
    ):
        attempt_intent_ledger = (
            resolution_root / attempt_intent_ledger
        )
    if not generated_samples.is_file():
        raise FileNotFoundError(generated_samples)
    if not attempt_ledger.is_file():
        raise FileNotFoundError(attempt_ledger)
    if (
        attempt_intent_ledger is not None
        and not attempt_intent_ledger.is_file()
    ):
        raise FileNotFoundError(attempt_intent_ledger)

    rows = read_jsonl(generated_samples)
    observed_ids = [str(row.get("sample_id") or "").strip() for row in rows]
    if len(set(observed_ids)) != len(observed_ids):
        raise ValueError("Generated samples contain duplicate sample_id")
    successful_ids = [
        str(row.get("sample_id") or "").strip()
        for row in rows
        if not str(row.get("generation_error") or "").strip()
    ]
    pending_ids = [
        str(row.get("sample_id") or "").strip()
        for row in rows
        if str(row.get("generation_error") or "").strip()
        and row.get("generation_failure_recovery_class")
        == "transport_pending"
    ]
    if successful_ids != checkpoint.get("successful_sample_ids"):
        raise ValueError("Checkpoint successful sample IDs mismatch")
    if pending_ids != checkpoint.get("transport_pending_ids"):
        raise ValueError("Checkpoint pending sample IDs mismatch")

    journal_hashes = checkpoint.get("accepted_response_journal_sha256")
    if not isinstance(journal_hashes, dict):
        raise ValueError(
            "Checkpoint accepted-response journal hashes missing"
        )
    if len(journal_hashes) != len(successful_ids):
        raise ValueError(
            "Checkpoint journal count does not match successful samples"
        )

    evidence = {
        "schema_version": "step9_generation_checkpoint_evidence_v1",
        "status": "CHECKPOINT_BYTES_VERIFIED",
        "protocol_file": checkpoint["protocol_file"],
        "protocol_hash": checkpoint["protocol_hash"],
        "selection_manifest_file": checkpoint["selection_manifest_file"],
        "selection_manifest_hash": checkpoint["selection_manifest_hash"],
        "method_freeze_file": checkpoint["method_freeze_file"],
        "method_freeze_hash": checkpoint["method_freeze_hash"],
        "method_closure_sha256": checkpoint["method_closure_sha256"],
        "prompt_file": checkpoint["prompt_file"],
        "prompt_sha256": checkpoint["prompt_sha256"],
        "request_contract_sha256": checkpoint["request_contract_sha256"],
        "checkpoint_file": checkpoint_path.as_posix(),
        "checkpoint_raw_sha256": raw_sha256(checkpoint_path),
        "generated_samples_file": generated_samples.as_posix(),
        "generated_samples_raw_sha256": raw_sha256(generated_samples),
        "attempt_ledger_file": attempt_ledger.as_posix(),
        "attempt_ledger_raw_sha256": raw_sha256(attempt_ledger),
        "attempt_intent_ledger_file": (
            attempt_intent_ledger.as_posix()
            if attempt_intent_ledger is not None
            else None
        ),
        "attempt_intent_ledger_raw_sha256": (
            raw_sha256(attempt_intent_ledger)
            if attempt_intent_ledger is not None
            else None
        ),
        "code_sidecar_sha256": checkpoint["code_sidecar_sha256"],
        "requirements_sidecar_sha256": checkpoint[
            "requirements_sidecar_sha256"
        ],
        "accepted_response_journal_sha256": journal_hashes,
        "successful_sample_ids": successful_ids,
        "accepted_complete_sample_ids": successful_ids,
        "transport_pending_ids": pending_ids,
        "generation_outcome_accounting_state": (
            "UNRESOLVED_RECOVERY_PENDING"
        ),
        "attempt_count_by_sample": checkpoint["attempt_count_by_sample"],
        "checkpoint_sequence": checkpoint["checkpoint_sequence"],
        "resume_round": checkpoint["resume_round"],
        "max_resume_rounds": checkpoint["max_resume_rounds"],
        "max_total_attempts_per_prompt": checkpoint[
            "max_total_attempts_per_prompt"
        ],
        "scientific_boundary": {
            "successful_samples_must_not_be_regenerated": True,
            "provider_attempt_intents_are_byte_bound": (
                attempt_intent_ledger is not None
            ),
            "only_transport_pending_samples_are_resume_eligible": True,
            "accepted_response_journals_are_byte_bound": True,
            "resume_must_restore_exact_checkpoint_bytes": True,
            "resume_must_restore_exact_generated_sample_bytes": True,
            "resume_must_restore_exact_attempt_ledger_bytes": True,
            "resume_must_restore_exact_sidecar_hashes": True,
            "checkpoint_evidence_is_unresolved_only": True,
            "terminal_final_outcome_resume_forbidden": True,
            "accepted_complete_samples_remain_in_selected_accounting": True,
            "checkpoint_does_not_authorize_downstream_analysis": True,
        },
    }

    if output_path.exists():
        raise FileExistsError(f"Refusing overwrite: {output_path}")
    atomic_write_json(output_path, evidence)
    return evidence


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--checkpoint", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument(
        "--root",
        type=Path,
        default=None,
        help="Root used to resolve checkpoint-relative artifact paths.",
    )
    args = parser.parse_args()
    evidence = build_checkpoint_evidence(
        checkpoint_path=args.checkpoint,
        output_path=args.out,
        root=args.root,
    )
    print("STEP9 GENERATION CHECKPOINT EVIDENCE PASS")
    print("status =", evidence["status"])
    print("successful_sample_count =", len(evidence["successful_sample_ids"]))
    print("transport_pending_count =", len(evidence["transport_pending_ids"]))
    print("checkpoint_raw_sha256 =", evidence["checkpoint_raw_sha256"])


if __name__ == "__main__":
    main()

