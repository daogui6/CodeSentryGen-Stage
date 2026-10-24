from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any


def raw_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    if path.exists():
        raise FileExistsError(f"refusing overwrite: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
        text=True,
    )
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        dir_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except Exception:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
        raise


def build_capture(
    *,
    generation_dir: Path,
    out: Path,
    split: str,
    workflow_run_id: str,
    source_commit: str,
    preflight_evidence_commit: str,
    selection_evidence_commit: str,
) -> dict[str, Any]:
    if split not in {"pilot", "test"}:
        raise ValueError("split must be pilot or test")
    if not generation_dir.is_dir():
        raise FileNotFoundError(generation_dir)

    files: list[dict[str, Any]] = []
    for path in sorted(generation_dir.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(generation_dir).as_posix()
        files.append(
            {
                "relative_path": rel,
                "raw_sha256": raw_sha256(path),
                "size_bytes": path.stat().st_size,
            }
        )
    if not files:
        raise ValueError("generation directory is empty")

    by_name = {item["relative_path"] for item in files}
    manifest = {
        "schema_version": "step9_generation_raw_capture_v1",
        "status": "RAW_CAPTURE_READY_FOR_REMOTE_PERSISTENCE",
        "capture_phase": "POST_PROVIDER_PRE_CLASSIFICATION",
        "split": split,
        "workflow_run_id": str(workflow_run_id),
        "source_commit": source_commit,
        "preflight_evidence_commit": preflight_evidence_commit,
        "selection_evidence_commit": selection_evidence_commit,
        "generation_directory": generation_dir.as_posix(),
        "file_count": len(files),
        "files": files,
        "observed_files": {
            "generated_samples_jsonl": "generated_samples.jsonl" in by_name,
            "attempt_intent_ledger": "generation_attempt_intents.jsonl" in by_name,
            "attempt_ledger": "generation_attempts.jsonl" in by_name,
            "checkpoint_manifest": "generation_checkpoint_manifest.json" in by_name,
            "generation_stage_manifest": "generation_stage_manifest.json" in by_name,
            "accepted_response_journal_count": sum(
                1 for name in by_name
                if name.startswith("accepted_response_journal/")
                and name.endswith(".accepted.json")
            ),
            "code_sidecar_count": sum(
                1 for name in by_name
                if name.startswith("code/") and name.endswith(".py")
            ),
            "requirements_sidecar_count": sum(
                1 for name in by_name
                if name.startswith("requirements/")
            ),
        },
        "scientific_boundary": {
            "provider_called_by_capture_builder": False,
            "classification_performed_by_capture_builder": False,
            "generation_files_mutated": False,
            "release_snapshot_created": False,
            "downstream_analysis_started": False,
        },
        "persistence_contract": {
            "remote_persistence_required_before_classification": True,
            "remote_reread_required_before_classification": True,
            "same_prompt_provider_recall_if_capture_fails": False,
        },
    }
    atomic_write_json(out, manifest)
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Build a content-addressed raw generation capture manifest before "
            "any post-provider classification. This tool never calls a provider."
        )
    )
    parser.add_argument("--generation-dir", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--split", required=True, choices=["pilot", "test"])
    parser.add_argument("--workflow-run-id", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--preflight-evidence-commit", required=True)
    parser.add_argument("--selection-evidence-commit", required=True)
    args = parser.parse_args()

    result = build_capture(
        generation_dir=args.generation_dir,
        out=args.out,
        split=args.split,
        workflow_run_id=args.workflow_run_id,
        source_commit=args.source_commit,
        preflight_evidence_commit=args.preflight_evidence_commit,
        selection_evidence_commit=args.selection_evidence_commit,
    )
    print("STEP9 RAW GENERATION CAPTURE MANIFEST PASS")
    print("file_count =", result["file_count"])
    print("capture_phase =", result["capture_phase"])


if __name__ == "__main__":
    main()
