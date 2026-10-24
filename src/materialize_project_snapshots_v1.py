from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from typing import Any

from freeze_hash_v1 import hash_record, verify_hash


ROOT = Path(__file__).resolve().parents[1]


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8-sig") as handle:
        for line_no, raw in enumerate(handle, start=1):
            text = raw.strip()
            if not text:
                continue
            value = json.loads(text)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_no}: expected object")
            rows.append(value)
    return rows


def safe_relative_path(value: str) -> Path:
    raw = str(value or "").replace("\\", "/").strip()
    path = Path(raw)
    if not raw or path.is_absolute() or ".." in path.parts:
        raise ValueError(f"Unsafe project snapshot path: {value!r}")
    return path


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(text), encoding="utf-8", newline="\n")


def repo_context_local_modules(sample: dict[str, Any]) -> list[str]:
    value = sample.get("repo_context")
    if not isinstance(value, dict):
        return []
    modules = value.get("local_modules")
    if not isinstance(modules, list):
        return []
    return sorted(
        {
            str(item).strip()
            for item in modules
            if str(item).strip()
        }
    )


def optional_project_files(sample: dict[str, Any]) -> dict[str, str]:
    value = sample.get("project_files")
    result: dict[str, str] = {}
    if isinstance(value, dict):
        for name, content in value.items():
            result[str(name)] = str(content or "")
        return result

    if isinstance(value, list):
        for row in value:
            if not isinstance(row, dict):
                continue
            name = str(
                row.get("path")
                or row.get("file")
                or row.get("name")
                or ""
            ).strip()
            if not name:
                continue
            result[name] = str(row.get("content") or "")
    return result


def materialize(
    *,
    samples_path: Path,
    code_dir: Path,
    requirements_dir: Path,
    out_dir: Path,
) -> dict[str, Any]:
    if out_dir.exists():
        raise FileExistsError(f"Refusing overwrite: {out_dir}")
    out_dir.mkdir(parents=True, exist_ok=False)

    samples = read_jsonl(samples_path)
    snapshot_rows: list[dict[str, Any]] = []

    for sample in samples:
        sample_id = str(sample.get("sample_id") or "").strip()
        if not sample_id:
            raise ValueError("sample_id missing in generated samples")

        sample_dir = out_dir / sample_id
        sample_dir.mkdir(parents=True, exist_ok=False)

        source_code = code_dir / f"{sample_id}.py"
        req_source = (
            requirements_dir / f"{sample_id}_requirements.txt"
        )
        if not source_code.exists():
            raise FileNotFoundError(source_code)
        if not req_source.exists():
            raise FileNotFoundError(req_source)

        generated_target = sample_dir / "generated.py"
        requirements_target = sample_dir / "requirements.txt"
        shutil.copyfile(source_code, generated_target)
        shutil.copyfile(req_source, requirements_target)

        supplemental = optional_project_files(sample)
        supplemental_written: list[str] = []
        for relative, text in sorted(supplemental.items()):
            target_rel = safe_relative_path(relative)
            if target_rel.as_posix() in {
                "generated.py",
                "requirements.txt",
                "snapshot_manifest.json",
            }:
                raise ValueError(
                    f"project_files conflicts with reserved path: {relative}"
                )
            target = sample_dir / target_rel
            write_text(target, text)
            supplemental_written.append(target_rel.as_posix())

        files: dict[str, dict[str, Any]] = {}
        for path in sorted(
            p for p in sample_dir.rglob("*") if p.is_file()
        ):
            relative = path.relative_to(sample_dir).as_posix()
            files[relative] = hash_record(path)

        project_context_status = str(
            sample.get("project_context_status")
            or (
                "supplied_project_files"
                if supplemental_written
                else (
                    "repo_context_metadata_only"
                    if sample.get("repo_context")
                    else "not_provided_by_source"
                )
            )
        )
        declared_local_modules = repo_context_local_modules(sample)
        manifest = {
            "schema_version": "codesentry_gen_project_snapshot_v1",
            "sample_id": sample_id,
            "scope": (
                "generated_artifacts_plus_supplied_project_files"
                if supplemental_written
                else "generated_artifacts_only"
            ),
            "generated_code_source": source_code.name,
            "requirements_source": req_source.name,
            "supplemental_project_files": supplemental_written,
            "source_project_context_status": project_context_status,
            "source_repo_context_metadata_present": bool(
                sample.get("repo_context")
            ),
            "repo_context_local_modules": declared_local_modules,
            "local_module_context_complete": (
                project_context_status
                in {
                    "complete",
                    "complete_project_context",
                    "complete_repo_context",
                }
            ),
            "local_module_filtering_boundary": (
                "Only modules physically present in this snapshot may be "
                "classified local_module. Missing project context remains "
                "unknown and is never invented."
            ),
            "files": files,
        }
        manifest_path = sample_dir / "snapshot_manifest.json"
        write_text(
            manifest_path,
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        )
        snapshot_rows.append(
            {
                "sample_id": sample_id,
                "snapshot_dir": sample_dir.relative_to(ROOT).as_posix(),
                "scope": manifest["scope"],
                "source_project_context_status": project_context_status,
                "repo_context_local_module_count": len(
                    declared_local_modules
                ),
                "supplemental_project_files": len(
                    supplemental_written
                ),
            }
        )

    index = {
        "schema_version": "codesentry_gen_project_snapshot_index_v1",
        "sample_count": len(snapshot_rows),
        "samples": snapshot_rows,
        "scientific_boundary": {
            "no_project_files_are_invented": True,
            "local_module_filtering_uses_snapshot_only": True,
            "generated_code_and_requirements_are_always_materialized": True,
            "missing_source_repo_context_is_recorded_not_invented": True,
            "repo_context_local_modules_are_preserved_when_supplied": True,
            "absence_from_incomplete_context_is_not_proof_of_not_local": True,
        },
    }
    write_text(
        out_dir / "snapshot_index.json",
        json.dumps(index, ensure_ascii=False, indent=2) + "\n",
    )
    return index


def verify_snapshot_index(out_dir: Path) -> dict[str, Any]:
    index_path = out_dir / "snapshot_index.json"
    if not index_path.exists():
        raise FileNotFoundError(index_path)
    index = json.loads(index_path.read_text(encoding="utf-8-sig"))
    if not isinstance(index, dict) or index.get("schema_version") != (
        "codesentry_gen_project_snapshot_index_v1"
    ):
        raise ValueError("Unexpected project snapshot index schema")
    samples = index.get("samples")
    if not isinstance(samples, list):
        raise ValueError("Project snapshot index samples missing")

    for row in samples:
        if not isinstance(row, dict):
            raise ValueError("Invalid project snapshot index row")
        sample_id = str(row.get("sample_id") or "").strip()
        sample_dir = out_dir / sample_id
        manifest_path = sample_dir / "snapshot_manifest.json"
        if not manifest_path.exists():
            raise FileNotFoundError(manifest_path)
        manifest = json.loads(
            manifest_path.read_text(encoding="utf-8-sig")
        )
        if not isinstance(manifest, dict) or manifest.get(
            "schema_version"
        ) != "codesentry_gen_project_snapshot_v1":
            raise ValueError(
                f"Unexpected snapshot manifest schema: {sample_id}"
            )
        if manifest.get("sample_id") != sample_id:
            raise ValueError(
                f"Snapshot sample_id mismatch: {sample_id}"
            )
        files = manifest.get("files")
        if not isinstance(files, dict) or not files:
            raise ValueError(f"Snapshot file hash set missing: {sample_id}")
        for relative, expected in files.items():
            verify_hash(
                sample_dir / relative,
                expected,
                label=f"project snapshot:{sample_id}:{relative}",
            )
    return index


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Materialize one immutable project snapshot per generated sample "
            "for identity/local-module/reachability analysis."
        )
    )
    parser.add_argument("--samples", required=True, type=Path)
    parser.add_argument("--code-dir", required=True, type=Path)
    parser.add_argument("--requirements-dir", required=True, type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify an existing snapshot index instead of materializing.",
    )
    args = parser.parse_args()

    def resolve(path: Path) -> Path:
        return path if path.is_absolute() else ROOT / path

    out_dir = resolve(args.out_dir)
    if args.verify:
        result = verify_snapshot_index(out_dir)
        print("PROJECT SNAPSHOT VERIFY PASS")
    else:
        result = materialize(
            samples_path=resolve(args.samples),
            code_dir=resolve(args.code_dir),
            requirements_dir=resolve(args.requirements_dir),
            out_dir=out_dir,
        )
        print("PROJECT SNAPSHOT MATERIALIZATION PASS")
    print("samples =", result["sample_count"])
    print("saved =", out_dir)


if __name__ == "__main__":
    main()
