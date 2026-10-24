from __future__ import annotations

import argparse
from pathlib import Path

from sceg_ir_v21 import (
    ROOT,
    build_base_ir,
    export_bundle,
    project_dependency_records,
    write_json,
    write_jsonl,
)


def resolve(path: Path) -> Path:
    return path if path.is_absolute() else ROOT / path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build the CodeSentry-Gen SCEG 2.1 base shared IR."
    )
    parser.add_argument("--samples", required=True, type=Path)
    parser.add_argument("--dependency-records", required=True, type=Path)
    parser.add_argument("--code-dir", required=True, type=Path)
    parser.add_argument(
        "--mapping",
        type=Path,
        default=Path("config/import_mapping.json"),
        help="Compatibility provenance only; identity uses --identity-policy.",
    )
    parser.add_argument(
        "--identity-policy",
        type=Path,
        default=Path("config/package_identity_policy_v1.json"),
    )
    parser.add_argument(
        "--project-snapshots-dir",
        type=Path,
        default=None,
    )
    parser.add_argument("--dataset-label", required=True)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument(
        "--dependency-projection-out",
        required=True,
        type=Path,
    )
    args = parser.parse_args()

    samples = resolve(args.samples)
    dependency_records = resolve(args.dependency_records)
    code_dir = resolve(args.code_dir)
    mapping = resolve(args.mapping)
    identity_policy = resolve(args.identity_policy)
    project_snapshots_dir = (
        resolve(args.project_snapshots_dir)
        if args.project_snapshots_dir is not None
        else None
    )
    out = resolve(args.out)
    projection_out = resolve(args.dependency_projection_out)

    for path in [out, projection_out]:
        if path.exists():
            raise FileExistsError(f"Refusing overwrite: {path}")

    ir = build_base_ir(
        samples_path=samples,
        dependency_records_path=dependency_records,
        code_dir=code_dir,
        mapping_path=mapping,
        dataset_label=args.dataset_label,
        identity_policy_path=identity_policy,
        project_snapshots_dir=project_snapshots_dir,
    )
    write_json(out, ir)
    projection = project_dependency_records(ir)
    write_jsonl(projection_out, projection)

    export_dir = out.parent / "base_bundle"
    if export_dir.exists():
        raise FileExistsError(f"Refusing overwrite: {export_dir}")
    export_dir.mkdir(parents=True, exist_ok=False)
    counts = export_bundle(ir=ir, out_dir=export_dir)

    print("SCEG 2.1 BASE IR PASS")
    print("source_snapshot_id =", ir["source_snapshot_id"])
    print("nodes =", counts["node_record_count"])
    print("evidence =", counts["evidence_record_count"])
    print("edges =", counts["edge_count"])
    print("dependency_projection =", len(projection))
    print("saved =", out)
    

if __name__ == "__main__":
    main()
