from __future__ import annotations

import argparse
from pathlib import Path

from sceg_ir_v21 import (
    ROOT,
    export_bundle,
    finalize_ir,
    read_json,
    read_jsonl,
    write_json,
)


def resolve(path: Path) -> Path:
    return path if path.is_absolute() else ROOT / path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Finalize SCEG 2.1 with THO, AVCS, and Risk Card evidence."
    )
    parser.add_argument("--base-ir", required=True, type=Path)
    parser.add_argument("--tho-records", required=True, type=Path)
    parser.add_argument("--avcs-dir", required=True, type=Path)
    parser.add_argument("--risk-cards", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    base_ir_path = resolve(args.base_ir)
    tho_records_path = resolve(args.tho_records)
    avcs_dir = resolve(args.avcs_dir)
    risk_cards_path = resolve(args.risk_cards)
    out = resolve(args.out)

    if out.exists():
        raise FileExistsError(f"Refusing overwrite: {out}")

    sample_root = avcs_dir / "samples"
    avcs_sample_dirs = (
        sorted(
            path
            for path in sample_root.iterdir()
            if path.is_dir() and (path / "manifest.json").exists()
        )
        if sample_root.exists()
        else []
    )

    ir = finalize_ir(
        base_ir=read_json(base_ir_path),
        tho_records=read_jsonl(tho_records_path),
        avcs_sample_dirs=avcs_sample_dirs,
        risk_cards=read_jsonl(risk_cards_path),
    )
    write_json(out, ir)

    export_dir = out.parent
    for name in ["nodes.jsonl", "evidence.jsonl", "edges.jsonl"]:
        if (export_dir / name).exists():
            raise FileExistsError(
                f"Refusing overwrite: {export_dir / name}"
            )
    counts = export_bundle(ir=ir, out_dir=export_dir)

    print("SCEG 2.1 ANALYZED IR PASS")
    print("source_snapshot_id =", ir["source_snapshot_id"])
    print("nodes =", counts["node_record_count"])
    print("evidence =", counts["evidence_record_count"])
    print("edges =", counts["edge_count"])
    print(
        "risk_nodes =",
        ir.get("analysis_summary", {}).get("risk_node_count", 0),
    )
    print("saved =", out)


if __name__ == "__main__":
    main()
