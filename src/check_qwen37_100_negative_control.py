import json
import pathlib
import collections


ROOT = pathlib.Path(__file__).resolve().parents[1]

SAMPLE_PATH = ROOT / "data" / "samples" / "auto_qwen37_100_generated_codes.jsonl"
PILOT_PATH = ROOT / "output" / "auto_qwen37_100_pilot_results.jsonl"
TEMPORAL_PATH = ROOT / "output" / "auto_qwen37_100_temporal_enriched.jsonl"
REACHABILITY_PATH = ROOT / "output" / "auto_qwen37_100_reachability_v2_enriched.jsonl"
CARDS_PATH = ROOT / "output" / "auto_qwen37_100_temporal_risk_cards_v2.jsonl"

OUT_PATH = ROOT / "output" / "auto_qwen37_100_negative_control_check.md"


def load_jsonl(path: pathlib.Path):
    if not path.exists():
        raise FileNotFoundError(f"missing file: {path}")

    if path.stat().st_size == 0:
        return []

    rows = []
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise ValueError(f"{path} line {line_no} is invalid json: {e}") from e

    return rows


def main():
    samples = load_jsonl(SAMPLE_PATH)
    pilot_rows = load_jsonl(PILOT_PATH)
    temporal_rows = load_jsonl(TEMPORAL_PATH)
    reachability_rows = load_jsonl(REACHABILITY_PATH)
    risk_cards = load_jsonl(CARDS_PATH)

    risk_type_counter = collections.Counter(
        row.get("type") or row.get("risk_type")
        for row in risk_cards
    )

    temporal_risk_cards = [
        row for row in risk_cards
        if (row.get("type") or row.get("risk_type")) == "temporal_package_hallucination"
    ]

    declaration_mismatch_cards = [
        row for row in risk_cards
        if (row.get("type") or row.get("risk_type")) == "dependency_declaration_mismatch"
    ]

    expected_manifest_only_cards = sum(
        1
        for row in reachability_rows
        if (row.get("temporal_status_v2") or row.get("status")) == "existed_at_tg"
        and row.get("source_type") in {"manifest", "requirements"}
        and (row.get("install_reachability_v2") or row.get("install_reachability")) == "manifest_declared"
    )

    temporal_counter = collections.Counter(
        row.get("temporal_status_v2") for row in temporal_rows
    )
    reachability_counter = collections.Counter(
        row.get("install_reachability_v2") for row in reachability_rows
    )

    generation_error_count = sum(
        1 for row in samples if row.get("generation_error")
    )

    all_pass = (
            len(samples) == 100
            and generation_error_count == 0
            and len(pilot_rows) == 260
            and len(temporal_rows) == len(pilot_rows)
            and len(reachability_rows) == len(pilot_rows)
            and len(temporal_risk_cards) == 0
            and len(declaration_mismatch_cards) == expected_manifest_only_cards
            and temporal_counter.get("nonexistent_now", 0) == 0
            and temporal_counter.get("created_after_tg", 0) == 0
            and temporal_counter.get("registry_query_error", 0) == 0
    )

    lines = []
    lines.append("# qwen37_100 Natural Negative Control Check\n\n")
    lines.append(f"ALL_PASS = {all_pass}\n")
    lines.append(f"samples = {len(samples)}\n")
    lines.append(f"generation_error = {generation_error_count}\n")
    lines.append(f"dependency_records = {len(pilot_rows)}\n")
    lines.append(f"risk_cards_v2 = {len(risk_cards)}\n")
    lines.append(f"temporal_risk_cards = {len(temporal_risk_cards)}\n")
    lines.append(f"declaration_mismatch_cards = {len(declaration_mismatch_cards)}\n")
    lines.append(f"expected_manifest_only_cards = {expected_manifest_only_cards}\n")

    lines.append("\n## temporal_status_v2\n")
    for key, value in sorted(temporal_counter.items()):
        lines.append(f"- {key}: {value}\n")

    lines.append("\n## risk_type\n")
    for key, value in sorted(risk_type_counter.items()):
        lines.append(f"- {key}: {value}\n")

    lines.append("\n## install_reachability_v2\n")
    for key, value in sorted(reachability_counter.items()):
        lines.append(f"- {key}: {value}\n")

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text("".join(lines), encoding="utf-8")

    print("[OK] saved:", OUT_PATH.relative_to(ROOT))
    print("ALL_PASS =", all_pass)
    print("samples =", len(samples))
    print("generation_error =", generation_error_count)
    print("dependency_records =", len(pilot_rows))
    print("risk_cards_v2 =", len(risk_cards))
    print("temporal_status_v2 =", dict(temporal_counter))
    print("install_reachability_v2 =", dict(reachability_counter))
    print("temporal_risk_cards =", len(temporal_risk_cards))
    print("declaration_mismatch_cards =", len(declaration_mismatch_cards))
    print("expected_manifest_only_cards =", expected_manifest_only_cards)
    print("risk_type =", dict(risk_type_counter))
    if not all_pass:
        raise SystemExit(1)


if __name__ == "__main__":
    main()