from pathlib import Path
import json
from collections import defaultdict

def read_jsonl(path):
    p = Path(path)
    rows = []
    with p.open("r", encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows

samples = read_jsonl("data/samples/risk_seed_validation_dataset.jsonl")
reach_rows = read_jsonl("output/risk_seed_validation_reachability_v2_enriched.jsonl")
card_rows = read_jsonl("output/risk_seed_validation_temporal_risk_cards_v2.jsonl")

reach_by_sample = {r["sample_id"]: r for r in reach_rows}

cards_by_sample = defaultdict(list)
for c in card_rows:
    cards_by_sample[c["sample_id"]].append(c)

lines = []
lines.append("# Risk Seed Validation Expected Check")
lines.append("")
lines.append("| sample_id | expected_temporal | actual_temporal | expected_reachability | actual_reachability | expected_card | actual_card | pass |")
lines.append("|---|---|---|---|---|---:|---:|---|")

all_pass = True

for s in samples:
    sid = s["sample_id"]
    r = reach_by_sample.get(sid, {})
    cards = cards_by_sample.get(sid, [])

    expected_temporal = s.get("expected_temporal_status_v2")
    actual_temporal = r.get("temporal_status_v2") or r.get("status")

    expected_reach = s.get("expected_install_reachability_v2")
    actual_reach = r.get("install_reachability_v2") or r.get("install_reachability")

    expected_card = int(s.get("expected_risk_card", 0))
    actual_card = len(cards)

    ok = (
        expected_temporal == actual_temporal
        and expected_reach == actual_reach
        and expected_card == actual_card
    )

    all_pass = all_pass and ok

    lines.append(
        f"| {sid} | {expected_temporal} | {actual_temporal} | "
        f"{expected_reach} | {actual_reach} | {expected_card} | {actual_card} | {ok} |"
    )

lines.append("")
lines.append(f"- ALL_PASS: `{all_pass}`")
lines.append(f"- samples: {len(samples)}")
lines.append(f"- reachability_records: {len(reach_rows)}")
lines.append(f"- risk_cards: {len(card_rows)}")

out = Path("output/risk_seed_validation_expected_check.md")
out.write_text("\n".join(lines) + "\n", encoding="utf-8")

print("[OK] saved:", out)
print("ALL_PASS =", all_pass)
print("samples =", len(samples))
print("reachability_records =", len(reach_rows))
print("risk_cards =", len(card_rows))
if not all_pass:
    raise SystemExit(1)