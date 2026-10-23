from pathlib import Path
import json
from collections import Counter, defaultdict

def read_jsonl(path):
    p = Path(path)
    if not p.exists():
        return []
    rows = []
    with p.open("r", encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows

samples = read_jsonl("data/samples/hard_negative_validation_dataset.jsonl")
pilot_rows = read_jsonl("output/hard_negative_validation_pilot_results.jsonl")
reach_rows = read_jsonl("output/hard_negative_validation_reachability_v2_enriched.jsonl")
card_rows = read_jsonl("output/hard_negative_validation_temporal_risk_cards_v2.jsonl")

cards_by_sample = defaultdict(list)
for c in card_rows:
    cards_by_sample[c.get("sample_id")].append(c)

status_counter = Counter(r.get("temporal_status_v2") or r.get("status") for r in reach_rows)
reach_counter = Counter(r.get("install_reachability_v2") or r.get("install_reachability") for r in reach_rows)
parse_counter = Counter(r.get("code_parse_status") for r in pilot_rows)

bad_status_count = (
    status_counter.get("nonexistent_now", 0)
    + status_counter.get("created_after_tg", 0)
    + status_counter.get("registry_query_error", 0)
)

fake_text_extracted = any(
    "codesentry-fake-dep-comment-only" in str(r.get("package", ""))
    or "codesentry-fake-dep-string-only" in str(r.get("package", ""))
    or "codesentry_fake_dep_comment_only" in str(r.get("raw_name", ""))
    or "codesentry_fake_dep_string_only" in str(r.get("raw_name", ""))
    for r in pilot_rows
)

mapping_google_ok = any(
    r.get("sample_id") == "hard_negative_googleapiclient_mapping_001"
    and r.get("raw_name") == "googleapiclient"
    and r.get("package") == "google-api-python-client"
    and (r.get("temporal_status_v2") or r.get("status")) == "existed_at_tg"
    for r in reach_rows
)

mapping_yaml_ok = any(
    r.get("sample_id") == "hard_negative_yaml_mapping_001"
    and r.get("raw_name") == "yaml"
    and r.get("package") == "pyyaml"
    and (r.get("temporal_status_v2") or r.get("status")) == "existed_at_tg"
    for r in reach_rows
)

sample_card_ok = True
sample_rows = []

for s in samples:
    sid = s["sample_id"]
    expected_card = int(s.get("expected_risk_card", 0))
    actual_card = len(cards_by_sample.get(sid, []))
    ok = expected_card == actual_card
    sample_card_ok = sample_card_ok and ok
    sample_rows.append((sid, expected_card, actual_card, ok))

expected_total_cards = sum(
    int(s.get("expected_risk_card", 0))
    for s in samples
)

all_pass = (
    len(samples) >= 1
    and len(card_rows) == expected_total_cards
    and bad_status_count == 0
    and parse_counter.get("ok", 0) == len(pilot_rows)
    and not fake_text_extracted
    and mapping_google_ok
    and mapping_yaml_ok
    and sample_card_ok
)

lines = []
lines.append("# Hard Negative Validation Expected Check")
lines.append("")
lines.append("## 1. Summary")
lines.append("")
lines.append(f"- samples: {len(samples)}")
lines.append(f"- dependency_records: {len(pilot_rows)}")
lines.append(f"- risk_cards: {len(card_rows)}")
lines.append(f"- expected_total_cards: {expected_total_cards}")
lines.append(f"- temporal_status_v2: {dict(status_counter)}")
lines.append(f"- install_reachability_v2: {dict(reach_counter)}")
lines.append(f"- code_parse_status: {dict(parse_counter)}")
lines.append(f"- bad_status_count: {bad_status_count}")
lines.append(f"- fake_text_extracted: {fake_text_extracted}")
lines.append(f"- mapping_google_ok: {mapping_google_ok}")
lines.append(f"- mapping_yaml_ok: {mapping_yaml_ok}")
lines.append(f"- ALL_PASS: `{all_pass}`")
lines.append("")
lines.append("## 2. Per-sample Risk Card Check")
lines.append("")
lines.append("| sample_id | expected_risk_card | actual_risk_card | pass |")
lines.append("|---|---:|---:|---|")
for sid, expected_card, actual_card, ok in sample_rows:
    lines.append(f"| {sid} | {expected_card} | {actual_card} | {ok} |")

lines.append("")
lines.append("## 3. Dependency Records")
lines.append("")
lines.append("| sample_id | raw_name | package | temporal_status | reachability |")
lines.append("|---|---|---|---|---|")
for r in reach_rows:
    lines.append(
        f"| {r.get('sample_id')} | {r.get('raw_name')} | {r.get('package')} | "
        f"{r.get('temporal_status_v2') or r.get('status')} | "
        f"{r.get('install_reachability_v2') or r.get('install_reachability')} |"
    )

out = Path("output/hard_negative_validation_expected_check.md")
out.write_text("\n".join(lines) + "\n", encoding="utf-8")

print("[OK] saved:", out)
print("ALL_PASS =", all_pass)
print("samples =", len(samples))
print("dependency_records =", len(pilot_rows))
print("risk_cards =", len(card_rows))
print("expected_total_cards =", expected_total_cards)
print("bad_status_count =", bad_status_count)
print("fake_text_extracted =", fake_text_extracted)
print("mapping_google_ok =", mapping_google_ok)
print("mapping_yaml_ok =", mapping_yaml_ok)
if not all_pass:
    raise SystemExit(1)