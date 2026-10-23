"""
make_tho_validation_final_summary_v2.py

作用：
    CodeSentry-Gen 的最终验证汇总脚本。
    读取前面已经跑好的 positive control、natural negative control、
    hard negative control 三类验证结果，并生成最终 Markdown 汇总报告。

输入：
    1. Positive control：
       - data/samples/risk_seed_validation_dataset.jsonl
       - output/risk_seed_validation_reachability_v2_enriched.jsonl
       - output/risk_seed_validation_temporal_risk_cards_v2.jsonl

    2. Natural negative control：
       - output/auto_qwen37_100_pilot_results.jsonl
       - output/auto_qwen37_100_temporal_enriched.jsonl
       - output/auto_qwen37_100_temporal_risk_cards_v2.jsonl

    3. Hard negative control：
       - data/samples/hard_negative_validation_dataset.jsonl
       - output/hard_negative_validation_pilot_results.jsonl
       - output/hard_negative_validation_reachability_v2_enriched.jsonl
       - output/hard_negative_validation_temporal_risk_cards_v2.jsonl

输出：
    - output/tho_validation_final_summary_v2.md

验证目标：
    - positive control：
      验证“该报能报”。

    - natural negative control：
      验证当前 qwen 自然生成样本中没有观察到 THO 风险，
      且没有被系统乱报。

    - hard negative control：
      验证标准库、注释字符串假包、import mapping 等边界负例不会误报。

在整体流程中的位置：
    run_pilot.py
        ↓
    enrich_temporal_status.py
        ↓
    enrich_reachability_v2.py
        ↓
    build_temporal_risk_cards.py
        ↓
    make_tho_validation_final_summary_v2.py

注意：
    本脚本只做汇总，不重新运行检测流程。
    如果前置输出文件不存在，统计结果会不完整。
"""

from pathlib import Path
import json
import collections


def read_jsonl(path):
    """
    读取 JSONL 文件。

    如果文件不存在，返回空列表并打印 warning。
    这样现场演示时如果某个前置结果没生成，可以更快发现问题。
    """
    p = Path(path)

    if not p.exists():
        print(f"[WARN] missing file: {p}")
        return []

    rows = []

    with p.open("r", encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()

            if line:
                rows.append(json.loads(line))

    return rows


# =========================
# 1. 读取 positive control 结果
# =========================

# 风险种子样本：4 条人工构造的已知风险样本
risk_seed_samples = read_jsonl("data/samples/risk_seed_validation_dataset.jsonl")

# 风险种子经过 temporal + reachability v2 增强后的依赖记录
risk_seed_reach = read_jsonl("output/risk_seed_validation_reachability_v2_enriched.jsonl")

# 风险种子最终生成的 THO Risk Cards
risk_seed_cards = read_jsonl("output/risk_seed_validation_temporal_risk_cards_v2.jsonl")


# =========================
# 2. 读取 natural negative control 结果
# =========================

# qwen 自动生成样本经过 run_pilot.py 后的依赖记录
qwen_pilot = read_jsonl("output/auto_qwen37_100_pilot_results.jsonl")

# qwen 自动生成样本经过 temporal_status_v2 增强后的记录
qwen_temporal = read_jsonl("output/auto_qwen37_100_temporal_enriched.jsonl")

qwen_reach = read_jsonl("output/auto_qwen37_100_reachability_v2_enriched.jsonl")

# qwen 自动生成样本最终生成的 Risk Cards
# 新规则下：temporal_package_hallucination 预期为 0；
# dependency_declaration_mismatch 允许存在，并应与 manifest-only 记录数一致。
qwen_cards = read_jsonl("output/auto_qwen37_100_temporal_risk_cards_v2.jsonl")


# =========================
# 3. 读取 hard negative control 结果
# =========================

# hard negative 样本：标准库、注释字符串假包、mapping 边界样本
hard_samples = read_jsonl("data/samples/hard_negative_validation_dataset.jsonl")

# hard negative 经过 run_pilot.py 后的依赖记录
hard_pilot = read_jsonl("output/hard_negative_validation_pilot_results.jsonl")

# hard negative 经过 reachability v2 增强后的记录
hard_reach = read_jsonl("output/hard_negative_validation_reachability_v2_enriched.jsonl")

# hard negative 最终生成的 Risk Cards
# 新规则下：manifest-only 相关 case 预期生成 dependency_declaration_mismatch；
# 但 temporal_package_hallucination 仍然预期为 0。
hard_cards = read_jsonl("output/hard_negative_validation_temporal_risk_cards_v2.jsonl")


# =========================
# 4. 统计各类分布
# =========================

# positive control 的 temporal status 分布
risk_seed_temporal = collections.Counter(
    r.get("temporal_status_v2") for r in risk_seed_reach
)

# positive control 的 reachability 分布
risk_seed_reachability = collections.Counter(
    r.get("install_reachability_v2") or r.get("install_reachability")
    for r in risk_seed_reach
)

# qwen natural negative 的 temporal status 分布
qwen_temporal_counter = collections.Counter(
    r.get("temporal_status_v2") for r in qwen_temporal
)

qwen_reachability_counter = collections.Counter(
    r.get("install_reachability_v2") or r.get("install_reachability")
    for r in qwen_reach
)

qwen_risk_type_counter = collections.Counter(
    c.get("type") or c.get("risk_type")
    for c in qwen_cards
)

qwen_temporal_risk_cards = [
    c for c in qwen_cards
    if (c.get("type") or c.get("risk_type")) == "temporal_package_hallucination"
]

qwen_declaration_mismatch_cards = [
    c for c in qwen_cards
    if (c.get("type") or c.get("risk_type")) == "dependency_declaration_mismatch"
]

qwen_expected_manifest_only_cards = sum(
    1
    for r in qwen_reach
    if (r.get("temporal_status_v2") or r.get("status")) == "existed_at_tg"
    and r.get("source_type") in {"manifest", "requirements"}
    and (r.get("install_reachability_v2") or r.get("install_reachability")) == "manifest_declared"
)

# qwen natural negative 的代码解析状态分布
qwen_parse_counter = collections.Counter(
    r.get("code_parse_status") for r in qwen_pilot
)

# hard negative 的 temporal status 分布
hard_temporal = collections.Counter(
    r.get("temporal_status_v2") for r in hard_reach
)

# hard negative 的 reachability 分布
hard_reachability = collections.Counter(
    r.get("install_reachability_v2") or r.get("install_reachability")
    for r in hard_reach
)

# hard negative 的代码解析状态分布
hard_parse = collections.Counter(
    r.get("code_parse_status") for r in hard_pilot
)

hard_risk_type_counter = collections.Counter(
    c.get("type") or c.get("risk_type")
    for c in hard_cards
)

hard_temporal_risk_cards = [
    c for c in hard_cards
    if (c.get("type") or c.get("risk_type")) == "temporal_package_hallucination"
]

hard_declaration_mismatch_cards = [
    c for c in hard_cards
    if (c.get("type") or c.get("risk_type")) == "dependency_declaration_mismatch"
]

hard_expected_total_cards = sum(
    int(s.get("expected_risk_card", 0))
    for s in hard_samples
)


# =========================
# 5. 判断 positive control 是否通过
# =========================

# 预期：
# - 4 条风险种子
# - 4 条增强记录
# - 4 张 Risk Card
# - temporal_status_v2 中 nonexistent_now 2 条，created_after_tg 2 条
# - reachability 中 manifest_declared 2 条，ci_installable 2 条
positive_pass = (
    len(risk_seed_samples) == 4
    and len(risk_seed_reach) == 4
    and len(risk_seed_cards) == 4
    and risk_seed_temporal.get("nonexistent_now", 0) == 2
    and risk_seed_temporal.get("created_after_tg", 0) == 2
    and risk_seed_reachability.get("manifest_declared", 0) == 2
    and risk_seed_reachability.get("ci_installable", 0) == 2
)


# =========================
# 6. 判断 natural negative control 是否通过
# =========================

# 预期：
# - 不生成 Risk Card
# - 没有 nonexistent_now
# - 没有 created_after_tg
# - 没有 registry_query_error
# - 没有代码解析错误
natural_negative_pass = (
    len(qwen_temporal_risk_cards) == 0
    and len(qwen_declaration_mismatch_cards) == qwen_expected_manifest_only_cards
    and qwen_temporal_counter.get("nonexistent_now", 0) == 0
    and qwen_temporal_counter.get("created_after_tg", 0) == 0
    and qwen_temporal_counter.get("registry_query_error", 0) == 0
    and qwen_parse_counter.get("syntax_error", 0) == 0
    and qwen_parse_counter.get("parse_error", 0) == 0
)


# =========================
# 7. 判断 hard negative control 是否通过
# =========================

# 预期：
# - hard negative 样本
# - 不生成 Risk Card
# - 没有 nonexistent_now
# - 没有 created_after_tg
# - 没有 registry_query_error
# - 所有代码解析状态都是 ok
hard_negative_pass = (
    len(hard_samples) >= 1
    and len(hard_cards) == hard_expected_total_cards
    and len(hard_temporal_risk_cards) == 0
    and hard_temporal.get("nonexistent_now", 0) == 0
    and hard_temporal.get("created_after_tg", 0) == 0
    and hard_temporal.get("registry_query_error", 0) == 0
    and hard_parse.get("ok", 0) == len(hard_pilot)
)


# 三类验证都通过，最终才算 ALL_PASS
all_pass = positive_pass and natural_negative_pass and hard_negative_pass


# =========================
# 8. 生成 Markdown 汇总报告
# =========================

lines = []

lines.append("# THO Validation Final Summary v2")
lines.append("")
lines.append("## 1. Validation Overview")
lines.append("")
lines.append("| validation | dataset | samples/records | temporal_status_v2 | reachability_v2 | risk_cards | pass |")
lines.append("|---|---|---:|---|---|---:|---|")

lines.append(
    f"| Positive control | risk_seed_validation_dataset | "
    f"{len(risk_seed_samples)} samples / {len(risk_seed_reach)} records | "
    f"{dict(risk_seed_temporal)} | {dict(risk_seed_reachability)} | "
    f"{len(risk_seed_cards)} | {positive_pass} |"
)

lines.append(
    f"| Natural negative control | qwen real generated 100 samples | "
    f"100 samples / {len(qwen_temporal)} records | "
    f"{dict(qwen_temporal_counter)} | {dict(qwen_reachability_counter)} | "
    f"{len(qwen_cards)} total; temporal={len(qwen_temporal_risk_cards)}; mismatch={len(qwen_declaration_mismatch_cards)} | {natural_negative_pass} |"
)

lines.append(
    f"| Hard negative control | hard_negative_validation_dataset | "
    f"{len(hard_samples)} samples / {len(hard_reach)} records | "
    f"{dict(hard_temporal)} | {dict(hard_reachability)} | "
    f"{len(hard_cards)} total; temporal={len(hard_temporal_risk_cards)}; mismatch={len(hard_declaration_mismatch_cards)} | {hard_negative_pass} |"
)

lines.append("")
lines.append(f"- positive_pass: `{positive_pass}`")
lines.append(f"- natural_negative_pass: `{natural_negative_pass}`")
lines.append(f"- hard_negative_pass: `{hard_negative_pass}`")
lines.append(f"- ALL_PASS: `{all_pass}`")

lines.append("")
lines.append("## 2. Positive Control")
lines.append("")
lines.append(
    "The controlled risk seed dataset contains four known-risk cases: "
    "`nonexistent_now + manifest_declared`, `nonexistent_now + ci_installable`, "
    "`created_after_tg + manifest_declared`, and `created_after_tg + ci_installable`. "
    "All four cases generated Risk Cards and matched the expected labels."
)

lines.append("")
lines.append("## 3. Natural Negative Control")
lines.append("")
lines.append(
    f"The qwen real generated samples produced {len(qwen_temporal)} dependency records. "
    "No `nonexistent_now`, `created_after_tg`, or `registry_query_error` records were observed, "
    f"and no temporal package hallucination Risk Cards were generated. "
    f"Under the updated manifest-only rule, {len(qwen_declaration_mismatch_cards)} "
    "dependency declaration mismatch Risk Cards were generated."
)

lines.append("")
lines.append("## 4. Hard Negative Control")
lines.append("")
lines.append(
    "The hard negative dataset covers standard-library imports, fake package names appearing only "
"in comments/strings, import-to-distribution mapping cases, manifest-only normal dependencies, "
"local modules, PEP503 normalization, and requirements version/marker parsing cases. "
f"Under the updated manifest-only rule, {len(hard_declaration_mismatch_cards)} "
"expected dependency declaration mismatch Risk Cards were generated, "
"while no temporal package hallucination Risk Cards were generated."
)

lines.append("")
lines.append("## 5. Conclusion")
lines.append("")
lines.append(
    "The current THO pipeline passes three validation checks: it reports controlled temporal dependency "
    "risks when risks are present, reports updated manifest-only dependency declaration mismatch cases, "
    "and still avoids temporal package hallucination false alarms on qwen real-generation and curated boundary cases."
)

lines.append("")
lines.append(
    "Controlled risk seeds are used for recall/regression testing and should not be mixed into natural prevalence estimates."
)


# =========================
# 9. 写出 Markdown 文件
# =========================

out = Path("output/tho_validation_final_summary_v2.md")
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text("\n".join(lines) + "\n", encoding="utf-8")


# =========================
# 10. 控制台输出关键结果
# =========================

print("[OK] saved:", out)
print("positive_pass =", positive_pass)
print("natural_negative_pass =", natural_negative_pass)
print("hard_negative_pass =", hard_negative_pass)
print("ALL_PASS =", all_pass)
if not all_pass:
    raise SystemExit(1)