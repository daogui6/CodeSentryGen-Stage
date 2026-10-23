from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List


ROOT = Path(__file__).resolve().parents[1]

BENCHMARK_JSONL = ROOT / "output" / "gen_dep_risk_bench_sample.jsonl"
RISK_CARDS_JSONL = ROOT / "output" / "risk_cards.jsonl"
SUMMARY_MD = ROOT / "output" / "benchmark_summary.md"
MANUAL_REVIEW_CSV = ROOT / "output" / "manual_review_template.csv"
SNAPSHOT_OUT = ROOT / "output" / "pilot_v0_snapshot.md"


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []

    if not path.exists():
        return rows

    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))

    return rows


def main() -> None:
    benchmark_rows = load_jsonl(BENCHMARK_JSONL)
    risk_rows = load_jsonl(RISK_CARDS_JSONL)

    sample_ids = sorted({row.get("sample_id", "unknown") for row in benchmark_rows})
    prompt_ids = sorted({row.get("prompt_id", "unknown") for row in benchmark_rows})

    status_counter = Counter(row.get("status", "unknown") for row in benchmark_rows)
    risk_type_counter = Counter(row.get("risk_type") or "none" for row in benchmark_rows)
    reachability_counter = Counter(row.get("install_reachability", "unknown") for row in benchmark_rows)
    auto_label_counter = Counter(row.get("auto_label", "unknown") for row in benchmark_rows)

    normal_count = sum(1 for row in benchmark_rows if row.get("auto_label") != "risk")
    risk_count = sum(1 for row in benchmark_rows if row.get("auto_label") == "risk")

    lines = []

    lines.append("# Pilot v0 Snapshot")
    lines.append("")
    lines.append(f"- 生成时间：{datetime.now().isoformat(timespec='seconds')}")
    lines.append("- 阶段名称：pilot_v0")
    lines.append("- 场景范围：Python / PyPI")
    lines.append("- 数据来源：PackageHallucination pilot20 + controlled risk seed")
    lines.append("")

    lines.append("## 1. 输入文件")
    lines.append("")
    lines.append("- `data/prompts/selected_prompts_pilot20.jsonl`：选出的 20 条 PackageHallucination Python prompt")
    lines.append("- `data/samples/generated_codes_pilot20.jsonl`：20 条 prompt 对应的生成代码样本")
    lines.append("- `data/samples/risk_seed_samples.jsonl`：2 条人工构造风险种子样本")
    lines.append("- `data/samples/generated_codes_pilot20_with_risk_seeds.jsonl`：pilot20 与风险种子的合并输入")
    lines.append("")

    lines.append("## 2. 输出文件")
    lines.append("")
    lines.append("- `output/pilot_results.jsonl`：完整依赖检测结果")
    lines.append("- `output/risk_cards.jsonl`：风险卡片")
    lines.append("- `output/summary_report.md`：检测结果汇总报告")
    lines.append("- `output/gen_dep_risk_bench_sample.jsonl`：GenDepRiskBench 风格样本记录")
    lines.append("- `output/benchmark_summary.md`：数据集汇总报告")
    lines.append("- `output/manual_review_template.csv`：人工复核模板")
    lines.append("")

    lines.append("## 3. 当前统计")
    lines.append("")
    lines.append(f"- 进入 benchmark 的样本数量：{len(sample_ids)}")
    lines.append(f"- Prompt 数量：{len(prompt_ids)}")
    lines.append(f"- 依赖记录数量：{len(benchmark_rows)}")
    lines.append(f"- 正常或未确认记录数量：{normal_count}")
    lines.append(f"- 自动标记为风险的记录数量：{risk_count}")
    lines.append(f"- Risk Card 数量：{len(risk_rows)}")
    lines.append("")

    lines.append("## 4. 状态分布")
    lines.append("")
    lines.append("| 状态 | 数量 |")
    lines.append("|---|---:|")
    for status, count in status_counter.most_common():
        lines.append(f"| {status} | {count} |")
    lines.append("")

    lines.append("## 5. 风险类型分布")
    lines.append("")
    lines.append("| 风险类型 | 数量 |")
    lines.append("|---|---:|")
    for risk_type, count in risk_type_counter.most_common():
        lines.append(f"| {risk_type} | {count} |")
    lines.append("")

    lines.append("## 6. 安装可达性分布")
    lines.append("")
    lines.append("| 安装可达性 | 数量 |")
    lines.append("|---|---:|")
    for reachability, count in reachability_counter.most_common():
        lines.append(f"| {reachability} | {count} |")
    lines.append("")

    lines.append("## 7. 自动标签分布")
    lines.append("")
    lines.append("| 自动标签 | 数量 |")
    lines.append("|---|---:|")
    for label, count in auto_label_counter.most_common():
        lines.append(f"| {label} | {count} |")
    lines.append("")

    lines.append("## 8. 风险样本")
    lines.append("")
    if not risk_rows:
        lines.append("当前快照中没有风险样本。")
    else:
        lines.append("| sample_id | package | raw_name | status | severity | reachability |")
        lines.append("|---|---|---|---|---|---|")
        for row in risk_rows:
            lines.append(
                "| "
                + f"{row.get('sample_id', '')} | "
                + f"{row.get('package', '')} | "
                + f"{row.get('raw_name', '')} | "
                + f"{row.get('status', '')} | "
                + f"{row.get('severity', '')} | "
                + f"{row.get('install_reachability', '')} |"
            )
    lines.append("")

    lines.append("## 9. 当前已验证能力")
    lines.append("")
    lines.append("- 可以从生成代码中抽取 import 依赖。")
    lines.append("- 可以从 requirements_text 中抽取 manifest 依赖。")
    lines.append("- 可以过滤 Python 标准库依赖，避免 json、os、shutil 等误报。")
    lines.append("- 可以进行 import 名到 PyPI 包名映射，例如 yaml -> PyYAML、bs4 -> beautifulsoup4。")
    lines.append("- 可以查询 PyPI 当前状态，区分 existed_at_tg、nonexistent_now、registry_query_error。")
    lines.append("- 可以根据 requirements_text 判断 manifest_declared 安装可达性。")
    lines.append("- 可以为不存在包生成 Risk Card。")
    lines.append("- 可以导出 GenDepRiskBench 风格样本记录。")
    lines.append("- 可以生成人工复核模板。")
    lines.append("")

    lines.append("## 10. 当前边界")
    lines.append("")
    lines.append("- 当前风险样本包含 controlled risk seed，不能用于估计真实 LLM 生成风险比例。")
    lines.append("- 当前时态判断主要基于审计时刻 PyPI 当前状态，还没有完整实现 created_after_tg。")
    lines.append("- 当前安装可达性主要覆盖 import_only 与 manifest_declared，还未扩展到 lockfile、Dockerfile、CI。")
    lines.append("- 当前尚未接入漏洞库和 AVCS。")
    lines.append("- 当前人工标签仍处于 unreviewed 状态。")
    lines.append("")

    SNAPSHOT_OUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"[OK] snapshot saved to: {SNAPSHOT_OUT}")


if __name__ == "__main__":
    main()