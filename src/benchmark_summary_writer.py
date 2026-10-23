from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List


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


def write_benchmark_summary(
    benchmark_jsonl_path: Path,
    summary_path: Path,
) -> None:
    records = load_jsonl(benchmark_jsonl_path)
    summary_path.parent.mkdir(parents=True, exist_ok=True)

    language_counter = Counter(row.get("language", "unknown") for row in records)
    ecosystem_counter = Counter(row.get("ecosystem", "unknown") for row in records)
    status_counter = Counter(row.get("status", "unknown") for row in records)
    risk_type_counter = Counter(row.get("risk_type") or "none" for row in records)
    auto_label_counter = Counter(row.get("auto_label", "unknown") for row in records)
    review_status_counter = Counter(row.get("review_status", "unknown") for row in records)
    reachability_counter = Counter(row.get("install_reachability", "unknown") for row in records)

    risk_records = [row for row in records if row.get("auto_label") == "risk"]
    normal_records = [row for row in records if row.get("auto_label") != "risk"]

    sample_ids = sorted({row.get("sample_id", "unknown") for row in records})
    prompt_ids = sorted({row.get("prompt_id", "unknown") for row in records})

    lines = []

    lines.append("# GenDepRiskBench Pilot 数据集汇总")
    lines.append("")

    lines.append("## 1. 数据集基本信息")
    lines.append("")
    lines.append(f"- 数据集阶段：pilot_v0")
    lines.append(f"- 样本数量：{len(sample_ids)}")
    lines.append(f"- Prompt 数量：{len(prompt_ids)}")
    lines.append(f"- 依赖记录数量：{len(records)}")
    lines.append(f"- 自动标记为风险的记录数量：{len(risk_records)}")
    lines.append(f"- 正常或未确认记录数量：{len(normal_records)}")
    lines.append("")

    lines.append("## 2. 语言与生态分布")
    lines.append("")
    lines.append("| 类型 | 名称 | 数量 |")
    lines.append("|---|---|---:|")
    for language, count in language_counter.most_common():
        lines.append(f"| language | {language} | {count} |")
    for ecosystem, count in ecosystem_counter.most_common():
        lines.append(f"| ecosystem | {ecosystem} | {count} |")
    lines.append("")

    lines.append("## 3. 状态分布")
    lines.append("")
    lines.append("| 状态 | 数量 | 含义 |")
    lines.append("|---|---:|---|")
    status_meaning = {
        "existed_at_tg": "当前流程判断为正常存在的依赖",
        "nonexistent_now": "审计时刻当前 registry 中不存在的包",
        "created_after_tg": "包首次发布时间晚于生成时间，属于后续时态检测重点",
        "registry_query_error": "查询 registry 失败，暂不作为不存在包处理",
    }
    for status, count in status_counter.most_common():
        lines.append(f"| {status} | {count} | {status_meaning.get(status, '')} |")
    lines.append("")

    lines.append("## 4. 风险类型分布")
    lines.append("")
    lines.append("| 风险类型 | 数量 |")
    lines.append("|---|---:|")
    for risk_type, count in risk_type_counter.most_common():
        lines.append(f"| {risk_type} | {count} |")
    lines.append("")

    lines.append("## 5. 安装可达性分布")
    lines.append("")
    lines.append("| 安装可达性 | 数量 |")
    lines.append("|---|---:|")
    for reachability, count in reachability_counter.most_common():
        lines.append(f"| {reachability} | {count} |")
    lines.append("")

    lines.append("## 6. 自动标签与人工复核状态")
    lines.append("")
    lines.append("### 6.1 自动标签")
    lines.append("")
    lines.append("| 自动标签 | 数量 |")
    lines.append("|---|---:|")
    for label, count in auto_label_counter.most_common():
        lines.append(f"| {label} | {count} |")
    lines.append("")

    lines.append("### 6.2 人工复核状态")
    lines.append("")
    lines.append("| 复核状态 | 数量 |")
    lines.append("|---|---:|")
    for status, count in review_status_counter.most_common():
        lines.append(f"| {status} | {count} |")
    lines.append("")

    lines.append("## 7. 风险样本列表")
    lines.append("")
    if not risk_records:
        lines.append("当前 pilot 数据集中暂无自动风险样本。")
    else:
        lines.append("| sample_id | package | raw_name | status | risk_type | severity | reachability | review_status |")
        lines.append("|---|---|---|---|---|---|---|---|")
        for row in risk_records:
            lines.append(
                "| "
                + f"{row.get('sample_id', '')} | "
                + f"{row.get('package', '')} | "
                + f"{row.get('raw_name', '')} | "
                + f"{row.get('status', '')} | "
                + f"{row.get('risk_type', '')} | "
                + f"{row.get('severity', '')} | "
                + f"{row.get('install_reachability', '')} | "
                + f"{row.get('review_status', '')} |"
            )
    lines.append("")

    lines.append("## 8. 当前数据集边界")
    lines.append("")
    lines.append(
        "当前文件是 GenDepRiskBench 的 pilot_v0 数据集雏形，"
        "主要用于验证字段结构、检测流程和证据保存方式是否可行。"
    )
    lines.append("")
    lines.append(
        "当前样本规模较小，且包含人工构造的风险样本，因此不能用于报告真实风险发生率，"
        "也不能作为正式 benchmark 结论。"
    )
    lines.append("")
    lines.append(
        "后续需要接入 PackageHallucination 的真实 Python prompt，"
        "扩大样本规模，并加入人工复核字段、hard negative 样本和更完整的时态证据。"
    )
    lines.append("")

    summary_path.write_text("\n".join(lines), encoding="utf-8")