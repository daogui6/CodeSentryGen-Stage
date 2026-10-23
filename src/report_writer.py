from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any, Dict, List


def write_summary_report(
    output_path: Path,
    all_rows: List[Dict[str, Any]],
    risk_rows: List[Dict[str, Any]],
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    sample_ids = sorted({row.get("sample_id", "unknown") for row in all_rows})
    status_counter = Counter(row.get("status", "unknown") for row in all_rows)
    package_counter = Counter(row.get("package", "unknown") for row in all_rows)
    reachability_counter = Counter(row.get("install_reachability", "unknown") for row in all_rows)

    normal_statuses = {
        "existed_at_tg",
        "filtered_false_positive",
        "local_module",
    }

    normal_count = sum(
        1 for row in all_rows
        if row.get("status") in normal_statuses
    )

    risk_count = len(risk_rows)

    lines = []

    lines.append("# CodeSentry-Gen 第一阶段 Pilot 汇总报告")
    lines.append("")

    lines.append("## 1. 基本统计")
    lines.append("")
    lines.append(f"- 样本数量：{len(sample_ids)}")
    lines.append(f"- 依赖记录数量：{len(all_rows)}")
    lines.append(f"- 正常或已过滤依赖数量：{normal_count}")
    lines.append(f"- 风险卡片数量：{risk_count}")
    lines.append("")

    lines.append("## 2. 状态分布")
    lines.append("")
    lines.append("| 状态 | 数量 |")
    lines.append("|---|---:|")
    for status, count in status_counter.most_common():
        lines.append(f"| {status} | {count} |")
    lines.append("")

    lines.append("## 3. 安装可达性分布")
    lines.append("")
    lines.append("| 安装可达性 | 数量 | 含义 |")
    lines.append("|---|---:|---|")
    for reachability, count in reachability_counter.most_common():
        meaning = {
            "import_only": "仅在代码 import 中出现，暂不能证明会被安装",
            "manifest_declared": "已在 requirements 等依赖声明中出现，更可能被安装",
            "unknown": "暂未识别到明确可达性",
        }.get(reachability, "")
        lines.append(f"| {reachability} | {count} | {meaning} |")
    lines.append("")

    lines.append("## 4. 抽取到的依赖包")
    lines.append("")
    lines.append("| 包名 | 出现次数 |")
    lines.append("|---|---:|")
    for package, count in package_counter.most_common():
        lines.append(f"| {package} | {count} |")
    lines.append("")

    lines.append("## 5. 风险卡片明细")
    lines.append("")
    if not risk_rows:
        lines.append("本次运行未生成风险卡片。")
    else:
        lines.append("| 样本 ID | 包名 | 原始 import 名 | 风险类型 | 状态 | 严重程度 | 安装可达性 | 证据等级 |")
        lines.append("|---|---|---|---|---|---|---|---|")

        for card in risk_rows:
            lines.append(
                "| "
                + f"{card.get('sample_id', '')} | "
                + f"{card.get('package', '')} | "
                + f"{card.get('raw_name', '')} | "
                + f"{card.get('type', '')} | "
                + f"{card.get('status', '')} | "
                + f"{card.get('severity', '')} | "
                + f"{card.get('install_reachability', '')} | "
                + f"{card.get('evidence_level', '')} |"
            )
    lines.append("")

    lines.append("## 6. 风险证据详情")
    lines.append("")
    if not risk_rows:
        lines.append("本次运行没有风险证据详情。")
    else:
        for idx, card in enumerate(risk_rows, start=1):
            location = card.get("location", {})
            evidence = card.get("evidence", {})
            repair = card.get("repair", {})

            lines.append(f"### 6.{idx} {card.get('package', '')}")
            lines.append("")
            lines.append(f"- 样本 ID：{card.get('sample_id', '')}")
            lines.append(f"- 原始名称：{card.get('raw_name', '')}")
            lines.append(f"- 风险类型：{card.get('type', '')}")
            lines.append(f"- 当前状态：{card.get('status', '')}")
            lines.append(f"- 严重程度：{card.get('severity', '')}")
            lines.append(f"- 置信度：{card.get('confidence', '')}")
            lines.append(f"- 安装可达性：{card.get('install_reachability', '')}")
            lines.append(f"- 证据等级：{card.get('evidence_level', '')}")
            lines.append(f"- 代码位置：{location.get('file', '')} 第 {location.get('line', '')} 行")
            lines.append(f"- 原始代码：`{evidence.get('original_text', '')}`")
            lines.append(f"- PyPI 查询地址：{evidence.get('query_url', '')}")
            lines.append(f"- PyPI 当前是否存在：{evidence.get('exists_now', '')}")
            lines.append(f"- 首次发布时间：{evidence.get('first_release_time', '')}")
            lines.append(f"- 最新版本：{evidence.get('latest_version', '')}")
            lines.append(f"- 修复建议：{repair.get('suggestion', '')}")
            lines.append(f"- 验证方式：{repair.get('verify', '')}")
            lines.append("")

    lines.append("## 7. 当前阶段说明")
    lines.append("")
    lines.append(
        "当前 pilot 只验证 Python/PyPI 场景下的第一阶段流程，"
        "包括生成代码样本读取、import 依赖抽取、包名规范化、false positive 过滤、"
        "PyPI 当前 registry 查询以及基础 Risk Card 输出。"
    )
    lines.append("")
    lines.append(
        "在本次增强后，系统已经可以识别样本中 requirements_text 提供的依赖声明信息，"
        "并将只在 import 中出现的依赖与已经在 manifest 中声明的依赖区分开来。"
    )
    lines.append("")
    lines.append(
        "当前阶段的风险证据主要来自审计时刻的 PyPI 当前状态，"
        "还没有完整实现 created_after_tg 判断、完整 THO 时态推理、CI/Dockerfile 级安装可达性分析或 AVCS。"
    )
    lines.append("")
    lines.append(
        "后续需要进一步补充包首次发布时间、生成时间视图、CI/Dockerfile 安装证据，"
        "再逐步扩展到完整的 temporal package hallucination 和 API-induced vulnerable dependency 检测。"
    )
    lines.append("")

    output_path.write_text("\n".join(lines), encoding="utf-8")