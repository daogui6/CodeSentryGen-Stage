"""
check_pilot50_against_reference.py

作用：
    CodeSentry-Gen 的离线参考核对模块。
    用离线 PyPI 包名列表和 false positive 包列表，对 run_pilot.py 的输出结果进行辅助核对。

输入：
    - run_pilot.py 输出的 dependency records JSONL
      例如：
        output/pilot50_results.jsonl

输出：
    - reference checked JSONL
      例如：
        output/pilot50_reference_check.jsonl

    - reference check summary
      例如：
        output/pilot50_reference_check_summary.md

核心补充字段：
    - offline_pypi_exists：
      当前 package 是否命中离线 PyPI 包名库。

    - reference_false_positive：
      当前 package 是否命中离线 false positive 表。

    - reference_effective_candidate：
      排除主流程已过滤误报后，这条记录是否仍然是有效候选。

在整体流程中的位置：
    run_pilot.py
        ↓
    check_pilot50_against_reference.py
        ↓
    enrich_temporal_status.py
        ↓
    enrich_reachability_v2.py
        ↓
    build_temporal_risk_cards.py

注意：
    本脚本不直接生成风险卡。
    offline_pypi_exists=False 也不等于风险。
    它只是 reference evidence，用于辅助发现误报、mapping 缺失和可疑候选。
"""

import argparse
import json
from pathlib import Path

from reference_resources import (
    load_pypi_package_names,
    load_false_positive_packages,
    is_in_offline_pypi_list,
    is_known_false_positive,
)


# 项目根目录。
# 当前文件位于 src/ 下，因此 parent.parent 回到项目根目录。
BASE_DIR = Path(__file__).resolve().parent.parent

# 默认输入输出路径。
# 这里默认使用 pilot50，更符合当前主流程。
DEFAULT_INPUT_PATH = BASE_DIR / "output" / "pilot50_results.jsonl"
DEFAULT_OUTPUT_PATH = BASE_DIR / "output" / "pilot50_reference_check.jsonl"
DEFAULT_SUMMARY_PATH = BASE_DIR / "output" / "pilot50_reference_check_summary.md"


def read_jsonl(path: Path):
    """
    逐行读取 JSONL 文件。

    输入通常是 run_pilot.py 的输出：
        output/pilot50_results.jsonl

    每一行是一条 dependency record。
    """
    if not path.exists():
        raise FileNotFoundError(f"找不到文件：{path}")

    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if line:
                yield json.loads(line)


def get_package_name(record: dict) -> str:
    """
    从一条 dependency record 中提取包名。

    不同阶段或不同版本的输出字段名可能不完全一致，
    所以这里兼容多个可能字段。

    当前 run_pilot.py 主要使用字段：
        package
    """
    for key in [
        "package",
        "package_name",
        "normalized_package",
        "normalized_name",
        "entity",
        "dependency",
    ]:
        value = record.get(key)

        if value:
            return str(value)

    return ""


def main():
    """
    主流程：
    1. 解析命令行参数
    2. 加载离线 PyPI 包名库和 false positive 表
    3. 读取 run_pilot.py 的输出记录
    4. 给每条记录补充 reference 字段
    5. 统计命中情况和有效候选情况
    6. 输出 JSONL 和 Markdown summary
    """
    parser = argparse.ArgumentParser(
        description="Check pilot dependency records against offline PyPI and false-positive references."
    )

    parser.add_argument(
        "--input",
        default=str(DEFAULT_INPUT_PATH),
        help="Input dependency records JSONL from run_pilot.py",
    )

    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT_PATH),
        help="Output reference-checked JSONL",
    )

    parser.add_argument(
        "--summary",
        default=str(DEFAULT_SUMMARY_PATH),
        help="Output Markdown summary",
    )

    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)
    summary_path = Path(args.summary)

    # =========================
    # 1. 加载离线 reference 资源
    # =========================

    # 离线 PyPI 包名列表：
    # 用来判断某个 package 是否在已知 PyPI 包名集合中出现过。
    pypi_names = load_pypi_package_names()

    # false positive 列表：
    # 用来判断某个 package 是否是已知误报名称。
    false_positive_names = load_false_positive_packages()

    # =========================
    # 2. 初始化统计变量
    # =========================

    total = 0
    offline_hit = 0
    offline_miss = 0
    false_positive_hit = 0
    empty_package = 0

    # 主流程已经过滤掉的记录数量
    filtered_records = 0

    # 排除主流程已过滤记录后的有效候选统计
    effective_total = 0
    effective_offline_hit = 0
    effective_offline_miss = 0
    effective_false_positive_hit = 0

    checked_records = []

    # =========================
    # 3. 逐条核对 dependency record
    # =========================

    for record in read_jsonl(input_path):
        total += 1

        package_name = get_package_name(record)

        # 如果包名为空，无法做 reference check
        if not package_name:
            empty_package += 1
            record["offline_pypi_exists"] = None
            record["reference_false_positive"] = None
            record["reference_effective_candidate"] = None
            checked_records.append(record)
            continue

        # 3.1 是否命中离线 PyPI 包名库
        in_offline = is_in_offline_pypi_list(package_name, pypi_names)

        # 3.2 是否命中 false positive 表
        in_false_positive = is_known_false_positive(package_name, false_positive_names)

        # 将 reference check 结果写回当前记录
        record["offline_pypi_exists"] = in_offline
        record["reference_false_positive"] = in_false_positive

        if in_offline:
            offline_hit += 1
        else:
            offline_miss += 1

        if in_false_positive:
            false_positive_hit += 1

        # 3.3 判断该记录是否已经被主流程过滤
        # 如果 run_pilot.py 已经将它标记为 false positive，
        # 那么它不应该再作为有效风险候选参与统计。
        is_filtered = (
            record.get("false_positive_filtered") is True
            or record.get("status") == "filtered_false_positive"
        )

        record["reference_effective_candidate"] = not is_filtered

        if is_filtered:
            filtered_records += 1
        else:
            effective_total += 1

            if in_offline:
                effective_offline_hit += 1
            else:
                effective_offline_miss += 1

            if in_false_positive:
                effective_false_positive_hit += 1

        checked_records.append(record)

    # =========================
    # 4. 输出 reference checked JSONL
    # =========================

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as f:
        for record in checked_records:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    # =========================
    # 5. 输出 Markdown summary
    # =========================

    summary = f"""# Pilot Reference Check Summary

## 1. 基本统计

- 输入文件：`{input_path}`
- 输出文件：`{output_path}`
- 总记录数：{total}
- 空包名记录数：{empty_package}
- 主流程已过滤误报记录数：{filtered_records}

## 2. 原始离线 PyPI 包名库命中情况

- 命中离线 PyPI 包名库：{offline_hit}
- 未命中离线 PyPI 包名库：{offline_miss}

## 3. 排除已过滤误报后的有效记录统计

- 有效候选记录数：{effective_total}
- 有效候选中命中离线 PyPI 包名库：{effective_offline_hit}
- 有效候选中未命中离线 PyPI 包名库：{effective_offline_miss}

## 4. 原仓库 false positive 表命中情况

- 原始记录中命中 false positive 表：{false_positive_hit}
- 有效候选中命中 false positive 表：{effective_false_positive_hit}

## 5. 说明

这一步把当前 pilot 结果与 PackageHallucination 原仓库提供的离线 PyPI 包名列表和误报包列表进行对比。

其中，“原始未命中”包含已经被主流程过滤掉的误报记录；“有效候选未命中”排除了 `filtered_false_positive` 等已过滤记录，更适合用于后续风险候选分析。

当前阶段不直接用离线包名库替代在线 PyPI 查询，而是把它作为 reference evidence，用于辅助误报分析、baseline 对比和后续数据集扩展。

注意：`offline_pypi_exists=False` 不等于风险，它只表示该包没有命中离线参考表。最终风险判断仍以后续 `temporal_status_v2` 和 `install_reachability_v2` 为准。
"""

    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(summary, encoding="utf-8")

    print("对比完成。")
    print("输入 JSONL：", input_path)
    print("输出 JSONL：", output_path)
    print("输出摘要：", summary_path)
    print(f"总记录数: {total}")
    print(f"有效候选记录数: {effective_total}")
    print(f"有效候选未命中离线 PyPI 包名库: {effective_offline_miss}")


if __name__ == "__main__":
    main()