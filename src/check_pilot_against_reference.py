import json
from pathlib import Path

from reference_resources import (
    load_pypi_package_names,
    load_false_positive_packages,
    is_in_offline_pypi_list,
    is_known_false_positive,
)


BASE_DIR = Path(__file__).resolve().parent.parent
PILOT_RESULTS_PATH = BASE_DIR / "output" / "pilot_results.jsonl"
OUTPUT_PATH = BASE_DIR / "output" / "pilot_reference_check.jsonl"
SUMMARY_PATH = BASE_DIR / "output" / "pilot_reference_check_summary.md"


def read_jsonl(path: Path):
    if not path.exists():
        raise FileNotFoundError(f"找不到文件：{path}")

    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def get_package_name(record: dict) -> str:
    """
    尽量兼容不同字段名。
    你的 pilot_results.jsonl 里如果字段名不一样，这里可以后面再微调。
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
    pypi_names = load_pypi_package_names()
    false_positive_names = load_false_positive_packages()

    total = 0
    offline_hit = 0
    offline_miss = 0
    false_positive_hit = 0
    empty_package = 0

    filtered_records = 0
    effective_total = 0
    effective_offline_hit = 0
    effective_offline_miss = 0
    effective_false_positive_hit = 0

    checked_records = []

    for record in read_jsonl(PILOT_RESULTS_PATH):
        total += 1

        package_name = get_package_name(record)

        if not package_name:
            empty_package += 1
            record["offline_pypi_exists"] = None
            record["reference_false_positive"] = None
            checked_records.append(record)
            continue

        in_offline = is_in_offline_pypi_list(package_name, pypi_names)
        in_false_positive = is_known_false_positive(package_name, false_positive_names)

        record["offline_pypi_exists"] = in_offline
        record["reference_false_positive"] = in_false_positive

        if in_offline:
            offline_hit += 1
        else:
            offline_miss += 1

        if in_false_positive:
            false_positive_hit += 1

        # 是否已经被主流程过滤为误报
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

    with OUTPUT_PATH.open("w", encoding="utf-8") as f:
        for record in checked_records:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    summary = f"""# pilot_v0 与原仓库离线资源对比结果

    ## 1. 基本统计

    - 输入文件：`output/pilot_results.jsonl`
    - 输出文件：`output/pilot_reference_check.jsonl`
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
    其中“原始未命中”包含已经被主流程过滤掉的误报记录；“有效候选未命中”排除了 `filtered_false_positive` 等已过滤记录，更适合用于后续风险候选分析。

    当前阶段不直接用离线包名库替代在线 PyPI 查询，而是把它作为 reference evidence，用于辅助误报分析、baseline 对比和后续数据集扩展。
    """

    SUMMARY_PATH.write_text(summary, encoding="utf-8")

    print("对比完成。")
    print("输出 JSONL：", OUTPUT_PATH)
    print("输出摘要：", SUMMARY_PATH)


if __name__ == "__main__":
    main()