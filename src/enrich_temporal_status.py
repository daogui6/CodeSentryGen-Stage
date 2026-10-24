"""
enrich_temporal_status.py

作用：
    CodeSentry-Gen 的时态状态增强模块。
    在 run_pilot.py 输出的依赖记录基础上，根据 generation_time 和 PyPI first_release_time
    生成 temporal_status_v2 字段，用于后续 THO 风险判断。

输入：
    - run_pilot.py 或 check_pilot50_against_reference.py 输出的 JSONL
      例如 output/pilot50_reference_check.jsonl

输出：
    - temporal enriched JSONL
      例如 output/pilot50_temporal_enriched.jsonl
    - temporal summary Markdown
      例如 output/pilot50_temporal_summary.md

核心字段：
    - generation_time：代码生成时间
    - pypi.first_release_time：PyPI 最早 release file upload time
    - temporal_status_v2：增强后的时态状态

主要状态：
    - existed_at_tg：代码生成时包已经存在
    - nonexistent_now：包当前明确不存在
    - created_after_tg：包首次发布时间晚于代码生成时间
    - registry_query_error：PyPI 查询失败
    - filtered_false_positive：已过滤误报
    - temporal_unknown：时间关系不确定

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
    本脚本不覆盖原始 status 字段，而是新增 temporal_status_v2。
    最终 Risk Card v2 由 build_temporal_risk_cards.py 基于 temporal_status_v2 和 install_reachability_v2 生成。
"""

import json
import argparse
from pathlib import Path
from datetime import datetime, timedelta, timezone
from collections import Counter


BASE_DIR = Path(__file__).resolve().parent.parent

# 默认输入输出路径配置
DEFAULT_INPUT_PATH = BASE_DIR / "output" / "pilot_reference_check.jsonl"
DEFAULT_OUTPUT_PATH = BASE_DIR / "output" / "pilot_temporal_enriched.jsonl"
DEFAULT_SUMMARY_PATH = BASE_DIR / "output" / "pilot_temporal_summary.md"

def read_jsonl(path: Path):
    """
    读取 JSONL 文件，逐行解析为字典对象
    
    Args:
        path: JSONL 文件路径
        
    Yields:
        dict: 解析后的记录字典
        
    Raises:
        FileNotFoundError: 文件不存在时抛出异常
    """
    if not path.exists():
        raise FileNotFoundError(f"找不到文件：{path}")

    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def parse_datetime(value: str):
    """
    解析 ISO 格式的时间字符串，统一转换为 UTC 时区
    
    支持的时间格式：
    - 2026-05-30T22:52:58+09:00
    - 2026-05-30T13:53:11.106943+00:00
    - 2026-05-30T13:53:11Z
    
    Args:
        value: 时间字符串
        
    Returns:
        datetime: UTC 时区的 datetime 对象，解析失败返回 None
    """
    if not value:
        return None

    value = str(value).strip()

    # 将 Z 后缀转换为 +00:00 格式
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"

    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None

    # 如果没有时区信息，默认视为 UTC
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt.astimezone(timezone.utc)


def get_first_release_time(record: dict):
    """
    从记录中提取包的首次发布时间
    
    Args:
        record: 数据记录字典
        
    Returns:
        datetime: 首次发布时间（UTC），不存在则返回 None
    """
    pypi = record.get("pypi") or {}
    return parse_datetime(pypi.get("first_release_time"))


def get_generation_time(record: dict):
    """
    从记录中提取代码生成时间
    
    Args:
        record: 数据记录字典
        
    Returns:
        datetime: 生成时间（UTC），不存在则返回 None
    """
    return parse_datetime(record.get("generation_time"))


def has_proven_generation_time_nonexistence(record: dict) -> bool:
    """Return whether an authoritative ``as_of_tg`` view proves absence.

    Current registry existence is an audit-time observation.  It must not
    erase an independently observed or completely reconstructed
    generation-time absence fact.
    """
    registry_view_tg = record.get("registry_view_tg")
    return (
        isinstance(registry_view_tg, dict)
        and registry_view_tg.get("exists") is False
        and registry_view_tg.get("evidence_status")
        in {"observed", "reconstructed_complete", "proven"}
    )


def has_proven_generation_time_existence(record: dict) -> bool:
    """Keep observed generation-time presence distinct from current releases.

    A current registry's earliest retained release can move when historical
    files disappear. It cannot override an authoritative presence at t_g.
    """
    view = record.get("registry_view_tg")
    return (isinstance(view, dict) and view.get("exists") is True
            and view.get("evidence_status") in {"observed", "reconstructed_complete", "proven"})


def classify_temporal_status(
    record: dict,
    uncertainty_days: float = 0,
    *,
    uncertainty_seconds: float | None = None,
) -> str:
    """
    根据生成时间和首次发布时间对样本进行时态状态分类
    
    分类边界：
    1. 先保留 filtered/local/private/wrong-ecosystem/lifecycle 事实；
    2. 当前 404 若同时有明确 as_of_tg 不存在证明，分类为
       nonexistent_at_tg；否则仅分类为 nonexistent_now；
    3. 当前存在时，优先用 release time 形成更具体的
       created_after_tg，再处理其他 generation-time 状态；
    4. 缺失或冲突证据保持 unknown，不猜测正式 positive。
    
    Args:
        record: 数据记录字典，包含 status、pypi、generation_time 等字段
        uncertainty_days: 兼容旧调用的天数容差，默认 0
        uncertainty_seconds: 新语义入口；提供时优先于 uncertainty_days
        
    Returns:
        str: 时态状态分类标签
    """
    old_status = record.get("status")

    # 优先级1: 已过滤的误报保持原状态
    if record.get("false_positive_filtered") is True or old_status == "filtered_false_positive":
        return "filtered_false_positive"

    # 优先级2: 本地或显式私有 registry 上下文保持 unknown。
    identity = record.get("package_identity")
    identity_status = (
        str(identity.get("identity_status") or "")
        if isinstance(identity, dict)
        else ""
    )
    if (
        record.get("local_module_filtered") is True
        or old_status in {"local_module", "private_unknown"}
        or identity_status in {"local_module", "private_unknown"}
    ):
        return "local_or_private_unknown"

    # 明确的生态语义不匹配证据优先保留为 wrong_ecosystem。
    # 不从普通 404/名字相似性中猜测该状态。
    if (
        old_status == "wrong_ecosystem"
        or record.get("wrong_ecosystem") is True
        or record.get("ecosystem_semantic_mismatch") is True
    ):
        return "wrong_ecosystem"

    # deleted_or_yanked 仅在上游/registry snapshot 已提供显式生命周期
    # 证据时保留；当前 repair line 不从普通不存在状态反推删除。
    if (
        old_status == "deleted_or_yanked"
        or record.get("deleted_or_yanked") is True
    ):
        return "deleted_or_yanked"

    # 获取 PyPI 信息
    pypi = record.get("pypi")

    # 优先级3: PyPI 信息缺失
    if not pypi:
        return "registry_unknown"

    # 如果 PyPI 查询本身失败，不应当当成包不存在
    if record.get("status") == "registry_query_error":
        return "registry_query_error"

    if pypi.get("error"):
        return "registry_query_error"

    if (
        pypi.get("lifecycle_status") == "deleted_or_yanked"
        or pypi.get("deleted_or_yanked") is True
    ):
        return "deleted_or_yanked"
    
    exists_now = pypi.get("exists_now")

    # generation-time existence and current existence are distinct temporal
    # observations.  When an authoritative as_of_tg view proves absence,
    # retain that stronger fact even if the audit-time registry also returns
    # 404.  The current observation remains available in pypi.exists_now.
    if exists_now is False:
        if (
            has_proven_generation_time_nonexistence(record)
            or old_status == "nonexistent_at_tg"
        ):
            return "nonexistent_at_tg"
        return "nonexistent_now"

    # 优先级5: 存在状态未知
    if exists_now is not True:
        return "registry_unknown"

    # 获取时间信息进行时态判断
    generation_time = get_generation_time(record)
    first_release_time = get_first_release_time(record)

    # 生成时间缺失
    if generation_time is None:
        return "generation_time_unknown"

    if has_proven_generation_time_existence(record):
        return "existed_at_tg"

    # 首次发布时间缺失
    if first_release_time is None:
        return "registry_unknown"

    # 计算 generation-time 不确定性区间。新修复线统一使用秒，
    # 旧 uncertainty_days 仅作为兼容入口。负值没有科学意义，直接拒绝。
    if uncertainty_seconds is None:
        resolved_uncertainty_seconds = float(uncertainty_days) * 86400.0
    else:
        resolved_uncertainty_seconds = float(uncertainty_seconds)

    if resolved_uncertainty_seconds < 0:
        raise ValueError("generation-time uncertainty must be >= 0")

    delta = timedelta(seconds=resolved_uncertainty_seconds)
    lower_bound = generation_time - delta
    upper_bound = generation_time + delta

    # 优先级6: 包创建于代码生成之后（时态风险样本）
    if first_release_time > upper_bound:
        return "created_after_tg"

    # 若历史 snapshot 明确证明 t_g 时没有可用版本，但当前最早 release
    # 时间不足以形成 created_after_tg 的更具体结论，则保留
    # nonexistent_at_tg。该状态必须来自显式历史证据，不靠猜测。
    if has_proven_generation_time_nonexistence(record):
        return "nonexistent_at_tg"

    if old_status == "nonexistent_at_tg":
        return "nonexistent_at_tg"

    # 优先级7: 时间在不确定区间内，无法确定先后关系
    if lower_bound <= first_release_time <= upper_bound:
        return "temporal_unknown"

    # 优先级8: 代码生成时包已存在
    return "existed_at_tg"

def parse_args():
    """
    解析命令行参数
    
    Returns:
        argparse.Namespace: 解析后的参数对象
    """
    parser = argparse.ArgumentParser(
        description="根据 generation_time 和 PyPI first_release_time 增强 temporal status"
    )

    parser.add_argument(
        "--input",
        default=str(DEFAULT_INPUT_PATH),
        help="输入 JSONL 文件路径，默认 output/pilot_reference_check.jsonl"
    )

    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT_PATH),
        help="输出 JSONL 文件路径，默认 output/pilot_temporal_enriched.jsonl"
    )

    parser.add_argument(
        "--summary",
        default=str(DEFAULT_SUMMARY_PATH),
        help="输出 Markdown 摘要路径，默认 output/pilot_temporal_summary.md"
    )

    parser.add_argument(
        "--uncertainty-days",
        type=float,
        default=None,
        help=(
            "Legacy compatibility option. Generation-time uncertainty in "
            "days. Do not combine with --uncertainty-seconds."
        ),
    )
    parser.add_argument(
        "--uncertainty-seconds",
        type=float,
        default=None,
        help=(
            "Generation-time uncertainty Δt in seconds. Repair-line E2E "
            "passes this explicitly."
        ),
    )

    return parser.parse_args()

def main():
    """
    主函数：执行时态状态增强流程
    
    处理步骤：
    1. 读取输入 JSONL 文件
    2. 对每条记录进行时态状态分类
    3. 添加 temporal_status_v2 字段
    4. 统计分布情况并生成摘要报告
    5. 输出增强后的数据和 Markdown 摘要
    """
    args = parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)
    summary_path = Path(args.summary)

    # 确保使用绝对路径
    if not input_path.is_absolute():
        input_path = BASE_DIR / input_path

    if not output_path.is_absolute():
        output_path = BASE_DIR / output_path

    if not summary_path.is_absolute():
        summary_path = BASE_DIR / summary_path

    if (
        args.uncertainty_days is not None
        and args.uncertainty_seconds is not None
    ):
        raise ValueError(
            "Use only one of --uncertainty-days or --uncertainty-seconds"
        )

    if args.uncertainty_seconds is not None:
        resolved_uncertainty_seconds = float(args.uncertainty_seconds)
        uncertainty_source = "explicit_seconds"
    elif args.uncertainty_days is not None:
        resolved_uncertainty_seconds = float(args.uncertainty_days) * 86400.0
        uncertainty_source = "legacy_days"
    else:
        resolved_uncertainty_seconds = 0.0
        uncertainty_source = "legacy_default_zero"

    if resolved_uncertainty_seconds < 0:
        raise ValueError("generation-time uncertainty must be >= 0")

    enriched_records = []
    status_counter = Counter()  # 新状态分布统计
    old_status_counter = Counter()  # 原始状态分布统计

    # 逐条处理记录
    for record in read_jsonl(input_path):
        old_status = record.get("status", "unknown")
        old_status_counter[old_status] += 1

        # 进行时态状态分类
        temporal_status_v2 = classify_temporal_status(
            record,
            uncertainty_seconds=resolved_uncertainty_seconds,
        )

        # 添加新字段，不覆盖原始 status
        record["temporal_status_v2"] = temporal_status_v2
        record["generation_time_uncertainty_seconds"] = (
            resolved_uncertainty_seconds
        )
        record["generation_time_uncertainty_source"] = uncertainty_source

        # 保留说明字段，便于后续理解和解释
        record["temporal_status_v2_note"] = (
            "computed from generation_time and PyPI first_release_time with "
            f"explicit Δt={resolved_uncertainty_seconds}s; "
            "does not overwrite original status"
        )

        status_counter[temporal_status_v2] += 1
        enriched_records.append(record)

    # 确保输出目录存在
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # 写入增强后的 JSONL 文件
    with output_path.open("w", encoding="utf-8") as f:
        for record in enriched_records:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    # 生成 Markdown 摘要报告
    lines = []
    lines.append("# 时态状态增强结果\n")
    lines.append(f"- 输入文件：`{input_path.relative_to(BASE_DIR)}`")
    lines.append(f"- 输出文件：`{output_path.relative_to(BASE_DIR)}`")
    lines.append(f"- 总记录数：{len(enriched_records)}")
    lines.append(
        f"- generation_time_uncertainty_seconds: "
        f"{resolved_uncertainty_seconds}"
    )
    lines.append(f"- uncertainty_source: {uncertainty_source}\n")

    # 原始状态分布
    lines.append("## 1. 原始 status 分布\n")
    lines.append("| status | count |")
    lines.append("|---|---:|")
    for status, count in old_status_counter.most_common():
        lines.append(f"| {status} | {count} |")

    # 新状态分布
    lines.append("\n## 2. temporal_status_v2 分布\n")
    lines.append("| temporal_status_v2 | count |")
    lines.append("|---|---:|")
    for status, count in status_counter.most_common():
        lines.append(f"| {status} | {count} |")

    # created_after_tg 样本详情
    lines.append("\n## 3. created_after_tg 样本\n")
    created_after_records = [
        r for r in enriched_records
        if r.get("temporal_status_v2") == "created_after_tg"
    ]

    if not created_after_records:
        lines.append("\n当前 pilot_v0 中暂未发现 `created_after_tg` 样本。\n")
    else:
        lines.append("| sample_id | package | generation_time | first_release_time |")
        lines.append("|---|---|---|---|")
        for r in created_after_records:
            pypi = r.get("pypi") or {}
            lines.append(
                f"| {r.get('sample_id', '')} | {r.get('package', '')} | "
                f"{r.get('generation_time', '')} | {pypi.get('first_release_time', '')} |"
            )

    # 说明部分
    lines.append("\n## 4. 说明\n")
    lines.append(
        "本步骤没有覆盖原始 `status` 字段，而是新增 `temporal_status_v2` 字段。"
        "该字段根据 `generation_time` 和 PyPI `first_release_time` 进行重新判断，"
        "用于后续支持 `created_after_tg` 时态风险检测。"
    )

    # 写入摘要文件
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text("\n".join(lines), encoding="utf-8")

    # 控制台输出统计信息
    print("时态状态增强完成。")
    print("输出 JSONL：", output_path)
    print("输出摘要：", summary_path)
    print("\ntemporal_status_v2 分布：")
    for status, count in status_counter.most_common():
        print(f"{status}: {count}")


if __name__ == "__main__":
    main()

