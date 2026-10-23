import argparse
import csv
import json
from pathlib import Path
from collections import Counter


BASE_DIR = Path(__file__).resolve().parent.parent

DEFAULT_REVIEW_CSV = BASE_DIR / "output" / "manual_review_template.csv"
DEFAULT_INPUT_JSONL = BASE_DIR / "output" / "gen_dep_risk_bench_sample.jsonl"
DEFAULT_OUTPUT_JSONL = BASE_DIR / "output" / "gen_dep_risk_bench_reviewed.jsonl"
DEFAULT_OUTPUT_CSV = BASE_DIR / "output" / "manual_review_backfilled.csv"
DEFAULT_SUMMARY_MD = BASE_DIR / "output" / "manual_review_summary.md"


def parse_args():
    parser = argparse.ArgumentParser(
        description="将 manual_review_template.csv 中的人工复核结果回填到 benchmark JSONL"
    )

    parser.add_argument(
        "--review-csv",
        default=str(DEFAULT_REVIEW_CSV),
        help="人工复核 CSV 文件路径"
    )

    parser.add_argument(
        "--input-jsonl",
        default=str(DEFAULT_INPUT_JSONL),
        help="待回填的 benchmark JSONL 文件路径"
    )

    parser.add_argument(
        "--output-jsonl",
        default=str(DEFAULT_OUTPUT_JSONL),
        help="输出 reviewed JSONL 文件路径"
    )

    parser.add_argument(
        "--output-csv",
        default=str(DEFAULT_OUTPUT_CSV),
        help="输出回填后的 CSV 文件路径"
    )

    parser.add_argument(
        "--summary-md",
        default=str(DEFAULT_SUMMARY_MD),
        help="输出回填摘要 Markdown 文件路径"
    )

    return parser.parse_args()


def resolve_path(path_str: str) -> Path:
    path = Path(path_str)
    if not path.is_absolute():
        path = BASE_DIR / path
    return path


def read_jsonl(path: Path):
    if not path.exists():
        raise FileNotFoundError(f"找不到 JSONL 文件：{path}")

    records = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))

    return records


def read_csv(path: Path):
    if not path.exists():
        raise FileNotFoundError(f"找不到 CSV 文件：{path}")

    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        return list(reader), reader.fieldnames or []


def write_jsonl(path: Path, records: list[dict]):
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")


def write_csv(path: Path, rows: list[dict], fieldnames: list[str]):
    path.parent.mkdir(parents=True, exist_ok=True)

    # 防止有新增字段但不在 fieldnames 中
    all_fields = list(fieldnames)
    for row in rows:
        for key in row.keys():
            if key not in all_fields:
                all_fields.append(key)

    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=all_fields)
        writer.writeheader()
        writer.writerows(rows)


def get_first_existing(record: dict, keys: list[str], default=""):
    for key in keys:
        value = record.get(key)
        if value not in [None, ""]:
            return str(value)
    return default


def make_key(record: dict) -> tuple[str, str]:
    """
    用 sample_id + package 作为主要匹配键。
    如果 package 字段不存在，就尝试 entity / dependency / raw_name。
    """
    sample_id = get_first_existing(record, ["sample_id", "id", "prompt_id"])
    package = get_first_existing(
        record,
        ["package", "package_name", "normalized_package", "normalized_name", "entity", "dependency", "raw_name"]
    )
    return sample_id, package


def normalize_review_row(row: dict) -> dict:
    """
    统一人工复核字段名。
    """
    manual_label = get_first_existing(row, ["manual_label", "label", "review_label"])
    review_reason = get_first_existing(row, ["review_reason", "reason", "comment", "comments"])
    reviewer = get_first_existing(row, ["reviewer", "annotator", "review_user"])
    review_status = get_first_existing(row, ["review_status", "status"])

    if not review_status:
        if manual_label:
            review_status = "reviewed"
        else:
            review_status = "unreviewed"

    return {
        "manual_label": manual_label,
        "review_reason": review_reason,
        "reviewer": reviewer,
        "review_status": review_status,
    }


def main():
    args = parse_args()

    review_csv = resolve_path(args.review_csv)
    input_jsonl = resolve_path(args.input_jsonl)
    output_jsonl = resolve_path(args.output_jsonl)
    output_csv = resolve_path(args.output_csv)
    summary_md = resolve_path(args.summary_md)

    records = read_jsonl(input_jsonl)
    review_rows, review_fieldnames = read_csv(review_csv)

    review_map = {}

    for row in review_rows:
        key = make_key(row)
        review_map[key] = normalize_review_row(row)

    reviewed_records = []
    matched = 0
    unmatched = 0

    status_counter = Counter()
    manual_label_counter = Counter()

    for record in records:
        key = make_key(record)
        review_info = review_map.get(key)

        new_record = dict(record)

        if review_info is None:
            unmatched += 1
            new_record["manual_label"] = ""
            new_record["review_reason"] = ""
            new_record["reviewer"] = ""
            new_record["review_status"] = "unmatched"
        else:
            matched += 1
            new_record.update(review_info)

        status_counter[new_record.get("review_status", "unknown")] += 1
        manual_label_counter[new_record.get("manual_label", "") or "empty"] += 1

        reviewed_records.append(new_record)

    # 同步生成一个带回填状态的 CSV，方便人工检查
    output_rows = []
    for record in reviewed_records:
        row = {
            "sample_id": get_first_existing(record, ["sample_id", "id", "prompt_id"]),
            "package": get_first_existing(
                record,
                ["package", "package_name", "normalized_package", "normalized_name", "entity", "dependency", "raw_name"]
            ),
            "auto_label": get_first_existing(record, ["auto_label", "status", "temporal_status_v2"]),
            "manual_label": record.get("manual_label", ""),
            "review_reason": record.get("review_reason", ""),
            "reviewer": record.get("reviewer", ""),
            "review_status": record.get("review_status", ""),
        }
        output_rows.append(row)

    write_jsonl(output_jsonl, reviewed_records)
    write_csv(
        output_csv,
        output_rows,
        [
            "sample_id",
            "package",
            "auto_label",
            "manual_label",
            "review_reason",
            "reviewer",
            "review_status",
        ]
    )

    lines = []
    lines.append("# manual review 回填结果\n")
    lines.append(f"- review CSV：`{review_csv.relative_to(BASE_DIR)}`")
    lines.append(f"- input JSONL：`{input_jsonl.relative_to(BASE_DIR)}`")
    lines.append(f"- output JSONL：`{output_jsonl.relative_to(BASE_DIR)}`")
    lines.append(f"- output CSV：`{output_csv.relative_to(BASE_DIR)}`")
    lines.append("")
    lines.append("## 1. 基本统计\n")
    lines.append(f"- 输入 benchmark 记录数：{len(records)}")
    lines.append(f"- review CSV 记录数：{len(review_rows)}")
    lines.append(f"- 成功匹配记录数：{matched}")
    lines.append(f"- 未匹配记录数：{unmatched}")
    lines.append("")
    lines.append("## 2. review_status 分布\n")
    lines.append("| review_status | count |")
    lines.append("|---|---:|")
    for status, count in status_counter.most_common():
        lines.append(f"| {status} | {count} |")

    lines.append("")
    lines.append("## 3. manual_label 分布\n")
    lines.append("| manual_label | count |")
    lines.append("|---|---:|")
    for label, count in manual_label_counter.most_common():
        lines.append(f"| {label} | {count} |")

    lines.append("")
    lines.append("## 4. 说明\n")
    lines.append(
        "本步骤将 `manual_review_template.csv` 中的人工复核字段回填到 benchmark JSONL 中。"
        "如果某条记录在 review CSV 中没有找到对应行，则标记为 `unmatched`。"
        "如果 review CSV 中 manual_label 为空，则该记录仍保留为 `unreviewed`。"
    )

    summary_md.parent.mkdir(parents=True, exist_ok=True)
    summary_md.write_text("\n".join(lines), encoding="utf-8")

    print("manual review 回填完成。")
    print("输出 JSONL：", output_jsonl)
    print("输出 CSV：", output_csv)
    print("输出摘要：", summary_md)
    print("成功匹配记录数：", matched)
    print("未匹配记录数：", unmatched)


if __name__ == "__main__":
    main()