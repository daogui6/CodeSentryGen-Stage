import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
INPUT_PATH = BASE_DIR / "output" / "pilot_reference_check.jsonl"
OUTPUT_MD = BASE_DIR / "output" / "reference_misses_detail.md"


def read_jsonl(path: Path):
    if not path.exists():
        raise FileNotFoundError(f"找不到文件：{path}")

    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def get_value(record: dict, keys: list[str], default=""):
    for key in keys:
        value = record.get(key)
        if value not in [None, ""]:
            return value
    return default


def main():
    miss_records = []

    for record in read_jsonl(INPUT_PATH):
        if record.get("offline_pypi_exists") is False:
            miss_records.append(record)

    lines = []
    lines.append("# 离线 PyPI 包名库未命中记录详情\n")
    lines.append(f"- 输入文件：`output/pilot_reference_check.jsonl`")
    lines.append(f"- 未命中记录数：{len(miss_records)}\n")

    lines.append("| 序号 | sample_id | package | import_name | status | risk_type | install_reachability | severity |")
    lines.append("|---|---|---|---|---|---|---|---|")

    for idx, record in enumerate(miss_records, start=1):
        sample_id = get_value(record, ["sample_id", "id", "prompt_id"])
        package = get_value(record, ["package", "package_name", "normalized_package", "normalized_name", "entity", "dependency"])
        import_name = get_value(record, ["import_name", "top_level_name", "module", "raw_import"])
        status = get_value(record, ["temporal_status", "status", "package_status"])
        risk_type = get_value(record, ["risk_type", "type"])
        reachability = get_value(record, ["install_reachability", "reachability"])
        severity = get_value(record, ["severity"])

        lines.append(
            f"| {idx} | {sample_id} | {package} | {import_name} | {status} | {risk_type} | {reachability} | {severity} |"
        )

    lines.append("\n## 原始记录节选\n")

    for idx, record in enumerate(miss_records, start=1):
        lines.append(f"### 记录 {idx}\n")
        lines.append("```json")
        lines.append(json.dumps(record, ensure_ascii=False, indent=2))
        lines.append("```\n")

    OUTPUT_MD.write_text("\n".join(lines), encoding="utf-8")

    print("未命中记录数：", len(miss_records))
    print("详情已输出到：", OUTPUT_MD)

    for idx, record in enumerate(miss_records, start=1):
        package = get_value(record, ["package", "package_name", "normalized_package", "normalized_name", "entity", "dependency"])
        status = get_value(record, ["temporal_status", "status", "package_status"])
        risk_type = get_value(record, ["risk_type", "type"])
        print(f"{idx}. package={package}, status={status}, risk_type={risk_type}")


if __name__ == "__main__":
    main()