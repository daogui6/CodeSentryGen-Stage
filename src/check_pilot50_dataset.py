from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

DATASET_PATH = ROOT / "data" / "samples" / "generated_codes_pilot50.jsonl"


def main() -> None:
    if not DATASET_PATH.exists():
        raise FileNotFoundError(f"dataset not found: {DATASET_PATH}")

    rows = []

    with DATASET_PATH.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))

    total = len(rows)
    with_code = sum(1 for row in rows if row.get("generated_code", "").strip())
    with_requirements = sum(1 for row in rows if row.get("requirements_text", "").strip())
    without_requirements = total - with_requirements

    print("pilot50 dataset 检查结果")
    print("=" * 60)
    print(f"dataset path: {DATASET_PATH}")
    print(f"总记录数: {total}")
    print(f"有 generated_code 的记录数: {with_code}")
    print(f"有 requirements_text 的记录数: {with_requirements}")
    print(f"无 requirements_text 的记录数: {without_requirements}")

    print("\n前 3 条 sample_id:")
    for row in rows[:3]:
        print(" ", row.get("sample_id"))

    print("\n后 3 条 sample_id:")
    for row in rows[-3:]:
        print(" ", row.get("sample_id"))

    missing_code = [
        row.get("sample_id")
        for row in rows
        if not row.get("generated_code", "").strip()
    ]

    if missing_code:
        print("\n缺失 generated_code 的样本:")
        for sample_id in missing_code:
            print(" ", sample_id)
    else:
        print("\n所有样本都有 generated_code。")


if __name__ == "__main__":
    main()