import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent

INPUT_PATH = BASE_DIR / "output" / "pilot_reference_check.jsonl"
OUTPUT_PATH = BASE_DIR / "output" / "pilot_reference_check_with_temporal_seed.jsonl"


def main():
    if not INPUT_PATH.exists():
        raise FileNotFoundError(f"找不到输入文件：{INPUT_PATH}")

    records = []

    with INPUT_PATH.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))

    temporal_seed = {
        "sample_id": "risk_seed_003_created_after_tg",
        "prompt_id": "risk_seed_prompt_003",
        "model": "controlled_seed_manual",
        "generation_time": "2018-01-01T00:00:00+00:00",
        "raw_name": "rich",
        "package": "rich",
        "source_type": "import",
        "location": {
            "file": "risk_seed_003_created_after_tg.py",
            "line": 1
        },
        "install_reachability": "manifest_declared",
        "status": "existed_now_temporal_pending",
        "false_positive_filtered": False,
        "local_module_filtered": False,
        "pypi": {
            "package": "rich",
            "exists_now": True,
            "query_url": "https://pypi.org/pypi/rich/json",
            "audit_time": "2026-05-30T00:00:00+00:00",
            "latest_version": "unknown",
            "first_release_time": "2019-11-13T00:00:00+00:00",
            "status_code": 200,
            "error": None
        },
        "offline_pypi_exists": True,
        "reference_false_positive": False,
        "controlled_seed_type": "created_after_tg",
        "controlled_seed_note": "This seed is used only to verify temporal_status_v2 created_after_tg logic."
    }

    records.append(temporal_seed)

    with OUTPUT_PATH.open("w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    print("已生成包含 created_after_tg seed 的文件：")
    print(OUTPUT_PATH)
    print("原始记录数：", len(records) - 1)
    print("新增 controlled temporal seed：1")
    print("总记录数：", len(records))


if __name__ == "__main__":
    main()