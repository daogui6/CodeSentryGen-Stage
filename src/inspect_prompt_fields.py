import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = ROOT / "data" / "prompts" / "packagehallucination_python_prompts.jsonl"


def main():
    if not SOURCE_PATH.exists():
        print(f"文件不存在: {SOURCE_PATH}")
        return

    with SOURCE_PATH.open("r", encoding="utf-8") as f:
        for i in range(5):
            line = f.readline()
            if not line:
                break

            record = json.loads(line)
            print("=" * 80)
            print(f"第 {i + 1} 条")
            print("字段名：")
            print(list(record.keys()))
            print()
            print("完整内容：")
            print(json.dumps(record, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()