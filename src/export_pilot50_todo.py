import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

INPUT_PATH = ROOT / "data" / "prompts" / "selected_prompts_pilot50.jsonl"
OUTPUT_PATH = ROOT / "docs" / "pilot50_generation_todo.md"


def load_jsonl(path: Path):
    records = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def main():
    records = load_jsonl(INPUT_PATH)

    lines = []
    lines.append("# pilot50 后 30 条代码生成待办\n")
    lines.append("说明：pilot50_001 到 pilot50_020 先沿用原 pilot20；这里主要整理 pilot50_021 到 pilot50_050。\n")

    for record in records:
        sample_id = record.get("sample_id", "")
        if not sample_id:
            continue

        try:
            idx = int(sample_id.split("_")[-1])
        except ValueError:
            continue

        if idx < 21:
            continue

        prompt = record.get("prompt", "").strip()
        source_dataset = record.get("source_dataset", "")

        lines.append(f"## {sample_id}\n")
        lines.append(f"- source_dataset: `{source_dataset}`\n")
        lines.append("### prompt\n")
        lines.append("```text\n")
        lines.append(prompt)
        lines.append("\n```\n")
        lines.append("### 需要生成的文件\n")
        lines.append(f"- `data/generated_code_files/{sample_id}.py`\n")
        lines.append(f"- 如果代码用到了第三方依赖，再建：`data/generated_requirements_files/{sample_id}_requirements.txt`\n")
        lines.append("\n---\n")

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text("\n".join(lines), encoding="utf-8")

    print("pilot50 后 30 条生成待办已导出")
    print(f"输出文件: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()