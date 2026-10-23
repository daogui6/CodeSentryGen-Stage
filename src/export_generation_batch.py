import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]

PROMPTS_PATH = ROOT / "data" / "prompts" / "selected_prompts_pilot50.jsonl"
OUTPUT_DIR = ROOT / "docs"


def load_jsonl(path: Path):
    records = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def get_sample_index(sample_id: str) -> int:
    return int(sample_id.split("_")[-1])


def export_batch(start_idx: int, end_idx: int):
    records = load_jsonl(PROMPTS_PATH)

    selected = []
    for record in records:
        sample_id = record.get("sample_id", "")
        if not sample_id.startswith("pilot50_"):
            continue

        idx = get_sample_index(sample_id)
        if start_idx <= idx <= end_idx:
            selected.append(record)

    if not selected:
        raise ValueError(f"没有找到 pilot50_{start_idx:03d} 到 pilot50_{end_idx:03d} 的样本")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    output_path = OUTPUT_DIR / f"pilot50_batch_generation_prompt_{start_idx:03d}_{end_idx:03d}.md"

    lines = []
    lines.append(f"# pilot50_{start_idx:03d} 到 pilot50_{end_idx:03d} 批量代码生成提示词\n")
    lines.append("请根据下面每个 sample 的 prompt 生成对应的 Python 代码文件和 requirements 文件。\n")
    lines.append("要求：\n")
    lines.append("1. 每个 sample 单独输出一个 Python 代码块。\n")
    lines.append("2. 代码应尽量像真实 LLM 生成代码，不要故意制造不存在的包名。\n")
    lines.append("3. 如果代码只使用 Python 标准库，则 requirements 写成 EMPTY。\n")
    lines.append("4. 如果代码使用第三方依赖，则 requirements 只列出直接依赖包名，不要写解释文字。\n")
    lines.append("5. 输出格式必须严格按照下面模板，方便后续脚本解析。\n")
    lines.append("6. 不要额外输出总结、说明、分析。\n")
    lines.append("\n")
    lines.append("输出模板如下：\n")
    lines.append("```text")
    lines.append("### sample_id: pilot50_XXX")
    lines.append("### file: data/generated_code_files/pilot50_XXX.py")
    lines.append("```python")
    lines.append("<Python code here>")
    lines.append("```")
    lines.append("### requirements: data/generated_requirements_files/pilot50_XXX_requirements.txt")
    lines.append("```text")
    lines.append("<dependency list or EMPTY>")
    lines.append("```")
    lines.append("```")
    lines.append("\n---\n")

    lines.append("下面是需要生成的 samples：\n")

    for record in selected:
        sample_id = record["sample_id"]
        prompt = record.get("prompt", "").strip()
        source_dataset = record.get("source_dataset", "")

        lines.append(f"## {sample_id}\n")
        lines.append(f"- source_dataset: `{source_dataset}`\n")
        lines.append("### prompt\n")
        lines.append("```text")
        lines.append(prompt)
        lines.append("```\n")

    output_path.write_text("\n".join(lines), encoding="utf-8")

    print("批量生成提示词已导出")
    print(f"输出文件: {output_path}")
    print(f"样本范围: pilot50_{start_idx:03d} 到 pilot50_{end_idx:03d}")
    print(f"样本数量: {len(selected)}")

def main():
    if len(sys.argv) == 3:
        start_idx = int(sys.argv[1])
        end_idx = int(sys.argv[2])
    else:
        start_idx = 21
        end_idx = 30

    export_batch(start_idx, end_idx)


if __name__ == "__main__":
    main()