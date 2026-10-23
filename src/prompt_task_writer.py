from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List


ROOT = Path(__file__).resolve().parents[1]

SELECTED_PROMPTS = ROOT / "data" / "prompts" / "selected_prompts_pilot20.jsonl"
TASK_MD_OUT = ROOT / "data" / "prompts" / "pilot20_generation_tasks.md"


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []

    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))

    return rows


def write_prompt_tasks_md(selected_prompts_path: Path, output_path: Path) -> None:
    rows = load_jsonl(selected_prompts_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    lines = []
    lines.append("# Pilot20 代码生成任务清单")
    lines.append("")
    lines.append("本文件由 `selected_prompts_pilot20.jsonl` 自动生成，用于手动调用模型生成 Python 代码。")
    lines.append("")
    lines.append("使用方法：")
    lines.append("")
    lines.append("1. 每次复制一条 Prompt 给模型。")
    lines.append("2. 要求模型只输出 Python 代码，不要输出解释。")
    lines.append("3. 将生成代码填入 `data/samples/generated_codes_pilot20.jsonl` 的 `generated_code` 字段。")
    lines.append("4. 填写当时的 `generation_time`。")
    lines.append("")

    for idx, row in enumerate(rows, start=1):
        lines.append(f"## {idx}. {row.get('sample_id', f'pilot20_{idx:03d}')}")
        lines.append("")
        lines.append(f"- prompt_id: `{row.get('prompt_id', '')}`")
        lines.append(f"- pilot_id: `{row.get('pilot_id', '')}`")
        lines.append("")
        lines.append("### Prompt")
        lines.append("")
        lines.append("```text")
        lines.append(row.get("prompt_text", ""))
        lines.append("```")
        lines.append("")
        lines.append("### 建议给模型的附加要求")
        lines.append("")
        lines.append("```text")
        lines.append("Please output only executable Python code. Do not include explanations, markdown fences, or extra text.")
        lines.append("```")
        lines.append("")

    output_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    if not SELECTED_PROMPTS.exists():
        print("[ERROR] selected prompts file not found:")
        print(f"        {SELECTED_PROMPTS}")
        return

    write_prompt_tasks_md(SELECTED_PROMPTS, TASK_MD_OUT)
    print(f"[OK] prompt task markdown saved to: {TASK_MD_OUT}")


if __name__ == "__main__":
    main()