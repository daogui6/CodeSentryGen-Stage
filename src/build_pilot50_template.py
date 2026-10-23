from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List


ROOT = Path(__file__).resolve().parents[1]

PROMPTS_PATH = ROOT / "data" / "prompts" / "selected_prompts_pilot50.jsonl"
OUTPUT_PATH = ROOT / "data" / "samples" / "generated_codes_pilot50_template.jsonl"


GENERATION_TIME = "2026-06-07T00:00:00+09:00"


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []

    if not path.exists():
        raise FileNotFoundError(f"Prompt file not found: {path}")

    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))

    return rows


def write_jsonl(path: Path, rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def main() -> None:
    prompts = load_jsonl(PROMPTS_PATH)

    if len(prompts) != 50:
        print(f"[WARN] prompt records count is {len(prompts)}, expected 50")

    rows: List[Dict[str, Any]] = []

    for prompt_row in prompts:
        sample_id = prompt_row.get("sample_id")
        prompt_text = prompt_row.get("prompt", "")

        if not sample_id:
            raise ValueError(f"Missing sample_id: {prompt_row}")

        row = {
            "sample_id": sample_id,
            "source_dataset": prompt_row.get("source_dataset", ""),
            "prompt_id": prompt_row.get("prompt_id", ""),
            "source": prompt_row.get("source", ""),
            "language": prompt_row.get("language", "python"),
            "ecosystem": prompt_row.get("ecosystem", "pypi"),
            "prompt": prompt_text,
            "generation_time": GENERATION_TIME,
            "generated_code": "",
            "requirements_text": "",
            "notes": "pilot50 template record",
        }

        rows.append(row)

    write_jsonl(OUTPUT_PATH, rows)

    print("[OK] pilot50 template generated")
    print(f"[OK] prompt records: {len(prompts)}")
    print(f"[OK] template records: {len(rows)}")
    print(f"[OK] output: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()