from __future__ import annotations

import re
import json
from pathlib import Path
from typing import Any, Dict, List


ROOT = Path(__file__).resolve().parents[1]

SOURCE_PROMPT_FILE = ROOT / "reference" / "PackageHallucination" / "Data" / "Python" / "LLM_AT.json"

ALL_PROMPTS_OUT = ROOT / "data" / "prompts" / "packagehallucination_python_prompts.jsonl"
SELECTED_PROMPTS_OUT = ROOT / "data" / "prompts" / "selected_prompts_pilot20.jsonl"
GENERATED_TEMPLATE_OUT = ROOT / "data" / "samples" / "generated_codes_pilot20_template.jsonl"


def read_json(path: Path) -> Any:
    """
    Read source prompt file.

    Supports both:
    1. standard JSON: list / dict
    2. JSONL-style file: one JSON object/string per line
    """
    text = path.read_text(encoding="utf-8-sig").strip()

    if not text:
        return []

    # First try standard JSON.
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Then try JSONL.
    rows = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue

        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as e:
            print(f"[WARN] Skip invalid JSON line {line_no}: {e}")

    return rows


def write_jsonl(path: Path, rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def extract_prompt_text(item: Any) -> str:
    """
    Try to extract prompt text from different possible JSON structures.
    This makes the script more robust to slight differences in artifact format.
    """
    if isinstance(item, str):
        return item.strip()

    if isinstance(item, dict):
        for key in [
            "prompt",
            "instruction",
            "task",
            "text",
            "query",
            "content",
            "input",
        ]:
            value = item.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()

        # If no obvious field exists, convert the whole dict to string for inspection.
        return json.dumps(item, ensure_ascii=False)

    return str(item).strip()


def split_prompt_text(prompt_text: str) -> List[str]:
    """
    Some records contain multiple numbered prompts in one text block.
    This function splits them into individual prompts when possible.
    """
    text = prompt_text.strip()
    if not text:
        return []

    text = text.replace("\\n", "\n")
    lines = text.splitlines()

    items: List[str] = []
    current: List[str] = []
    prefix: List[str] = []

    def clean_item(s: str) -> str:
        s = s.strip()
        s = s.strip('"').strip()
        s = s.rstrip('",').strip()
        return s

    def looks_like_prompt(s: str) -> bool:
        lower = s.lower()
        starts = [
            "generate python code",
            "write a python",
            "use the ",
            "create a python",
            "implement ",
        ]
        return any(lower.startswith(x) for x in starts)

    for line in lines:
        raw = line.strip()

        if not raw:
            continue

        # Skip broken dangling numbers, such as a final line: 8
        if raw.isdigit():
            continue

        m = re.match(r'^\s*\d+\.\s*(.*)$', raw)

        if m:
            if current:
                item = clean_item(" ".join(current))
                if item:
                    items.append(item)
                current = []

            current.append(m.group(1))
        else:
            if current:
                current.append(raw)
            else:
                prefix.append(raw)

    if current:
        item = clean_item(" ".join(current))
        if item:
            items.append(item)

    # Special case:
    # first prompt has no "1.", but following lines start from 2.
    if items and prefix:
        first = clean_item(" ".join(prefix))
        if first and looks_like_prompt(first):
            items.insert(0, first)

    if items:
        return [item for item in items if item]

    return [clean_item(text)]


def normalize_prompt_records(data: Any) -> List[Dict[str, Any]]:
    """
    Convert source JSON into a list of prompt records.
    Supports:
    - list[str]
    - list[dict]
    - dict[str, str]
    - dict[str, dict]

    If one record contains multiple numbered prompts, split it into multiple records.
    """
    records: List[Dict[str, Any]] = []
    idx = 1

    if isinstance(data, list):
        iterable = enumerate(data, start=1)
        for _, item in iterable:
            prompt_text = extract_prompt_text(item)
            sub_prompts = split_prompt_text(prompt_text)

            for sub_prompt in sub_prompts:
                records.append(
                    {
                        "prompt_id": f"ph_py_{idx:04d}",
                        "source": "PackageHallucination",
                        "language": "python",
                        "ecosystem": "pypi",
                        "prompt_text": sub_prompt,
                    }
                )
                idx += 1

    elif isinstance(data, dict):
        for key, item in data.items():
            prompt_text = extract_prompt_text(item)
            sub_prompts = split_prompt_text(prompt_text)

            for sub_prompt in sub_prompts:
                records.append(
                    {
                        "prompt_id": f"ph_py_{idx:04d}",
                        "source_id": str(key),
                        "source": "PackageHallucination",
                        "language": "python",
                        "ecosystem": "pypi",
                        "prompt_text": sub_prompt,
                    }
                )
                idx += 1

    else:
        raise ValueError(f"Unsupported JSON format: {type(data)}")

    return records


def select_pilot_prompts(records: List[Dict[str, Any]], limit: int = 20) -> List[Dict[str, Any]]:
    """
    Select the first N prompts for pilot.
    Later we can replace this with stratified selection by task type.
    """
    selected = []

    for idx, row in enumerate(records[:limit], start=1):
        new_row = dict(row)
        new_row["pilot_id"] = f"pilot20_prompt_{idx:03d}"
        selected.append(new_row)

    return selected


def build_generated_code_template(selected_prompts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Build a JSONL template.
    You will paste generated_code manually after calling a model.
    """
    rows = []

    for idx, row in enumerate(selected_prompts, start=1):
        rows.append(
            {
                "sample_id": f"pilot20_{idx:03d}",
                "prompt_id": row.get("prompt_id"),
                "pilot_id": row.get("pilot_id"),
                "source": row.get("source"),
                "language": "python",
                "ecosystem": "pypi",
                "model": "chatgpt_manual",
                "generation_time": "",
                "prompt_text": row.get("prompt_text"),
                "generated_code": "",
                "requirements_text": "",
                "notes": "Paste the model-generated Python code into generated_code and fill generation_time.",
            }
        )

    return rows


def main() -> None:
    if not SOURCE_PROMPT_FILE.exists():
        print("[ERROR] Source prompt file not found:")
        print(f"        {SOURCE_PROMPT_FILE}")
        print("")
        print("Please copy LLM_AT.json to:")
        print("        reference/PackageHallucination/Data/Python/LLM_AT.json")
        return

    data = read_json(SOURCE_PROMPT_FILE)
    records = normalize_prompt_records(data)
    selected = select_pilot_prompts(records, limit=20)
    template = build_generated_code_template(selected)

    write_jsonl(ALL_PROMPTS_OUT, records)
    write_jsonl(SELECTED_PROMPTS_OUT, selected)
    write_jsonl(GENERATED_TEMPLATE_OUT, template)

    print(f"[OK] source prompt file: {SOURCE_PROMPT_FILE}")
    print(f"[OK] total prompts: {len(records)}")
    print(f"[OK] selected pilot prompts: {len(selected)}")
    print(f"[OK] all prompts saved to: {ALL_PROMPTS_OUT}")
    print(f"[OK] selected prompts saved to: {SELECTED_PROMPTS_OUT}")
    print(f"[OK] generated code template saved to: {GENERATED_TEMPLATE_OUT}")


if __name__ == "__main__":
    main()