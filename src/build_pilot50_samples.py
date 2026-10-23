from __future__ import annotations

import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List


ROOT = Path(__file__).resolve().parents[1]

TEMPLATE_PATH = ROOT / "data" / "samples" / "generated_codes_pilot50_template.jsonl"
CODE_DIR = ROOT / "data" / "generated_code_files"
REQUIREMENTS_DIR = ROOT / "data" / "generated_requirements_files"
OUTPUT_PATH = ROOT / "data" / "samples" / "generated_codes_pilot50.jsonl"


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []

    if not path.exists():
        raise FileNotFoundError(f"Template file not found: {path}")

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


def now_jst_iso() -> str:
    """
    Use Japan/Korea-like UTC+09:00 time format to keep consistent with previous samples.
    """
    tz = timezone(timedelta(hours=9))
    return datetime.now(tz).replace(microsecond=0).isoformat()


def read_text_if_exists(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8-sig").strip().lstrip("\ufeff")


def build_samples() -> List[Dict[str, Any]]:
    template_rows = load_jsonl(TEMPLATE_PATH)
    output_rows: List[Dict[str, Any]] = []

    CODE_DIR.mkdir(parents=True, exist_ok=True)
    REQUIREMENTS_DIR.mkdir(parents=True, exist_ok=True)

    filled_count = 0

    for row in template_rows:
        new_row = dict(row)
        sample_id = new_row.get("sample_id", "")

        code_path = CODE_DIR / f"{sample_id}.py"
        req_path = REQUIREMENTS_DIR / f"{sample_id}_requirements.txt"

        generated_code = read_text_if_exists(code_path)
        requirements_text = read_text_if_exists(req_path)

        if generated_code:
            new_row["generated_code"] = generated_code
            filled_count += 1

            if not new_row.get("generation_time"):
                new_row["generation_time"] = now_jst_iso()

            new_row["notes"] = f"generated_code loaded from {code_path.as_posix()}"
        else:
            new_row["generated_code"] = ""
            new_row["notes"] = f"waiting for generated code file: {code_path.as_posix()}"

        if requirements_text:
            new_row["requirements_text"] = requirements_text

        output_rows.append(new_row)

    print(f"[OK] template records: {len(template_rows)}")
    print(f"[OK] filled generated_code records: {filled_count}")
    print(f"[OK] code directory: {CODE_DIR}")
    print(f"[OK] requirements directory: {REQUIREMENTS_DIR}")

    return output_rows


def main() -> None:
    rows = build_samples()
    write_jsonl(OUTPUT_PATH, rows)
    print(f"[OK] generated samples saved to: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()