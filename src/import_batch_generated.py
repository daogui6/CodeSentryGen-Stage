from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List


ROOT = Path(__file__).resolve().parents[1]
CODE_DIR = ROOT / "data" / "generated_code_files"
REQ_DIR = ROOT / "data" / "generated_requirements_files"


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows = []

    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue

            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON at line {line_no}: {e}") from e

    return rows


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.strip() + "\n", encoding="utf-8")


def import_batch(batch_file: Path) -> None:
    rows = load_jsonl(batch_file)

    CODE_DIR.mkdir(parents=True, exist_ok=True)
    REQ_DIR.mkdir(parents=True, exist_ok=True)

    code_count = 0
    req_count = 0

    for row in rows:
        sample_id = row.get("sample_id")
        generated_code = row.get("generated_code", "")
        requirements_text = row.get("requirements_text", "")

        if not sample_id:
            raise ValueError("Missing sample_id in one row")

        if generated_code:
            code_path = CODE_DIR / f"{sample_id}.py"
            write_text(code_path, generated_code)
            code_count += 1
            print(f"[OK] code written: {code_path}")

        if requirements_text:
            req_path = REQ_DIR / f"{sample_id}_requirements.txt"
            write_text(req_path, requirements_text)
            req_count += 1
            print(f"[OK] requirements written: {req_path}")

    print(f"[OK] imported code files: {code_count}")
    print(f"[OK] imported requirements files: {req_count}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--batch", required=True, help="Path to batch generated jsonl file")
    args = parser.parse_args()

    import_batch(Path(args.batch))


if __name__ == "__main__":
    main()