from __future__ import annotations

import json
from datetime import datetime, timezone, timedelta
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT_PATH = ROOT / "data" / "samples" / "risk_seed_samples.jsonl"


def now_jst_iso() -> str:
    tz = timezone(timedelta(hours=9))
    return datetime.now(tz).replace(microsecond=0).isoformat()


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def main() -> None:
    generation_time = now_jst_iso()

    rows = [
        {
            "sample_id": "risk_seed_001",
            "prompt_id": "risk_seed_prompt_001",
            "pilot_id": "controlled_risk_seed_001",
            "source": "synthetic_controlled_seed",
            "language": "python",
            "ecosystem": "pypi",
            "model": "controlled_seed_manual",
            "generation_time": generation_time,
            "prompt_text": "Controlled seed: generate Python code that imports a plausible but nonexistent YAML security helper package.",
            "generated_code": (
                "import requests\n"
                "import secure_yaml_loader\n\n"
                "\n"
                "def load_remote_yaml(url):\n"
                "    response = requests.get(url, timeout=10)\n"
                "    response.raise_for_status()\n"
                "    return secure_yaml_loader.safe_load(response.text)\n"
            ),
            "requirements_text": (
                "requests>=2.31.0\n"
                "secure-yaml-loader==1.0.0"
            ),
            "notes": "controlled package hallucination seed; expected risk package: secure-yaml-loader",
        },
        {
            "sample_id": "risk_seed_002",
            "prompt_id": "risk_seed_prompt_002",
            "pilot_id": "controlled_risk_seed_002",
            "source": "synthetic_controlled_seed",
            "language": "python",
            "ecosystem": "pypi",
            "model": "controlled_seed_manual",
            "generation_time": generation_time,
            "prompt_text": "Controlled seed: generate Python code that imports a plausible but nonexistent AI data validation package.",
            "generated_code": (
                "import ai_data_validator_pro\n\n"
                "\n"
                "def validate_record(record):\n"
                "    schema = {\n"
                "        \"name\": str,\n"
                "        \"score\": int\n"
                "    }\n"
                "    return ai_data_validator_pro.validate(record, schema)\n"
            ),
            "requirements_text": "ai-data-validator-pro==0.1.0",
            "notes": "controlled package hallucination seed; expected risk package: ai-data-validator-pro",
        },
    ]

    write_jsonl(OUTPUT_PATH, rows)

    print(f"[OK] risk seed samples saved to: {OUTPUT_PATH}")
    print(f"[OK] risk seed sample count: {len(rows)}")


if __name__ == "__main__":
    main()