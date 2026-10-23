import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

PILOT50_PATH = ROOT / "data" / "prompts" / "selected_prompts_pilot50.jsonl"
SOURCE_PROMPTS_PATH = ROOT / "data" / "prompts" / "packagehallucination_python_prompts.jsonl"

OUTPUT_PATH = ROOT / "data" / "prompts" / "selected_prompts_pilot100_extra.jsonl"


def load_jsonl(path: Path):
    records = []

    if not path.exists():
        raise FileNotFoundError(f"文件不存在: {path}")

    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue

            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise ValueError(f"{path} 第 {line_no} 行不是合法 JSON: {e}") from e

    return records


def get_prompt_text(record: dict) -> str:
    for key in ["prompt", "prompt_text", "question", "text", "content", "task"]:
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()

    skip_keys = {
        "prompt_id",
        "sample_id",
        "id",
        "source",
        "language",
        "ecosystem",
        "source_dataset",
        "pilot_split",
    }

    for key, value in record.items():
        if key in skip_keys:
            continue

        if isinstance(value, str) and value.strip():
            return value.strip()

    return ""


def normalize_record(record: dict, new_id: str) -> dict:
    prompt_text = get_prompt_text(record)

    if not prompt_text:
        raise ValueError(f"{new_id} 没有找到可用 prompt 文本: {record}")

    new_record = dict(record)
    new_record["sample_id"] = new_id
    new_record["prompt"] = prompt_text
    new_record["source_dataset"] = record.get("source_dataset", "packagehallucination_python_prompts")
    new_record["pilot_split"] = "pilot100_extra"

    return new_record


def main():
    pilot50 = load_jsonl(PILOT50_PATH)
    source_prompts = load_jsonl(SOURCE_PROMPTS_PATH)

    if len(pilot50) < 50:
        raise ValueError(f"pilot50 数量不足 50 条，当前只有 {len(pilot50)} 条")

    used_prompts = set()

    for record in pilot50:
        prompt_text = get_prompt_text(record)
        if prompt_text:
            used_prompts.add(prompt_text)

    extra = []
    next_idx = 51

    for record in source_prompts:
        if next_idx > 100:
            break

        prompt_text = get_prompt_text(record)

        if not prompt_text:
            continue

        if prompt_text in used_prompts:
            continue

        new_id = f"pilot100_{next_idx:03d}"
        new_record = normalize_record(record, new_id)

        extra.append(new_record)
        used_prompts.add(prompt_text)
        next_idx += 1

    if len(extra) != 50:
        raise ValueError(f"最终没有凑够 50 条新增 prompt，当前只有 {len(extra)} 条")

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_PATH.open("w", encoding="utf-8") as f:
        for record in extra:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    print("[OK] pilot100 extra prompt 文件生成完成")
    print(f"[OK] 输出文件: {OUTPUT_PATH}")
    print(f"[OK] 新增样本数量: {len(extra)}")

    print("[OK] 前 3 条 sample_id:")
    for record in extra[:3]:
        print(" ", record["sample_id"])

    print("[OK] 后 3 条 sample_id:")
    for record in extra[-3:]:
        print(" ", record["sample_id"])


if __name__ == "__main__":
    main()