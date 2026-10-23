import json
from pathlib import Path


# 项目根目录。
# 当前脚本位于 src/prepare_pilot50.py，
# Path(__file__).resolve().parents[1] 表示回到项目根目录 CodeSentryGen_Pilot/
ROOT = Path(__file__).resolve().parents[1]

# 输入 1：前期 pilot20 已经选好的 20 条 prompt
PILOT20_PATH = ROOT / "data" / "prompts" / "selected_prompts_pilot20.jsonl"

# 输入 2：从 PackageHallucination 原始数据中清洗出的 Python prompt 池
SOURCE_PROMPTS_PATH = ROOT / "data" / "prompts" / "packagehallucination_python_prompts.jsonl"

# 输出：最终 pilot50 使用的 50 条 prompt
OUTPUT_PATH = ROOT / "data" / "prompts" / "selected_prompts_pilot50.jsonl"


def load_jsonl(path: Path):
    """
    读取 JSONL 文件。

    JSONL 的格式是一行一个 JSON 对象。
    这里返回 records 列表，每个元素是一条 prompt 记录。

    作用：
    - 读取 selected_prompts_pilot20.jsonl
    - 读取 packagehallucination_python_prompts.jsonl
    """
    records = []

    # 如果输入文件不存在，直接报错，避免后面静默生成空数据
    if not path.exists():
        raise FileNotFoundError(f"文件不存在: {path}")

    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()

            # 跳过空行
            if not line:
                continue

            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as e:
                # 如果某一行不是合法 JSON，明确指出文件和行号，方便排查数据问题
                raise ValueError(f"{path} 第 {line_no} 行不是合法 JSON: {e}") from e

    return records


def get_prompt_text(record: dict) -> str:
    """
    从一条原始记录中提取真正的 prompt 文本。

    不同来源的数据字段名可能不同：
    有的叫 prompt_text，有的叫 prompt，有的叫 question / text / content / task。

    注意：
    prompt_id、sample_id 这类字段只是编号，不能当成 prompt 文本。
    """
    # 1. 优先从常见 prompt 字段中提取文本
    for key in ["prompt_text", "prompt", "question", "text", "content", "task"]:
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()

    # 2. 如果没有标准字段，再从其他字符串字段中兜底提取
    # 这些字段是元数据，不是真正的 prompt 内容，所以要跳过
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

    # 如果完全找不到可用 prompt，就返回空字符串
    return ""


def normalize_record(record: dict, new_id: str, source_dataset: str) -> dict:
    """
    将不同来源的 prompt 记录统一整理成 pilot50 的格式。

    主要补充 / 覆盖字段：
    - sample_id：统一编号为 pilot50_001 ~ pilot50_050
    - prompt：统一保存真正的 prompt 文本
    - source_dataset：记录这条 prompt 来源
    - pilot_split：标记为 pilot50
    """
    prompt_text = get_prompt_text(record)

    # 如果找不到 prompt 文本，说明这条记录不能作为样本使用
    if not prompt_text:
        raise ValueError(f"{new_id} 没有找到可用 prompt 文本: {record}")

    # 保留原始记录中的其他字段，同时补充统一字段
    new_record = dict(record)
    new_record["sample_id"] = new_id
    new_record["prompt"] = prompt_text
    new_record["source_dataset"] = record.get("source_dataset", source_dataset)
    new_record["pilot_split"] = "pilot50"

    return new_record


def main():
    """
    主流程：
    1. 读取 pilot20 prompt 和 PackageHallucination Python prompt 池
    2. 先继承 pilot20 的前 20 条，编号为 pilot50_001 ~ pilot50_020
    3. 再从原 prompt 池中补充 30 条不重复 prompt，编号为 pilot50_021 ~ pilot50_050
    4. 输出 selected_prompts_pilot50.jsonl
    """
    pilot20 = load_jsonl(PILOT20_PATH)
    source_prompts = load_jsonl(SOURCE_PROMPTS_PATH)

    # pilot50 的前 20 条要继承 pilot20，所以必须保证 pilot20 至少有 20 条
    if len(pilot20) < 20:
        raise ValueError(f"pilot20 数量不足 20 条，当前只有 {len(pilot20)} 条")

    pilot50 = []

    # 用 prompt 文本去重，避免 pilot50 中出现完全相同的任务描述
    used_prompts = set()

    # 1. 先放入原 pilot20 的 20 条
    # 这些样本重新编号为 pilot50_001 ~ pilot50_020
    for idx, record in enumerate(pilot20[:20], start=1):
        new_id = f"pilot50_{idx:03d}"
        new_record = normalize_record(record, new_id, "pilot20_inherited")
        pilot50.append(new_record)
        used_prompts.add(new_record["prompt"])

    # 2. 再从原始 PackageHallucination Python prompt 池中补充 30 条
    # 补充编号为 pilot50_021 ~ pilot50_050
    next_idx = 21

    for record in source_prompts:
        if next_idx > 50:
            break

        prompt_text = get_prompt_text(record)

        # 没有 prompt 文本的记录不能使用，直接跳过
        if not prompt_text:
            continue

        # 避免和前 20 条，或者已经补充的 prompt 重复
        if prompt_text in used_prompts:
            continue

        new_id = f"pilot50_{next_idx:03d}"
        new_record = normalize_record(record, new_id, "packagehallucination_python_prompts")
        pilot50.append(new_record)
        used_prompts.add(prompt_text)
        next_idx += 1

    # 最终必须正好凑够 50 条，否则说明原始 prompt 池不够或去重后数量不足
    if len(pilot50) != 50:
        raise ValueError(f"最终没有凑够 50 条，当前只有 {len(pilot50)} 条")

    # 确保输出目录存在
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    # 写出 selected_prompts_pilot50.jsonl
    # 一行一个 JSON 对象
    with OUTPUT_PATH.open("w", encoding="utf-8") as f:
        for record in pilot50:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    # 输出简单检查信息，方便运行后确认结果
    print("pilot50 prompt 文件生成完成")
    print(f"输出文件: {OUTPUT_PATH}")
    print(f"样本数量: {len(pilot50)}")

    print("前 3 条 sample_id:")
    for record in pilot50[:3]:
        print(" ", record["sample_id"])

    print("后 3 条 sample_id:")
    for record in pilot50[-3:]:
        print(" ", record["sample_id"])


if __name__ == "__main__":
    main()