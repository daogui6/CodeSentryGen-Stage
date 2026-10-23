from __future__ import annotations

"""
generate_code_from_prompts.py

作用：
    将 prompt JSONL 自动转换为 generated sample JSONL，
    是 CodeSentry-Gen 流程中的“API 自动生成代码”模块。

输入：
    - data/prompts/selected_prompts_pilot50.jsonl
    - 或通过 --prompts 指定其他 prompt JSONL

输出：
    - data/samples/auto_generated_codes.jsonl
    - data/auto_generated_code_files/*.py
    - data/auto_generated_requirements_files/*_requirements.txt

核心字段：
    - generated_code：模型生成的 Python 代码
    - requirements_text：模型生成或声明的第三方依赖
    - generation_time：代码生成时间，用于后续 THO 时态判断
    - raw_response：模型原始返回
    - generation_error：单条样本生成失败时的错误信息

两种模式：
    1. mock 模式：
       不调用真实 API，生成固定 requests 示例代码，用于测试后续 pipeline。
    2. real 模式：
       使用 --real 调用 qwen-plus，生成真实模型代码样本。

在整体流程中的位置：
    prepare_pilot50.py
        ↓
    generate_code_from_prompts.py
        ↓
    run_pilot.py
        ↓
    enrich_temporal_status.py / enrich_reachability_v2.py / build_temporal_risk_cards.py
"""

import argparse
import json
import os
import re
import time
import requests
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List


# 项目根目录：当前文件位于 src/ 下，因此向上一级就是项目根目录。
ROOT = Path(__file__).resolve().parents[1]

# 本地 API 配置文件。该文件只应保存在本地，不应提交到公开仓库。
LOCAL_API_CONFIG = ROOT / "config" / "local_api_config.json"

# 默认输入输出路径：不传命令行参数时使用这些路径。
DEFAULT_PROMPTS = ROOT / "data" / "prompts" / "selected_prompts_pilot50.jsonl"
DEFAULT_OUTPUT = ROOT / "data" / "samples" / "auto_generated_codes.jsonl"
DEFAULT_CODE_DIR = ROOT / "data" / "auto_generated_code_files"
DEFAULT_REQ_DIR = ROOT / "data" / "auto_generated_requirements_files"


def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    """读取 JSONL 文件，每一行解析成一个字典。"""
    rows = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def write_jsonl(path: Path, rows: List[Dict[str, Any]]) -> None:
    """一次性写入 JSONL 文件。当前主流程已改为逐条追加写入，该函数主要保留备用。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def append_jsonl_row(path: Path, row: Dict[str, Any]) -> None:
    """向 JSONL 文件追加一条记录，避免长批量生成中途失败时丢失前面结果。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")


def read_existing_sample_ids(path: Path) -> set[str]:
    """读取已有输出文件中的 sample_id，用于 --resume 模式跳过已生成样本。"""
    if not path.exists():
        return set()

    sample_ids = set()
    with path.open("r", encoding="utf-8-sig") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                # 如果已有输出文件中存在坏行，直接跳过，避免影响恢复生成。
                continue

            sample_id = row.get("sample_id")
            if sample_id:
                sample_ids.add(sample_id)

    return sample_ids


def write_text(path: Path, text: str) -> None:
    """写入普通文本文件，用于保存生成代码和 requirements sidecar。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.strip() + "\n", encoding="utf-8")


def now_iso() -> str:
    """返回当前本地时间的 ISO 格式字符串，用作代码生成时间。"""
    return datetime.now().astimezone().replace(microsecond=0).isoformat()


def build_mock_code(prompt: str) -> str:
    """构造 mock 代码，用于不调用真实 API 时测试后续 pipeline。"""
    return f'''import requests


def main():
    task = {prompt!r}
    response = requests.get("https://example.com", timeout=10)
    print("task:", task)
    print("status_code:", response.status_code)


if __name__ == "__main__":
    main()
'''


def extract_json_object(text: str) -> Dict[str, Any]:
    """从模型输出中提取 JSON 对象。

    正常情况下模型应只输出 JSON；如果模型输出前后混入少量文本，
    则尝试用正则提取第一个完整 JSON 对象。
    """
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if not match:
            raise
        return json.loads(match.group(0))


def load_local_api_config() -> Dict[str, Any]:
    """读取本地 API 配置文件。文件不存在时返回空字典。"""
    if not LOCAL_API_CONFIG.exists():
        return {}

    with LOCAL_API_CONFIG.open("r", encoding="utf-8") as f:
        return json.load(f)


def call_qwen(prompt: str, model: str, timeout: int) -> Dict[str, str]:
    """调用通义千问兼容 OpenAI 格式的接口，返回代码、requirements 和说明。"""
    local_config = load_local_api_config()

    # API Key 优先从环境变量读取；如果没有，再从本地配置文件读取。
    api_key = os.getenv("DASHSCOPE_API_KEY") or local_config.get("dashscope_api_key")
    if not api_key:
        raise RuntimeError(
            "未找到 API Key。请设置 DASHSCOPE_API_KEY，或在 config/local_api_config.json 中配置 dashscope_api_key。")

    # 默认使用阿里云百炼 DashScope 的兼容模式接口，也允许通过本地配置覆盖。
    url = local_config.get(
        "qwen_base_url",
        "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions",
    )

    # system prompt 固定模型角色，要求输出严格 JSON，便于后续自动解析。
    system_prompt = """你是一个用于 CodeSentry-Gen 实验的 Python 代码生成器。
请只输出 JSON，不要输出 Markdown。
JSON 必须包含三个字段：
generated_code: 生成的 Python 代码字符串
requirements_text: requirements.txt 内容，如果只使用标准库则为空字符串
notes: 简短说明
"""

    # user prompt 中加入格式约束，降低模型输出 Markdown 代码块或缩进异常的概率。
    user_prompt = f"""请根据下面 prompt 生成 Python 代码：

    {prompt}

    要求：
    1. 如果使用第三方库，必须在 requirements_text 中列出。
    2. requirements_text 每行一个包名，不要写解释。
    3. generated_code 不要包含 Markdown 代码块。
    4. generated_code 必须是语法正确、缩进正确、可以直接保存为 .py 文件运行的 Python 代码。
    5. 不要在顶层语句前添加多余缩进。
    6. 只输出 JSON。
    """

    # 发送真实模型请求。timeout 由命令行参数控制，避免长时间卡死。
    resp = requests.post(
        url,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.2,
        },
        timeout=timeout,
    )

    if resp.status_code >= 400:
        raise RuntimeError(f"通义千问调用失败：{resp.status_code} {resp.text}")

    # 解析模型响应，并从 message.content 中提取 JSON。
    data = resp.json()
    content = data["choices"][0]["message"]["content"]
    parsed = extract_json_object(content)

    return {
        "raw_response": content,
        "generated_code": parsed.get("generated_code", ""),
        "requirements_text": parsed.get("requirements_text", ""),
        "notes": parsed.get("notes", "qwen real generation"),
    }


def main() -> None:
    """命令行入口：读取 prompt，生成代码，并保存 JSONL 与 sidecar 文件。"""
    parser = argparse.ArgumentParser()

    # 输入输出参数。
    parser.add_argument("--prompts", default=str(DEFAULT_PROMPTS))
    parser.add_argument("--out", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--limit", type=int, default=2)
    parser.add_argument("--start", type=int, default=1)

    # 模型调用参数。
    parser.add_argument("--real", action="store_true")
    parser.add_argument("--model", default="qwen-plus")
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--retries", type=int, default=0)
    parser.add_argument("--resume", action="store_true")

    # sidecar 输出目录：分别保存生成代码和 requirements。
    parser.add_argument("--code-dir", default=str(DEFAULT_CODE_DIR))
    parser.add_argument("--requirements-dir", default=str(DEFAULT_REQ_DIR))
    args = parser.parse_args()

    # 读取 prompt JSONL，并初始化输出路径。
    prompt_rows = read_jsonl(Path(args.prompts))

    code_dir = Path(args.code_dir)
    req_dir = Path(args.requirements_dir)
    out_path = Path(args.out)

    out_path.parent.mkdir(parents=True, exist_ok=True)

    # resume 模式保留已有输出并跳过已生成样本；非 resume 模式则重新生成输出文件。
    if args.resume:
        existing_sample_ids = read_existing_sample_ids(out_path)
    else:
        existing_sample_ids = set()
        if out_path.exists():
            out_path.unlink()

    if args.start < 1:
        raise ValueError("--start 必须大于等于 1")

    # 根据 --start 和 --limit 截取本次要处理的 prompt 范围。
    prompt_rows = prompt_rows[args.start - 1:]

    if args.limit > 0:
        prompt_rows = prompt_rows[:args.limit]

    output_rows = []
    total = len(prompt_rows)
    skipped_count = 0

    for i, row in enumerate(prompt_rows, start=1):
        source_sample_id = row.get("sample_id", "unknown_sample")
        sample_id = f"auto_{source_sample_id}"

        # resume 模式下，如果该 sample 已经在输出文件中，就跳过，避免重复生成。
        if sample_id in existing_sample_ids:
            skipped_count += 1
            print(f"[{i}/{total}] skip existing {sample_id}")
            continue

        print(f"[{i}/{total}] generating {sample_id} ...")
        prompt = row.get("prompt") or row.get("prompt_text") or ""

        try:
            if args.real:
                # 真实模型模式：支持失败重试，最后一次仍失败则交给外层 except 记录 generation_error。
                gen = None
                max_attempts = args.retries + 1
                for attempt in range(1, max_attempts + 1):
                    try:
                        gen = call_qwen(prompt, args.model, args.timeout)
                        break
                    except Exception as e:
                        if attempt >= max_attempts:
                            raise
                        print(
                            f"[WARN] attempt {attempt}/{max_attempts} failed for {sample_id}: "
                            f"{type(e).__name__}: {e}"
                        )
                        time.sleep(2)

                raw_response = gen["raw_response"]
                generated_code = gen["generated_code"]
                requirements_text = gen["requirements_text"]
                notes = gen["notes"]
                model_name = args.model
            else:
                # mock 模式：不调用真实 API，用固定模板生成代码，便于本地快速测试 pipeline。
                generated_code = build_mock_code(prompt)
                requirements_text = "requests>=2.31.0"
                raw_response = generated_code
                notes = "mock generated sample for pipeline test"
                model_name = "mock_generation_v0"

            generation_error = ""
        except Exception as e:
            # 单条样本失败时不终止整个批次，而是把失败原因写入 JSONL。
            raw_response = ""
            generated_code = ""
            requirements_text = ""
            notes = ""
            model_name = args.model if args.real else "mock_generation_v0"
            generation_error = f"{type(e).__name__}: {e}"
            print(f"[ERROR] failed {sample_id}: {generation_error}")

        # 只有生成成功时才写 sidecar 文件，避免失败样本用空内容覆盖旧文件。
        if not generation_error:
            write_text(code_dir / f"{sample_id}.py", generated_code)
            # requirements 为空时也写空文件，用来覆盖可能残留的旧 requirements。
            write_text(req_dir / f"{sample_id}_requirements.txt", requirements_text)

        # 保存统一 JSONL 记录，供后续 run_pilot.py 读取。
        output_row = {
            "sample_id": sample_id,
            "source_sample_id": source_sample_id,
            "source_dataset": row.get("source_dataset"),
            "prompt_id": row.get("prompt_id"),
            "source": row.get("source"),
            "language": row.get("language", "python"),
            "ecosystem": row.get("ecosystem", "pypi"),
            "prompt": prompt,
            "generation_time": now_iso(),
            "model": model_name,
            "raw_response": raw_response,
            "generated_code": generated_code,
            "requirements_text": requirements_text,
            "notes": notes,
            "generation_error": generation_error,
        }

        output_rows.append(output_row)
        # 每条样本生成后立即写入，防止中途异常导致整批结果丢失。
        append_jsonl_row(out_path, output_row)
        existing_sample_ids.add(sample_id)

        if generation_error:
            print(f"[FAILED] recorded {sample_id}")
        else:
            print(f"[OK] saved {sample_id}")

    # output rows have already been written incrementally

    print(f"[OK] prompt rows used: {len(prompt_rows)}")
    if args.resume:
        print(f"[OK] skipped existing samples: {skipped_count}")
    print(f"[OK] generated samples saved to: {args.out}")


if __name__ == "__main__":
    main()
