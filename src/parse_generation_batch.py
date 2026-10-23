import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

CODE_DIR = ROOT / "data" / "generated_code_files"
REQ_DIR = ROOT / "data" / "generated_requirements_files"


SAMPLE_PATTERN = re.compile(
    r"### sample_id:\s*(?P<sample_id>pilot50_\d{3})\s*"
    r"### file:\s*(?P<file_path>data/generated_code_files/pilot50_\d{3}\.py)\s*"
    r"```python\s*(?P<code>.*?)\s*```\s*"
    r"### requirements:\s*(?P<req_path>data/generated_requirements_files/pilot50_\d{3}_requirements\.txt)\s*"
    r"```text\s*(?P<requirements>.*?)\s*```",
    re.DOTALL,
)


def parse_raw_file(raw_path: Path) -> None:
    if not raw_path.exists():
        raise FileNotFoundError(f"raw 文件不存在: {raw_path}")

    raw_text = raw_path.read_text(encoding="utf-8")
    matches = list(SAMPLE_PATTERN.finditer(raw_text))

    if not matches:
        raise ValueError("没有解析到任何 sample。请检查 raw.md 格式是否符合模板。")

    CODE_DIR.mkdir(parents=True, exist_ok=True)
    REQ_DIR.mkdir(parents=True, exist_ok=True)

    parsed_count = 0
    written_code_count = 0
    written_req_count = 0
    empty_req_count = 0

    for match in matches:
        sample_id = match.group("sample_id")
        file_path = match.group("file_path")
        req_path = match.group("req_path")
        code = match.group("code").strip() + "\n"
        requirements = match.group("requirements").strip()

        expected_code_path = f"data/generated_code_files/{sample_id}.py"
        expected_req_path = f"data/generated_requirements_files/{sample_id}_requirements.txt"

        if file_path != expected_code_path:
            raise ValueError(f"{sample_id} 代码路径不一致: {file_path} != {expected_code_path}")

        if req_path != expected_req_path:
            raise ValueError(f"{sample_id} requirements 路径不一致: {req_path} != {expected_req_path}")

        code_output = ROOT / file_path
        code_output.parent.mkdir(parents=True, exist_ok=True)
        code_output.write_text(code, encoding="utf-8")
        written_code_count += 1

        req_output = ROOT / req_path
        if requirements.upper() == "EMPTY":
            if req_output.exists():
                req_output.unlink()
            empty_req_count += 1
        else:
            req_output.parent.mkdir(parents=True, exist_ok=True)
            req_output.write_text(requirements + "\n", encoding="utf-8")
            written_req_count += 1

        parsed_count += 1
        print(f"解析完成: {sample_id}")

    print("\n批量解析完成")
    print(f"raw 文件: {raw_path}")
    print(f"解析 sample 数量: {parsed_count}")
    print(f"写入代码文件数量: {written_code_count}")
    print(f"写入 requirements 文件数量: {written_req_count}")
    print(f"EMPTY requirements 数量: {empty_req_count}")

    parsed_ids = [m.group("sample_id") for m in matches]
    print("解析到的 sample_id:")
    print(", ".join(parsed_ids))


def main():
    if len(sys.argv) == 2:
        raw_path = ROOT / sys.argv[1]
    else:
        raw_path = ROOT / "data" / "llm_raw_outputs" / "pilot50_021_030_raw.md"

    parse_raw_file(raw_path)


if __name__ == "__main__":
    main()