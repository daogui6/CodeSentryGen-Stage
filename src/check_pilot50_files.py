from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

CODE_DIR = ROOT / "data" / "generated_code_files"
REQ_DIR = ROOT / "data" / "generated_requirements_files"
PROMPT_PATH = ROOT / "data" / "prompts" / "selected_prompts_pilot50.jsonl"


def main():
    missing_code = []
    existing_code = []
    existing_req = []
    no_req = []

    for i in range(1, 51):
        sample_id = f"pilot50_{i:03d}"

        code_path = CODE_DIR / f"{sample_id}.py"
        req_path = REQ_DIR / f"{sample_id}_requirements.txt"

        if code_path.exists():
            existing_code.append(sample_id)
        else:
            missing_code.append(sample_id)

        if req_path.exists():
            existing_req.append(sample_id)
        else:
            no_req.append(sample_id)

    print("pilot50 文件检查结果")
    print("=" * 60)

    print(f"prompt 文件是否存在: {PROMPT_PATH.exists()}")
    print(f"代码文件数量: {len(existing_code)}/50")
    print(f"requirements 文件数量: {len(existing_req)}/50")
    print(f"无 requirements 样本数量: {len(no_req)}/50")

    if missing_code:
        print("\n缺失代码文件:")
        for sample_id in missing_code:
            print(" ", sample_id)
    else:
        print("\n代码文件齐全。")

    print("\n有 requirements 的样本:")
    print(", ".join(existing_req))

    print("\n无 requirements 的样本:")
    print(", ".join(no_req))

    print("\n说明：无 requirements 不一定是问题，很多样本只使用 Python 标准库。")


if __name__ == "__main__":
    main()