from pathlib import Path
import shutil


ROOT = Path(__file__).resolve().parents[1]

CODE_DIR = ROOT / "data" / "generated_code_files"
REQ_DIR = ROOT / "data" / "generated_requirements_files"


def copy_if_exists(src: Path, dst: Path) -> bool:
    if not src.exists():
        return False

    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    return True


def main():
    copied_code = 0
    copied_req = 0
    missing_code = []
    missing_req = []

    for i in range(1, 21):
        old_id = f"pilot20_{i:03d}"
        new_id = f"pilot50_{i:03d}"

        old_code = CODE_DIR / f"{old_id}.py"
        new_code = CODE_DIR / f"{new_id}.py"

        old_req = REQ_DIR / f"{old_id}_requirements.txt"
        new_req = REQ_DIR / f"{new_id}_requirements.txt"

        if copy_if_exists(old_code, new_code):
            copied_code += 1
        else:
            missing_code.append(str(old_code))

        if copy_if_exists(old_req, new_req):
            copied_req += 1
        else:
            missing_req.append(str(old_req))

    print("复制完成")
    print(f"代码文件复制数量: {copied_code}/20")
    print(f"requirements 文件复制数量: {copied_req}/20")

    if missing_code:
        print("\n缺失的代码文件:")
        for path in missing_code:
            print(" ", path)

    if missing_req:
        print("\n没有 requirements 的样本数量:", len(missing_req))
        print("说明：这不一定是问题，有些样本只用标准库，本来就没有 requirements。")


if __name__ == "__main__":
    main()