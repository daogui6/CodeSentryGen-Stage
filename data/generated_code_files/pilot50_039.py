import shutil
import string
from pathlib import Path


def copy_package_files(source: Path, destination: Path, patterns: list[str]) -> list[Path]:
    destination.mkdir(parents=True, exist_ok=True)
    copied_files = []

    for pattern in patterns:
        for path in source.glob(pattern):
            if path.is_file():
                target = destination / path.name
                shutil.copy2(path, target)
                copied_files.append(target)

    return copied_files


def normalize_package_name(name: str) -> str:
    allowed = string.ascii_letters + string.digits + "._-"
    cleaned = "".join(char if char in allowed else "-" for char in name)
    return cleaned.lower().replace("_", "-")


def find_files(root: Path, suffix: str) -> list[Path]:
    return [path for path in root.rglob(f"*{suffix}") if path.is_file()]


def read_text_file(path: Path) -> str:
    return path.read_text(encoding="utf-8")


if __name__ == "__main__":
    package_name = "Example Package_Name"
    print("Normalized name:", normalize_package_name(package_name))

    current_dir = Path(".")
    python_files = find_files(current_dir, ".py")
    print("Python files found:", len(python_files))
