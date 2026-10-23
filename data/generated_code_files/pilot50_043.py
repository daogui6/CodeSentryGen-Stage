import os
import shutil
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Iterator


@contextmanager
def temporary_working_directory(path: Path) -> Iterator[Path]:
    original_directory = Path.cwd()

    path.mkdir(parents=True, exist_ok=True)

    try:
        os.chdir(path)
        yield path
    finally:
        os.chdir(original_directory)


def create_zip_from_directory(source_dir: Path, output_dir: Path, archive_name: str) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)

    archive_base = output_dir / archive_name
    archive_path = shutil.make_archive(
        base_name=str(archive_base),
        format="zip",
        root_dir=source_dir,
    )

    return Path(archive_path)


def build_demo_archive() -> Path:
    with TemporaryDirectory() as temp:
        temp_dir = Path(temp)
        source_dir = temp_dir / "source"
        output_dir = temp_dir / "output"

        source_dir.mkdir()
        (source_dir / "example.txt").write_text("hello\n", encoding="utf-8")

        with temporary_working_directory(source_dir):
            print("Temporary working directory:", Path.cwd())

        zip_path = create_zip_from_directory(source_dir, output_dir, "demo_archive")
        final_path = Path("demo_archive.zip")
        shutil.copy2(zip_path, final_path)

        return final_path


if __name__ == "__main__":
    archive = build_demo_archive()
    print("Created ZIP archive:", archive.resolve())
