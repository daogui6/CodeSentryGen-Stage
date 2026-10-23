import os
import shutil
from datetime import datetime


def create_backup(source_dir, backup_root):
    if not os.path.isdir(source_dir):
        raise ValueError(f"Source directory does not exist: {source_dir}")

    os.makedirs(backup_root, exist_ok=True)

    source_name = os.path.basename(os.path.abspath(source_dir))
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_name = f"{source_name}_backup_{timestamp}"
    backup_path = os.path.join(backup_root, backup_name)

    shutil.copytree(source_dir, backup_path)
    return backup_path


if __name__ == "__main__":
    src = input("Enter source directory: ").strip()
    dst = input("Enter backup destination directory: ").strip()

    try:
        result = create_backup(src, dst)
        print(f"Backup created successfully: {result}")
    except Exception as e:
        print(f"Backup failed: {e}")