import os
import shutil
import sys

def create_backup(source_dir, backup_dir):
    if not os.path.exists(source_dir):
        raise FileNotFoundError(f"Source directory not found: {source_dir}")
    
    if os.path.exists(backup_dir):
        shutil.rmtree(backup_dir)
        
    shutil.copytree(source_dir, backup_dir)
    print(f"Backup created successfully at {backup_dir}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python backup.py <source_directory> <backup_directory>")
        sys.exit(1)
    
    src = sys.argv[1]
    dst = sys.argv[2]
    create_backup(src, dst)
