import os
import shutil
from pathlib import Path
from contextlib import contextmanager
import tempfile

@contextmanager
def temp_working_directory(new_dir):
    old_dir = os.getcwd()
    try:
        os.chdir(new_dir)
        yield
    finally:
        os.chdir(old_dir)

@contextmanager
def zip_file_context():
    with tempfile.TemporaryDirectory() as temp_dir:
        with temp_working_directory(temp_dir):
            zip_path = Path(temp_dir) / "archive.zip"
            shutil.make_archive(str(zip_path.with_suffix('')), 'zip', temp_dir)
            yield zip_path
