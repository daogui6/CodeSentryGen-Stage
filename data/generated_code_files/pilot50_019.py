import subprocess
import sys
import pip


class PipPackageManager:
    def __init__(self, python_executable=None):
        self.python_executable = python_executable or sys.executable

    def run_pip(self, args):
        command = [self.python_executable, "-m", "pip"] + args
        result = subprocess.run(
            command,
            capture_output=True,
            text=True
        )
        return result.returncode, result.stdout, result.stderr

    def install(self, package_name):
        return self.run_pip(["install", package_name])

    def install_from_pypi(self, package_name, version=None):
        target = package_name if version is None else f"{package_name}=={version}"
        return self.install(target)

    def show_version(self):
        return self.run_pip(["--version"])


if __name__ == "__main__":
    manager = PipPackageManager()
    code, out, err = manager.show_version()
    print(out if code == 0 else err)
    print("pip module version:", pip.__version__)
