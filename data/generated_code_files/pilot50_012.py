import subprocess
import sys
import pip


def run_pip_command(args):
    command = [sys.executable, "-m", "pip"] + args
    result = subprocess.run(command, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr


def install_package(package_name):
    return run_pip_command(["install", package_name])


def upgrade_package(package_name):
    return run_pip_command(["install", "--upgrade", package_name])


def uninstall_package(package_name):
    return run_pip_command(["uninstall", "-y", package_name])


def download_package(package_name, destination):
    return run_pip_command(["download", package_name, "-d", destination])


def build_package(source_dir):
    return run_pip_command(["wheel", source_dir])


if __name__ == "__main__":
    print("pip version:", pip.__version__)
    code, out, err = run_pip_command(["--version"])
    print(out if code == 0 else err)
