import subprocess
import sys

def run_pip_command(args):
    command = [sys.executable, '-m', 'pip'] + args
    result = subprocess.run(command, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr

def download_package(package_name, dest='.'):
    return run_pip_command(['download', package_name, '-d', dest])

def build_package(package_name, dest='.'):
    return run_pip_command(['wheel', package_name, '-w', dest])

def install_package(package_name):
    return run_pip_command(['install', package_name])

def upgrade_package(package_name):
    return run_pip_command(['install', '--upgrade', package_name])

def uninstall_package(package_name):
    return run_pip_command(['uninstall', '-y', package_name])

if __name__ == '__main__':
    pkg = 'requests'
    print('Downloading...')
    download_package(pkg)
    print('Building...')
    build_package(pkg)
    print('Installing...')
    install_package(pkg)
    print('Upgrading...')
    upgrade_package(pkg)
    print('Uninstalling...')
    uninstall_package(pkg)
