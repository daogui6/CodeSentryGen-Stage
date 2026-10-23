import pip

def install_package(package_name):
    try:
        from pip._internal.cli.main import main
        main(['install', package_name])
    except ImportError:
        pip.main(['install', package_name])

if __name__ == '__main__':
    install_package('requests')
