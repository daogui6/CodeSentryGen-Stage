from reference_resources import (
    load_pypi_package_names,
    load_false_positive_packages,
    is_in_offline_pypi_list,
    is_known_false_positive,
)


def main():
    pypi_names = load_pypi_package_names()
    false_positive_names = load_false_positive_packages()

    print("PyPI 离线包名数量：", len(pypi_names))
    print("误报过滤包名数量：", len(false_positive_names))

    test_packages = [
        "requests",
        "numpy",
        "pandas",
        "beautifulsoup4",
        "pyyaml",
        "secure-yaml-loader",
        "ai-data-validator-pro",
    ]

    print("\n测试几个包是否在离线 PyPI 包名库中：")
    for pkg in test_packages:
        print(pkg, "=>", is_in_offline_pypi_list(pkg, pypi_names))

    print("\n测试几个包是否在误报过滤表中：")
    for pkg in test_packages:
        print(pkg, "=>", is_known_false_positive(pkg, false_positive_names))


if __name__ == "__main__":
    main()