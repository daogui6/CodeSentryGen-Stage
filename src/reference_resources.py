from pathlib import Path
import csv


BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_DIR = BASE_DIR / "config"


def normalize_package_name(name: str) -> str:
    """
    PyPI 包名规范化：
    把下划线和点统一成短横线，并转小写。
    例如：
    beautiful_soup4 -> beautiful-soup4
    BackPorts.ZoneInfo -> backports-zoneinfo
    """
    if not name:
        return ""
    return name.strip().lower().replace("_", "-").replace(".", "-")


def load_simple_csv_names(path: Path) -> set[str]:
    """
    读取只有一列或多列的 csv 文件。
    默认把每行第一个非空字段当作包名。
    """
    names = set()

    if not path.exists():
        return names

    with path.open("r", encoding="utf-8", errors="ignore", newline="") as f:
        reader = csv.reader(f)

        for row in reader:
            if not row:
                continue

            first = row[0].strip()
            if not first:
                continue

            # 跳过可能的表头
            if first.lower() in {"package", "package_name", "name", "module", "import"}:
                continue

            names.add(normalize_package_name(first))

    return names


def load_pypi_package_names() -> set[str]:
    """
    读取原仓库中的 PyPI 包名列表。
    文件路径：config/pypi_package_names.csv
    """
    path = CONFIG_DIR / "pypi_package_names.csv"
    return load_simple_csv_names(path)


def load_false_positive_packages() -> set[str]:
    """
    读取原仓库中的误报包列表。
    优先读取 false_positive_packages_original.csv；
    如果不存在，再读取 false_positive_packages.csv。
    """
    original_path = CONFIG_DIR / "false_positive_packages_original.csv"
    default_path = CONFIG_DIR / "false_positive_packages.csv"

    if original_path.exists():
        return load_simple_csv_names(original_path)

    return load_simple_csv_names(default_path)


def is_in_offline_pypi_list(package_name: str, pypi_names: set[str] | None = None) -> bool:
    """
    判断某个包名是否出现在离线 PyPI 包名库中。
    """
    if pypi_names is None:
        pypi_names = load_pypi_package_names()

    return normalize_package_name(package_name) in pypi_names


def is_known_false_positive(package_name: str, false_positive_names: set[str] | None = None) -> bool:
    """
    判断某个包名是否出现在误报过滤表中。
    """
    if false_positive_names is None:
        false_positive_names = load_false_positive_packages()

    return normalize_package_name(package_name) in false_positive_names