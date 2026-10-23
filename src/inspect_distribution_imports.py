import argparse
import io
import json
import re
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

CACHE_PATH = (
    ROOT
    / "cache"
    / "distribution_import_prefixes.json"
)


def normalize_distribution_name(name: str) -> str:
    """
    按照类似 PEP 503 的规则规范化 distribution 名称。

    例如：
        google_auth -> google-auth
        google.auth -> google-auth
    """
    return re.sub(
        r"[-_.]+",
        "-",
        name,
    ).lower()


def load_cache() -> dict[str, Any]:
    """读取本地缓存。"""
    if not CACHE_PATH.exists():
        return {}

    try:
        return json.loads(
            CACHE_PATH.read_text(encoding="utf-8")
        )
    except json.JSONDecodeError:
        return {}


def save_cache(cache: dict[str, Any]) -> None:
    """保存自动发现的映射，避免重复下载 wheel。"""
    CACHE_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    CACHE_PATH.write_text(
        json.dumps(
            cache,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def fetch_pypi_metadata(
    distribution: str,
) -> dict[str, Any]:
    """调用 PyPI JSON 接口取得当前版本元数据。"""
    encoded_name = urllib.parse.quote(distribution)

    url = (
        f"https://pypi.org/pypi/"
        f"{encoded_name}/json"
    )

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": (
                "CodeSentry-Gen/"
                "distribution-import-resolver"
            )
        },
    )

    with urllib.request.urlopen(
        request,
        timeout=30,
    ) as response:
        return json.load(response)


def choose_wheel(
    metadata: dict[str, Any],
) -> dict[str, Any] | None:
    """
    从当前版本的发布文件中选择一个 wheel。

    优先选择通用的 py3-none-any wheel；
    如果没有，再选其他 wheel。
    """
    urls = metadata.get("urls", [])

    wheels = [
        item
        for item in urls
        if item.get("packagetype") == "bdist_wheel"
        and str(item.get("filename", "")).endswith(".whl")
    ]

    if not wheels:
        return None

    universal_wheels = [
        item
        for item in wheels
        if "py3-none-any.whl"
        in str(item.get("filename", ""))
    ]

    if universal_wheels:
        return universal_wheels[0]

    return wheels[0]


def download_bytes(url: str) -> bytes:
    """下载 wheel 文件内容。"""
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": (
                "CodeSentry-Gen/"
                "distribution-import-resolver"
            )
        },
    )

    with urllib.request.urlopen(
        request,
        timeout=60,
    ) as response:
        return response.read()


def valid_module_part(value: str) -> bool:
    """
    判断路径片段是否可以作为 Python 模块名的一部分。
    """
    return bool(
        re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_]*",
            value,
        )
    )


def add_prefixes(
    results: set[str],
    module_parts: list[str],
    max_depth: int = 5,
) -> None:
    """
    将模块路径的各级前缀加入结果。

    例如：
        google.auth.transport.requests

    会加入：
        google
        google.auth
        google.auth.transport
        google.auth.transport.requests
    """
    clean_parts: list[str] = []

    for part in module_parts:
        if not valid_module_part(part):
            break

        clean_parts.append(part)

    limit = min(
        len(clean_parts),
        max_depth,
    )

    for depth in range(1, limit + 1):
        results.add(
            ".".join(clean_parts[:depth])
        )


def infer_import_prefixes(
    wheel_bytes: bytes,
) -> set[str]:
    """
    从 wheel 文件中推断 distribution 提供的 import 路径。

    数据来源包括：
    1. *.dist-info/top_level.txt
    2. wheel 中实际存在的 Python 包和模块路径
    """
    results: set[str] = set()

    with zipfile.ZipFile(
        io.BytesIO(wheel_bytes)
    ) as wheel:
        names = wheel.namelist()

        # 优先读取 wheel 自带的 top_level.txt。
        for name in names:
            if not name.endswith(
                ".dist-info/top_level.txt"
            ):
                continue

            text = wheel.read(name).decode(
                "utf-8",
                errors="replace",
            )

            for line in text.splitlines():
                module = line.strip()

                if module and valid_module_part(module):
                    results.add(module)

        # 再根据 wheel 内的实际文件路径推断。
        for name in names:
            if name.endswith("/"):
                continue

            parts = [
                part
                for part in name.split("/")
                if part
            ]

            if not parts:
                continue

            first = parts[0]

            # 排除 wheel 元数据和安装数据目录。
            if (
                first.endswith(".dist-info")
                or first.endswith(".data")
            ):
                continue

            filename = parts[-1]
            directories = parts[:-1]

            module_parts: list[str] = []

            if filename in {
                "__init__.py",
                "__init__.pyi",
            }:
                module_parts = directories

            elif filename.endswith(".py"):
                module_parts = (
                    directories
                    + [filename[:-3]]
                )

            elif filename.endswith(".pyi"):
                module_parts = (
                    directories
                    + [filename[:-4]]
                )

            elif (
                filename.endswith(".so")
                or filename.endswith(".pyd")
            ):
                # 处理类似：
                # _message.cpython-311-x86_64-linux-gnu.so
                module_name = filename.split(".")[0]

                module_parts = (
                    directories
                    + [module_name]
                )

            if module_parts:
                add_prefixes(
                    results,
                    module_parts,
                )

    return results

def parse_requires_dist(
    raw_requirements: Any,
) -> list[dict[str, Any]]:
    """
    解析 PyPI JSON 中的 requires_dist 字段。

    当前阶段主要提取：
    - distribution 名称
    - 版本约束
    - environment marker
    - extras

    示例：
        google-auth-httplib2>=0.2.0
        cryptography>=3.4.0; extra == "crypto"
        requests[socks]>=2.31.0
    """
    if not isinstance(raw_requirements, list):
        return []

    results: list[dict[str, Any]] = []

    pattern = re.compile(
        r"""
        ^\s*
        (?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)
        (?:\[(?P<extras>[^\]]+)\])?
        \s*
        (?P<specifier>
            (?:
                ~=|==|!=|<=|>=|<|>|===
            )
            [^;,\s]+
            (?:
                \s*,\s*
                (?:
                    ~=|==|!=|<=|>=|<|>|===
                )
                [^;,\s]+
            )*
        )?
        \s*
        (?:;\s*(?P<marker>.+))?
        $
        """,
        re.VERBOSE,
    )

    for raw_value in raw_requirements:
        if not isinstance(raw_value, str):
            continue

        match = pattern.match(raw_value)

        if match is None:
            results.append(
                {
                    "name": "",
                    "specifier": "",
                    "marker": "",
                    "extras": [],
                    "raw": raw_value,
                    "parse_status": "unparsed",
                }
            )
            continue

        extras_text = match.group("extras") or ""

        extras = sorted(
            {
                item.strip()
                for item in extras_text.split(",")
                if item.strip()
            }
        )

        results.append(
            {
                "name": normalize_distribution_name(
                    match.group("name")
                ),
                "specifier": (
                    match.group("specifier") or ""
                ),
                "marker": (
                    match.group("marker") or ""
                ).strip(),
                "extras": extras,
                "raw": raw_value,
                "parse_status": "ok",
            }
        )

    return results

def inspect_distribution(
    distribution: str,
    refresh: bool = False,
    metadata_only: bool = False,
) -> dict[str, Any]:
    """
    查询一个 PyPI distribution，并返回它提供的 import 前缀。
    """
    normalized_name = normalize_distribution_name(
        distribution
    )

    cache = load_cache()

    if (
            not refresh
            and normalized_name in cache
            and "requires_dist" in cache[normalized_name]
    ):
        cached = cache[normalized_name]

        print(
            f"[CACHE] {distribution}"
        )

        return cached

    metadata = fetch_pypi_metadata(distribution)

    info = metadata.get("info", {})
    version = str(info.get("version", ""))

    requires_dist = parse_requires_dist(
        info.get("requires_dist")
    )

    if metadata_only:
        return {
            "distribution": normalized_name,
            "version": version,
            "wheel_filename": None,
            "import_prefixes": [],
            "requires_dist": requires_dist,
            "status": "metadata_only",
            "metadata_only_requested": True,
        }

    wheel = choose_wheel(metadata)

    if wheel is None:
        result = {
            "distribution": normalized_name,
            "version": version,
            "wheel_filename": None,
            "import_prefixes": [],
            "requires_dist": requires_dist,
            "status": "no_wheel_available",
        }

        cache[normalized_name] = result
        save_cache(cache)

        return result

    wheel_url = str(wheel["url"])
    wheel_filename = str(wheel["filename"])

    print(
        f"[DOWNLOAD] {wheel_filename}"
    )

    wheel_download_error = ""

    try:
        wheel_bytes = download_bytes(
            wheel_url
        )

        import_prefixes = sorted(
            infer_import_prefixes(wheel_bytes)
        )

        status = "ok"

    except Exception as exc:
        """
        wheel 下载或解析失败时，仍然保留 PyPI JSON 中已经取得的
        requires_dist 元数据。

        依赖关系分析不应该因为某个平台 wheel 无法下载而完全失败。
        """
        import_prefixes = []
        wheel_download_error = str(exc)
        status = "metadata_only"

        print(
            f"[WARN] wheel unavailable: {exc}"
        )

    result = {
        "distribution": normalized_name,
        "version": version,
        "wheel_filename": wheel_filename,
        "import_prefixes": import_prefixes,
        "requires_dist": requires_dist,
        "wheel_download_error": wheel_download_error,
        "status": status,
    }

    cache[normalized_name] = result
    save_cache(cache)

    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Inspect Python import paths provided by "
            "PyPI distributions."
        )
    )

    parser.add_argument(
        "distributions",
        nargs="+",
        help="PyPI distribution names",
    )

    parser.add_argument(
        "--refresh",
        action="store_true",
        help="Ignore local cache and query PyPI again",
    )

    args = parser.parse_args()

    all_ok = True

    for distribution in args.distributions:
        print("")
        print(
            "=" * 60
        )
        print(
            f"Distribution: {distribution}"
        )
        print(
            "=" * 60
        )

        try:
            result = inspect_distribution(
                distribution,
                refresh=args.refresh,
            )
        except Exception as exc:
            all_ok = False

            print(
                f"[FAIL] {distribution}: {exc}"
            )

            continue

        print(
            f"normalized_distribution = "
            f"{result['distribution']}"
        )
        print(
            f"version = {result['version']}"
        )
        print(
            f"wheel = {result['wheel_filename']}"
        )
        print(
            f"status = {result['status']}"
        )
        wheel_download_error = result.get(
            "wheel_download_error",
            "",
        )

        if wheel_download_error:
            print(
                "wheel_download_error = "
                f"{wheel_download_error}"
            )
        print("import_prefixes:")

        prefixes = result["import_prefixes"]

        for prefix in prefixes:
            print(f"  - {prefix}")

        print("requires_dist:")

        requirements = result.get(
            "requires_dist",
            [],
        )

        if not requirements:
            print("  - <none>")

        for requirement in requirements:
            name = requirement.get(
                "name",
                "",
            )
            specifier = requirement.get(
                "specifier",
                "",
            )
            marker = requirement.get(
                "marker",
                "",
            )
            parse_status = requirement.get(
                "parse_status",
                "",
            )

            if parse_status != "ok":
                raw_value = requirement.get(
                    "raw",
                    "",
                )
                print(
                    f"  - <unparsed> {raw_value}"
                )
                continue

            text = f"  - {name}{specifier}"

            if marker:
                text += f" ; {marker}"

            print(text)

    print("")
    print(
        "=" * 60
    )
    print(
        f"ALL_PASS = {all_ok}"
    )
    print(
        f"CACHE = {CACHE_PATH.relative_to(ROOT)}"
    )
    print(
        "=" * 60
    )

    if not all_ok:
        raise SystemExit(1)


if __name__ == "__main__":
    main()