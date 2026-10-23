import csv
from pathlib import Path
from typing import Any

from extractor import extract_imports_from_code
from inspect_distribution_imports import inspect_distribution
from normalizer import (
    load_import_mapping,
    map_import_path_to_distribution,
    pep503_normalize,
)


ROOT = Path(__file__).resolve().parents[1]

INPUT_PATH = (
    ROOT
    / "output"
    / "auto_qwen37_100_manifest_only_review.csv"
)

OUTPUT_PATH = (
    ROOT
    / "output"
    / "auto_qwen37_100_manifest_only_auto_recheck.csv"
)

MAPPING_PATH = (
    ROOT
    / "config"
    / "import_mapping.json"
)


def load_csv(path: Path) -> list[dict[str, str]]:
    """读取待复核的 manifest-only CSV。"""
    with path.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as file:
        return list(csv.DictReader(file))


def load_import_paths(
    code_file: str,
) -> list[tuple[str, str]]:
    """
    读取对应代码，并返回：

    (raw_name, import_path)
    """
    if not code_file:
        return []

    path = ROOT / code_file

    if not path.exists():
        return []

    code = path.read_text(
        encoding="utf-8",
    )

    entities = extract_imports_from_code(
        code,
        file_name=str(path),
    )

    return [
        (
            entity.raw_name,
            entity.import_path,
        )
        for entity in entities
        if entity.source_type == "import"
    ]


def wheel_prefix_match(
    import_path: str,
    prefix: str,
) -> bool:
    """
    判断 import 路径是否由 wheel 中的模块前缀支持。

    需要避免把公共 namespace 的顶层路径误当成证据：

        google
        azure

    因此：
    1. 完全相等时可以匹配；
    2. 前缀匹配时，prefix 至少要包含两级路径。
    """
    if not import_path or not prefix:
        return False

    if import_path == prefix:
        return True

    prefix_depth = len(
        prefix.split(".")
    )

    if (
        prefix_depth >= 2
        and import_path.startswith(prefix + ".")
    ):
        return True

    return False


def find_curated_matches(
    distribution: str,
    imports: list[tuple[str, str]],
    mapping: dict[str, str],
) -> list[str]:
    """
    使用人工维护的 import-to-distribution 映射表，
    检查代码中的 import 是否对应当前待复核的 PyPI distribution。

    参数：
        distribution:
            当前正在复核的、已经规范化后的 PyPI distribution 名。

        imports:
            从生成代码中提取出的 import 列表。
            每个元素的格式为：
                (raw_name, import_path)

        mapping:
            从 config/import_mapping.json 加载的人工映射表，
            用于处理 import 名和 PyPI distribution 名不一致的情况。

    返回：
        所有能够映射到当前 distribution 的完整 import_path。
        返回前会去重并排序。
    """

    # 保存所有匹配成功的代码 import 路径。
    # 这些路径可以作为“代码直接使用当前软件包”的证据。
    matches: list[str] = []

    # 逐条检查生成代码中提取出的 import。
    for raw_name, import_path in imports:
        # 将代码中的 import 名或完整 import 路径
        # 映射成对应的 PyPI distribution 名。
        #
        # 例如：
        #   googleapiclient.discovery
        #       -> google-api-python-client
        #
        #   jwt
        #       -> PyJWT
        mapped = map_import_path_to_distribution(
            raw_name=raw_name,
            import_path=import_path,
            mapping=mapping,
        )

        # 将映射结果按 PEP 503 风格规范化后，
        # 与当前待复核的 distribution 比较。
        #
        # 规范化可以消除大小写以及 "-", "_" 和 "." 的差异。
        # 例如：
        #   PyJWT -> pyjwt
        #   google_api_python_client
        #       -> google-api-python-client
        if (
            pep503_normalize(mapped)
            == distribution
        ):
            # 映射结果与当前候选包一致，
            # 说明这条 import 可以作为直接使用证据。
            matches.append(import_path)

    # set() 去除重复 import 路径；
    # sorted() 保证每次输出顺序稳定，便于复核和测试。
    return sorted(set(matches))


def find_wheel_matches(
    imports: list[tuple[str, str]],
    prefixes: list[str],
) -> list[tuple[str, str]]:
    """
    使用 wheel 文件中自动提取出的模块前缀，
    检查代码中的 import_path 是否由当前 distribution 提供。

    参数：
        imports:
            从生成代码中提取出的 import 列表。
            每个元素格式为：
                (raw_name, import_path)

        prefixes:
            从软件包 wheel 文件中提取出的模块前缀。

    返回：
        匹配成功的二元组列表：

            (
                代码中的 import_path,
                wheel 中匹配到的最佳 prefix
            )

    """

    # 保存代码 import 路径与 wheel 模块前缀之间的匹配结果。
    matches: list[tuple[str, str]] = []

    # 遍历代码中的每一条完整 import 路径。
    # 这里不需要 raw_name，所以使用下划线忽略该变量。
    for _, import_path in imports:
        # 从 wheel 提供的所有模块前缀中，
        # 找出能够匹配当前 import_path 的候选前缀。
        #
        # wheel_prefix_match() 会处理：
        #   1. 完全相等匹配；
        #   2. 多级模块前缀匹配；
        #   3. 避免 google、azure 等公共顶层命名空间误匹配。
        candidates = [
            prefix
            for prefix in prefixes
            if wheel_prefix_match(
                import_path,
                prefix,
            )
        ]

        # 当前 import_path 没有匹配到任何 wheel 模块前缀，
        # 说明暂时不能用 wheel 证明当前软件包提供了该 import。
        if not candidates:
            continue

        # 同一条 import_path 可能匹配多个前缀。
        #
        # 例如：
        #   import_path = google.auth.transport.requests
        #
        # 可能匹配：
        #   google.auth
        #   google.auth.transport
        #   google.auth.transport.requests
        #
        # 这里优先选择层级最深、长度最长的前缀，
        # 因为它最具体，误匹配的可能性更低。
        best_prefix = max(
            candidates,
            key=lambda item: (
                # 优先比较模块层级数量。
                len(item.split(".")),

                # 层级相同时，再比较字符串长度。
                len(item),
            ),
        )

        # 保存代码中的 import_path，
        # 以及 wheel 中能够支持它的最具体模块前缀。
        matches.append(
            (
                import_path,
                best_prefix,
            )
        )

    # 去重并排序，使输出结果稳定、便于检查。
    return sorted(set(matches))


def write_csv(
    rows: list[dict[str, Any]],
    path: Path,
) -> None:
    """写出自动复核结果。"""
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fieldnames = list(rows[0].keys())

    with path.open(
        "w",
        encoding="utf-8-sig",
        newline="",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )

        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    if not INPUT_PATH.exists():
        raise FileNotFoundError(
            f"Input file not found: {INPUT_PATH}"
        )

    mapping = load_import_mapping(
        MAPPING_PATH
    )

    review_rows = load_csv(INPUT_PATH)

    # 同一 distribution 可能在多张卡片中出现，
    # 这里避免重复查询和重复读取缓存。
    distribution_cache: dict[
        str,
        dict[str, Any],
    ] = {}

    output_rows: list[dict[str, Any]] = []

    direct_import_backed = 0
    no_direct_import_match = 0
    resolver_errors = 0

    for row in review_rows:
        distribution = pep503_normalize(
            row.get("package", "")
        )

        imports = load_import_paths(
            row.get("code_file", "")
        )

        curated_matches = find_curated_matches(
            distribution=distribution,
            imports=imports,
            mapping=mapping,
        )

        resolver_status = ""
        resolver_error = ""
        wheel_matches: list[
            tuple[str, str]
        ] = []

        if distribution not in distribution_cache:
            try:
                distribution_cache[
                    distribution
                ] = inspect_distribution(
                    distribution
                )
            except Exception as exc:
                distribution_cache[
                    distribution
                ] = {
                    "status": "resolver_error",
                    "import_prefixes": [],
                    "error": str(exc),
                }

        metadata = distribution_cache[
            distribution
        ]

        resolver_status = str(
            metadata.get("status", "")
        )

        resolver_error = str(
            metadata.get("error", "")
        )

        prefixes = metadata.get(
            "import_prefixes",
            [],
        )

        if isinstance(prefixes, list):
            wheel_matches = find_wheel_matches(
                imports=imports,
                prefixes=[
                    str(item)
                    for item in prefixes
                ],
            )

        matched_by: list[str] = []

        if curated_matches:
            matched_by.append(
                "curated_mapping"
            )

        if wheel_matches:
            matched_by.append(
                "wheel_metadata"
            )

        if curated_matches or wheel_matches:
            auto_label = "direct_import_backed"
            direct_import_backed += 1

        elif resolver_status == "resolver_error":
            auto_label = "resolver_error"
            resolver_errors += 1

        else:
            # 这里只表示没有找到“直接 import”证据。
            # 它仍可能是工具依赖、插件依赖、可选依赖
            # 或者间接依赖，暂时不能直接断言是错误依赖。
            auto_label = "no_direct_import_match"
            no_direct_import_match += 1

        matched_import_paths = sorted(
            set(
                curated_matches
                + [
                    import_path
                    for import_path, _
                    in wheel_matches
                ]
            )
        )

        matched_wheel_prefixes = sorted(
            set(
                prefix
                for _, prefix
                in wheel_matches
            )
        )

        output_row: dict[str, Any] = dict(row)

        output_row.update(
            {
                "auto_label": auto_label,
                "matched_by": " | ".join(
                    matched_by
                ),
                "matched_import_paths": (
                    " | ".join(
                        matched_import_paths
                    )
                ),
                "matched_wheel_prefixes": (
                    " | ".join(
                        matched_wheel_prefixes
                    )
                ),
                "resolver_status": (
                    resolver_status
                ),
                "resolver_error": (
                    resolver_error
                ),
            }
        )

        output_rows.append(output_row)

        print(
            f"[{auto_label}] "
            f"{row.get('sample_id', '')} | "
            f"{distribution} | "
            f"matched_by="
            f"{','.join(matched_by) or 'none'}"
        )

    if output_rows:
        write_csv(
            output_rows,
            OUTPUT_PATH,
        )

    print("")
    print(
        "============================================================"
    )
    print(
        "Manifest-only automatic recheck summary"
    )
    print(
        "============================================================"
    )
    print(
        f"total_cards = {len(review_rows)}"
    )
    print(
        "direct_import_backed = "
        f"{direct_import_backed}"
    )
    print(
        "no_direct_import_match = "
        f"{no_direct_import_match}"
    )
    print(
        f"resolver_errors = {resolver_errors}"
    )
    print(
        f"output = "
        f"{OUTPUT_PATH.relative_to(ROOT)}"
    )
    print(
        "============================================================"
    )

    if resolver_errors:
        raise SystemExit(1)


if __name__ == "__main__":
    main()