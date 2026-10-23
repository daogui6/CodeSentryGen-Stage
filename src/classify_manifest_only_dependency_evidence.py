import csv
import re
from collections import Counter, deque
from pathlib import Path
from typing import Any, TypedDict

from extractor import extract_imports_from_code
from inspect_distribution_imports import inspect_distribution
from normalizer import (
    load_import_mapping,
    map_import_path_to_distribution,
    pep503_normalize,
)


ROOT = Path(__file__).resolve().parents[1]

class DependencyPathState(TypedDict):
    """
    三层依赖搜索队列中的一项状态。

    例如搜索路径：

        package-a -> package-b -> target-package

    当搜索到 package-b 时：
    - current_distribution 是 package-b
    - depth 是 1
    - path 是 [package-a, package-b]
    - edge_types 保存已经经过的依赖边类型
    - requires_dist_records 保存每条边的原始依赖证据
    """

    current_distribution: str
    depth: int
    path: list[str]
    edge_types: list[str]
    requires_dist_records: list[dict[str, Any]]

INPUT_PATH = (
    ROOT
    / "output"
    / "auto_qwen37_100_manifest_only_auto_recheck.csv"
)

OUTPUT_PATH = (
    ROOT
    / "output"
    / "auto_qwen37_100_manifest_only_dependency_recheck.csv"
)

REQUIREMENTS_DIR = (
    ROOT
    / "data"
    / "auto_qwen37_100_requirements_files"
)

MAPPING_PATH = (
    ROOT
    / "config"
    / "import_mapping.json"
)

def classify_requirement_edge(
    requirement: dict[str, Any],
) -> str:
    """
    判断一条 Requires-Dist 记录属于哪种依赖边。

    返回值：
    - required_dependency：普通必要依赖
    - conditional_dependency：带环境条件的依赖
    - optional_extra_dependency：由 extra 控制的可选依赖
    """
    marker = str(
        requirement.get(
            "marker",
            "",
        )
    ).strip()

    if re.search(
        r"\bextra\s*==",
        marker,
    ):
        return "optional_extra_dependency"

    if marker:
        return "conditional_dependency"

    return "required_dependency"

def find_dependency_paths(
    target: str,
    direct_distributions: list[str],
    metadata_cache: dict[str, dict[str, Any]],
    max_depth: int = 3,
) -> list[dict[str, Any]]:
    """
    从代码直接使用的 distribution 出发，
    使用广度优先搜索查找最多三层的依赖路径。

    深度定义：
    - 直接使用的包：depth = 0
    - A -> B：depth = 1
    - A -> B -> C：depth = 2
    - A -> B -> C -> D：depth = 3

    返回所有找到 target 的路径。
    """
    normalized_target = pep503_normalize(
        target
    )

    queue: deque[DependencyPathState] = deque()
    matched_paths: list[
        dict[str, Any]
    ] = []

    for distribution in sorted(
        set(direct_distributions)
    ):
        normalized_distribution = (
            pep503_normalize(
                distribution
            )
        )

        queue.append(
            {
                "current_distribution": (
                    normalized_distribution
                ),
                "depth": 0,
                "path": [
                    normalized_distribution
                ],
                "edge_types": [],
                "requires_dist_records": [],
            }
        )

    while queue:
        state = queue.popleft()

        current_distribution = state[
            "current_distribution"
        ]
        current_depth = state["depth"]

        if current_depth >= max_depth:
            continue

        metadata = get_distribution_metadata(
            distribution=current_distribution,
            metadata_cache=metadata_cache,
            metadata_only=True,
        )

        requirements = metadata.get(
            "requires_dist",
            [],
        )

        if not isinstance(
            requirements,
            list,
        ):
            continue

        for requirement in requirements:
            if requirement.get(
                "parse_status"
            ) != "ok":
                continue

            dependency_name = pep503_normalize(
                str(
                    requirement.get(
                        "name",
                        "",
                    )
                )
            )

            if not dependency_name:
                continue

            next_depth = current_depth + 1
            edge_type = (
                classify_requirement_edge(
                    requirement
                )
            )

            next_path = (
                state["path"]
                + [dependency_name]
            )

            next_edge_types = (
                state["edge_types"]
                + [edge_type]
            )

            edge_record = {
                "provider": (
                    current_distribution
                ),
                "dependency": (
                    dependency_name
                ),
                "depth": next_depth,
                "edge_type": edge_type,
                "specifier": requirement.get(
                    "specifier",
                    "",
                ),
                "marker": requirement.get(
                    "marker",
                    "",
                ),
                "extras": requirement.get(
                    "extras",
                    [],
                ),
                "raw": requirement.get(
                    "raw",
                    "",
                ),
                "parse_status": (
                    requirement.get(
                        "parse_status"
                    )
                ),
            }

            next_requires_dist_records = (
                state[
                    "requires_dist_records"
                ]
                + [edge_record]
            )

            if (
                dependency_name
                == normalized_target
            ):
                matched_paths.append(
                    {
                        "matched": True,
                        "depth": next_depth,
                        "path": next_path,
                        "edge_types": (
                            next_edge_types
                        ),
                        "requires_dist_records": (
                            next_requires_dist_records
                        ),
                    }
                )
                continue

            if next_depth >= max_depth:
                continue

            # 当前路径中已经出现过该包，
            # 说明形成了循环依赖，不再继续。
            if dependency_name in state[
                "path"
            ]:
                continue

            queue.append(
                {
                    "current_distribution": (
                        dependency_name
                    ),
                    "depth": next_depth,
                    "path": next_path,
                    "edge_types": (
                        next_edge_types
                    ),
                    "requires_dist_records": (
                        next_requires_dist_records
                    ),
                }
            )

    return matched_paths

def format_dependency_path_evidence(
    path_record: dict[str, Any],
) -> str:
    """
    将一条完整依赖路径格式化为可读证据文本。

    示例输出：

        package-a -> package-b -> target-package
        | depth=2
        | requires_dist=[
            package-b>=1.0;
            target-package; python_version < "3.12"
          ]
    """
    path = path_record.get(
        "path",
        [],
    )
    depth = path_record.get(
        "depth",
        0,
    )
    requires_dist_records = path_record.get(
        "requires_dist_records",
        [],
    )

    path_text = " -> ".join(
        str(item)
        for item in path
    )

    raw_requirements: list[str] = []

    for record in requires_dist_records:
        raw_requirement = str(
            record.get(
                "raw",
                "",
            )
        ).strip()

        if raw_requirement:
            raw_requirements.append(
                raw_requirement
            )

    evidence = (
        f"{path_text} | depth={depth}"
    )

    if raw_requirements:
        evidence += (
            " | requires_dist=["
            + " ; ".join(raw_requirements)
            + "]"
        )

    return evidence

def classify_dependency_path(
    path_record: dict[str, Any],
) -> str:
    """
    根据完整依赖路径中的边类型，
    判断这条路径属于哪一种依赖证据。

    判断优先级：
    1. 路径中出现 optional extra
    2. 路径中出现 conditional marker
    3. 全部为普通必要依赖
    """
    edge_types = path_record.get(
        "edge_types",
        [],
    )

    if (
        "optional_extra_dependency"
        in edge_types
    ):
        return "optional_extra_dependency"

    if (
        "conditional_dependency"
        in edge_types
    ):
        return "conditional_dependency_backed"

    return "transitive_dependency_backed"

def read_csv(
    path: Path,
) -> list[dict[str, str]]:
    with path.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as file:
        return list(csv.DictReader(file))


def write_csv(
    rows: list[dict[str, Any]],
    path: Path,
) -> None:
    if not rows:
        return

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with path.open(
        "w",
        encoding="utf-8-sig",
        newline="",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=list(rows[0].keys()),
        )

        writer.writeheader()
        writer.writerows(rows)


def parse_requirement_names(
    sample_id: str,
) -> list[str]:
    """
    读取一个样本 requirements 文件中的 distribution 名称。
    """
    path = (
        REQUIREMENTS_DIR
        / f"{sample_id}_requirements.txt"
    )

    if not path.exists():
        return []

    results: list[str] = []

    for raw_line in path.read_text(
        encoding="utf-8",
    ).splitlines():
        line = raw_line.split("#", 1)[0].strip()

        if not line:
            continue

        if line.startswith("-"):
            continue

        match = re.match(
            r"^([A-Za-z0-9][A-Za-z0-9._-]*)",
            line,
        )

        if match:
            results.append(
                pep503_normalize(
                    match.group(1)
                )
            )

    return sorted(set(results))


def load_import_paths(
    code_file: str,
) -> list[tuple[str, str]]:
    path = Path(code_file)

    if not path.is_absolute():
        path = ROOT / path

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
    if not import_path or not prefix:
        return False

    if import_path == prefix:
        return True

    # google、azure 这类单层公共 namespace
    # 不能单独作为充分证据。
    if len(prefix.split(".")) < 2:
        return False

    return import_path.startswith(
        prefix + "."
    )


def distribution_is_directly_used(
    distribution: str,
    imports: list[tuple[str, str]],
    mapping: dict[str, str],
    metadata: dict[str, Any],
) -> bool:
    """
    判断某个 requirements distribution
    是否与代码中的 import 存在直接对应关系。
    """
    for raw_name, import_path in imports:
        mapped = map_import_path_to_distribution(
            raw_name=raw_name,
            import_path=import_path,
            mapping=mapping,
        )

        if (
            pep503_normalize(mapped)
            == distribution
        ):
            return True

    prefixes = metadata.get(
        "import_prefixes",
        [],
    )

    if not isinstance(prefixes, list):
        return False

    for _, import_path in imports:
        for prefix in prefixes:
            if wheel_prefix_match(
                import_path,
                str(prefix),
            ):
                return True

    return False

def get_distribution_metadata(
    distribution: str,
    metadata_cache: dict[str, dict[str, Any]],
    metadata_only: bool = False,
) -> dict[str, Any]:
    """
    获取 PyPI distribution 的元数据。

    metadata_only=False：
        完整检查模式，可获取 wheel 中的 import_prefixes，
        用于判断代码是否直接使用该 distribution。

    metadata_only=True：
        轻量依赖模式，只读取 PyPI JSON 中的 requires_dist，
        用于向第二层、第三层继续搜索，避免下载 wheel。
    """
    normalized_distribution = pep503_normalize(
        distribution
    )

    # 完整模式的缓存本身也包含 requires_dist。
    # 轻量查询时优先复用，避免重复请求，
    # 同时兼容人工测试中预先构造的缓存数据。
    if metadata_only:
        full_metadata = metadata_cache.get(
            normalized_distribution
        )

        if (
            isinstance(full_metadata, dict)
            and isinstance(
                full_metadata.get(
                    "requires_dist"
                ),
                list,
            )
        ):
            return full_metadata

    cache_key = normalized_distribution

    if metadata_only:
        cache_key = (
            f"{normalized_distribution}"
            "::metadata_only"
        )

    if cache_key not in metadata_cache:
        try:
            metadata_cache[
                cache_key
            ] = inspect_distribution(
                normalized_distribution,
                metadata_only=metadata_only,
            )
        except Exception as exc:
            metadata_cache[
                cache_key
            ] = {
                "distribution": (
                    normalized_distribution
                ),
                "status": "resolver_error",
                "import_prefixes": [],
                "requires_dist": [],
                "error": str(exc),
            }

    return metadata_cache[cache_key]

def find_dependency_evidence(
    target: str,
    direct_distributions: list[str],
    metadata_cache: dict[str, dict[str, Any]],
) -> tuple[str, str]:
    """
    从代码直接使用的 distribution 出发，
    检查 target 是否能够通过最多三层依赖路径到达。

    返回：
    - 证据分类标签
    - 包含完整路径、深度和原始 Requires-Dist 的证据文本
    """
    matched_paths = find_dependency_paths(
        target=target,
        direct_distributions=direct_distributions,
        metadata_cache=metadata_cache,
        max_depth=3,
    )

    evidence_by_type: dict[
        str,
        list[str],
    ] = {
        "transitive_dependency_backed": [],
        "optional_extra_dependency": [],
        "conditional_dependency_backed": [],
    }

    sorted_paths = sorted(
        matched_paths,
        key=lambda record: (
            int(record.get("depth", 0)),
            " -> ".join(
                str(item)
                for item in record.get(
                    "path",
                    [],
                )
            ),
        ),
    )

    for path_record in sorted_paths:
        evidence_type = (
            classify_dependency_path(
                path_record
            )
        )

        evidence_text = (
            format_dependency_path_evidence(
                path_record
            )
        )

        evidence_list = evidence_by_type[
            evidence_type
        ]

        if evidence_text not in evidence_list:
            evidence_list.append(
                evidence_text
            )

    required_evidence = evidence_by_type[
        "transitive_dependency_backed"
    ]

    optional_evidence = evidence_by_type[
        "optional_extra_dependency"
    ]

    conditional_evidence = evidence_by_type[
        "conditional_dependency_backed"
    ]

    if required_evidence:
        return (
            "transitive_dependency_backed",
            " || ".join(required_evidence),
        )

    if optional_evidence:
        return (
            "optional_extra_dependency",
            " || ".join(optional_evidence),
        )

    if conditional_evidence:
        return (
            "conditional_dependency_backed",
            " || ".join(
                conditional_evidence
            ),
        )

    return (
        "no_dependency_evidence",
        "",
    )


def main() -> None:
    rows = read_csv(INPUT_PATH)
    mapping = load_import_mapping(
        MAPPING_PATH
    )

    metadata_cache: dict[
        str,
        dict[str, Any],
    ] = {}

    output_rows: list[
        dict[str, Any]
    ] = []

    for row in rows:
        old_label = row.get(
            "auto_label",
            "",
        )

        # 已经有直接 import 证据的15张无需再次判断。
        if old_label != "no_direct_import_match":
            new_row = dict(row)
            new_row["dependency_label"] = (
                old_label
            )
            new_row["direct_distributions"] = ""
            new_row["dependency_evidence"] = ""

            output_rows.append(new_row)
            continue

        sample_id = row.get(
            "sample_id",
            "",
        )

        target = pep503_normalize(
            row.get("package", "")
        )

        imports = load_import_paths(
            row.get("code_file", "")
        )

        manifest_distributions = (
            parse_requirement_names(
                sample_id
            )
        )

        direct_distributions: list[str] = []

        for distribution in manifest_distributions:
            metadata = get_distribution_metadata(
                distribution=distribution,
                metadata_cache=metadata_cache,
            )

            if distribution_is_directly_used(
                    distribution=distribution,
                    imports=imports,
                    mapping=mapping,
                    metadata=metadata,
            ):
                direct_distributions.append(
                    distribution
                )

            if distribution_is_directly_used(
                distribution=distribution,
                imports=imports,
                mapping=mapping,
                metadata=metadata,
            ):
                direct_distributions.append(
                    distribution
                )

        dependency_label, evidence = (
            find_dependency_evidence(
                target=target,
                direct_distributions=(
                    direct_distributions
                ),
                metadata_cache=metadata_cache,
            )
        )

        new_row = dict(row)

        new_row.update(
            {
                "dependency_label": (
                    dependency_label
                ),
                "direct_distributions": (
                    " | ".join(
                        sorted(
                            set(
                                direct_distributions
                            )
                        )
                    )
                ),
                "dependency_evidence": (
                    evidence
                ),
            }
        )

        output_rows.append(new_row)

        print(
            f"[{dependency_label}] "
            f"{sample_id} | "
            f"{target} | "
            f"evidence={evidence or 'none'}"
        )

    write_csv(
        output_rows,
        OUTPUT_PATH,
    )

    counts = Counter(
        row["dependency_label"]
        for row in output_rows
    )

    print("")
    print(
        "============================================================"
    )
    print(
        "Manifest-only dependency evidence summary"
    )
    print(
        "============================================================"
    )

    for label, count in sorted(
        counts.items()
    ):
        print(
            f"{label} = {count}"
        )

    print(
        f"output = "
        f"{OUTPUT_PATH.relative_to(ROOT)}"
    )
    print(
        "============================================================"
    )


if __name__ == "__main__":
    main()