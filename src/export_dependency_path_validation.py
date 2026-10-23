import csv
from pathlib import Path
from typing import Any

from classify_manifest_only_dependency_evidence import (
    find_dependency_evidence,
    find_dependency_paths,
)


ROOT = Path(__file__).resolve().parents[1]
OUTPUT_PATH = (
    ROOT
    / "output"
    / "dependency_path_search_validation.csv"
)


def make_requirement(
    name: str,
    marker: str = "",
) -> dict[str, Any]:
    """构造一条测试用的 Requires-Dist 记录。"""
    return {
        "name": name,
        "specifier": "",
        "marker": marker,
        "extras": [],
        "raw": (
            name
            if not marker
            else f"{name}; {marker}"
        ),
        "parse_status": "ok",
    }


def make_metadata(
    requirements: list[dict[str, Any]],
) -> dict[str, Any]:
    """构造一个测试包的简化元数据。"""
    return {
        "status": "ok",
        "import_prefixes": [],
        "requires_dist": requirements,
    }


def join_path(path: list[str] | None) -> str:
    if not path:
        return ""
    return " -> ".join(path)


def join_values(values: list[str] | None) -> str:
    if not values:
        return ""
    return " | ".join(values)


def build_path_result(
    *,
    test_id: str,
    test_name: str,
    scenario_type: str,
    graph: str,
    target: str,
    direct_distributions: list[str],
    metadata_cache: dict[str, dict[str, Any]],
    max_depth: int,
    expected_found: bool,
    expected_depth: int | None,
    expected_path: list[str] | None,
    expected_edge_types: list[str] | None = None,
    note: str = "",
) -> dict[str, Any]:
    paths = find_dependency_paths(
        target=target,
        direct_distributions=direct_distributions,
        metadata_cache=metadata_cache,
        max_depth=max_depth,
    )

    actual_found = bool(paths)
    selected_path = paths[0] if paths else {}

    actual_depth = selected_path.get("depth")
    actual_path = selected_path.get("path", [])
    actual_edge_types = selected_path.get(
        "edge_types",
        [],
    )
    raw_requires_dist = selected_path.get(
        "raw_requires_dist",
        selected_path.get(
            "requires_dist_records",
            [],
        ),
    )

    checks = [
        actual_found == expected_found,
    ]

    if expected_found:
        checks.extend(
            [
                actual_depth == expected_depth,
                actual_path == expected_path,
            ]
        )

        if expected_edge_types is not None:
            checks.append(
                actual_edge_types
                == expected_edge_types
            )
    else:
        checks.append(paths == [])

    status = (
        "PASS"
        if all(checks)
        else "FAIL"
    )

    return {
        "test_id": test_id,
        "test_name": test_name,
        "scenario_type": scenario_type,
        "constructed_dependency_graph": graph,
        "direct_distributions": join_values(
            direct_distributions
        ),
        "target_package": target,
        "max_depth": max_depth,
        "expected_match": expected_found,
        "actual_match": actual_found,
        "expected_depth": (
            ""
            if expected_depth is None
            else expected_depth
        ),
        "actual_depth": (
            ""
            if actual_depth is None
            else actual_depth
        ),
        "expected_path": join_path(
            expected_path
        ),
        "actual_path": join_path(
            actual_path
        ),
        "expected_classification": "",
        "actual_classification": "",
        "edge_types": join_values(
            actual_edge_types
        ),
        "raw_requires_dist_evidence": str(
            raw_requires_dist
        ),
        "validation_points": (
            "match result; dependency depth; "
            "complete path; edge types"
        ),
        "status": status,
        "explanation": note,
    }


def build_classification_result(
    *,
    test_id: str,
    test_name: str,
    scenario_type: str,
    graph: str,
    target: str,
    direct_distributions: list[str],
    metadata_cache: dict[str, dict[str, Any]],
    expected_classification: str,
    expected_text_fragments: list[str],
    note: str = "",
) -> dict[str, Any]:
    actual_classification, evidence_text = (
        find_dependency_evidence(
            target=target,
            direct_distributions=(
                direct_distributions
            ),
            metadata_cache=metadata_cache,
        )
    )

    text_checks = [
        fragment in evidence_text
        for fragment in expected_text_fragments
    ]

    status = (
        "PASS"
        if (
            actual_classification
            == expected_classification
            and all(text_checks)
        )
        else "FAIL"
    )

    return {
        "test_id": test_id,
        "test_name": test_name,
        "scenario_type": scenario_type,
        "constructed_dependency_graph": graph,
        "direct_distributions": join_values(
            direct_distributions
        ),
        "target_package": target,
        "max_depth": 3,
        "expected_match": True,
        "actual_match": bool(evidence_text),
        "expected_depth": "",
        "actual_depth": "",
        "expected_path": "",
        "actual_path": evidence_text,
        "expected_classification": (
            expected_classification
        ),
        "actual_classification": (
            actual_classification
        ),
        "edge_types": "",
        "raw_requires_dist_evidence": (
            evidence_text
        ),
        "validation_points": (
            "classification; selected dependency "
            "path; depth; marker; raw Requires-Dist"
        ),
        "status": status,
        "explanation": note,
    }


def build_validation_rows() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    rows.append(
        build_path_result(
            test_id="DEPTH_1",
            test_name="一层依赖路径",
            scenario_type="depth_boundary",
            graph=(
                "one-a -> target-package"
            ),
            target="target-package",
            direct_distributions=["one-a"],
            metadata_cache={
                "one-a": make_metadata(
                    [
                        make_requirement(
                            "target-package"
                        )
                    ]
                ),
            },
            max_depth=3,
            expected_found=True,
            expected_depth=1,
            expected_path=[
                "one-a",
                "target-package",
            ],
            expected_edge_types=[
                "required_dependency"
            ],
            note=(
                "验证一层必要依赖能够返回"
                "完整路径和 depth=1。"
            ),
        )
    )

    rows.append(
        build_path_result(
            test_id="DEPTH_2",
            test_name="两层依赖路径",
            scenario_type="depth_boundary",
            graph=(
                "two-a -> two-b "
                "-> target-package"
            ),
            target="target-package",
            direct_distributions=["two-a"],
            metadata_cache={
                "two-a": make_metadata(
                    [
                        make_requirement(
                            "two-b"
                        )
                    ]
                ),
                "two-b": make_metadata(
                    [
                        make_requirement(
                            "target-package"
                        )
                    ]
                ),
            },
            max_depth=3,
            expected_found=True,
            expected_depth=2,
            expected_path=[
                "two-a",
                "two-b",
                "target-package",
            ],
            expected_edge_types=[
                "required_dependency",
                "required_dependency",
            ],
            note=(
                "验证两层传递依赖能够返回"
                "完整路径和 depth=2。"
            ),
        )
    )

    rows.append(
        build_path_result(
            test_id="DEPTH_3",
            test_name="三层依赖路径",
            scenario_type="depth_boundary",
            graph=(
                "three-a -> three-b "
                "-> three-c -> target-package"
            ),
            target="target-package",
            direct_distributions=["three-a"],
            metadata_cache={
                "three-a": make_metadata(
                    [
                        make_requirement(
                            "three-b"
                        )
                    ]
                ),
                "three-b": make_metadata(
                    [
                        make_requirement(
                            "three-c"
                        )
                    ]
                ),
                "three-c": make_metadata(
                    [
                        make_requirement(
                            "target-package",
                            marker=(
                                'extra == "feature"'
                            ),
                        )
                    ]
                ),
            },
            max_depth=3,
            expected_found=True,
            expected_depth=3,
            expected_path=[
                "three-a",
                "three-b",
                "three-c",
                "target-package",
            ],
            expected_edge_types=[
                "required_dependency",
                "required_dependency",
                "optional_extra_dependency",
            ],
            note=(
                "验证三层路径，并确认路径中"
                " optional extra 边能够被保留。"
            ),
        )
    )

    rows.append(
        build_path_result(
            test_id="OVER_MAX_DEPTH",
            test_name="超过最大深度",
            scenario_type="depth_boundary",
            graph=(
                "depth-a -> depth-b -> depth-c "
                "-> depth-d -> target-package"
            ),
            target="target-package",
            direct_distributions=["depth-a"],
            metadata_cache={
                "depth-a": make_metadata(
                    [
                        make_requirement(
                            "depth-b"
                        )
                    ]
                ),
                "depth-b": make_metadata(
                    [
                        make_requirement(
                            "depth-c"
                        )
                    ]
                ),
                "depth-c": make_metadata(
                    [
                        make_requirement(
                            "depth-d"
                        )
                    ]
                ),
                "depth-d": make_metadata(
                    [
                        make_requirement(
                            "target-package"
                        )
                    ]
                ),
            },
            max_depth=3,
            expected_found=False,
            expected_depth=None,
            expected_path=None,
            note=(
                "目标位于第四层，超过 max_depth=3，"
                "因此不应被匹配。"
            ),
        )
    )

    rows.append(
        build_path_result(
            test_id="CYCLE_GUARD",
            test_name="循环依赖保护",
            scenario_type="cycle_guard",
            graph=(
                "cycle-a -> cycle-b -> cycle-a"
            ),
            target="target-package",
            direct_distributions=["cycle-a"],
            metadata_cache={
                "cycle-a": make_metadata(
                    [
                        make_requirement(
                            "cycle-b"
                        )
                    ]
                ),
                "cycle-b": make_metadata(
                    [
                        make_requirement(
                            "cycle-a"
                        )
                    ]
                ),
            },
            max_depth=3,
            expected_found=False,
            expected_depth=None,
            expected_path=None,
            note=(
                "验证循环依赖不会造成无限搜索，"
                "并且不会误报目标路径。"
            ),
        )
    )

    rows.append(
        build_path_result(
            test_id="NO_PATH",
            test_name="不存在目标路径",
            scenario_type="negative_case",
            graph="empty-a (no dependencies)",
            target="target-package",
            direct_distributions=["empty-a"],
            metadata_cache={
                "empty-a": make_metadata([]),
            },
            max_depth=3,
            expected_found=False,
            expected_depth=None,
            expected_path=None,
            note=(
                "验证没有任何依赖路径时"
                "返回空结果。"
            ),
        )
    )

    rows.append(
        build_classification_result(
            test_id="REQUIRED_PRIORITY",
            test_name="必要路径优先",
            scenario_type="classification",
            graph=(
                "a-optional -> shared-middle "
                "-> target-package; "
                "z-required -> shared-middle "
                "-> target-package"
            ),
            target="target-package",
            direct_distributions=[
                "a-optional",
                "z-required",
            ],
            metadata_cache={
                "a-optional": make_metadata(
                    [
                        make_requirement(
                            "shared-middle",
                            marker=(
                                'extra == "feature"'
                            ),
                        )
                    ]
                ),
                "z-required": make_metadata(
                    [
                        make_requirement(
                            "shared-middle"
                        )
                    ]
                ),
                "shared-middle": make_metadata(
                    [
                        make_requirement(
                            "target-package"
                        )
                    ]
                ),
            },
            expected_classification=(
                "transitive_dependency_backed"
            ),
            expected_text_fragments=[
                (
                    "z-required -> shared-middle "
                    "-> target-package"
                )
            ],
            note=(
                "同一目标同时存在必要路径和可选路径时，"
                "应优先采用证据更强的必要依赖路径。"
            ),
        )
    )

    rows.append(
        build_classification_result(
            test_id="OPTIONAL_CLASS",
            test_name="可选依赖分类",
            scenario_type="classification",
            graph=(
                "optional-root "
                "-> middle-package "
                "-> target-package"
            ),
            target="target-package",
            direct_distributions=[
                "optional-root"
            ],
            metadata_cache={
                "optional-root": make_metadata(
                    [
                        make_requirement(
                            "middle-package",
                            marker=(
                                'extra == "feature"'
                            ),
                        )
                    ]
                ),
                "middle-package": make_metadata(
                    [
                        make_requirement(
                            "target-package"
                        )
                    ]
                ),
            },
            expected_classification=(
                "optional_extra_dependency"
            ),
            expected_text_fragments=[
                (
                    "optional-root "
                    "-> middle-package "
                    "-> target-package"
                ),
                "depth=2",
                'extra == "feature"',
                "requires_dist=[",
            ],
            note=(
                "验证路径中只要包含 extra 条件，"
                "整条路径会标记为可选依赖证据。"
            ),
        )
    )

    rows.append(
        build_classification_result(
            test_id="CONDITIONAL_CLASS",
            test_name="条件依赖分类",
            scenario_type="classification",
            graph=(
                "conditional-root "
                "-> target-package"
            ),
            target="target-package",
            direct_distributions=[
                "conditional-root"
            ],
            metadata_cache={
                "conditional-root": make_metadata(
                    [
                        make_requirement(
                            "target-package",
                            marker=(
                                'python_version < "3.12"'
                            ),
                        )
                    ]
                ),
            },
            expected_classification=(
                "conditional_dependency_backed"
            ),
            expected_text_fragments=[
                (
                    "conditional-root "
                    "-> target-package"
                ),
                "depth=1",
                'python_version < "3.12"',
                "requires_dist=[",
            ],
            note=(
                "验证带 Python 版本 marker 的依赖"
                "会被分类为条件依赖证据。"
            ),
        )
    )

    return rows


def main() -> None:
    rows = build_validation_rows()

    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fieldnames = [
        "test_id",
        "test_name",
        "scenario_type",
        "constructed_dependency_graph",
        "direct_distributions",
        "target_package",
        "max_depth",
        "expected_match",
        "actual_match",
        "expected_depth",
        "actual_depth",
        "expected_path",
        "actual_path",
        "expected_classification",
        "actual_classification",
        "edge_types",
        "raw_requires_dist_evidence",
        "validation_points",
        "status",
        "explanation",
    ]

    with OUTPUT_PATH.open(
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

    passed = sum(
        row["status"] == "PASS"
        for row in rows
    )

    failed = len(rows) - passed

    print(
        "[OK] dependency path validation "
        "CSV generated"
    )
    print(f"[OK] total tests: {len(rows)}")
    print(f"[OK] passed: {passed}")
    print(f"[OK] failed: {failed}")
    print(f"[OK] output: {OUTPUT_PATH}")

    if failed:
        raise AssertionError(
            f"{failed} validation case(s) failed"
        )


if __name__ == "__main__":
    main()
