from typing import Any

from classify_manifest_only_dependency_evidence import (
    find_dependency_evidence,
    find_dependency_paths,
)

def make_requirement(
    name: str,
    marker: str = "",
) -> dict[str, Any]:
    """
    构造一条测试用的 Requires-Dist 记录。
    """
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
    """
    构造一个测试包的简化元数据。
    """
    return {
        "status": "ok",
        "import_prefixes": [],
        "requires_dist": requirements,
    }


def test_one_layer() -> None:
    """
    测试：

        one-a -> target-package
    """
    metadata_cache = {
        "one-a": make_metadata(
            [
                make_requirement(
                    "target-package"
                )
            ]
        ),
    }

    paths = find_dependency_paths(
        target="target-package",
        direct_distributions=["one-a"],
        metadata_cache=metadata_cache,
        max_depth=3,
    )

    assert len(paths) == 1
    assert paths[0]["depth"] == 1
    assert paths[0]["path"] == [
        "one-a",
        "target-package",
    ]

    print("[PASS] one-layer dependency path")


def test_two_layers() -> None:
    """
    测试：

        two-a -> two-b -> target-package
    """
    metadata_cache = {
        "two-a": make_metadata(
            [
                make_requirement("two-b")
            ]
        ),
        "two-b": make_metadata(
            [
                make_requirement(
                    "target-package"
                )
            ]
        ),
    }

    paths = find_dependency_paths(
        target="target-package",
        direct_distributions=["two-a"],
        metadata_cache=metadata_cache,
        max_depth=3,
    )

    assert len(paths) == 1
    assert paths[0]["depth"] == 2
    assert paths[0]["path"] == [
        "two-a",
        "two-b",
        "target-package",
    ]

    print("[PASS] two-layer dependency path")


def test_three_layers() -> None:
    """
    测试：

        three-a
        -> three-b
        -> three-c
        -> target-package

    最后一条边故意设置成 optional extra，
    同时验证依赖边类型是否被保存。
    """
    metadata_cache = {
        "three-a": make_metadata(
            [
                make_requirement("three-b")
            ]
        ),
        "three-b": make_metadata(
            [
                make_requirement("three-c")
            ]
        ),
        "three-c": make_metadata(
            [
                make_requirement(
                    "target-package",
                    marker='extra == "feature"',
                )
            ]
        ),
    }

    paths = find_dependency_paths(
        target="target-package",
        direct_distributions=["three-a"],
        metadata_cache=metadata_cache,
        max_depth=3,
    )

    assert len(paths) == 1
    assert paths[0]["depth"] == 3
    assert paths[0]["path"] == [
        "three-a",
        "three-b",
        "three-c",
        "target-package",
    ]
    assert paths[0]["edge_types"] == [
        "required_dependency",
        "required_dependency",
        "optional_extra_dependency",
    ]

    print("[PASS] three-layer dependency path")

def test_over_max_depth() -> None:
    """
    测试：

        depth-a
        -> depth-b
        -> depth-c
        -> depth-d
        -> target-package

    target 位于第4层，超过 max_depth=3，
    因此不应该被找到。
    """
    metadata_cache = {
        "depth-a": make_metadata(
            [
                make_requirement("depth-b")
            ]
        ),
        "depth-b": make_metadata(
            [
                make_requirement("depth-c")
            ]
        ),
        "depth-c": make_metadata(
            [
                make_requirement("depth-d")
            ]
        ),
        "depth-d": make_metadata(
            [
                make_requirement(
                    "target-package"
                )
            ]
        ),
    }

    paths = find_dependency_paths(
        target="target-package",
        direct_distributions=["depth-a"],
        metadata_cache=metadata_cache,
        max_depth=3,
    )

    assert paths == []

    print(
        "[PASS] dependency beyond "
        "max depth is not matched"
    )


def test_cycle_dependency() -> None:
    """
    测试循环依赖：

        cycle-a -> cycle-b -> cycle-a

    搜索过程必须正常结束，
    不能无限循环。
    """
    metadata_cache = {
        "cycle-a": make_metadata(
            [
                make_requirement("cycle-b")
            ]
        ),
        "cycle-b": make_metadata(
            [
                make_requirement("cycle-a")
            ]
        ),
    }

    paths = find_dependency_paths(
        target="target-package",
        direct_distributions=["cycle-a"],
        metadata_cache=metadata_cache,
        max_depth=3,
    )

    assert paths == []

    print(
        "[PASS] cyclic dependency "
        "does not cause infinite search"
    )


def test_no_dependency_path() -> None:
    """
    测试没有任何路径可以到达 target。
    """
    metadata_cache = {
        "empty-a": make_metadata([]),
    }

    paths = find_dependency_paths(
        target="target-package",
        direct_distributions=["empty-a"],
        metadata_cache=metadata_cache,
        max_depth=3,
    )

    assert paths == []

    print(
        "[PASS] missing dependency "
        "path returns empty result"
    )

def test_required_path_has_priority() -> None:
    """
    同一个中间包可以通过两条路径到达：

        a-optional
        -> shared-middle
        -> target-package

        z-required
        -> shared-middle
        -> target-package

    第一条路径包含 optional extra，
    第二条路径全部是普通必要依赖。

    最终必须选择：
        transitive_dependency_backed
    """
    metadata_cache = {
        "a-optional": make_metadata(
            [
                make_requirement(
                    "shared-middle",
                    marker='extra == "feature"',
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
    }

    evidence_type, evidence_text = (
        find_dependency_evidence(
            target="target-package",
            direct_distributions=[
                "a-optional",
                "z-required",
            ],
            metadata_cache=metadata_cache,
        )
    )

    assert evidence_type == (
        "transitive_dependency_backed"
    )

    assert (
        "z-required -> shared-middle "
        "-> target-package"
        in evidence_text
    )

    print(
        "[PASS] required path has priority "
        "over optional path"
    )

def test_optional_path_classification() -> None:
    """
    测试：

        optional-root
        -> middle-package
        -> target-package

    第一条边由 extra 控制，因此整条路径应分类为：
        optional_extra_dependency
    """
    metadata_cache = {
        "optional-root": make_metadata(
            [
                make_requirement(
                    "middle-package",
                    marker='extra == "feature"',
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
    }

    evidence_type, evidence_text = (
        find_dependency_evidence(
            target="target-package",
            direct_distributions=[
                "optional-root"
            ],
            metadata_cache=metadata_cache,
        )
    )

    assert evidence_type == (
        "optional_extra_dependency"
    )

    assert (
        "optional-root -> middle-package "
        "-> target-package"
        in evidence_text
    )

    assert "depth=2" in evidence_text
    assert 'extra == "feature"' in evidence_text
    assert "requires_dist=[" in evidence_text

    print(
        "[PASS] optional dependency path "
        "classification"
    )


def test_conditional_path_classification() -> None:
    """
    测试：

        conditional-root
        -> target-package

    依赖受到 Python 版本条件限制，因此应分类为：
        conditional_dependency_backed
    """
    metadata_cache = {
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
    }

    evidence_type, evidence_text = (
        find_dependency_evidence(
            target="target-package",
            direct_distributions=[
                "conditional-root"
            ],
            metadata_cache=metadata_cache,
        )
    )

    assert evidence_type == (
        "conditional_dependency_backed"
    )

    assert (
        "conditional-root -> target-package"
        in evidence_text
    )

    assert "depth=1" in evidence_text
    assert (
        'python_version < "3.12"'
        in evidence_text
    )
    assert "requires_dist=[" in evidence_text

    print(
        "[PASS] conditional dependency path "
        "classification"
    )

def main() -> None:
    test_one_layer()
    test_two_layers()
    test_three_layers()
    test_over_max_depth()
    test_cycle_dependency()
    test_no_dependency_path()
    test_required_path_has_priority()
    test_optional_path_classification()
    test_conditional_path_classification()

    print("")
    print(
        "[PASS] All dependency path "
        "search tests passed."
    )



if __name__ == "__main__":
    main()