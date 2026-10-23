from __future__ import annotations

import argparse
import ast
import copy
from pathlib import Path
from typing import Any

from collect_python_module_api_facts import (
    build_signature,
    decode_python_source,
    find_module_record,
    read_archive_member,
    read_json,
    write_json,
)


SCHEMA_VERSION = (
    "avcs_python_public_api_symbol_v0.1"
)


def load_module_source(
    source_index: dict[str, Any],
    module_name: str,
) -> tuple[
    dict[str, Any],
    str,
    ast.Module,
    str,
]:
    record = find_module_record(
        source_index,
        module_name,
    )

    artifact_file = str(
        source_index.get(
            "artifact",
            {},
        ).get(
            "cache_file",
            "",
        )
    ).strip()

    if not artifact_file:
        raise RuntimeError(
            "source index has no "
            "artifact.cache_file"
        )

    artifact_path = Path(
        artifact_file
    )

    if not artifact_path.exists():
        raise FileNotFoundError(
            artifact_path
        )

    archive_path = str(
        record.get(
            "archive_path",
            "",
        )
    ).strip()

    if not archive_path:
        raise RuntimeError(
            f"module {module_name!r} "
            "has no archive_path"
        )

    source = decode_python_source(
        read_archive_member(
            artifact_path,
            archive_path,
        )
    )

    logical_path = str(
        record.get(
            "logical_path"
        )
        or archive_path
    )

    try:
        tree = ast.parse(
            source,
            filename=logical_path,
        )

        parse_mode = (
            "native_python3"
        )

    except SyntaxError as native_exc:
        try:
            from lib2to3.refactor import (
                RefactoringTool,
                get_fixers_from_package,
            )

            tool = RefactoringTool(
                get_fixers_from_package(
                    "lib2to3.fixes"
                )
            )

            analysis_source = str(
                tool.refactor_string(
                    source,
                    logical_path,
                )
            )

            tree = ast.parse(
                analysis_source,
                filename=logical_path,
            )

            source = analysis_source

            parse_mode = (
                "python2_compat"
            )

        except Exception as compat_exc:
            raise RuntimeError(
                "native AST parse failed: "
                f"{native_exc}; "
                "python2 compatibility "
                "parse also failed: "
                f"{compat_exc}"
            ) from compat_exc

    return (
        record,
        source,
        tree,
        parse_mode,
    )


def module_names(
    source_index: dict[str, Any],
) -> set[str]:
    names: set[str] = set()

    for item in source_index.get(
        "python_sources",
        [],
    ):
        if not isinstance(
            item,
            dict,
        ):
            continue

        module = str(
            item.get(
                "module",
                "",
            )
            or ""
        ).strip()

        if module:
            names.add(
                module
            )

    return names


def split_public_symbol(
    source_index: dict[str, Any],
    api_symbol: str,
) -> tuple[str, str] | None:
    parts = [
        part
        for part in api_symbol.split(".")
        if part
    ]

    available_modules = module_names(
        source_index
    )

    # 找最长的真实 module 前缀。
    #
    # jwt.decode
    # -> module = jwt
    # -> member = decode
    for index in range(
        len(parts) - 1,
        0,
        -1,
    ):
        candidate_module = ".".join(
            parts[:index]
        )

        remaining = parts[
            index:
        ]

        if (
            candidate_module
            in available_modules
            and len(remaining) == 1
        ):
            return (
                candidate_module,
                remaining[0],
            )

    return None


def resolve_relative_import_module(
    current_module: str,
    current_record: dict[str, Any],
    imported_module: str | None,
    level: int,
) -> str:
    if level == 0:
        return (
            imported_module
            or ""
        )

    current_parts = (
        current_module.split(".")
    )

    is_package_init = bool(
        current_record.get(
            "is_package_init",
            False,
        )
    )

    if is_package_init:
        package_parts = (
            current_parts
        )
    else:
        package_parts = (
            current_parts[:-1]
        )

    # from .api import decode
    #
    # level = 1
    # 当前 package jwt
    # -> jwt.api
    parents_to_remove = (
        level - 1
    )

    if (
        parents_to_remove
        > len(package_parts)
    ):
        return ""

    if parents_to_remove:
        base_parts = (
            package_parts[
                :-parents_to_remove
            ]
        )
    else:
        base_parts = (
            package_parts
        )

    if imported_module:
        base_parts = [
            *base_parts,
            *imported_module.split("."),
        ]

    return ".".join(
        base_parts
    )



def has_future_absolute_import(
    tree: ast.Module,
) -> bool:
    """
    Return whether the source explicitly enables
    Python-2 absolute-import semantics.
    """
    for statement in tree.body:
        if not isinstance(
            statement,
            ast.ImportFrom,
        ):
            continue

        if (
            statement.module
            != "__future__"
        ):
            continue

        if any(
            alias.name
            == "absolute_import"
            for alias
            in statement.names
        ):
            return True

    return False


def resolve_import_from_module(
    source_index: dict[str, Any],
    tree: ast.Module,
    current_module: str,
    current_record: dict[str, Any],
    imported_module: str | None,
    level: int,
) -> str:
    """
    Resolve ImportFrom targets conservatively.

    Explicit relative imports and normal absolute
    imports keep their current behavior.

    A Python-2 implicit-relative fallback is allowed
    only when all of these hold:

    - level == 0
    - current file is a package __init__.py
    - imported module is a single-component name
    - the absolute target is absent
    - a same-package sibling module exists
    - __future__.absolute_import is not enabled

    Example historical package form:

        from engine import *

    may resolve to:

        package.engine

    when the artifact itself supplies that evidence.
    """
    resolved = (
        resolve_relative_import_module(
            current_module=
                current_module,
            current_record=
                current_record,
            imported_module=
                imported_module,
            level=
                level,
        )
    )

    if level != 0:
        return resolved

    if not resolved:
        return resolved

    available_modules = (
        module_names(
            source_index
        )
    )

    # If the absolute import actually exists,
    # absolute semantics always win.
    if resolved in available_modules:
        return resolved

    if not bool(
        current_record.get(
            "is_package_init",
            False,
        )
    ):
        return resolved

    if (
        not imported_module
        or "."
        in imported_module
    ):
        return resolved

    if has_future_absolute_import(
        tree
    ):
        return resolved

    implicit_relative = (
        f"{current_module}."
        f"{imported_module}"
    )

    if (
        implicit_relative
        in available_modules
    ):
        return implicit_relative

    return resolved


def resolve_imported_module_alias(
    source_index: dict[str, Any],
    current_module: str,
    current_record: dict[str, Any],
    tree: ast.Module,
    local_name: str,
) -> str | None:
    available_modules = module_names(
        source_index
    )

    for statement in tree.body:
        if isinstance(
            statement,
            ast.Import,
        ):
            for alias in statement.names:
                bound_name = (
                    alias.asname
                    or alias.name.split(
                        ".",
                        1,
                    )[0]
                )

                if bound_name != local_name:
                    continue

                candidate_module = (
                    alias.name
                    if alias.asname
                    else bound_name
                )

                if (
                    candidate_module
                    in available_modules
                ):
                    return candidate_module

        if not isinstance(
            statement,
            ast.ImportFrom,
        ):
            continue

        base_module = (
            resolve_import_from_module(
                source_index=
                    source_index,
                tree=
                    tree,
                current_module=
                    current_module,
                current_record=
                    current_record,
                imported_module=
                    statement.module,
                level=
                    int(
                        statement.level
                        or 0
                    ),
            )
        )

        for alias in statement.names:
            if alias.name == "*":
                continue

            bound_name = (
                alias.asname
                or alias.name
            )

            if bound_name != local_name:
                continue

            candidate_module = (
                f"{base_module}."
                f"{alias.name}"
                if base_module
                else alias.name
            )

            if (
                candidate_module
                in available_modules
            ):
                return candidate_module

    return None


def strip_bound_receiver(
    signature: dict[str, Any],
) -> dict[str, Any]:
    result = copy.deepcopy(
        signature
    )

    parameters = result.get(
        "parameters",
        [],
    )

    if (
        isinstance(
            parameters,
            list,
        )
        and parameters
        and parameters[0].get(
            "name"
        )
        in {
            "self",
            "cls",
        }
    ):
        parameters = (
            parameters[1:]
        )

    result["parameters"] = (
        parameters
    )

    result[
        "explicit_parameter_names"
    ] = [
        parameter.get(
            "name"
        )
        for parameter
        in parameters
        if isinstance(
            parameter,
            dict,
        )
    ]

    return result


def find_direct_function(
    tree: ast.Module,
    name: str,
) -> (
    ast.FunctionDef
    | ast.AsyncFunctionDef
    | None
):
    for node in tree.body:
        if (
            isinstance(
                node,
                (
                    ast.FunctionDef,
                    ast.AsyncFunctionDef,
                ),
            )
            and node.name == name
        ):
            return node

    return None


def find_class(
    tree: ast.Module,
    name: str,
) -> ast.ClassDef | None:
    for node in tree.body:
        if (
            isinstance(
                node,
                ast.ClassDef,
            )
            and node.name == name
        ):
            return node

    return None


def find_class_method(
    class_node: ast.ClassDef,
    method_name: str,
) -> (
    ast.FunctionDef
    | ast.AsyncFunctionDef
    | None
):
    for node in class_node.body:
        if (
            isinstance(
                node,
                (
                    ast.FunctionDef,
                    ast.AsyncFunctionDef,
                ),
            )
            and node.name
            == method_name
        ):
            return node

    return None


def find_name_assignment(
    tree: ast.Module,
    target_name: str,
) -> tuple[
    ast.Assign | ast.AnnAssign,
    ast.AST,
] | None:
    for statement in tree.body:
        if isinstance(
            statement,
            ast.Assign,
        ):
            if (
                len(
                    statement.targets
                )
                == 1
                and isinstance(
                    statement.targets[0],
                    ast.Name,
                )
                and statement.targets[
                    0
                ].id
                == target_name
            ):
                return (
                    statement,
                    statement.value,
                )

        elif isinstance(
            statement,
            ast.AnnAssign,
        ):
            if (
                isinstance(
                    statement.target,
                    ast.Name,
                )
                and statement.target.id
                == target_name
                and statement.value
                is not None
            ):
                return (
                    statement,
                    statement.value,
                )

    return None


def find_instance_class(
    tree: ast.Module,
    instance_name: str,
    before_line: int,
) -> tuple[
    str,
    int,
] | None:
    candidates: list[
        tuple[str, int]
    ] = []

    for statement in tree.body:
        line = int(
            getattr(
                statement,
                "lineno",
                0,
            )
            or 0
        )

        if (
            line <= 0
            or line >= before_line
        ):
            continue

        assignment = None

        if (
            isinstance(
                statement,
                ast.Assign,
            )
            and len(
                statement.targets
            )
            == 1
            and isinstance(
                statement.targets[0],
                ast.Name,
            )
            and statement.targets[
                0
            ].id
            == instance_name
        ):
            assignment = (
                statement.value
            )

        elif (
            isinstance(
                statement,
                ast.AnnAssign,
            )
            and isinstance(
                statement.target,
                ast.Name,
            )
            and statement.target.id
            == instance_name
        ):
            assignment = (
                statement.value
            )

        if not isinstance(
            assignment,
            ast.Call,
        ):
            continue

        if isinstance(
            assignment.func,
            ast.Name,
        ):
            candidates.append(
                (
                    assignment.func.id,
                    line,
                )
            )

    if not candidates:
        return None

    return max(
        candidates,
        key=lambda item: item[1],
    )


def build_function_result(
    module_name: str,
    record: dict[str, Any],
    function_node: (
        ast.FunctionDef
        | ast.AsyncFunctionDef
    ),
    source: str,
    parse_mode: str,
) -> dict[str, Any]:
    signature = build_signature(
        function_node,
        source,
    )

    return {
        "status":
            "resolved",

        "implementation": {
            "module":
                module_name,

            "qualname":
                function_node.name,

            "kind":
                "function",

            "logical_path":
                record.get(
                    "logical_path"
                ),

            "line":
                function_node.lineno,

            "signature":
                signature,
        },

        "public_signature":
            copy.deepcopy(
                signature
            ),

        "resolution_chain":
            [
                {
                    "kind":
                        "direct_function",

                    "module":
                        module_name,

                    "name":
                        function_node.name,

                    "logical_path":
                        record.get(
                            "logical_path"
                        ),

                    "line":
                        function_node.lineno,

                    "parse_mode":
                        parse_mode,
                }
            ],
    }


def build_class_result(
    module_name: str,
    record: dict[str, Any],
    class_node: ast.ClassDef,
    source: str,
    parse_mode: str,
) -> dict[str, Any]:
    """
    Resolve one directly defined public class.

    Only an explicitly defined __init__ is used
    to derive a constructor signature. Inherited
    constructor semantics are intentionally not
    inferred here.
    """

    init_node = find_class_method(
        class_node,
        "__init__",
    )

    public_signature = None

    if init_node is not None:
        implementation_signature = (
            build_signature(
                init_node,
                source,
            )
        )

        public_signature = (
            strip_bound_receiver(
                implementation_signature
            )
        )

    return {
        "status":
            "resolved",

        "implementation": {
            "module":
                module_name,

            "qualname":
                class_node.name,

            "kind":
                "class",

            "logical_path":
                record.get(
                    "logical_path"
                ),

            "line":
                class_node.lineno,

            "signature":
                public_signature,
        },

        "public_signature":
            (
                copy.deepcopy(
                    public_signature
                )
                if public_signature
                is not None
                else None
            ),

        "resolution_chain":
            [
                {
                    "kind":
                        "direct_class",

                    "module":
                        module_name,

                    "name":
                        class_node.name,

                    "logical_path":
                        record.get(
                            "logical_path"
                        ),

                    "line":
                        class_node.lineno,

                    "parse_mode":
                        parse_mode,

                    "explicit_init":
                        init_node
                        is not None,
                }
            ],
    }


def build_bound_method_result(
    module_name: str,
    record: dict[str, Any],
    assignment_node: (
        ast.Assign
        | ast.AnnAssign
    ),
    public_name: str,
    instance_name: str,
    class_name: str,
    method_node: (
        ast.FunctionDef
        | ast.AsyncFunctionDef
    ),
    source: str,
    parse_mode: str,
) -> dict[str, Any]:
    implementation_signature = (
        build_signature(
            method_node,
            source,
        )
    )

    public_signature = (
        strip_bound_receiver(
            implementation_signature
        )
    )

    return {
        "status":
            "resolved",

        "implementation": {
            "module":
                module_name,

            "qualname":
                (
                    f"{class_name}."
                    f"{method_node.name}"
                ),

            "kind":
                "bound_instance_method",

            "logical_path":
                record.get(
                    "logical_path"
                ),

            "line":
                method_node.lineno,

            "signature":
                implementation_signature,
        },

        "public_signature":
            public_signature,

        "resolution_chain":
            [
                {
                    "kind":
                        "instance_method_alias",

                    "module":
                        module_name,

                    "public_name":
                        public_name,

                    "instance_name":
                        instance_name,

                    "class_name":
                        class_name,

                    "method_name":
                        method_node.name,

                    "logical_path":
                        record.get(
                            "logical_path"
                        ),

                    "line":
                        getattr(
                            assignment_node,
                            "lineno",
                            None,
                        ),

                    "parse_mode":
                        parse_mode,
                },

                {
                    "kind":
                        "bound_instance_method",

                    "module":
                        module_name,

                    "class_name":
                        class_name,

                    "method_name":
                        method_node.name,

                    "logical_path":
                        record.get(
                            "logical_path"
                        ),

                    "line":
                        method_node.lineno,

                    "parse_mode":
                        parse_mode,
                },
            ],
    }


def resolve_module_member(
    source_index: dict[str, Any],
    module_name: str,
    member_name: str,
    visited: set[
        tuple[str, str]
    ] | None = None,
) -> dict[str, Any]:
    if visited is None:
        visited = set()

    key = (
        module_name,
        member_name,
    )

    if key in visited:
        return {
            "status":
                "circular_resolution",

            "implementation":
                None,

            "public_signature":
                None,

            "resolution_chain":
                [],
        }

    next_visited = {
        *visited,
        key,
    }

    try:
        (
            record,
            source,
            tree,
            parse_mode,
        ) = load_module_source(
            source_index,
            module_name,
        )
    except Exception as exc:
        return {
            "status":
                "module_source_unresolved",

            "error":
                str(exc),

            "implementation":
                None,

            "public_signature":
                None,

            "resolution_chain":
                [],
        }

    # 1. 最直接的：
    #
    # def decode(...):
    direct_function = (
        find_direct_function(
            tree,
            member_name,
        )
    )

    if direct_function is not None:
        return build_function_result(
            module_name=
                module_name,
            record=
                record,
            function_node=
                direct_function,
            source=
                source,

            parse_mode=
                parse_mode,
        )

    # 1b. ??????? class?
    #
    # class Flask(...):
    direct_class = (
        find_class(
            tree,
            member_name,
        )
    )

    if direct_class is not None:
        return build_class_result(
            module_name=
                module_name,

            record=
                record,

            class_node=
                direct_class,

            source=
                source,

            parse_mode=
                parse_mode,
        )

    # 2. package/module re-export：
    #
    # from .api import decode
    for statement in tree.body:
        if not isinstance(
            statement,
            ast.ImportFrom,
        ):
            continue

        for alias in statement.names:
            if alias.name == "*":
                continue

            local_name = (
                alias.asname
                or alias.name
            )

            if (
                local_name
                != member_name
            ):
                continue

            target_module = (
                resolve_import_from_module(
                    source_index=
                        source_index,
                    tree=
                        tree,
                    current_module=
                        module_name,

                    current_record=
                        record,

                    imported_module=
                        statement.module,

                    level=
                        int(
                            statement.level
                            or 0
                        ),
                )
            )

            if not target_module:
                return {
                    "status":
                        "import_target_unresolved",

                    "implementation":
                        None,

                    "public_signature":
                        None,

                    "resolution_chain":
                        [
                            {
                                "kind":
                                    "module_reexport",

                                "from_module":
                                    module_name,

                                "public_name":
                                    member_name,

                                "target_module":
                                    None,

                                "target_name":
                                    alias.name,

                                "logical_path":
                                    record.get(
                                        "logical_path"
                                    ),

                                "line":
                                    statement.lineno,

                                "parse_mode":
                                    parse_mode,
                            }
                        ],
                }

            downstream = (
                resolve_module_member(
                    source_index=
                        source_index,

                    module_name=
                        target_module,

                    member_name=
                        alias.name,

                    visited=
                        next_visited,
                )
            )

            chain = [
                {
                    "kind":
                        "module_reexport",

                    "from_module":
                        module_name,

                    "public_name":
                        member_name,

                    "target_module":
                        target_module,

                    "target_name":
                        alias.name,

                    "logical_path":
                        record.get(
                            "logical_path"
                        ),

                    "line":
                        statement.lineno,

                    "parse_mode":
                        parse_mode,
                },

                *downstream.get(
                    "resolution_chain",
                    [],
                ),
            ]

            downstream[
                "resolution_chain"
            ] = chain

            return downstream

    # 3. 本地 alias：
    #
    # decode = _jwt_global_obj.decode
    assignment = (
        find_name_assignment(
            tree,
            member_name,
        )
    )

    if assignment is not None:
        (
            assignment_node,
            value,
        ) = assignment

        # 新增：处理工厂函数动态生成 API
        #
        # read_csv = _make_parser_function(...)
        #
        # 这类 API 有明确的公开符号，
        # 但是实现不是普通 def 或简单 alias
        if isinstance(
                value,
                ast.Call,
        ):
            return {
                "status":
                    "resolved",

                "implementation":
                    f"{module_name}.{member_name}",

                "implementation_kind":
                    "generated_callable",

                "kind":
                    "factory_generated",

                "public_signature":
                    None,

                "resolution_chain":
                    [
                        {
                            "kind":
                                "factory_generated_assignment",

                            "module":
                                module_name,

                            "public_name":
                                member_name,

                            "factory":
                                getattr(
                                    value.func,
                                    "id",
                                    None,
                                ),

                            "logical_path":
                                record.get(
                                    "logical_path"
                                ),

                            "line":
                                getattr(
                                    assignment_node,
                                    "lineno",
                                    None,
                                ),

                            "parse_mode":
                                parse_mode,
                        }
                    ],
            }

        # alias 到同模块另一个 Name：
        #
        # public = internal
        if isinstance(
                value,
                ast.Name,
        ):
            downstream = (
                resolve_module_member(
                    source_index=
                        source_index,

                    module_name=
                        module_name,

                    member_name=
                        value.id,

                    visited=
                        next_visited,
                )
            )

            downstream[
                "resolution_chain"
            ] = [
                {
                    "kind":
                        "local_name_alias",

                    "module":
                        module_name,

                    "public_name":
                        member_name,

                    "target_name":
                        value.id,

                    "logical_path":
                        record.get(
                            "logical_path"
                        ),

                    "line":
                        getattr(
                            assignment_node,
                            "lineno",
                            None,
                        ),
                },

                *downstream.get(
                    "resolution_chain",
                    [],
                ),
            ]

            return downstream

        # PyJWT 1.0.0：
        #
        # _jwt_global_obj = PyJWT()
        # decode = _jwt_global_obj.decode
        if (
            isinstance(
                value,
                ast.Attribute,
            )
            and isinstance(
                value.value,
                ast.Name,
            )
        ):
            instance_name = (
                value.value.id
            )

            method_name = (
                value.attr
            )

            imported_module = (
                resolve_imported_module_alias(
                    source_index=
                        source_index,
                    current_module=
                        module_name,
                    current_record=
                        record,
                    tree=
                        tree,
                    local_name=
                        instance_name,
                )
            )

            if imported_module is not None:
                downstream = (
                    resolve_module_member(
                        source_index=
                            source_index,
                        module_name=
                            imported_module,
                        member_name=
                            method_name,
                        visited=
                            next_visited,
                    )
                )

                downstream[
                    "resolution_chain"
                ] = [
                    {
                        "kind":
                            "module_attribute_alias",

                        "module":
                            module_name,

                        "public_name":
                            member_name,

                        "module_alias":
                            instance_name,

                        "target_module":
                            imported_module,

                        "target_name":
                            method_name,

                        "logical_path":
                            record.get(
                                "logical_path"
                            ),

                        "line":
                            getattr(
                                assignment_node,
                                "lineno",
                                None,
                            ),

                        "parse_mode":
                            parse_mode,
                    },

                    *downstream.get(
                        "resolution_chain",
                        [],
                    ),
                ]

                return downstream

            instance_class = (
                find_instance_class(
                    tree=
                        tree,

                    instance_name=
                        instance_name,

                    before_line=
                        int(
                            getattr(
                                assignment_node,
                                "lineno",
                                0,
                            )
                            or 0
                        ),
                )
            )

            if (
                instance_class
                is not None
            ):
                (
                    class_name,
                    _,
                ) = instance_class

                class_node = (
                    find_class(
                        tree,
                        class_name,
                    )
                )

                if class_node is not None:
                    method_node = (
                        find_class_method(
                            class_node,
                            method_name,
                        )
                    )

                    if (
                        method_node
                        is not None
                    ):
                        return (
                            build_bound_method_result(
                                module_name=
                                    module_name,

                                record=
                                    record,

                                assignment_node=
                                    assignment_node,

                                public_name=
                                    member_name,

                                instance_name=
                                    instance_name,

                                class_name=
                                    class_name,

                                method_node=
                                    method_node,

                                source=
                                    source,

                                parse_mode=
                                    parse_mode,
                            )
                        )

        return {
            "status":
                "assignment_target_unresolved",

            "implementation":
                None,

            "public_signature":
                None,

            "resolution_chain":
                [
                    {
                        "kind":
                            "unresolved_assignment",

                        "module":
                            module_name,

                        "public_name":
                            member_name,

                        "logical_path":
                            record.get(
                                "logical_path"
                            ),

                        "line":
                            getattr(
                                assignment_node,
                                "lineno",
                                None,
                            ),
                    }
                ],
        }

    # 4. star-import re-export fallback：
    #
    # from pandas.core.api import *
    #
    # Only try this after all more explicit resolution
    # strategies above have failed.
    star_successes = []
    star_unknowns = []

    for statement in tree.body:
        if not isinstance(
            statement,
            ast.ImportFrom,
        ):
            continue

        if not any(
            alias.name == "*"
            for alias in statement.names
        ):
            continue

        target_module = (
            resolve_import_from_module(
                source_index=
                    source_index,
                tree=
                    tree,
                current_module=
                    module_name,

                current_record=
                    record,

                imported_module=
                    statement.module,

                level=
                    int(
                        statement.level
                        or 0
                    ),
            )
        )

        star_step = {
            "kind":
                "star_module_reexport",

            "from_module":
                module_name,

            "public_name":
                member_name,

            "target_module":
                target_module,

            "target_name":
                member_name,

            "logical_path":
                record.get(
                    "logical_path"
                ),

            "line":
                statement.lineno,

            "parse_mode":
                parse_mode,
        }

        if not target_module:
            star_step[
                "reason"
            ] = (
                "import_target_unresolved"
            )

            star_unknowns.append(
                star_step
            )

            continue

        # Respect target-module __all__ when it can
        # be determined statically.
        try:
            (
                _target_record,
                _target_source,
                target_tree,
                _target_parse_mode,
            ) = load_module_source(
                source_index,
                target_module,
            )
        except Exception as exc:
            star_step[
                "reason"
            ] = (
                "target_module_source_unresolved"
            )

            star_step[
                "error"
            ] = str(exc)

            star_unknowns.append(
                star_step
            )

            continue

        all_values = []
        all_dynamic = False

        for target_statement in (
            target_tree.body
        ):
            if isinstance(
                target_statement,
                ast.Assign,
            ):
                has_all_target = any(
                    isinstance(
                        target,
                        ast.Name,
                    )
                    and target.id == "__all__"
                    for target
                    in target_statement.targets
                )

                if has_all_target:
                    all_values.append(
                        target_statement.value
                    )

            elif (
                isinstance(
                    target_statement,
                    ast.AnnAssign,
                )
                and isinstance(
                    target_statement.target,
                    ast.Name,
                )
                and (
                    target_statement.target.id
                    == "__all__"
                )
            ):
                if (
                    target_statement.value
                    is not None
                ):
                    all_values.append(
                        target_statement.value
                    )

            elif (
                isinstance(
                    target_statement,
                    ast.AugAssign,
                )
                and isinstance(
                    target_statement.target,
                    ast.Name,
                )
                and (
                    target_statement.target.id
                    == "__all__"
                )
            ):
                all_dynamic = True

        if (
            len(all_values) > 1
            or all_dynamic
        ):
            star_step[
                "reason"
            ] = (
                "dynamic_or_multiple___all__"
            )

            star_unknowns.append(
                star_step
            )

            continue

        if len(all_values) == 1:
            try:
                exported_names = (
                    ast.literal_eval(
                        all_values[0]
                    )
                )
            except Exception:
                exported_names = None

            if (
                not isinstance(
                    exported_names,
                    (list, tuple, set),
                )
                or not all(
                    isinstance(name, str)
                    for name
                    in exported_names
                )
            ):
                star_step[
                    "reason"
                ] = (
                    "static___all___unresolved"
                )

                star_unknowns.append(
                    star_step
                )

                continue

            if (
                member_name
                not in exported_names
            ):
                continue

        elif member_name.startswith("_"):
            # Without __all__, import * excludes
            # underscore-prefixed names.
            continue

        downstream = (
            resolve_module_member(
                source_index=
                    source_index,

                module_name=
                    target_module,

                member_name=
                    member_name,

                visited=
                    next_visited,
            )
        )

        if (
                downstream.get(
                    "implementation"
                )
                is not None
                or downstream.get(
            "status"
        )
                == "assignment_target_unresolved"
        ):
            downstream[
                "resolution_chain"
            ] = [
                star_step,

                *downstream.get(
                    "resolution_chain",
                    [],
                ),
            ]

            star_successes.append(
                (
                    statement.lineno,
                    downstream,
                )
            )

            continue

        if (
            downstream.get("status")
            != "member_not_found"
        ):
            unknown_step = dict(
                star_step
            )

            unknown_step[
                "reason"
            ] = (
                "downstream_unresolved"
            )

            unknown_step[
                "downstream_status"
            ] = downstream.get(
                "status"
            )

            star_unknowns.append(
                unknown_step
            )

    if star_successes:
        # Python executes top-level imports in order.
        # If several star imports export the same name,
        # the later one wins.
        (
            _,
            selected,
        ) = max(
            star_successes,
            key=lambda item: item[0],
        )

        return selected

    if star_unknowns:
        return {
            "status":
                "star_import_unresolved",

            "implementation":
                None,

            "public_signature":
                None,

            "resolution_chain":
                star_unknowns,
        }

    return {
        "status":
            "member_not_found",

        "implementation":
            None,

        "public_signature":
            None,

        "resolution_chain":
            [],
    }


def resolve_public_api_symbol(
    source_index_path: Path,
    api_symbol: str,
) -> dict[str, Any]:
    source_index = read_json(
        source_index_path
    )

    cleaned_symbol = (
        api_symbol.strip()
    )

    split_result = (
        split_public_symbol(
            source_index,
            cleaned_symbol,
        )
    )

    if split_result is None:
        return {
            "schema_version":
                SCHEMA_VERSION,

            "distribution":
                source_index.get(
                    "distribution",
                    "",
                ),

            "normalized_distribution":
                source_index.get(
                    "normalized_distribution",
                    "",
                ),

            "version":
                source_index.get(
                    "version",
                    "",
                ),

            "api_symbol":
                cleaned_symbol,

            "status":
                "public_module_unresolved",

            "implementation":
                None,

            "public_signature":
                None,

            "resolution_chain":
                [],
        }

    (
        public_module,
        public_member,
    ) = split_result

    resolved = resolve_module_member(
        source_index=
            source_index,

        module_name=
            public_module,

        member_name=
            public_member,
    )

    return {
        "schema_version":
            SCHEMA_VERSION,

        "ecosystem":
            source_index.get(
                "ecosystem",
                "pypi",
            ),

        "distribution":
            source_index.get(
                "distribution",
                "",
            ),

        "normalized_distribution":
            source_index.get(
                "normalized_distribution",
                "",
            ),

        "version":
            source_index.get(
                "version",
                "",
            ),

        "api_symbol":
            cleaned_symbol,

        "public_module":
            public_module,

        "public_member":
            public_member,

        "status":
            resolved.get(
                "status",
                "unresolved",
            ),

        "implementation":
            resolved.get(
                "implementation"
            ),

        "public_signature":
            resolved.get(
                "public_signature"
            ),

        "resolution_chain":
            resolved.get(
                "resolution_chain",
                [],
            ),

        **(
            {
                "error":
                    resolved[
                        "error"
                    ]
            }
            if resolved.get(
                "error"
            )
            else {}
        ),
    }


def main() -> None:
    parser = (
        argparse.ArgumentParser(
            description=(
                "Resolve one public Python "
                "API symbol to a statically "
                "observable historical "
                "implementation and callable "
                "signature."
            )
        )
    )

    parser.add_argument(
        "--source-index",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--api-symbol",
        required=True,
    )

    parser.add_argument(
        "--out",
        required=True,
        type=Path,
    )

    args = parser.parse_args()

    result = (
        resolve_public_api_symbol(
            source_index_path=
                args.source_index,

            api_symbol=
                args.api_symbol,
        )
    )

    write_json(
        args.out,
        result,
    )

    print(
        f"[OK] distribution: "
        f"{result['distribution']}"
    )

    print(
        f"[OK] version: "
        f"{result['version']}"
    )

    print(
        f"[OK] API symbol: "
        f"{result['api_symbol']}"
    )

    print(
        f"[OK] status: "
        f"{result['status']}"
    )

    implementation = (
        result.get(
            "implementation"
        )
    )

    if isinstance(
        implementation,
        dict,
    ):
        print(
            f"[OK] implementation: "
            f"{implementation.get('module')}"
            f"."
            f"{implementation.get('qualname')}"
        )

        print(
            f"[OK] implementation kind: "
            f"{implementation.get('kind')}"
        )

    print(
        f"[OK] result saved to: "
        f"{args.out}"
    )


if __name__ == "__main__":
    main()