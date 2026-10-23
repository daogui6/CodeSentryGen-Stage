from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
from typing import Any

from collect_python_module_api_facts import (
    build_signature,
)
from resolve_python_public_api_symbol import (
    find_class,
    find_class_method,
    find_direct_function,
    load_module_source,
)


SCHEMA_VERSION = (
    "avcs_python_keyword_forwarding_v0.2"
)


def read_json(
    path: Path,
) -> dict[str, Any]:
    return json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )


def write_json(
    path: Path,
    data: dict[str, Any],
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        json.dumps(
            data,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )


def find_api_call(
    api_calls: dict[str, Any],
    api_symbol: str,
) -> dict[str, Any]:
    matches = [
        row
        for row in api_calls.get(
            "api_calls",
            [],
        )
        if (
            isinstance(row, dict)
            and row.get(
                "api_symbol"
            )
            == api_symbol
        )
    ]

    if len(matches) != 1:
        raise RuntimeError(
            f"API symbol "
            f"{api_symbol!r} "
            f"matched "
            f"{len(matches)} "
            f"observed calls"
        )

    return matches[0]


def find_parameter(
    signature: dict[str, Any],
    parameter_name: str,
) -> dict[str, Any] | None:
    parameters = signature.get(
        "parameters",
        [],
    )

    if not isinstance(
        parameters,
        list,
    ):
        return None

    for parameter in parameters:
        if (
            isinstance(
                parameter,
                dict,
            )
            and parameter.get(
                "name"
            )
            == parameter_name
        ):
            return parameter

    return None


def find_positional_evidence(
    call_shape: dict[str, Any],
    position: int,
) -> dict[str, Any] | None:
    rows = call_shape.get(
        "positional_arg_values",
        [],
    )

    if not isinstance(
        rows,
        list,
    ):
        return None

    for row in rows:
        if (
            isinstance(
                row,
                dict,
            )
            and row.get(
                "position"
            )
            == position
        ):
            return row

    return None


def bind_public_arguments(
    call_shape: dict[str, Any],
    public_signature: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """
将观察到的调用形态与历史 public signature 对齐。

这里只解析能够静态确定的 literal 和 historical default。

例如观察到：

    package.api(
        value,
        key,
        target_keyword=...
    )

而历史签名为：

    api(
        value,
        key='',
        enabled=True,
        **kwargs
    )

可以确定：

    value    -> observed positional
    key      -> observed positional
    enabled  -> historical default True

如果 target_keyword 不属于显式参数，
则它会进入 **kwargs，后续再由 forwarding 分析判断
该历史实现是否真正支持这个关键字的语义。
"""

    parameters = (
        public_signature.get(
            "parameters",
            [],
        )
    )

    if not isinstance(
        parameters,
        list,
    ):
        return {}

    positional_count = int(
        call_shape.get(
            "explicit_positional_arg_count",
            0,
        )
        or 0
    )

    keyword_values = (
        call_shape.get(
            "keyword_arg_values",
            {},
        )
    )

    if not isinstance(
        keyword_values,
        dict,
    ):
        keyword_values = {}

    bindings: dict[
        str,
        dict[str, Any],
    ] = {}

    positional_index = 0

    for parameter in parameters:
        if not isinstance(
            parameter,
            dict,
        ):
            continue

        name = str(
            parameter.get(
                "name",
                "",
            )
        )

        if not name:
            continue

        kind = parameter.get(
            "kind"
        )

        can_take_position = (
            kind
            in {
                "positional_only",
                "positional_or_keyword",
            }
        )

        if (
            can_take_position
            and positional_index
            < positional_count
        ):
            positional_evidence = (
                find_positional_evidence(
                    call_shape,
                    positional_index,
                )
            )

            binding: dict[
                str,
                Any,
            ] = {
                "source":
                    "observed_positional",

                "position":
                    positional_index,

                "resolved":
                    False,

                "literal_value":
                    None,
            }

            if (
                isinstance(
                    positional_evidence,
                    dict,
                )
                and "literal_value"
                in positional_evidence
            ):
                binding[
                    "resolved"
                ] = True

                binding[
                    "literal_value"
                ] = (
                    positional_evidence[
                        "literal_value"
                    ]
                )

            bindings[name] = (
                binding
            )

            positional_index += 1
            continue

        if name in keyword_values:
            keyword_evidence = (
                keyword_values[
                    name
                ]
            )

            binding = {
                "source":
                    "observed_keyword",

                "resolved":
                    False,

                "literal_value":
                    None,
            }

            if (
                isinstance(
                    keyword_evidence,
                    dict,
                )
                and "literal_value"
                in keyword_evidence
            ):
                binding[
                    "resolved"
                ] = True

                binding[
                    "literal_value"
                ] = (
                    keyword_evidence[
                        "literal_value"
                    ]
                )

            bindings[name] = (
                binding
            )
            continue

        default = parameter.get(
            "default",
            {},
        )

        if (
            isinstance(
                default,
                dict,
            )
            and default.get(
                "has_default"
            )
        ):
            binding = {
                "source":
                    "historical_default",

                "source_text":
                    default.get(
                        "source_text"
                    ),

                "resolved":
                    (
                        "literal_value"
                        in default
                    ),

                "literal_value":
                    default.get(
                        "literal_value"
                    ),
            }

            bindings[name] = (
                binding
            )
            continue

        bindings[name] = {
            "source":
                "unresolved",

            "resolved":
                False,

            "literal_value":
                None,
        }

    return bindings


def evaluate_boolean_condition(
    node: ast.AST,
    bindings: dict[
        str,
        dict[str, Any],
    ],
) -> tuple[
    bool | None,
    dict[str, Any],
]:
    """
    v0 只处理：

        if verify:
        if not verify:

    且 verify 必须能够由调用参数或历史默认值
    静态解析为 bool。
    """

    if isinstance(
        node,
        ast.Name,
    ):
        binding = bindings.get(
            node.id
        )

        if (
            isinstance(
                binding,
                dict,
            )
            and binding.get(
                "resolved"
            )
            and isinstance(
                binding.get(
                    "literal_value"
                ),
                bool,
            )
        ):
            value = bool(
                binding[
                    "literal_value"
                ]
            )

            return (
                value,
                {
                    "kind":
                        "boolean_name",

                    "name":
                        node.id,

                    "value":
                        value,

                    "binding":
                        binding,
                },
            )

    if (
        isinstance(
            node,
            ast.UnaryOp,
        )
        and isinstance(
            node.op,
            ast.Not,
        )
    ):
        (
            operand_value,
            operand_evidence,
        ) = evaluate_boolean_condition(
            node.operand,
            bindings,
        )

        if operand_value is not None:
            return (
                not operand_value,
                {
                    "kind":
                        "boolean_not",

                    "value":
                        not operand_value,

                    "operand":
                        operand_evidence,
                },
            )

    return (
        None,
        {
            "kind":
                "unresolved_condition",
        },
    )


def collect_definite_calls(
    statements: list[ast.stmt],
    bindings: dict[
        str,
        dict[str, Any],
    ],
    path: list[
        dict[str, Any]
    ] | None = None,
) -> list[
    tuple[
        ast.Call,
        list[dict[str, Any]],
    ]
]:
    """
    只收集静态确定会执行的简单分支中的调用。

    v0：
    - 普通顶层 statement：收集其中调用
    - if 条件能确定 True/False：只进入确定分支
    - if 条件未知：不猜
    """

    if path is None:
        path = []

    results: list[
        tuple[
            ast.Call,
            list[dict[str, Any]],
        ]
    ] = []

    for statement in statements:
        if isinstance(
            statement,
            ast.If,
        ):
            (
                condition_value,
                condition_evidence,
            ) = evaluate_boolean_condition(
                statement.test,
                bindings,
            )

            if condition_value is True:
                results.extend(
                    collect_definite_calls(
                        statement.body,
                        bindings,
                        [
                            *path,
                            {
                                "if_line":
                                    statement.lineno,

                                "branch":
                                    "body",

                                "condition":
                                    condition_evidence,
                            },
                        ],
                    )
                )

            elif condition_value is False:
                results.extend(
                    collect_definite_calls(
                        statement.orelse,
                        bindings,
                        [
                            *path,
                            {
                                "if_line":
                                    statement.lineno,

                                "branch":
                                    "orelse",

                                "condition":
                                    condition_evidence,
                            },
                        ],
                    )
                )

            # 条件 unknown 时不进入任何一侧。
            continue

        # 避免把嵌套函数/类定义内部调用误认为
        # 当前函数此次执行一定会触发。
        if isinstance(
            statement,
            (
                ast.FunctionDef,
                ast.AsyncFunctionDef,
                ast.ClassDef,
            ),
        ):
            continue

        for node in ast.walk(
            statement
        ):
            if isinstance(
                node,
                ast.Call,
            ):
                results.append(
                    (
                        node,
                        list(path),
                    )
                )

    return results


def call_forwards_var_keyword(
    call_node: ast.Call,
    var_keyword_name: str,
) -> bool:
    for keyword in call_node.keywords:
        if keyword.arg is not None:
            continue

        if (
            isinstance(
                keyword.value,
                ast.Name,
            )
            and keyword.value.id
            == var_keyword_name
        ):
            return True

    return False


def call_name(
    call_node: ast.Call,
) -> str | None:
    if isinstance(
        call_node.func,
        ast.Name,
    ):
        return call_node.func.id

    return None


def find_implementation_node(
    tree: ast.Module,
    implementation: dict[str, Any],
) -> (
    ast.FunctionDef
    | ast.AsyncFunctionDef
    | None
):
    qualname = str(
        implementation.get(
            "qualname",
            "",
        )
    ).strip()

    if not qualname:
        return None

    parts = qualname.split(".")

    if len(parts) == 1:
        return find_direct_function(
            tree,
            parts[0],
        )

    if len(parts) == 2:
        class_node = find_class(
            tree,
            parts[0],
        )

        if class_node is None:
            return None

        return find_class_method(
            class_node,
            parts[1],
        )

    return None

def build_current_scope_parent_map(
    function_node: (
        ast.FunctionDef
        | ast.AsyncFunctionDef
    ),
) -> dict[int, ast.AST]:
    """
    为当前函数作用域建立 child -> parent 映射。

    不进入嵌套函数、lambda 或 class，
    避免把内部定义里的 kwargs 使用错误归因
    到当前函数的一次调用上。
    """

    parents: dict[
        int,
        ast.AST,
    ] = {}

    stack: list[ast.AST] = list(
        function_node.body
    )

    nested_scope_types = (
        ast.FunctionDef,
        ast.AsyncFunctionDef,
        ast.Lambda,
        ast.ClassDef,
    )

    while stack:
        node = stack.pop()

        if isinstance(
            node,
            nested_scope_types,
        ):
            continue

        for child in ast.iter_child_nodes(
            node
        ):
            parents[
                id(child)
            ] = node

            if isinstance(
                child,
                nested_scope_types,
            ):
                continue

            stack.append(
                child
            )

    return parents


def literal_string_value(
    node: ast.AST,
) -> str | None:
    if (
        isinstance(
            node,
            ast.Constant,
        )
        and isinstance(
            node.value,
            str,
        )
    ):
        return node.value

    return None


def analyze_var_keyword_usage(
    function_node: (
        ast.FunctionDef
        | ast.AsyncFunctionDef
    ),
    var_keyword_name: str,
    keyword_name: str,
) -> dict[str, Any]:
    """
    分析 **kwargs 在目标函数内部到底怎样使用。

    当前只在证据足够明确时做判断：

    1. kwargs.get("target")
       kwargs.pop("target")
       kwargs.setdefault("target")
       kwargs["target"]
       -> 目标关键字被显式消费。

    2. foo(**kwargs)
       -> kwargs 被继续转发，当前层不能结束判断。

    3. kwargs 只访问其他固定字符串键，
       而目标键从未出现、也没有继续转发或动态使用
       -> 目标关键字会被吞掉但没有语义作用。

    4. kwargs.items()、for x in kwargs、
       kwargs.get(variable) 等动态模式
       -> 保守 unknown。
    """

    parent_map = (
        build_current_scope_parent_map(
            function_node
        )
    )

    literal_accesses: list[
        dict[str, Any]
    ] = []

    forwarding_uses: list[
        dict[str, Any]
    ] = []

    dynamic_uses: list[
        dict[str, Any]
    ] = []

    stack: list[ast.AST] = list(
        function_node.body
    )

    nested_scope_types = (
        ast.FunctionDef,
        ast.AsyncFunctionDef,
        ast.Lambda,
        ast.ClassDef,
    )

    nodes: list[ast.AST] = []

    while stack:
        node = stack.pop()

        if isinstance(
            node,
            nested_scope_types,
        ):
            continue

        nodes.append(
            node
        )

        for child in ast.iter_child_nodes(
            node
        ):
            if isinstance(
                child,
                nested_scope_types,
            ):
                continue

            stack.append(
                child
            )

    for node in nodes:
        if not (
            isinstance(
                node,
                ast.Name,
            )
            and node.id
            == var_keyword_name
        ):
            continue

        parent = parent_map.get(
            id(node)
        )

        # ------------------------------------------
        # kwargs.get("x")
        # kwargs.pop("x")
        # kwargs.setdefault("x")
        # ------------------------------------------

        if (
            isinstance(
                parent,
                ast.Attribute,
            )
            and parent.value
            is node
        ):
            grandparent = parent_map.get(
                id(parent)
            )

            if (
                isinstance(
                    grandparent,
                    ast.Call,
                )
                and grandparent.func
                is parent
                and parent.attr
                in {
                    "get",
                    "pop",
                    "setdefault",
                }
            ):
                if not grandparent.args:
                    dynamic_uses.append(
                        {
                            "line":
                                getattr(
                                    grandparent,
                                    "lineno",
                                    None,
                                ),

                            "kind":
                                "mapping_method_without_key",

                            "method":
                                parent.attr,
                        }
                    )

                    continue

                literal_key = (
                    literal_string_value(
                        grandparent.args[0]
                    )
                )

                if literal_key is None:
                    dynamic_uses.append(
                        {
                            "line":
                                getattr(
                                    grandparent,
                                    "lineno",
                                    None,
                                ),

                            "kind":
                                "dynamic_mapping_key",

                            "method":
                                parent.attr,
                        }
                    )

                    continue

                literal_accesses.append(
                    {
                        "line":
                            getattr(
                                grandparent,
                                "lineno",
                                None,
                            ),

                        "kind":
                            "mapping_method",

                        "method":
                            parent.attr,

                        "key":
                            literal_key,

                        "is_target_keyword":
                            (
                                literal_key
                                == keyword_name
                            ),
                    }
                )

                continue

            # kwargs.items() / kwargs.keys() /
            # kwargs.update(...) / 其他动态对象使用。
            dynamic_uses.append(
                {
                    "line":
                        getattr(
                            parent,
                            "lineno",
                            None,
                        ),

                    "kind":
                        "dynamic_attribute_usage",

                    "attribute":
                        parent.attr,
                }
            )

            continue

        # ------------------------------------------
        # kwargs["x"]
        # ------------------------------------------

        if (
            isinstance(
                parent,
                ast.Subscript,
            )
            and parent.value
            is node
        ):
            literal_key = (
                literal_string_value(
                    parent.slice
                )
            )

            if literal_key is None:
                dynamic_uses.append(
                    {
                        "line":
                            getattr(
                                parent,
                                "lineno",
                                None,
                            ),

                        "kind":
                            "dynamic_subscript_key",
                    }
                )

                continue

            literal_accesses.append(
                {
                    "line":
                        getattr(
                            parent,
                            "lineno",
                            None,
                        ),

                    "kind":
                        "subscript",

                    "method":
                        None,

                    "key":
                        literal_key,

                    "is_target_keyword":
                        (
                            literal_key
                            == keyword_name
                        ),
                }
            )

            continue

        # ------------------------------------------
        # foo(**kwargs)
        # ------------------------------------------

        if (
            isinstance(
                parent,
                ast.keyword,
            )
            and parent.arg is None
            and parent.value
            is node
        ):
            grandparent = parent_map.get(
                id(parent)
            )

            forwarding_uses.append(
                {
                    "line":
                        getattr(
                            grandparent,
                            "lineno",
                            None,
                        ),

                    "kind":
                        "var_keyword_forwarding",
                }
            )

            continue

        # ------------------------------------------
        # 其他无法精确解释的 kwargs 使用。
        #
        # 比如：
        #   for key in kwargs
        #   len(kwargs)
        #   dict(kwargs)
        #   helper(kwargs)
        # ------------------------------------------

        dynamic_uses.append(
            {
                "line":
                    getattr(
                        node,
                        "lineno",
                        None,
                    ),

                "kind":
                    "dynamic_var_keyword_usage",

                "parent_type":
                    (
                        type(
                            parent
                        ).__name__
                        if parent
                        is not None
                        else None
                    ),
            }
        )

    target_accesses = [
        row
        for row in literal_accesses
        if row.get(
            "is_target_keyword"
        )
    ]

    other_literal_keys = sorted(
        {
            str(
                row.get(
                    "key"
                )
            )
            for row
            in literal_accesses
            if (
                row.get(
                    "key"
                )
                is not None
                and not row.get(
                    "is_target_keyword"
                )
            )
        }
    )

    return {
        "var_keyword":
            var_keyword_name,

        "target_keyword":
            keyword_name,

        "literal_accesses":
            literal_accesses,

        "target_literal_access_count":
            len(
                target_accesses
            ),

        "target_literal_accessed":
            bool(
                target_accesses
            ),

        "other_literal_keys":
            other_literal_keys,

        "forwarding_use_count":
            len(
                forwarding_uses
            ),

        "forwards_var_keyword":
            bool(
                forwarding_uses
            ),

        "forwarding_uses":
            forwarding_uses,

        "dynamic_use_count":
            len(
                dynamic_uses
            ),

        "has_dynamic_usage":
            bool(
                dynamic_uses
            ),

        "dynamic_uses":
            dynamic_uses,
    }


def classify_callee_keyword_support(
    callee_node: (
        ast.FunctionDef
        | ast.AsyncFunctionDef
    ),
    source: str,
    keyword_name: str,
) -> dict[str, Any]:
    signature = build_signature(
        callee_node,
        source,
    )

    explicit = find_parameter(
        signature,
        keyword_name,
    )

    accepts_var_keyword = bool(
        signature.get(
            "accepts_var_keyword",
            False,
        )
    )

    var_keyword_usage: (
        dict[str, Any]
        | None
    ) = None

    # ----------------------------------------------
    # 最强证据：
    # target keyword 是显式参数。
    # ----------------------------------------------

    if explicit is not None:
        status = "supported"

        reason = (
            "callee_explicit_parameter"
        )

    # ----------------------------------------------
    # 完全没有 **kwargs：
    # 目标关键字无法被接收。
    # ----------------------------------------------

    elif not accepts_var_keyword:
        status = "unsupported"

        reason = (
            "callee_parameter_absent_"
            "and_no_var_keyword"
        )

    else:
        var_keyword_name = str(
            signature.get(
                "var_keyword",
                "",
            )
            or ""
        )

        var_keyword_usage = (
            analyze_var_keyword_usage(
                function_node=
                    callee_node,

                var_keyword_name=
                    var_keyword_name,

                keyword_name=
                    keyword_name,
            )
        )

        # ------------------------------------------
        # **kwargs 被继续整体转发。
        #
        # 当前层不能知道下游是否真正支持，
        # 所以继续保守 unknown。
        # ------------------------------------------

        if var_keyword_usage.get(
            "forwards_var_keyword"
        ):
            status = "unknown"

            reason = (
                "callee_var_keyword_"
                "forwarded"
            )

        # ------------------------------------------
        # 存在动态 kwargs 使用：
        #
        # 例如 kwargs.items()、
        # kwargs.get(variable)、
        # helper(kwargs)。
        #
        # 不能安全证明 target 被忽略。
        # ------------------------------------------

        elif var_keyword_usage.get(
            "has_dynamic_usage"
        ):
            status = "unknown"

            reason = (
                "callee_var_keyword_"
                "dynamic_usage"
            )

        # ------------------------------------------
        # 函数体明确读取目标键。
        #
        # 这说明目标 keyword 不只是被 **kwargs
        # 语法接收，而是真正被该函数识别。
        # ------------------------------------------

        elif var_keyword_usage.get(
            "target_literal_accessed"
        ):
            status = "supported"

            reason = (
                "callee_var_keyword_"
                "target_consumed"
            )

        # ------------------------------------------
        # 最关键的新情况：
        #
        # **kwargs 存在，但：
        # - 没有继续转发
        # - 没有动态使用
        # - 只读取已知的其他 literal keys
        # - 从未读取 target keyword
        #
        # 因此 target 虽然语法上被吞掉，
        # 但语义上没有任何作用。
        #
        # 对 AVCS API History 来说，
        # 这不是目标参数真正受到支持。
        # ------------------------------------------

        else:
            status = "unsupported"

            reason = (
                "callee_var_keyword_"
                "target_unconsumed"
            )

    return {
        "status":
            status,

        "reason":
            reason,

        "callee":
            callee_node.name,

        "callee_line":
            callee_node.lineno,

        "keyword":
            keyword_name,

        "keyword_explicit":
            explicit is not None,

        "accepts_var_keyword":
            accepts_var_keyword,

        "signature":
            signature,

        "var_keyword_usage":
            var_keyword_usage,
    }


def analyze_keyword_forwarding(
    api_calls_path: Path,
    public_symbol_path: Path,
    source_index_path: Path,
    api_symbol: str,
    keyword_name: str,
) -> dict[str, Any]:
    api_calls = read_json(
        api_calls_path
    )

    public_evidence = read_json(
        public_symbol_path
    )

    source_index = read_json(
        source_index_path
    )

    observed_call = find_api_call(
        api_calls,
        api_symbol,
    )

    call_shape = observed_call.get(
        "call_shape",
        {},
    )

    if not isinstance(
        call_shape,
        dict,
    ):
        raise RuntimeError(
            "observed call has no "
            "valid call_shape"
        )

    observed_keywords = (
        call_shape.get(
            "keyword_arg_names",
            [],
        )
    )

    if (
        not isinstance(
            observed_keywords,
            list,
        )
        or keyword_name
        not in observed_keywords
    ):
        return {
            "schema_version":
                SCHEMA_VERSION,

            "distribution":
                public_evidence.get(
                    "distribution",
                    "",
                ),

            "version":
                public_evidence.get(
                    "version",
                    "",
                ),

            "api_symbol":
                api_symbol,

            "keyword":
                keyword_name,

            "status":
                "not_observed",

            "support_status":
                "not_applicable",

            "support_reason":
                "keyword_not_observed_"
                "in_generated_call",
        }

    if (
        public_evidence.get(
            "status"
        )
        != "resolved"
    ):
        return {
            "schema_version":
                SCHEMA_VERSION,

            "distribution":
                public_evidence.get(
                    "distribution",
                    "",
                ),

            "version":
                public_evidence.get(
                    "version",
                    "",
                ),

            "api_symbol":
                api_symbol,

            "keyword":
                keyword_name,

            "status":
                "public_symbol_unresolved",

            "support_status":
                "unknown",

            "support_reason":
                "public_symbol_unresolved",
        }

    public_signature = (
        public_evidence.get(
            "public_signature"
        )
    )

    if not isinstance(
        public_signature,
        dict,
    ):
        raise RuntimeError(
            "public symbol evidence "
            "has no public_signature"
        )

    explicit_parameter = (
        find_parameter(
            public_signature,
            keyword_name,
        )
    )

    # 最简单情况：
    # public API 已经显式声明该关键字。
    if explicit_parameter is not None:
        return {
            "schema_version":
                SCHEMA_VERSION,

            "distribution":
                public_evidence.get(
                    "distribution",
                    "",
                ),

            "normalized_distribution":
                public_evidence.get(
                    "normalized_distribution",
                    "",
                ),

            "version":
                public_evidence.get(
                    "version",
                    "",
                ),

            "api_symbol":
                api_symbol,

            "keyword":
                keyword_name,

            "status":
                "resolved",

            "support_status":
                "supported",

            "support_reason":
                "public_explicit_parameter",

            "parameter_evidence":
                explicit_parameter,

            "observed_call":
                observed_call,

            "forwarding_evidence":
                [],
        }

    var_keyword_name = str(
        public_signature.get(
            "var_keyword",
            "",
        )
        or ""
    )

    if not var_keyword_name:
        return {
            "schema_version":
                SCHEMA_VERSION,

            "distribution":
                public_evidence.get(
                    "distribution",
                    "",
                ),

            "normalized_distribution":
                public_evidence.get(
                    "normalized_distribution",
                    "",
                ),

            "version":
                public_evidence.get(
                    "version",
                    "",
                ),

            "api_symbol":
                api_symbol,

            "keyword":
                keyword_name,

            "status":
                "resolved",

            "support_status":
                "unsupported",

            "support_reason":
                "public_parameter_absent_"
                "and_no_var_keyword",

            "observed_call":
                observed_call,

            "forwarding_evidence":
                [],
        }

    implementation = (
        public_evidence.get(
            "implementation"
        )
    )

    if not isinstance(
        implementation,
        dict,
    ):
        raise RuntimeError(
            "public symbol evidence "
            "has no implementation"
        )

    implementation_module = str(
        implementation.get(
            "module",
            "",
        )
    ).strip()

    if not implementation_module:
        raise RuntimeError(
            "implementation module missing"
        )

    (
        _,
        source,
        tree,
    ) = load_module_source(
        source_index,
        implementation_module,
    )

    implementation_node = (
        find_implementation_node(
            tree,
            implementation,
        )
    )

    if implementation_node is None:
        return {
            "schema_version":
                SCHEMA_VERSION,

            "distribution":
                public_evidence.get(
                    "distribution",
                    "",
                ),

            "version":
                public_evidence.get(
                    "version",
                    "",
                ),

            "api_symbol":
                api_symbol,

            "keyword":
                keyword_name,

            "status":
                "implementation_unresolved",

            "support_status":
                "unknown",

            "support_reason":
                "implementation_node_unresolved",
        }

    bindings = bind_public_arguments(
        call_shape,
        public_signature,
    )

    definite_calls = (
        collect_definite_calls(
            implementation_node.body,
            bindings,
        )
    )

    forwarding_rows: list[
        dict[str, Any]
    ] = []

    for (
        call_node,
        path,
    ) in definite_calls:
        if not call_forwards_var_keyword(
            call_node,
            var_keyword_name,
        ):
            continue

        callee_name = call_name(
            call_node
        )

        if callee_name is None:
            forwarding_rows.append(
                {
                    "line":
                        getattr(
                            call_node,
                            "lineno",
                            None,
                        ),

                    "path":
                        path,

                    "callee":
                        None,

                    "status":
                        "unknown",

                    "reason":
                        "dynamic_or_attribute_"
                        "callee_unresolved",
                }
            )
            continue

        callee_node = (
            find_direct_function(
                tree,
                callee_name,
            )
        )

        if callee_node is None:
            forwarding_rows.append(
                {
                    "line":
                        getattr(
                            call_node,
                            "lineno",
                            None,
                        ),

                    "path":
                        path,

                    "callee":
                        callee_name,

                    "status":
                        "unknown",

                    "reason":
                        "same_module_callee_"
                        "unresolved",
                }
            )
            continue

        callee_support = (
            classify_callee_keyword_support(
                callee_node,
                source,
                keyword_name,
            )
        )

        forwarding_rows.append(
            {
                "line":
                    getattr(
                        call_node,
                        "lineno",
                        None,
                    ),

                "path":
                    path,

                **callee_support,
            }
        )

    unsupported_rows = [
        row
        for row in forwarding_rows
        if row.get(
            "status"
        )
        == "unsupported"
    ]

    unknown_rows = [
        row
        for row in forwarding_rows
        if row.get(
            "status"
        )
        == "unknown"
    ]

    supported_rows = [
        row
        for row in forwarding_rows
        if row.get(
            "status"
        )
        == "supported"
    ]

    ignored_rows = [
        row
        for row in unsupported_rows
        if row.get(
            "reason"
        )
           == (
               "callee_var_keyword_"
               "target_unconsumed"
           )
    ]

    rejecting_rows = [
        row
        for row in unsupported_rows
        if row.get(
            "reason"
        )
           != (
               "callee_var_keyword_"
               "target_unconsumed"
           )
    ]

    if rejecting_rows:
        support_status = (
            "unsupported"
        )

        support_reason = (
            "definite_forwarding_to_"
            "callee_rejecting_keyword"
        )

        assessment = (
            "unsupported_for_"
            "observed_call_shape"
        )

    elif ignored_rows:
        support_status = (
            "unsupported"
        )

        support_reason = (
            "definite_forwarding_to_"
            "callee_ignoring_keyword"
        )

        assessment = (
            "target_keyword_semantically_"
            "ignored_for_observed_call_shape"
        )

    elif unknown_rows:
        support_status = "unknown"

        support_reason = (
            "forwarding_target_"
            "support_unresolved"
        )

        assessment = (
            "requires_further_"
            "forwarding_analysis"
        )

    elif supported_rows:
        support_status = "supported"

        support_reason = (
            "definite_forwarding_to_"
            "callee_accepting_keyword"
        )

        assessment = (
            "supported_for_"
            "observed_call_shape"
        )

    else:
        support_status = "unknown"

        support_reason = (
            "no_definite_keyword_"
            "forwarding_observed"
        )

        assessment = (
            "requires_further_"
            "body_analysis"
        )

    return {
        "schema_version":
            SCHEMA_VERSION,

        "distribution":
            public_evidence.get(
                "distribution",
                "",
            ),

        "normalized_distribution":
            public_evidence.get(
                "normalized_distribution",
                "",
            ),

        "version":
            public_evidence.get(
                "version",
                "",
            ),

        "api_symbol":
            api_symbol,

        "keyword":
            keyword_name,

        "status":
            "resolved"
            if support_status
            != "unknown"
            else "partial",

        "support_status":
            support_status,

        "support_reason":
            support_reason,

        "assessment":
            assessment,

        "public_parameter_explicit":
            False,

        "public_var_keyword":
            var_keyword_name,

        "argument_bindings":
            bindings,

        "observed_call":
            observed_call,

        "implementation": {
            "module":
                implementation_module,

            "qualname":
                implementation.get(
                    "qualname"
                ),

            "line":
                implementation.get(
                    "line"
                ),
        },

        "definite_call_count":
            len(definite_calls),

        "forwarding_call_count":
            len(forwarding_rows),

        "forwarding_evidence":
            forwarding_rows,
    }


def main() -> None:
    parser = (
        argparse.ArgumentParser(
            description=(
                "Analyze whether an observed "
                "Python API keyword accepted "
                "through **kwargs is definitely "
                "forwarded to a callee that "
                "accepts or rejects it."
            )
        )
    )

    parser.add_argument(
        "--api-calls",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--public-symbol-evidence",
        required=True,
        type=Path,
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
        "--keyword",
        required=True,
    )

    parser.add_argument(
        "--out",
        required=True,
        type=Path,
    )

    args = parser.parse_args()

    result = analyze_keyword_forwarding(
        api_calls_path=
            args.api_calls,

        public_symbol_path=
            args.public_symbol_evidence,

        source_index_path=
            args.source_index,

        api_symbol=
            args.api_symbol.strip(),

        keyword_name=
            args.keyword.strip(),
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
        f"[OK] keyword: "
        f"{result['keyword']}"
    )

    print(
        f"[OK] status: "
        f"{result['status']}"
    )

    print(
        f"[OK] support status: "
        f"{result['support_status']}"
    )

    print(
        f"[OK] support reason: "
        f"{result['support_reason']}"
    )

    if result.get(
        "assessment"
    ):
        print(
            f"[OK] assessment: "
            f"{result['assessment']}"
        )

    print(
        f"[OK] result saved to: "
        f"{args.out}"
    )


if __name__ == "__main__":
    main()