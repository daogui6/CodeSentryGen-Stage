from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
from typing import Any
from normalizer import (
    load_import_mapping,
    map_import_path_to_distribution,
)

def attribute_chain(node: ast.AST) -> str | None:
    """
    将 API 调用节点还原为点分形式。

    例如：
    yaml.safe_load       -> yaml.safe_load
    requests.get         -> requests.get
    """
    if isinstance(node, ast.Name):
        return node.id

    if isinstance(node, ast.Attribute):
        prefix = attribute_chain(node.value)
        if prefix:
            return f"{prefix}.{node.attr}"

    return None


def collect_import_bindings(
    tree: ast.AST,
) -> tuple[dict[str, str], dict[str, str]]:
    """
    收集当前文件中的 import 绑定。

    module_bindings 示例：
    import yaml as y
    y -> yaml

    symbol_bindings 示例：
    from yaml import safe_load as load
    load -> yaml.safe_load
    """
    module_bindings: dict[str, str] = {}
    symbol_bindings: dict[str, str] = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    # import google.cloud.storage as storage
                    # 本地名称 storage 对应完整模块 google.cloud.storage
                    local_name = alias.asname
                    imported_module = alias.name
                else:
                    # import google.cloud.storage
                    # Python 实际绑定到当前作用域的是顶层名称 google
                    local_name = alias.name.split(".")[0]
                    imported_module = local_name

                module_bindings[local_name] = imported_module

        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                if alias.name == "*":
                    continue

                local_name = alias.asname or alias.name
                symbol_bindings[local_name] = f"{node.module}.{alias.name}"

    return module_bindings, symbol_bindings

def collect_module_call_result_bindings(
    tree: ast.AST,
    source_code: str,
    module_bindings: dict[str, str],
    symbol_bindings: dict[str, str],
) -> dict[str, list[dict[str, Any]]]:
    """
    收集模块顶层最直接的：

        x = imported_api(...)

    调用结果绑定。

    例如：

        import urllib3

        http = urllib3.PoolManager(
            retries=0,
        )

    记录：

        http
        -> urllib3.PoolManager

    注意：
    这里仅记录静态可观察的赋值来源，
    不判断这个调用是不是漏洞相关构造器。

    v0 仅处理模块顶层、
    单一 Name 目标的直接赋值。
    """

    if not isinstance(
        tree,
        ast.Module,
    ):
        return {}

    bindings: dict[
        str,
        list[dict[str, Any]],
    ] = {}

    for statement in tree.body:
        target_name: str | None = None
        value: ast.AST | None = None

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
        ):
            target_name = (
                statement.targets[0].id
            )
            value = statement.value

        elif (
            isinstance(
                statement,
                ast.AnnAssign,
            )
            and isinstance(
                statement.target,
                ast.Name,
            )
        ):
            target_name = (
                statement.target.id
            )
            value = statement.value

        if target_name is None:
            continue

        event: dict[str, Any] = {
            "assignment_line":
                getattr(
                    statement,
                    "lineno",
                    None,
                ),

            "producer_import_root":
                None,

            "producer_api_symbol":
                None,

            "producer_binding_type":
                None,

            "producer_call_shape":
                None,
        }

        if isinstance(
            value,
            ast.Call,
        ):
            resolved = resolve_call_symbol(
                value,
                module_bindings=(
                    module_bindings
                ),
                symbol_bindings=(
                    symbol_bindings
                ),
            )

            if resolved is not None:
                (
                    producer_import_root,
                    producer_api_symbol,
                    producer_binding_type,
                ) = resolved

                event[
                    "producer_import_root"
                ] = producer_import_root

                event[
                    "producer_api_symbol"
                ] = producer_api_symbol

                event[
                    "producer_binding_type"
                ] = producer_binding_type

                event[
                    "producer_call_shape"
                ] = build_call_shape(
                    value,
                    source_code=(
                        source_code
                    ),
                    module_bindings=(
                        module_bindings
                    ),
                    symbol_bindings=(
                        symbol_bindings
                    ),
                )

        bindings.setdefault(
            target_name,
            [],
        ).append(
            event
        )

    return bindings


def find_call_result_binding(
    call_node: ast.Call,
    receiver_name: str,
    call_result_bindings: (
        dict[
            str,
            list[dict[str, Any]],
        ]
        | None
    ),
) -> dict[str, Any] | None:
    """
    找到某次方法调用之前，
    receiver 最近一次模块顶层直接赋值。

    例如：

        http = urllib3.PoolManager(...)
        http.request(...)

    对 http.request(...) 返回 http 的
    PoolManager 来源证据。
    """

    if not call_result_bindings:
        return None

    events = (
        call_result_bindings.get(
            receiver_name,
            [],
        )
    )

    call_line = int(
        getattr(
            call_node,
            "lineno",
            0,
        )
        or 0
    )

    candidates = [
        event
        for event in events
        if int(
            event.get(
                "assignment_line",
                0,
            )
            or 0
        )
        < call_line
    ]

    if not candidates:
        return None

    return max(
        candidates,
        key=lambda event: int(
            event.get(
                "assignment_line",
                0,
            )
            or 0
        ),
    )



def resolve_call_symbol(
    call_node: ast.Call,
    module_bindings: dict[str, str],
    symbol_bindings: dict[str, str],
    call_result_bindings: (
        dict[
            str,
            list[dict[str, Any]],
        ]
        | None
    ) = None,
) -> tuple[str, str, str] | None:
    """
    将代码中的调用还原为完整 API symbol。

    返回：
    import 根名称、完整 API symbol、绑定类型。
    """
    raw_chain = attribute_chain(call_node.func)
    if not raw_chain:
        return None

    parts = raw_chain.split(".")
    local_root = parts[0]

    if local_root in module_bindings:
        imported_module = module_bindings[local_root]
        suffix = parts[1:]

        resolved_symbol = ".".join([imported_module, *suffix])
        import_root = imported_module.split(".")[0]

        return import_root, resolved_symbol, "module_import"

    if local_root in symbol_bindings:
        imported_symbol = symbol_bindings[local_root]
        suffix = parts[1:]

        resolved_symbol = ".".join(
            [
                imported_symbol,
                *suffix,
            ]
        )
        import_root = (
            imported_symbol
            .split(".")[0]
        )

        return (
            import_root,
            resolved_symbol,
            "from_import",
        )

    if (
            call_result_bindings
            and len(parts) > 1
    ):
        receiver_binding = (
            find_call_result_binding(
                call_node=call_node,
                receiver_name=local_root,
                call_result_bindings=(
                    call_result_bindings
                ),
            )
        )

        if receiver_binding is not None:
            producer_api_symbol = str(
                receiver_binding.get(
                    "producer_api_symbol",
                    "",
                )
                or ""
            ).strip()

            producer_import_root = str(
                receiver_binding.get(
                    "producer_import_root",
                    "",
                )
                or ""
            ).strip()

            if (
                    producer_api_symbol
                    and producer_import_root
            ):
                suffix = parts[1:]

                resolved_symbol = ".".join(
                    [
                        producer_api_symbol,
                        *suffix,
                    ]
                )

                return (
                    producer_import_root,
                    resolved_symbol,
                    "call_result_method",
                )

    return None

def resolve_expression_symbol(
    node: ast.AST,
    module_bindings: dict[str, str],
    symbol_bindings: dict[str, str],
) -> str | None:
    """
    尝试把一个参数表达式解析为完整导入符号。

    例如：

        import yaml
        yaml.FullLoader
        -> yaml.FullLoader

        import yaml as y
        y.FullLoader
        -> yaml.FullLoader

        from yaml import SafeLoader as SL
        SL
        -> yaml.SafeLoader

    对 False、字符串、函数调用等无法稳定解析为
    导入符号的表达式返回 None。
    """
    raw_chain = attribute_chain(node)

    if not raw_chain:
        return None

    parts = raw_chain.split(".")
    local_root = parts[0]

    if local_root in module_bindings:
        imported_module = (
            module_bindings[
                local_root
            ]
        )

        suffix = parts[1:]

        return ".".join(
            [
                imported_module,
                *suffix,
            ]
        )

    if local_root in symbol_bindings:
        imported_symbol = (
            symbol_bindings[
                local_root
            ]
        )

        suffix = parts[1:]

        return ".".join(
            [
                imported_symbol,
                *suffix,
            ]
        )

    return None

def resolve_literal_value(
    node: ast.AST,
) -> tuple[bool, Any]:
    """
    尝试解析简单 Python literal 参数值。

    当前只处理 ast.Constant，例如：

        True
        False
        None
        "text"
        123
        1.5

    返回：
        (是否成功解析, literal 值)

    不解析变量、函数调用、属性访问等表达式，
    避免把不确定值猜成确定值。
    """
    if not isinstance(
        node,
        ast.Constant,
    ):
        return False, None

    value = node.value

    if (
        value is None
        or isinstance(
            value,
            (
                bool,
                int,
                float,
                str,
            ),
        )
    ):
        return True, value

    return False, None

def build_call_shape(
    call_node: ast.Call,
    source_code: str,
    module_bindings: dict[str, str],
    symbol_bindings: dict[str, str],
) -> dict[str, Any]:
    """
    记录调用的参数形态以及可解析的参数值。

    关键字参数示例：

        yaml.load(
            data,
            Loader=yaml.SafeLoader,
        )

        -> keyword_arg_values:
           {
               "Loader": {
                   "source_text": "yaml.SafeLoader",
                   "resolved_symbol": "yaml.SafeLoader"
               }
           }

    位置参数示例：

        requests.get(
            "http://example.com"
        )

        -> positional_arg_values:
           [
               {
                   "position": 0,
                   "source_text": "\"http://example.com\"",
                   "resolved_symbol": None,
                   "literal_value": "http://example.com"
               }
           ]

    extractor 这里只记录静态可观察事实，
    不在这里加入任何漏洞语义。

    对变量、动态表达式等无法静态确认的值，
    不猜测 literal_value。
    """
    explicit_positional_arg_count = sum(
        not isinstance(
            argument,
            ast.Starred,
        )
        for argument in call_node.args
    )

    positional_arg_values: list[
        dict[str, Any]
    ] = []

    explicit_position = 0

    for argument in call_node.args:
        if isinstance(
            argument,
            ast.Starred,
        ):
            continue

        source_text = (
            ast.get_source_segment(
                source_code,
                argument,
            )
            or ""
        )

        resolved_symbol = (
            resolve_expression_symbol(
                argument,
                module_bindings=(
                    module_bindings
                ),
                symbol_bindings=(
                    symbol_bindings
                ),
            )
        )

        literal_resolved, literal_value = (
            resolve_literal_value(
                argument
            )
        )

        resolved_call_symbol: (
            str | None
        ) = None

        if isinstance(
            argument,
            ast.Call,
        ):
            resolved_call = (
                resolve_call_symbol(
                    argument,
                    module_bindings=(
                        module_bindings
                    ),
                    symbol_bindings=(
                        symbol_bindings
                    ),
                )
            )

            if resolved_call is not None:
                (
                    _,
                    resolved_call_symbol,
                    _,
                ) = resolved_call

        value_evidence: dict[
            str,
            Any,
        ] = {
            "position":
                explicit_position,

            "source_text":
                source_text,

            "resolved_symbol":
                resolved_symbol,
        }

        if literal_resolved:
            value_evidence[
                "literal_value"
            ] = literal_value

        if (
            resolved_call_symbol
            is not None
        ):
            value_evidence[
                "resolved_call_symbol"
            ] = resolved_call_symbol

        positional_arg_values.append(
            value_evidence
        )

        explicit_position += 1

    keyword_arg_names = sorted(
        keyword.arg
        for keyword in call_node.keywords
        if keyword.arg is not None
    )

    keyword_arg_values: dict[
        str,
        dict[str, Any],
    ] = {}

    for keyword in call_node.keywords:
        if keyword.arg is None:
            continue

        source_text = (
            ast.get_source_segment(
                source_code,
                keyword.value,
            )
            or ""
        )

        resolved_symbol = (
            resolve_expression_symbol(
                keyword.value,
                module_bindings=(
                    module_bindings
                ),
                symbol_bindings=(
                    symbol_bindings
                ),
            )
        )

        literal_resolved, literal_value = (
            resolve_literal_value(
                keyword.value
            )
        )

        resolved_call_symbol: (
            str | None
        ) = None

        if isinstance(
            keyword.value,
            ast.Call,
        ):
            resolved_call = (
                resolve_call_symbol(
                    keyword.value,
                    module_bindings=(
                        module_bindings
                    ),
                    symbol_bindings=(
                        symbol_bindings
                    ),
                )
            )

            if resolved_call is not None:
                (
                    _,
                    resolved_call_symbol,
                    _,
                ) = resolved_call

        value_evidence: dict[
            str,
            Any,
        ] = {
            "source_text":
                source_text,

            "resolved_symbol":
                resolved_symbol,
        }

        if literal_resolved:
            value_evidence[
                "literal_value"
            ] = literal_value

        if (
            resolved_call_symbol
            is not None
        ):
            value_evidence[
                "resolved_call_symbol"
            ] = resolved_call_symbol

        keyword_arg_values[
            keyword.arg
        ] = value_evidence

    return {
        "explicit_positional_arg_count":
            explicit_positional_arg_count,

        "positional_arg_values":
            positional_arg_values,

        "keyword_arg_names":
            keyword_arg_names,

        "keyword_arg_values":
            keyword_arg_values,

        "has_star_args":
            any(
                isinstance(
                    argument,
                    ast.Starred,
                )
                for argument
                in call_node.args
            ),

        "has_star_kwargs":
            any(
                keyword.arg is None
                for keyword
                in call_node.keywords
            ),
    }

def extract_api_calls(
    code_path: Path,
    mapping_path: Path,
    sample_id: str | None = None,
) -> dict[str, Any]:
    """从单个 Python 文件中抽取高置信 API 调用。"""
    source_code = code_path.read_text(
        encoding="utf-8-sig",
        errors="ignore",
    )
    mapping = load_import_mapping(mapping_path)

    try:
        tree = ast.parse(source_code, filename=str(code_path))
    except SyntaxError as exc:
        return {
            "schema_version": "api_call_evidence_v0.1",
            "sample_id": sample_id or code_path.stem,
            "code_file": str(code_path).replace("\\", "/"),
            "parse_status": "syntax_error",
            "parse_error": str(exc),
            "api_calls": [],
        }

    module_bindings, symbol_bindings = (
        collect_import_bindings(
            tree
        )
    )

    call_result_bindings = (
        collect_module_call_result_bindings(
            tree=tree,
            source_code=(
                source_code
            ),
            module_bindings=(
                module_bindings
            ),
            symbol_bindings=(
                symbol_bindings
            ),
        )
    )

    api_calls: list[dict[str, Any]] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        resolved = resolve_call_symbol(
            node,
            module_bindings=(
                module_bindings
            ),
            symbol_bindings=(
                symbol_bindings
            ),
            call_result_bindings=(
                call_result_bindings
            ),
        )
        if resolved is None:
            continue

        import_name, api_symbol, binding_type = resolved
        distribution = map_import_path_to_distribution(
            raw_name=import_name,
            import_path=api_symbol,
            mapping=mapping,
        )

        call_record: dict[
            str,
            Any,
        ] = {
            "import_name":
                import_name,

            "distribution":
                distribution,

            "api_symbol":
                api_symbol,

            "binding_type":
                binding_type,

            "location": {
                "file":
                    str(
                        code_path
                    ).replace(
                        "\\",
                        "/",
                    ),

                "line":
                    node.lineno,

                "column":
                    node.col_offset + 1,
            },

            "call_text":
                (
                        ast.get_source_segment(
                            source_code,
                            node,
                        )
                        or ""
                ),

            "call_shape":
                build_call_shape(
                    node,
                    source_code=(
                        source_code
                    ),
                    module_bindings=(
                        module_bindings
                    ),
                    symbol_bindings=(
                        symbol_bindings
                    ),
                ),
        }

        if (
                binding_type
                == "call_result_method"
        ):
            raw_chain = (
                attribute_chain(
                    node.func
                )
            )

            receiver_name = (
                raw_chain.split(".")[0]
                if raw_chain
                else ""
            )

            receiver_binding = (
                find_call_result_binding(
                    call_node=node,
                    receiver_name=(
                        receiver_name
                    ),
                    call_result_bindings=(
                        call_result_bindings
                    ),
                )
            )

            if receiver_binding is not None:
                call_record[
                    "receiver_provenance"
                ] = {
                    "receiver_name":
                        receiver_name,

                    "assignment_line":
                        receiver_binding.get(
                            "assignment_line"
                        ),

                    "producer_api_symbol":
                        receiver_binding.get(
                            "producer_api_symbol"
                        ),

                    "producer_binding_type":
                        receiver_binding.get(
                            "producer_binding_type"
                        ),

                    "producer_call_shape":
                        receiver_binding.get(
                            "producer_call_shape"
                        ),
                }

        api_calls.append(
            call_record
        )

    api_calls.sort(
        key=lambda row: (
            row["location"]["line"],
            row["location"]["column"],
            row["api_symbol"],
        )
    )

    return {
        "schema_version": "api_call_evidence_v0.1",
        "sample_id": sample_id or code_path.stem,
        "code_file": str(code_path).replace("\\", "/"),
        "parse_status": "ok",
        "parse_error": "",
        "api_call_count": len(api_calls),
        "api_calls": api_calls,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract high-confidence Python API calls for AVCS."
    )
    parser.add_argument("--code", required=True, type=Path)
    parser.add_argument("--sample-id")
    parser.add_argument(
        "--mapping",
        type=Path,
        default=Path("config/import_mapping.json"),
    )
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    result = extract_api_calls(
        code_path=args.code,
        mapping_path=args.mapping,
        sample_id=args.sample_id,
    )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        json.dumps(result, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print(f"[OK] parse status: {result['parse_status']}")
    print(f"[OK] API calls: {len(result['api_calls'])}")
    print(f"[OK] result saved to: {args.out}")


if __name__ == "__main__":
    main()