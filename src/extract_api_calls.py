from __future__ import annotations

import argparse
import ast
import json
from python_binding_context_v1 import BindingContexts
from pathlib import Path
from typing import Any
from package_identity_v1 import (
    DEFAULT_POLICY as DEFAULT_IDENTITY_POLICY,
    PackageIdentityService,
)

ROOT = Path(__file__).resolve().parents[1]


def repo_relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return path.name

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
    receiver 在可信词法作用域中的最近一次直接赋值。

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
        < call_line or (
            int(event.get("assignment_line", 0) or 0) == call_line
            and event.get("assignment_column") is not None
            and int(event["assignment_column"]) <= call_node.col_offset
        )
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
    # Arguments can mutate a binding after the callable was evaluated.
    # Keep the callable identity, but do not invent symbols for later values.
    mutated = {item.target.id for argument in [*call_node.args,
               *[keyword.value for keyword in call_node.keywords]]
               for item in ast.walk(argument) if isinstance(item, ast.NamedExpr)
               and isinstance(item.target, ast.Name)}
    module_bindings = {name: value for name, value in module_bindings.items() if name not in mutated}
    symbol_bindings = {name: value for name, value in symbol_bindings.items() if name not in mutated}
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
    mapping_path: Path | None = None,
    sample_id: str | None = None,
    identity_policy_path: Path = DEFAULT_IDENTITY_POLICY,
    project_root: Path | None = None,
) -> dict[str, Any]:
    """从单个 Python 文件中抽取高置信 API 调用。"""
    identity_service = PackageIdentityService(
        policy_path=identity_policy_path,
        project_root=project_root,
    )
    raw_bytes = code_path.read_bytes()
    try:
        source_code = raw_bytes.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        return {
            "schema_version": "api_call_evidence_v0.1",
            "sample_id": sample_id or code_path.stem,
            "code_file": repo_relative(code_path),
            "parse_status": "decode_error",
            "parse_error": str(exc),
            "identity_policy_version": identity_service.policy_version,
            "api_call_count": 0,
            "api_calls": [],
        }

    try:
        tree = ast.parse(source_code, filename=str(code_path))
    except SyntaxError as exc:
        return {
            "schema_version": "api_call_evidence_v0.1",
            "sample_id": sample_id or code_path.stem,
            "code_file": repo_relative(code_path),
            "parse_status": "syntax_error",
            "parse_error": str(exc),
            "identity_policy_version": identity_service.policy_version,
            "api_call_count": 0,
            "api_calls": [],
        }

    contexts = BindingContexts(tree, resolve_call_symbol, build_call_shape, source_code)

    api_calls: list[dict[str, Any]] = []
    binding_unresolved: list[dict[str, Any]] = []
    dynamic_imports: list[dict[str, Any]] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        dynamic = contexts.dynamic_import(node)
        if dynamic is not None:
            fact = {**dynamic, "location": {"file": repo_relative(code_path),
                    "line": node.lineno, "column": node.col_offset + 1},
                    "call_text": ast.get_source_segment(source_code, node) or ""}
            if dynamic["status"] == "resolved":
                identity = identity_service.resolve(
                    raw_name=dynamic["import_path"].split(".")[0], source_type="import",
                    import_path=dynamic["import_path"],
                )
                fact["package_identity"] = identity.to_dict()
            else:
                binding_unresolved.append({
                    "raw_chain": attribute_chain(node.func), "reason": dynamic["reason"],
                    "candidate_distributions": [], "unresolved_scope": "sample",
                    "requested_module": dynamic["requested_module"],
                    "location": fact["location"],
                })
            dynamic_imports.append(fact)
            continue  # A module loader is dependency evidence, not a package API factory.
        if node in contexts.mutation_calls:
            continue  # Mutation machinery cannot establish a public package API.

        module_bindings, symbol_bindings, call_result_bindings = contexts.for_call(node)

        resolved = contexts.dynamic_api_call(node) or resolve_call_symbol(
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
            candidates = []
            for import_root in contexts.possible_roots(node):
                candidate = identity_service.resolve(raw_name=import_root, source_type="import")
                if candidate.avcs_candidate:
                    candidates.append(candidate.normalized_distribution)
            if candidates:
                binding_unresolved.append({
                    "raw_chain": attribute_chain(node.func),
                    "reason": "lexical_or_temporal_binding_not_proven",
                    "candidate_distributions": sorted(set(candidates)),
                    "location": {"file": repo_relative(code_path),
                                 "line": node.lineno, "column": node.col_offset + 1},
                })
            continue

        import_name, api_symbol, binding_type = resolved
        identity = identity_service.resolve(
            raw_name=import_name,
            source_type="import",
            import_path=api_symbol,
        )
        distribution = identity.distribution

        call_record: dict[
            str,
            Any,
        ] = {
            "import_name":
                import_name,

            "distribution":
                distribution,

            "normalized_distribution":
                identity.normalized_distribution,

            "package_identity":
                identity.to_dict(),

            "api_symbol":
                api_symbol,

            "binding_type":
                binding_type,

            "location": {
                "file":
                    repo_relative(
                        code_path
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
    binding_unresolved.sort(key=lambda row: (row["location"]["line"], row["location"]["column"]))
    dynamic_imports.sort(key=lambda row: (row["location"]["line"], row["location"]["column"]))

    return {
        "schema_version": "api_call_evidence_v0.1",
        "sample_id": sample_id or code_path.stem,
        "code_file": repo_relative(code_path),
        "parse_status": "ok",
        "parse_error": "",
        "identity_policy_version": identity_service.policy_version,
        "api_call_count": len(api_calls),
        "api_calls": api_calls,
        "binding_resolution_policy": "lexical_source_order_v2_dynamic_import_mutation",
        "binding_unresolved": binding_unresolved,
        "dynamic_imports": dynamic_imports,
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
        default=None,
        help="Deprecated compatibility argument; identity uses --identity-policy.",
    )
    parser.add_argument(
        "--identity-policy",
        type=Path,
        default=Path("config/package_identity_policy_v1.json"),
    )
    parser.add_argument("--project-root", type=Path, default=None)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    identity_policy = args.identity_policy
    if not identity_policy.is_absolute():
        identity_policy = Path(__file__).resolve().parents[1] / identity_policy
    project_root = args.project_root
    if project_root is not None and not project_root.is_absolute():
        project_root = Path(__file__).resolve().parents[1] / project_root

    result = extract_api_calls(
        code_path=args.code,
        mapping_path=args.mapping,
        sample_id=args.sample_id,
        identity_policy_path=identity_policy,
        project_root=project_root,
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
