from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


SCHEMA_VERSION = (
    "avcs_python_api_symbol_release_history_refined_v0.1"
)


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(
        path.read_text(encoding="utf-8")
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


def load_module_names(
    source_index_path: Path,
) -> set[str]:
    source_index = read_json(
        source_index_path
    )

    result: set[str] = set()

    for item in source_index.get(
        "python_sources",
        [],
    ):
        if not isinstance(item, dict):
            continue

        module = str(
            item.get("module", "")
        ).strip()

        if module:
            result.add(module)

    return result


def derive_exact_zero_arg_call_shape(
    signature: dict[str, Any] | None,
) -> dict[str, Any] | None:
    """
    当前只自动编译最保守的一类 call shape：

        f()

    即：
    - 没有显式参数；
    - 不接受 *args；
    - 不接受 **kwargs。

    其他更复杂 signature 暂时不自动编译，
    避免扩大当前自动化声明边界。
    """

    if not isinstance(signature, dict):
        return None

    parameters = signature.get(
        "parameters",
        [],
    )

    if not isinstance(parameters, list):
        return None

    if parameters:
        return None

    if bool(
        signature.get(
            "accepts_var_positional",
            False,
        )
    ):
        return None

    if bool(
        signature.get(
            "accepts_var_keyword",
            False,
        )
    ):
        return None

    return {
        "kind":
            "exact_zero_argument_call",

        "required_positional_args_min":
            0,

        "required_positional_args_max":
            0,

        "required_keyword_args":
            [],

        "supported_keyword_args":
            [],

        "forbidden_keyword_args":
            [],

        "accepts_var_positional":
            False,

        "accepts_var_keyword":
            False,
    }


def classify_release(
    batch: dict[str, Any],
    record: dict[str, Any],
) -> dict[str, Any]:
    api_symbol = str(
        batch.get("api_symbol", "")
    ).strip()

    version = str(
        record.get("version", "")
    ).strip()

    source_status = str(
        record.get(
            "source_index_status",
            "",
        )
    ).strip()

    public_status = str(
        record.get(
            "public_symbol_status",
            "",
        )
    ).strip()

    result: dict[str, Any] = {
        "version": version,
        "api_symbol": api_symbol,
        "support_target":
            "api_symbol_presence",
        "public_symbol_status":
            public_status,
        "source_index_status":
            source_status,
        "analysis_mode":
            "public_symbol_presence",
        "support_status":
            "unknown",
        "support_reason":
            None,

        # 保留这些兼容字段，
        # 方便后面的 candidate compiler
        # 继续消费 records。
        "parameter_explicit":
            None,
        "accepts_var_keyword":
            None,

        "expected_public_module":
            None,
        "expected_public_module_present":
            None,
        "call_shape_status":
            "not_applicable",

        "call_shape":
            None,
    }

    # 源码索引本身失败时，
    # 不能把解析失败当成 API 不存在。
    if source_status != "resolved":
        result["support_reason"] = (
            "source_index_unresolved"
        )
        return result

    # API 已经成功解析：
    # 可以直接确认该 release 支持此 symbol。
    if public_status == "resolved":
        result["support_status"] = (
            "supported"
        )

        result["support_reason"] = (
            "public_symbol_resolved"
        )



        call_shape = (
            derive_exact_zero_arg_call_shape(
                record.get(
                    "public_signature"
                )
            )
        )

        if call_shape is not None:
            result["call_shape_status"] = (
                "resolved"
            )

            result["call_shape"] = (
                call_shape
            )
        else:
            result["call_shape_status"] = (
                "not_compiled"
            )

        return result

    # resolver 已经观察到目标 member
    # 由顶层 assignment 创建，
    # 只是暂时无法进一步解析其实现或签名。
    #
    # 对当前 presence-history 阶段来说，
    # 这足以确认该 release 中 symbol 存在。
    if (
        public_status
        == "assignment_target_unresolved"
    ):
        result["support_status"] = (
            "supported"
        )

        result["support_reason"] = (
            "public_symbol_assignment_present"
        )

        result["call_shape_status"] = (
            "not_compiled"
        )

        return result

    # module 已经存在，
    # resolver 明确找不到目标 member。
    if public_status == "member_not_found":
        result["support_status"] = (
            "unsupported"
        )
        result["support_reason"] = (
            "public_member_not_found"
        )
        return result

    # 对 public_module_unresolved
    # 再检查真实 source index。
    if (
        public_status
        == "public_module_unresolved"
    ):
        if "." not in api_symbol:
            result["support_reason"] = (
                "expected_module_unknown"
            )
            return result

        expected_module = (
            api_symbol.rsplit(".", 1)[0]
        )

        result[
            "expected_public_module"
        ] = expected_module

        source_index_text = str(
            record.get(
                "source_index_file",
                "",
            )
        ).strip()

        if not source_index_text:
            result["support_reason"] = (
                "source_index_file_missing"
            )
            return result

        source_index_path = Path(
            source_index_text
        )

        if not source_index_path.exists():
            result["support_reason"] = (
                "source_index_file_missing"
            )
            return result

        module_names = load_module_names(
            source_index_path
        )

        module_present = (
            expected_module
            in module_names
        )

        result[
            "expected_public_module_present"
        ] = module_present

        if not module_present:
            result["support_status"] = (
                "unsupported"
            )
            result["support_reason"] = (
                "public_module_absent_"
                "from_source_index"
            )
            return result

        # resolver 说 module unresolved，
        # 但 source index 又说 module 存在，
        # 这种矛盾情况必须保守留下 unknown。
        result["support_reason"] = (
            "resolver_source_index_"
            "inconsistency"
        )
        return result

    result["support_reason"] = (
        "unhandled_public_symbol_status"
    )

    return result


def summarize(
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    supported = [
        row
        for row in records
        if row.get("support_status")
        == "supported"
    ]

    supported_count = len(
        supported
    )

    unsupported_count = sum(
        row.get("support_status")
        == "unsupported"
        for row in records
    )

    unknown_count = sum(
        row.get("support_status")
        == "unknown"
        for row in records
    )

    call_shape_resolved = [
        row
        for row in supported
        if (
            row.get("call_shape_status")
            == "resolved"
            and isinstance(
                row.get("call_shape"),
                dict,
            )
        )
    ]

    shape_map: dict[
        str,
        dict[str, Any],
    ] = {}

    for row in call_shape_resolved:
        shape = row["call_shape"]

        key = json.dumps(
            shape,
            ensure_ascii=False,
            sort_keys=True,
        )

        shape_map[key] = shape

    call_shape_resolved_count = len(
        call_shape_resolved
    )

    call_shape_unresolved_count = (
        supported_count
        - call_shape_resolved_count
    )

    uniform_supported_call_shape = (
        supported_count > 0
        and call_shape_unresolved_count == 0
        and len(shape_map) == 1
    )

    supported_call_shape = None

    if uniform_supported_call_shape:
        supported_call_shape = next(
            iter(
                shape_map.values()
            )
        )

    return {
        "release_count":
            len(records),

        "supported_count":
            supported_count,

        "unsupported_count":
            unsupported_count,

        "unknown_count":
            unknown_count,

        "call_shape_resolved_count":
            call_shape_resolved_count,

        "call_shape_unresolved_count":
            call_shape_unresolved_count,

        "supported_call_shape_variant_count":
            len(shape_map),

        "uniform_supported_call_shape":
            uniform_supported_call_shape,

        "supported_call_shape":
            supported_call_shape,
    }


def refine_symbol_release_history(
    release_history_batch_path: Path,
) -> dict[str, Any]:
    batch = read_json(
        release_history_batch_path
    )

    records = batch.get(
        "records",
        [],
    )

    if not isinstance(records, list):
        raise RuntimeError(
            "release-history batch has "
            "no valid records list"
        )

    refined_records: list[
        dict[str, Any]
    ] = []

    for index, record in enumerate(
        records,
        start=1,
    ):
        if not isinstance(record, dict):
            continue

        refined = classify_release(
            batch=batch,
            record=record,
        )

        refined_records.append(
            refined
        )

        print(
            f"[RUN] {index}/{len(records)} "
            f"{refined.get('version')} | "
            f"public="
            f"{refined.get('public_symbol_status')} | "
            f"support="
            f"{refined.get('support_status')} | "
            f"reason="
            f"{refined.get('support_reason')}"
        )

    return {
        "schema_version":
            SCHEMA_VERSION,

        "ecosystem":
            batch.get(
                "ecosystem",
                "pypi",
            ),

        "distribution":
            batch.get(
                "distribution",
                "",
            ),

        "normalized_distribution":
            batch.get(
                "normalized_distribution",
                "",
            ),

        "api_symbol":
            batch.get(
                "api_symbol",
                "",
            ),

        "support_target":
            "api_symbol_presence",

        # 暂时保留空字符串，
        # 与 parameter-history candidate
        # 的结构保持兼容。
        "parameter":
            "",

        "release_history_batch_source":
            str(
                release_history_batch_path
            ).replace("\\", "/"),

        **summarize(
            refined_records
        ),

        "records":
            refined_records,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Refine release-level Python "
            "API symbol presence from "
            "historical source evidence."
        )
    )

    parser.add_argument(
        "--release-history-batch",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--out",
        required=True,
        type=Path,
    )

    args = parser.parse_args()

    result = (
        refine_symbol_release_history(
            release_history_batch_path=
                args.release_history_batch,
        )
    )

    write_json(
        args.out,
        result,
    )

    print("")
    print("=" * 60)
    print(
        "API SYMBOL RELEASE HISTORY "
        "REFINEMENT SUMMARY"
    )
    print("=" * 60)
    print(
        "[OK] releases:",
        result["release_count"],
    )
    print(
        "[OK] supported:",
        result["supported_count"],
    )
    print(
        "[OK] unsupported:",
        result["unsupported_count"],
    )
    print(
        "[OK] unknown:",
        result["unknown_count"],
    )
    print(
        "[OK] result saved to:",
        args.out,
    )


if __name__ == "__main__":
    main()