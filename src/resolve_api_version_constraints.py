from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from normalizer import pep503_normalize


def read_json(path: Path) -> dict[str, Any]:
    """读取 JSON 文件。"""
    return json.loads(path.read_text(encoding="utf-8"))


def build_history_index(
    history: dict[str, Any],
) -> dict[tuple[str, str], list[dict[str, Any]]]:
    """
    将 API 历史知识库转换为索引。

    索引键：
        规范化 distribution 名称
        API symbol

    示例：
        ("pyyaml", "yaml.safe_dump")
    """
    index: dict[
        tuple[str, str],
        list[dict[str, Any]],
    ] = {}

    for entry in history.get("entries", []):
        distribution = pep503_normalize(
            str(entry.get("distribution", ""))
        )
        api_symbol = str(entry.get("api_symbol", "")).strip()

        if not distribution or not api_symbol:
            continue

        index.setdefault(
            (distribution, api_symbol),
            [],
        ).append(entry)

    return index


def validate_version_specifier(
    version_specifier: str,
) -> tuple[bool, str]:
    """检查版本约束是否符合 packaging 的格式。"""
    try:
        SpecifierSet(version_specifier)
    except InvalidSpecifier as exc:
        return False, str(exc)

    return True, ""


def match_rule_to_call(
    call: dict[str, Any],
    rule: dict[str, Any],
) -> tuple[bool, list[str]]:
    """
    判断一个 API 历史规则是否适用于当前调用形态。

    当前检查：
        位置参数数量
        必需关键字参数
        支持的关键字参数
        禁止的关键字参数
    """
    reasons: list[str] = []

    call_shape = call.get("call_shape", {})

    if call_shape.get("has_star_args"):
        reasons.append(
            "call uses *args, so positional argument count is unresolved"
        )

    if call_shape.get("has_star_kwargs"):
        reasons.append(
            "call uses **kwargs, so keyword arguments are unresolved"
        )

    if reasons:
        return False, reasons

    positional_count = int(
        call_shape.get(
            "explicit_positional_arg_count",
            0,
        )
    )

    minimum = int(
        rule.get(
            "required_positional_args_min",
            0,
        )
    )

    maximum_raw = rule.get(
        "required_positional_args_max"
    )

    maximum = (
        int(maximum_raw)
        if maximum_raw is not None
        else None
    )

    if positional_count < minimum:
        reasons.append(
            f"positional argument count {positional_count} "
            f"is lower than required minimum {minimum}"
        )

    if maximum is not None and positional_count > maximum:
        reasons.append(
            f"positional argument count {positional_count} "
            f"is greater than supported maximum {maximum}"
        )

    actual_keywords = {
        str(keyword)
        for keyword in call_shape.get(
            "keyword_arg_names",
            [],
        )
    }

    required_keywords = {
        str(keyword)
        for keyword in rule.get(
            "required_keyword_args",
            [],
        )
    }

    forbidden_keywords = {
        str(keyword)
        for keyword in rule.get(
            "forbidden_keyword_args",
            [],
        )
    }

    supported_keywords_raw = rule.get(
        "supported_keyword_args"
    )

    missing_required = (
        required_keywords - actual_keywords
    )

    if missing_required:
        reasons.append(
            "missing required keyword arguments: "
            + ", ".join(sorted(missing_required))
        )

    forbidden_used = (
        actual_keywords & forbidden_keywords
    )

    if forbidden_used:
        reasons.append(
            "forbidden keyword arguments used: "
            + ", ".join(sorted(forbidden_used))
        )

    # supported_keyword_args 存在时，将其视为当前规则
    # 明确支持的关键字参数集合。
    if supported_keywords_raw is not None:
        supported_keywords = {
            str(keyword)
            for keyword in supported_keywords_raw
        }

        unsupported_keywords = (
            actual_keywords - supported_keywords
        )

        if unsupported_keywords:
            reasons.append(
                "keyword arguments not supported by this rule: "
                + ", ".join(
                    sorted(unsupported_keywords)
                )
            )

    return not reasons, reasons


def combine_specifiers(
    version_specifiers: list[str],
) -> str:
    """
    将多个版本约束按交集形式合并。

    例如：
        >=3.01
        >=5.1

    合并为：
        >=3.01,>=5.1
    """
    unique_specifiers: list[str] = []

    for specifier in version_specifiers:
        cleaned = str(specifier).strip()

        if cleaned and cleaned not in unique_specifiers:
            unique_specifiers.append(cleaned)

    combined = ",".join(unique_specifiers)

    if combined:
        SpecifierSet(combined)

    return combined


def simplify_lower_bound_specifiers(
    version_specifiers: list[str],
) -> str:
    """
    对仅包含 >= 下界的约束做简化。

    例如：
        >=3.01
        >=5.1

    简化为：
        >=5.1

    遇到复杂约束时不强行简化。
    """
    lower_bounds: list[Version] = []

    for version_specifier in version_specifiers:
        parts = version_specifier.split(",")

        for part in parts:
            cleaned = part.strip()

            if not cleaned.startswith(">="):
                return ""

            version_text = cleaned[2:].strip()

            try:
                lower_bounds.append(
                    Version(version_text)
                )
            except InvalidVersion:
                return ""

    if not lower_bounds:
        return ""

    return f">={max(lower_bounds)}"


def resolve_single_call(
    call: dict[str, Any],
    history_index: dict[
        tuple[str, str],
        list[dict[str, Any]],
    ],
) -> dict[str, Any]:
    """解析单个 API 调用所产生的版本约束。"""
    distribution = str(
        call.get("distribution", "")
    )
    normalized_distribution = pep503_normalize(
        distribution
    )
    api_symbol = str(
        call.get("api_symbol", "")
    )

    history_entries = history_index.get(
        (
            normalized_distribution,
            api_symbol,
        ),
        [],
    )

    base_result: dict[str, Any] = {
        "distribution": distribution,
        "normalized_distribution": (
            normalized_distribution
        ),
        "api_symbol": api_symbol,
        "call_text": call.get("call_text", ""),
        "call_shape": call.get(
            "call_shape",
            {},
        ),
        "location": call.get(
            "location",
            {},
        ),
        "status": "",
        "matched_rules": [],
        "rejected_rules": [],
        "version_specifiers": [],
        "combined_version_specifier": "",
        "simplified_version_specifier": "",
    }

    receiver_provenance = call.get(
        "receiver_provenance"
    )

    if (
        isinstance(
            receiver_provenance,
            dict,
        )
        and receiver_provenance
    ):
        base_result[
            "receiver_provenance"
        ] = receiver_provenance

    if not history_entries:
        base_result["status"] = (
            "no_history_entry"
        )
        return base_result

    call_shape = call.get("call_shape", {})

    if (
        call_shape.get("has_star_args")
        or call_shape.get("has_star_kwargs")
    ):
        base_result["status"] = (
            "dynamic_arguments_unresolved"
        )
        return base_result

    matched_rules: list[dict[str, Any]] = []
    rejected_rules: list[dict[str, Any]] = []
    version_specifiers: list[str] = []

    for entry in history_entries:
        for rule in entry.get(
            "version_rules",
            [],
        ):
            matched, reasons = match_rule_to_call(
                call,
                rule,
            )

            version_specifier = str(
                rule.get(
                    "version_specifier",
                    "",
                )
            ).strip()

            valid_specifier, specifier_error = (
                validate_version_specifier(
                    version_specifier
                )
            )

            if not valid_specifier:
                reasons.append(
                    "invalid version specifier: "
                    + specifier_error
                )
                matched = False

            rule_evidence = {
                "rule_id": rule.get(
                    "rule_id",
                    "",
                ),
                "version_specifier": (
                    version_specifier
                ),
                "evidence_type": rule.get(
                    "evidence_type",
                    "",
                ),
                "evidence_ref": rule.get(
                    "evidence_ref",
                    "",
                ),
                "evidence_note": rule.get(
                    "evidence_note",
                    "",
                ),
            }

            if matched:
                matched_rules.append(
                    rule_evidence
                )
                version_specifiers.append(
                    version_specifier
                )
            else:
                rejected_rules.append(
                    {
                        **rule_evidence,
                        "rejection_reasons": reasons,
                    }
                )

    base_result["matched_rules"] = matched_rules
    base_result["rejected_rules"] = (
        rejected_rules
    )
    base_result["version_specifiers"] = (
        version_specifiers
    )

    if not matched_rules:
        base_result["status"] = (
            "no_compatible_rule"
        )
        return base_result

    combined = combine_specifiers(
        version_specifiers
    )

    simplified = (
        simplify_lower_bound_specifiers(
            version_specifiers
        )
    )

    base_result["status"] = "resolved"
    base_result[
        "combined_version_specifier"
    ] = combined
    base_result[
        "simplified_version_specifier"
    ] = simplified

    return base_result


def build_distribution_constraints(
    call_constraints: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    按 distribution 合并所有 API 调用产生的约束。

    该结果即当前最小原型中的 S_api。
    """
    grouped: dict[
        str,
        list[dict[str, Any]],
    ] = {}

    for call_result in call_constraints:
        normalized_distribution = (
            call_result[
                "normalized_distribution"
            ]
        )

        grouped.setdefault(
            normalized_distribution,
            [],
        ).append(call_result)

    results: list[dict[str, Any]] = []

    for normalized_distribution, calls in sorted(
        grouped.items()
    ):
        resolved_calls = [
            call
            for call in calls
            if call["status"] == "resolved"
        ]

        unresolved_calls = [
            call
            for call in calls
            if call["status"] != "resolved"
        ]

        version_specifiers: list[str] = []

        for call in resolved_calls:
            version_specifiers.extend(
                call["version_specifiers"]
            )

        combined = combine_specifiers(
            version_specifiers
        )

        simplified = (
            simplify_lower_bound_specifiers(
                version_specifiers
            )
        )

        if resolved_calls and not unresolved_calls:
            status = "resolved"
        elif resolved_calls:
            status = "partial"
        else:
            status = "unresolved"

        display_distribution = (
            calls[0]["distribution"]
            if calls
            else normalized_distribution
        )

        results.append(
            {
                "distribution": (
                    display_distribution
                ),
                "normalized_distribution": (
                    normalized_distribution
                ),
                "status": status,
                "api_call_count": len(calls),
                "resolved_api_call_count": len(
                    resolved_calls
                ),
                "unresolved_api_call_count": len(
                    unresolved_calls
                ),
                "resolved_api_symbols": [
                    call["api_symbol"]
                    for call in resolved_calls
                ],
                "unresolved_api_symbols": [
                    call["api_symbol"]
                    for call in unresolved_calls
                ],
                "s_api": {
                    "raw_specifier": combined,
                    "simplified_specifier": (
                        simplified
                    ),
                    "evidence_rule_ids": [
                        rule["rule_id"]
                        for call in resolved_calls
                        for rule in call[
                            "matched_rules"
                        ]
                    ],
                },
            }
        )

    return results


def resolve_api_version_constraints(
    api_calls_path: Path,
    history_path: Path,
) -> dict[str, Any]:
    """解析一个样本中所有 API 调用的版本约束。"""
    api_call_evidence = read_json(
        api_calls_path
    )
    history = read_json(history_path)

    history_index = build_history_index(
        history
    )

    call_constraints = [
        resolve_single_call(
            call,
            history_index,
        )
        for call in api_call_evidence.get(
            "api_calls",
            [],
        )
    ]

    distribution_constraints = (
        build_distribution_constraints(
            call_constraints
        )
    )

    resolved_count = sum(
        call["status"] == "resolved"
        for call in call_constraints
    )

    unresolved_count = (
        len(call_constraints) - resolved_count
    )

    if call_constraints and unresolved_count == 0:
        overall_status = "resolved"
    elif resolved_count:
        overall_status = "partial"
    else:
        overall_status = "unresolved"

    return {
        "schema_version": (
            "api_version_constraint_v0.1"
        ),
        "sample_id": api_call_evidence.get(
            "sample_id",
            "",
        ),
        "api_call_evidence_file": str(
            api_calls_path
        ).replace("\\", "/"),
        "history_file": str(
            history_path
        ).replace("\\", "/"),
        "history_schema_version": history.get(
            "schema_version",
            "",
        ),
        "status": overall_status,
        "api_call_count": len(
            call_constraints
        ),
        "resolved_api_call_count": (
            resolved_count
        ),
        "unresolved_api_call_count": (
            unresolved_count
        ),
        "call_constraints": call_constraints,
        "distribution_constraints": (
            distribution_constraints
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Resolve API-compatible package "
            "version constraints for AVCS."
        )
    )

    parser.add_argument(
        "--api-calls",
        required=True,
        type=Path,
    )
    parser.add_argument(
        "--history",
        type=Path,
        default=Path(
            "config/avcs_api_history_seed.json"
        ),
    )
    parser.add_argument(
        "--out",
        required=True,
        type=Path,
    )

    args = parser.parse_args()

    result = resolve_api_version_constraints(
        api_calls_path=args.api_calls,
        history_path=args.history,
    )

    args.out.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    args.out.write_text(
        json.dumps(
            result,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    print(
        f"[OK] sample id: "
        f"{result['sample_id']}"
    )
    print(
        f"[OK] API calls: "
        f"{result['api_call_count']}"
    )
    print(
        f"[OK] resolved calls: "
        f"{result['resolved_api_call_count']}"
    )
    print(
        f"[OK] unresolved calls: "
        f"{result['unresolved_api_call_count']}"
    )
    print(
        f"[OK] status: "
        f"{result['status']}"
    )

    for constraint in result["distribution_constraints"]:
        s_api = constraint["s_api"]

        display_specifier = (
                s_api.get("simplified_specifier")
                or s_api.get("raw_specifier")
                or "(unresolved)"
        )

        print(
            f"[OK] {constraint['distribution']} "
            f"S_api: {display_specifier}"
        )

    print(
        f"[OK] result saved to: "
        f"{args.out}"
    )


if __name__ == "__main__":
    main()