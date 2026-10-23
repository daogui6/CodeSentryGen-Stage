from __future__ import annotations

import argparse
import json
from pathlib import Path
from urllib.parse import urlparse
from typing import Any

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from normalizer import pep503_normalize


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))

def find_sample_record(
    path: Path,
    sample_id: str,
) -> dict[str, Any] | None:
    with path.open(
        "r",
        encoding="utf-8-sig",
    ) as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            row = json.loads(line)

            if row.get("sample_id") == sample_id:
                return row

    return None

def update_lower_bound(
    current: tuple[Version, bool] | None,
    version: Version,
    inclusive: bool,
) -> tuple[Version, bool]:
    if current is None:
        return version, inclusive

    current_version, current_inclusive = current

    if version > current_version:
        return version, inclusive

    if version == current_version:
        return version, current_inclusive and inclusive

    return current


def update_upper_bound(
    current: tuple[Version, bool] | None,
    version: Version,
    inclusive: bool,
) -> tuple[Version, bool]:
    if current is None:
        return version, inclusive

    current_version, current_inclusive = current

    if version < current_version:
        return version, inclusive

    if version == current_version:
        return version, current_inclusive and inclusive

    return current


def intersect_simple_specifiers(
    first_specifier: str,
    second_specifier: str,
) -> dict[str, Any]:
    """
    计算简单版本区间的交集。

    当前支持：
        >=
        >
        <=
        <
        ==

    当前 AVCS seed 使用的版本范围都在这个范围内。
    """
    combined_text = ",".join(
        value
        for value in [
            first_specifier.strip(),
            second_specifier.strip(),
        ]
        if value
    )

    try:
        specifier_set = SpecifierSet(combined_text)
    except InvalidSpecifier as exc:
        return {
            "status": "invalid_specifier",
            "has_overlap": False,
            "intersection_specifier": "",
            "error": str(exc),
        }

    lower_bound: tuple[Version, bool] | None = None
    upper_bound: tuple[Version, bool] | None = None
    unsupported_operators: list[str] = []

    for specifier in specifier_set:
        operator = specifier.operator
        version_text = specifier.version

        if operator == "==" and "*" in version_text:
            unsupported_operators.append(
                f"{operator}{version_text}"
            )
            continue

        try:
            version = Version(version_text)
        except InvalidVersion:
            return {
                "status": "invalid_version",
                "has_overlap": False,
                "intersection_specifier": "",
                "error": version_text,
            }

        if operator == ">=":
            lower_bound = update_lower_bound(
                lower_bound,
                version,
                True,
            )
        elif operator == ">":
            lower_bound = update_lower_bound(
                lower_bound,
                version,
                False,
            )
        elif operator == "<=":
            upper_bound = update_upper_bound(
                upper_bound,
                version,
                True,
            )
        elif operator == "<":
            upper_bound = update_upper_bound(
                upper_bound,
                version,
                False,
            )
        elif operator == "==":
            lower_bound = update_lower_bound(
                lower_bound,
                version,
                True,
            )
            upper_bound = update_upper_bound(
                upper_bound,
                version,
                True,
            )
        else:
            unsupported_operators.append(
                f"{operator}{version_text}"
            )

    if unsupported_operators:
        return {
            "status": "unsupported_specifier",
            "has_overlap": None,
            "intersection_specifier": "",
            "unsupported_specifiers": unsupported_operators,
        }

    has_overlap = True

    if lower_bound is not None and upper_bound is not None:
        lower_version, lower_inclusive = lower_bound
        upper_version, upper_inclusive = upper_bound

        if lower_version > upper_version:
            has_overlap = False
        elif lower_version == upper_version:
            has_overlap = (
                lower_inclusive and upper_inclusive
            )

    if not has_overlap:
        return {
            "status": "empty",
            "has_overlap": False,
            "intersection_specifier": "",
        }

    parts: list[str] = []

    if lower_bound is not None:
        lower_version, lower_inclusive = lower_bound
        lower_operator = ">=" if lower_inclusive else ">"
        parts.append(
            f"{lower_operator}{lower_version}"
        )

    if upper_bound is not None:
        upper_version, upper_inclusive = upper_bound
        upper_operator = "<=" if upper_inclusive else "<"
        parts.append(
            f"{upper_operator}{upper_version}"
        )

    if (
        lower_bound is not None
        and upper_bound is not None
        and lower_bound[0] == upper_bound[0]
        and lower_bound[1]
        and upper_bound[1]
    ):
        intersection_specifier = f"=={lower_bound[0]}"
    else:
        intersection_specifier = ",".join(parts)

    return {
        "status": "overlap",
        "has_overlap": True,
        "intersection_specifier": intersection_specifier,
    }


def find_distribution_constraint(
    api_constraints: dict[str, Any],
    normalized_distribution: str,
) -> dict[str, Any] | None:
    for constraint in api_constraints.get(
        "distribution_constraints",
        [],
    ):
        if (
            constraint.get("normalized_distribution")
            == normalized_distribution
        ):
            return constraint

    return None

def validate_exposed_release_context(
    exposed_releases: dict[str, Any] | None,
    sample_id: str,
    normalized_distribution: str,
) -> str:
    if exposed_releases is None:
        return "not_provided"

    exposed_sample_id = str(
        exposed_releases.get(
            "sample_id",
            "",
        )
    )

    if exposed_sample_id != sample_id:
        return "sample_id_mismatch"

    exposed_normalized_distribution = (
        exposed_releases.get(
            "normalized_distribution"
        )
        or pep503_normalize(
            str(
                exposed_releases.get(
                    "distribution",
                    "",
                )
            )
        )
    )

    if (
        exposed_normalized_distribution
        != normalized_distribution
    ):
        return "distribution_mismatch"

    return "matched"

def find_exposed_release_evaluation(
    exposed_releases: dict[str, Any] | None,
    vulnerability_id: str,
) -> dict[str, Any] | None:
    if exposed_releases is None:
        return None

    for evaluation in exposed_releases.get(
        "evaluations",
        [],
    ):
        if (
            evaluation.get(
                "vulnerability_id"
            )
            == vulnerability_id
        ):
            return evaluation

    return None

def get_environment_precondition_context(
    vulnerability: dict[str, Any],
) -> dict[str, Any]:
    """
    读取漏洞 Trigger Evidence 中声明的
    运行环境前提。

    例如某些漏洞除了满足：

        vulnerable version
        +
        trigger API / call shape

    之外，还依赖：

        credential file
        environment variable
        runtime configuration
        permission
        platform capability

    这些条件通常不能仅通过当前静态代码
    直接确认，因此需要单独保留 review 状态。

    注意：

    这里只读取已经进入 Trigger Evidence
    的事实，不包含任何 Requests 特判。
    """

    trigger_evidence = (
        vulnerability.get(
            "trigger_evidence",
            {},
        )
    )

    if not isinstance(
        trigger_evidence,
        dict,
    ):
        trigger_evidence = {}

    scope = trigger_evidence.get(
        "scope",
        {},
    )

    if not isinstance(
        scope,
        dict,
    ):
        scope = {}

    environment_preconditions = (
        scope.get(
            "environment_preconditions",
            {},
        )
    )

    if not isinstance(
        environment_preconditions,
        dict,
    ):
        environment_preconditions = {}

    # 旧案例没有 environment_preconditions，
    # 因此保持原有行为，不要求环境 review。
    if not environment_preconditions:
        return {
            "present": False,
            "evaluation_status":
                "not_required",
            "requires_review": False,
            "preconditions": {},
        }

    evaluation_status = str(
        environment_preconditions.get(
            "evaluation_status",
            "unknown",
        )
    ).strip() or "unknown"

    # 只有显式确认环境条件已经满足，
    # 或明确不需要环境条件时，
    # 才可以跳过 environment review。
    #
    # 其他状态，包括：
    #
    #   unknown
    #   unresolved
    #   not_statically_evaluated
    #
    # 都保守地进入人工/运行时环境检查。
    no_review_statuses = {
        "satisfied",
        "statically_satisfied",
        "not_required",
    }

    requires_review = (
        evaluation_status
        not in no_review_statuses
    )

    return {
        "present": True,
        "evaluation_status":
            evaluation_status,
        "requires_review":
            requires_review,
        "preconditions":
            environment_preconditions,
    }



def get_keyword_argument_symbol(
    call: dict[str, Any],
    keyword_name: str,
) -> str | None:
    """
    从 call_shape 中读取某个关键字参数解析后的符号。

    例如：

        yaml.load(
            data,
            Loader=yaml.FullLoader,
        )

    返回：

        yaml.FullLoader
    """
    call_shape = call.get(
        "call_shape",
        {},
    )

    keyword_values = call_shape.get(
        "keyword_arg_values",
        {},
    )

    if not isinstance(
        keyword_values,
        dict,
    ):
        return None

    keyword_value = keyword_values.get(
        keyword_name
    )

    if not isinstance(
        keyword_value,
        dict,
    ):
        return None

    resolved_symbol = (
        keyword_value.get(
            "resolved_symbol"
        )
    )

    if resolved_symbol is None:
        return None

    return str(
        resolved_symbol
    ).strip() or None

def get_keyword_argument_call_symbol(
    call: dict[str, Any],
    keyword_name: str,
) -> str | None:
    """
    从 call_shape 中读取某个关键字参数值
    所对应的已确认函数调用 symbol。

    例如：

        jwt.decode(
            token,
            key,
            algorithms=(
                jwt.algorithms
                .get_default_algorithms()
            ),
        )

    返回：

        jwt.algorithms.get_default_algorithms

    这里只读取 extractor 已经通过 AST
    确认的调用 symbol，不执行函数，
    也不推断函数返回值。
    """
    call_shape = call.get(
        "call_shape",
        {},
    )

    keyword_values = call_shape.get(
        "keyword_arg_values",
        {},
    )

    if not isinstance(
        keyword_values,
        dict,
    ):
        return None

    keyword_value = keyword_values.get(
        keyword_name
    )

    if not isinstance(
        keyword_value,
        dict,
    ):
        return None

    resolved_call_symbol = (
        keyword_value.get(
            "resolved_call_symbol"
        )
    )

    if resolved_call_symbol is None:
        return None

    return str(
        resolved_call_symbol
    ).strip() or None

def get_positional_argument_literal(
    call: dict[str, Any],
    position: int,
) -> tuple[bool, Any]:
    """
    从 call_shape 中读取指定位置参数的
    已确认 literal 值。

    例如：

        requests.get(
            "https://example.com"
        )

    position=0 时返回：

        (
            True,
            "https://example.com",
        )

    如果参数来自变量：

        requests.get(url)

    extractor 没有确认 literal_value，
    则返回：

        (False, None)

    这里仍然只读取 extractor 已确认的事实，
    不执行表达式，也不猜测变量值。
    """
    call_shape = call.get(
        "call_shape",
        {},
    )

    positional_values = (
        call_shape.get(
            "positional_arg_values",
            [],
        )
    )

    if not isinstance(
        positional_values,
        list,
    ):
        return False, None

    for value_evidence in (
        positional_values
    ):
        if not isinstance(
            value_evidence,
            dict,
        ):
            continue

        if (
            value_evidence.get(
                "position"
            )
            != position
        ):
            continue

        if (
            "literal_value"
            not in value_evidence
        ):
            return False, None

        return (
            True,
            value_evidence.get(
                "literal_value"
            ),
        )

    return False, None

def has_legacy_netrc_host_confusion(
    url_value: Any,
) -> bool:
    """
    判断一个静态 URL 是否具有 Requests
    CVE-2024-47081 所涉及的 authority
    host-confusion 结构。

    漏洞旧逻辑近似为：

        urlparse(url).netloc.split(":")[0]

    修复后的正确逻辑使用：

        urlparse(url).hostname

    如果两者得到的 host 不一致，
    说明 URL authority 中存在可能导致
    .netrc 主机归属混淆的结构。

    注意：

    这里只判断 URL 结构本身。

    是否真的存在 .netrc 凭据、
    trust_env 是否启用、
    输入是否由攻击者控制，
    属于更上层的运行环境/风险证据，
    不能在这里假设。
    """
    if not isinstance(
        url_value,
        str,
    ):
        return False

    if not url_value.strip():
        return False

    try:
        parsed = urlparse(
            url_value
        )

        netloc = parsed.netloc
        hostname = parsed.hostname

    except ValueError:
        return False

    if (
        not netloc
        or not hostname
    ):
        return False

    # CVE-2024-47081 的可利用 URL
    # 依赖 authority 中存在 user-info，
    # 使旧版 netloc.split(":")[0]
    # 错把 user-info 部分当作 .netrc host。
    #
    # 这里只接受 http / https URL，
    # 同时要求存在 username，
    # 避免把普通 IPv6 authority 等
    # “解析结果不同但并非本漏洞利用结构”
    # 误认为 Trigger。
    if (
        parsed.scheme
        not in {
            "http",
            "https",
        }
    ):
        return False

    if parsed.username is None:
        return False

    legacy_lookup_host = (
        netloc.split(
            ":",
            1,
        )[0]
    )

    if not legacy_lookup_host:
        return False

    return (
        legacy_lookup_host
        != hostname
    )

def get_keyword_argument_literal(
    call: dict[str, Any],
    keyword_name: str,
) -> tuple[bool, Any]:
    """
    从 call_shape 中读取某个关键字参数的
    已确认 literal 值。

    例如：

        web.static(
            "/assets",
            "./assets",
            follow_symlinks=True,
        )

    返回：

        (True, True)

    如果参数值来自变量、函数调用等，
    extractor 没有确认 literal_value，
    则返回：

        (False, None)

    使用单独的 resolved 标志，
    是为了区分：

        literal_value=None

    和：

        无法解析 literal
    """
    call_shape = call.get(
        "call_shape",
        {},
    )

    keyword_values = call_shape.get(
        "keyword_arg_values",
        {},
    )

    if not isinstance(
        keyword_values,
        dict,
    ):
        return False, None

    keyword_value = keyword_values.get(
        keyword_name
    )

    if not isinstance(
        keyword_value,
        dict,
    ):
        return False, None

    if (
        "literal_value"
        not in keyword_value
    ):
        return False, None

    return (
        True,
        keyword_value.get(
            "literal_value"
        ),
    )

def call_uses_keyword(
    call: dict[str, Any],
    keyword_name: str,
) -> bool:
    """
    判断调用是否显式写出了指定关键字参数。
    """
    call_shape = call.get(
        "call_shape",
        {},
    )

    keyword_names = call_shape.get(
        "keyword_arg_names",
        [],
    )

    if not isinstance(
        keyword_names,
        list,
    ):
        return False

    return (
        keyword_name
        in {
            str(value)
            for value in keyword_names
        }
    )


def release_matches_version_scope(
    version_text: str,
    version_scope: str,
) -> bool:
    """
    判断一个真实 release 是否位于 Trigger Evidence
    声明的版本语义范围内。

    这里复用 AVCS 已有的简单区间交集逻辑，
    而不是直接使用 SpecifierSet.contains。

    例如：

        version = 5.4b1
        scope   = >=5.1,<5.4

    按版本边界比较仍属于该区间。
    """
    version_text = str(
        version_text
    ).strip()

    version_scope = str(
        version_scope
    ).strip()

    if not version_text:
        return False

    if not version_scope:
        return True

    overlap = (
        intersect_simple_specifiers(
            f"=={version_text}",
            version_scope,
        )
    )

    return (
        overlap.get(
            "has_overlap"
        )
        is True
    )


def exposed_releases_in_scope(
    confirmed_exposed_releases: list[Any],
    version_scope: str,
) -> list[str]:
    """
    从真实 confirmed exposed releases 中筛出
    位于 Trigger Evidence version scope 内的版本。
    """
    matched_versions: list[str] = []

    for release in (
        confirmed_exposed_releases
    ):
        if isinstance(
            release,
            dict,
        ):
            version_text = str(
                release.get(
                    "version",
                    "",
                )
            ).strip()

        else:
            version_text = str(
                release
            ).strip()

        if not version_text:
            continue

        if release_matches_version_scope(
            version_text=version_text,
            version_scope=version_scope,
        ):
            matched_versions.append(
                version_text
            )

    return matched_versions

def match_direct_trigger_rule(
    call: dict[str, Any],
    rule: dict[str, Any],
    confirmed_exposed_releases: list[Any],
) -> dict[str, Any]:
    """
    判断一个直接 Trigger API 是否满足
    Real Trigger Evidence 中的版本范围。

    例如：

        yaml.full_load(...)

    不能只因为 API symbol 相同就判 Trigger，
    还需要真实 exposed release 落在：

        >=5.1,<5.4

    这样的 Trigger Evidence scope 内。
    """
    api_symbol = str(
        call.get(
            "api_symbol",
            "",
        )
    )

    rule_api_symbol = str(
        rule.get(
            "api_symbol",
            "",
        )
    )

    trigger_id = str(
        rule.get(
            "trigger_id",
            "",
        )
    )

    version_scope = str(
        rule.get(
            "version_scope",
            "",
        )
        or ""
    )

    result = {
        "trigger_id":
            trigger_id,

        "api_symbol":
            rule_api_symbol,

        "kind":
            str(
                rule.get(
                    "kind",
                    "",
                )
            ),

        "version_scope":
            version_scope,

        "matched":
            False,

        "reason":
            "",

        "scoped_exposed_releases":
            [],
    }

    if api_symbol != rule_api_symbol:
        result[
            "reason"
        ] = "api_symbol_not_matched"

        return result

    scoped_exposed = (
        exposed_releases_in_scope(
            confirmed_exposed_releases=(
                confirmed_exposed_releases
            ),
            version_scope=version_scope,
        )
    )

    result[
        "scoped_exposed_releases"
    ] = scoped_exposed

    if (
        version_scope
        and not scoped_exposed
    ):
        result[
            "reason"
        ] = (
            "no_exposed_release_"
            "within_trigger_version_scope"
        )

        return result

    result["matched"] = True
    result[
        "reason"
    ] = (
        "direct_api_and_"
        "version_scope_matched"
    )

    return result

def match_conditional_trigger_rule(
    call: dict[str, Any],
    rule: dict[str, Any],
    confirmed_exposed_releases: list[Any],
) -> dict[str, Any]:
    """
    判断一个 API 调用是否满足一条 conditional Trigger rule。

    当前支持：

    1. keyword_argument_condition
       例如：
       yaml.load(..., Loader=yaml.FullLoader)

    2. keyword_literal_condition
       例如：
       web.static(..., follow_symlinks=True)

    3. keyword_call_condition
       例如：
       jwt.decode(
           ...,
           algorithms=jwt.algorithms.get_default_algorithms(),
       )

    4. omitted_keyword_historical_default
       例如：
       yaml.load(...)
       且历史版本默认使用 FullLoader

    5. positional_url_condition
       例如：
       requests.get(
           "http://github.com:@evil.example.net"
       )

    6. receiver_producer_keyword_literal_condition
   例如：
   http = urllib3.PoolManager(
       retries=0,
   )
   http.request(...)
    """
    api_symbol = str(
        call.get(
            "api_symbol",
            "",
        )
    )

    rule_api_symbol = str(
        rule.get(
            "api_symbol",
            "",
        )
    )

    trigger_id = str(
        rule.get(
            "trigger_id",
            "",
        )
    )

    kind = str(
        rule.get(
            "kind",
            "",
        )
    )

    version_scope = str(
        rule.get(
            "version_scope",
            "",
        )
        or ""
    )

    base_result = {
        "trigger_id":
            trigger_id,

        "api_symbol":
            rule_api_symbol,

        "kind":
            kind,

        "version_scope":
            version_scope,

        "matched":
            False,

        "reason":
            "",

        "scoped_exposed_releases":
            [],
    }

    if api_symbol != rule_api_symbol:
        base_result[
            "reason"
        ] = "api_symbol_not_matched"

        return base_result

    call_shape = call.get(
        "call_shape",
        {},
    )

    if call_shape.get(
        "has_star_kwargs"
    ):
        base_result[
            "reason"
        ] = (
            "star_kwargs_make_"
            "keyword_value_unresolved"
        )

        return base_result

    scoped_exposed = (
        exposed_releases_in_scope(
            confirmed_exposed_releases=(
                confirmed_exposed_releases
            ),
            version_scope=version_scope,
        )
    )

    base_result[
        "scoped_exposed_releases"
    ] = scoped_exposed

    if (
        version_scope
        and not scoped_exposed
    ):
        base_result[
            "reason"
        ] = (
            "no_exposed_release_"
            "within_trigger_version_scope"
        )

        return base_result

    keyword_rule = rule.get(
        "keyword_argument",
        {},
    )

    if not isinstance(
        keyword_rule,
        dict,
    ):
        keyword_rule = {}

    keyword_name = str(
        keyword_rule.get(
            "name",
            "",
        )
    )

    if (
        kind
        == "keyword_argument_condition"
    ):
        required_symbol = str(
            keyword_rule.get(
                "required_symbol",
                "",
            )
        )

        if not keyword_name:
            base_result[
                "reason"
            ] = (
                "keyword_name_missing_"
                "from_rule"
            )

            return base_result

        if not call_uses_keyword(
            call=call,
            keyword_name=keyword_name,
        ):
            base_result[
                "reason"
            ] = (
                "required_keyword_"
                "not_observed"
            )

            return base_result

        actual_symbol = (
            get_keyword_argument_symbol(
                call=call,
                keyword_name=keyword_name,
            )
        )

        if actual_symbol is None:
            base_result[
                "reason"
            ] = (
                "keyword_symbol_unresolved"
            )

            return base_result

        if (
            actual_symbol
            != required_symbol
        ):
            base_result[
                "reason"
            ] = (
                "keyword_symbol_not_matched"
            )

            return base_result

        base_result["matched"] = True
        base_result[
            "reason"
        ] = "keyword_symbol_matched"

        return base_result

    if (
        kind
        == "keyword_call_condition"
    ):
        required_call_symbol = str(
            keyword_rule.get(
                "required_call_symbol",
                "",
            )
        ).strip()

        if not keyword_name:
            base_result[
                "reason"
            ] = (
                "keyword_name_missing_"
                "from_rule"
            )

            return base_result

        if not required_call_symbol:
            base_result[
                "reason"
            ] = (
                "required_call_symbol_"
                "missing_from_rule"
            )

            return base_result

        if not call_uses_keyword(
            call=call,
            keyword_name=keyword_name,
        ):
            base_result[
                "reason"
            ] = (
                "required_keyword_"
                "not_observed"
            )

            return base_result

        actual_call_symbol = (
            get_keyword_argument_call_symbol(
                call=call,
                keyword_name=keyword_name,
            )
        )

        if actual_call_symbol is None:
            base_result[
                "reason"
            ] = (
                "keyword_call_unresolved"
            )

            return base_result

        if (
            actual_call_symbol
            != required_call_symbol
        ):
            base_result[
                "reason"
            ] = (
                "keyword_call_not_matched"
            )

            return base_result

        base_result[
            "matched"
        ] = True

        base_result[
            "reason"
        ] = (
            "keyword_call_matched"
        )

        return base_result

    if (
        kind
        == "keyword_literal_condition"
    ):
        if not keyword_name:
            base_result[
                "reason"
            ] = (
                "keyword_name_missing_"
                "from_rule"
            )

            return base_result

        if (
            "required_literal"
            not in keyword_rule
        ):
            base_result[
                "reason"
            ] = (
                "required_literal_"
                "missing_from_rule"
            )

            return base_result

        if not call_uses_keyword(
            call=call,
            keyword_name=keyword_name,
        ):
            base_result[
                "reason"
            ] = (
                "required_keyword_"
                "not_observed"
            )

            return base_result

        (
            literal_resolved,
            actual_literal,
        ) = get_keyword_argument_literal(
            call=call,
            keyword_name=keyword_name,
        )

        if not literal_resolved:
            base_result[
                "reason"
            ] = (
                "keyword_literal_"
                "unresolved"
            )

            return base_result

        required_literal = (
            keyword_rule[
                "required_literal"
            ]
        )

        if (
            type(actual_literal)
            is not type(required_literal)
            or actual_literal
            != required_literal
        ):
            base_result[
                "reason"
            ] = (
                "keyword_literal_"
                "not_matched"
            )

            return base_result

        base_result[
            "matched"
        ] = True

        base_result[
            "reason"
        ] = (
            "keyword_literal_matched"
        )

        return base_result

    if (
        kind
        == "positional_url_condition"
    ):
        positional_rule = (
            rule.get(
                "positional_argument",
                {},
            )
        )

        if not isinstance(
            positional_rule,
            dict,
        ):
            positional_rule = {}

        position = (
            positional_rule.get(
                "position"
            )
        )

        url_condition = str(
            positional_rule.get(
                "url_condition",
                "",
            )
        ).strip()

        if not isinstance(
            position,
            int,
        ):
            base_result[
                "reason"
            ] = (
                "positional_argument_"
                "position_missing"
            )

            return base_result

        if (
            url_condition
            != (
                "legacy_netrc_host_"
                "differs_from_hostname"
            )
        ):
            base_result[
                "reason"
            ] = (
                "unsupported_url_"
                "condition"
            )

            return base_result

        (
            literal_resolved,
            actual_url,
        ) = (
            get_positional_argument_literal(
                call=call,
                position=position,
            )
        )

        if not literal_resolved:
            base_result[
                "reason"
            ] = (
                "positional_url_"
                "literal_unresolved"
            )

            return base_result

        if not isinstance(
            actual_url,
            str,
        ):
            base_result[
                "reason"
            ] = (
                "positional_url_"
                "is_not_string"
            )

            return base_result

        if not (
            has_legacy_netrc_host_confusion(
                actual_url
            )
        ):
            base_result[
                "reason"
            ] = (
                "url_authority_"
                "host_confusion_not_observed"
            )

            return base_result

        base_result[
            "matched"
        ] = True

        base_result[
            "reason"
        ] = (
            "url_authority_"
            "host_confusion_matched"
        )

        return base_result

    if (
        kind
        == (
            "receiver_producer_"
            "keyword_literal_condition"
        )
    ):
        receiver_rule = (
            rule.get(
                "receiver_provenance",
                {},
            )
        )

        if not isinstance(
            receiver_rule,
            dict,
        ):
            receiver_rule = {}

        required_producer_api = str(
            receiver_rule.get(
                "producer_api_symbol",
                "",
            )
        ).strip()

        producer_keyword_rule = (
            receiver_rule.get(
                "producer_keyword_argument",
                {},
            )
        )

        if not isinstance(
            producer_keyword_rule,
            dict,
        ):
            producer_keyword_rule = {}

        producer_keyword_name = str(
            producer_keyword_rule.get(
                "name",
                "",
            )
        ).strip()

        if not required_producer_api:
            base_result[
                "reason"
            ] = (
                "producer_api_symbol_"
                "missing_from_rule"
            )

            return base_result

        if not producer_keyword_name:
            base_result[
                "reason"
            ] = (
                "producer_keyword_name_"
                "missing_from_rule"
            )

            return base_result

        if (
            "required_literal"
            not in producer_keyword_rule
        ):
            base_result[
                "reason"
            ] = (
                "producer_required_literal_"
                "missing_from_rule"
            )

            return base_result

        receiver_provenance = (
            call.get(
                "receiver_provenance",
                {},
            )
        )

        if not isinstance(
            receiver_provenance,
            dict,
        ) or not receiver_provenance:
            base_result[
                "reason"
            ] = (
                "receiver_provenance_"
                "unresolved"
            )

            return base_result

        actual_producer_api = str(
            receiver_provenance.get(
                "producer_api_symbol",
                "",
            )
        ).strip()

        if (
            actual_producer_api
            != required_producer_api
        ):
            base_result[
                "reason"
            ] = (
                "receiver_producer_api_"
                "not_matched"
            )

            return base_result

        producer_call_shape = (
            receiver_provenance.get(
                "producer_call_shape",
                {},
            )
        )

        if not isinstance(
            producer_call_shape,
            dict,
        ):
            base_result[
                "reason"
            ] = (
                "producer_call_shape_"
                "unresolved"
            )

            return base_result

        if producer_call_shape.get(
            "has_star_kwargs"
        ):
            base_result[
                "reason"
            ] = (
                "producer_star_kwargs_"
                "make_keyword_value_unresolved"
            )

            return base_result

        producer_keyword_names = (
            producer_call_shape.get(
                "keyword_arg_names",
                [],
            )
        )

        if not isinstance(
            producer_keyword_names,
            list,
        ):
            producer_keyword_names = []

        if (
            producer_keyword_name
            not in producer_keyword_names
        ):
            base_result[
                "reason"
            ] = (
                "producer_required_keyword_"
                "not_observed"
            )

            return base_result

        producer_keyword_values = (
            producer_call_shape.get(
                "keyword_arg_values",
                {},
            )
        )

        if not isinstance(
            producer_keyword_values,
            dict,
        ):
            producer_keyword_values = {}

        producer_value_evidence = (
            producer_keyword_values.get(
                producer_keyword_name
            )
        )

        if not isinstance(
            producer_value_evidence,
            dict,
        ):
            base_result[
                "reason"
            ] = (
                "producer_keyword_literal_"
                "unresolved"
            )

            return base_result

        if (
            "literal_value"
            not in producer_value_evidence
        ):
            base_result[
                "reason"
            ] = (
                "producer_keyword_literal_"
                "unresolved"
            )

            return base_result

        actual_literal = (
            producer_value_evidence[
                "literal_value"
            ]
        )

        required_literal = (
            producer_keyword_rule[
                "required_literal"
            ]
        )

        if (
            type(actual_literal)
            is not type(required_literal)
            or actual_literal
            != required_literal
        ):
            base_result[
                "reason"
            ] = (
                "producer_keyword_literal_"
                "not_matched"
            )

            return base_result

        base_result[
            "matched"
        ] = True

        base_result[
            "reason"
        ] = (
            "receiver_producer_"
            "keyword_literal_matched"
        )

        return base_result

    if (
        kind
        == "omitted_keyword_historical_default"
    ):
        must_be_omitted = bool(
            keyword_rule.get(
                "must_be_omitted",
                False,
            )
        )

        if not must_be_omitted:
            base_result[
                "reason"
            ] = (
                "omission_requirement_"
                "not_enabled"
            )

            return base_result

        if not keyword_name:
            base_result[
                "reason"
            ] = (
                "keyword_name_missing_"
                "from_rule"
            )

            return base_result

        if call_uses_keyword(
            call=call,
            keyword_name=keyword_name,
        ):
            base_result[
                "reason"
            ] = (
                "keyword_is_explicitly_"
                "provided"
            )

            return base_result

        historical_default_symbol = str(
            rule.get(
                "historical_default_symbol",
                "",
            )
        ).strip()

        has_historical_default_literal = (
                "historical_default_literal"
                in rule
        )

        if (
                not historical_default_symbol
                and not has_historical_default_literal
        ):
            base_result[
                "reason"
            ] = (
                "historical_default_"
                "missing"
            )

            return base_result

        base_result["matched"] = True
        base_result[
            "reason"
        ] = (
            "keyword_omitted_and_"
            "historical_default_applies"
        )

        return base_result

    base_result[
        "reason"
    ] = "unsupported_rule_kind"

    return base_result


def match_safe_api_rule(
    call: dict[str, Any],
    rule: dict[str, Any],
) -> dict[str, Any]:
    """
    判断调用是否满足参数级安全规则。

    当前主要用于：

        yaml.load(
            data,
            Loader=yaml.SafeLoader,
        )
    """
    api_symbol = str(
        call.get(
            "api_symbol",
            "",
        )
    )

    rule_api_symbol = str(
        rule.get(
            "api_symbol",
            "",
        )
    )

    result = {
        "api_symbol":
            rule_api_symbol,

        "matched":
            False,

        "reason":
            "",
    }

    if api_symbol != rule_api_symbol:
        result[
            "reason"
        ] = "api_symbol_not_matched"

        return result

    call_shape = call.get(
        "call_shape",
        {},
    )

    if call_shape.get(
        "has_star_kwargs"
    ):
        result[
            "reason"
        ] = (
            "star_kwargs_make_"
            "keyword_value_unresolved"
        )

        return result

    keyword_rule = rule.get(
        "keyword_argument",
        {},
    )

    if not isinstance(
        keyword_rule,
        dict,
    ):
        keyword_rule = {}

    keyword_name = str(
        keyword_rule.get(
            "name",
            "",
        )
    )

    required_symbol = str(
        keyword_rule.get(
            "required_symbol",
            "",
        )
    )

    if (
        not keyword_name
        or not required_symbol
    ):
        result[
            "reason"
        ] = "safe_rule_incomplete"

        return result

    actual_symbol = (
        get_keyword_argument_symbol(
            call=call,
            keyword_name=keyword_name,
        )
    )

    if (
        actual_symbol
        != required_symbol
    ):
        result[
            "reason"
        ] = (
            "safe_keyword_symbol_"
            "not_matched"
        )

        return result

    result["matched"] = True
    result[
        "reason"
    ] = "safe_keyword_symbol_matched"

    return result

def evaluate_avcs(
    api_constraints_path: Path,
    vulnerability_constraints_path: Path,
    sample_records_path: Path | None = None,
    exposed_releases_path: Path | None = None,
) -> dict[str, Any]:
    api_constraints = load_json(api_constraints_path)
    vulnerability_constraints = load_json(
        vulnerability_constraints_path
    )
    exposed_releases: dict[str, Any] | None = None

    if exposed_releases_path is not None:
        exposed_releases = load_json(
            exposed_releases_path
        )

    sample_id = str(
        api_constraints.get(
            "sample_id",
            "",
        )
    )

    sample_context_status = "not_provided"
    sample_context: dict[str, Any] = {}

    if sample_records_path is not None:
        sample_record = find_sample_record(
            sample_records_path,
            sample_id,
        )

        if sample_record is None:
            sample_context_status = "sample_not_found"
        else:
            sample_context_status = "matched"

            sample_context = {
                "source_sample_id": sample_record.get(
                    "source_sample_id"
                ),
                "source_dataset": sample_record.get(
                    "source_dataset"
                ),
                "prompt_id": sample_record.get(
                    "prompt_id"
                ),
                "source": sample_record.get(
                    "source"
                ),
                "language": sample_record.get(
                    "language"
                ),
                "ecosystem": sample_record.get(
                    "ecosystem"
                ),
                "generation_time": sample_record.get(
                    "generation_time"
                ),
                "model": sample_record.get(
                    "model"
                ),
            }

    distribution = vulnerability_constraints.get(
        "distribution",
        "",
    )
    normalized_distribution = pep503_normalize(
        distribution
    )

    discrete_evidence_status = (
        validate_exposed_release_context(
            exposed_releases=exposed_releases,
            sample_id=sample_id,
            normalized_distribution=(
                normalized_distribution
            ),
        )
    )

    distribution_constraint = find_distribution_constraint(
        api_constraints,
        normalized_distribution,
    )

    observed_api_calls = [
        call
        for call in api_constraints.get(
            "call_constraints",
            [],
        )
        if call.get("api_symbol")
    ]

    observed_api_symbols = {
        call.get("api_symbol", "")
        for call in api_constraints.get(
            "call_constraints",
            [],
        )
        if call.get("api_symbol")
    }

    evaluations: list[dict[str, Any]] = []

    if distribution_constraint is None:
        return {
            "schema_version": "avcs_evaluation_v0.1",
            "sample_id": sample_id,
            "sample_context_status": (
                sample_context_status
            ),
            "sample_context": sample_context,
            "distribution": distribution,
            "status": "api_constraint_not_found",
            "evaluations": [],
            "risk_card_candidate_count": 0,
        }

    api_constraint_status = str(
        distribution_constraint.get(
            "status",
            "unresolved",
        )
    )

    s_api = (
        distribution_constraint
        .get("s_api", {})
        .get("simplified_specifier")
        or distribution_constraint
        .get("s_api", {})
        .get("raw_specifier")
        or ""
    )

    for vulnerability in vulnerability_constraints.get(
        "vulnerabilities",
        [],
    ):
        s_vuln = vulnerability.get(
            "affected_version_specifier",
            "",
        )

        vulnerability_id = str(
            vulnerability.get(
                "vulnerability_id",
                "",
            )
        )

        vulnerability_constraint_status = str(
            vulnerability.get(
                "constraint_status",
                "resolved",
            )
        )

        if discrete_evidence_status == "matched":
            discrete_exposure = (
                find_exposed_release_evaluation(
                    exposed_releases=exposed_releases,
                    vulnerability_id=vulnerability_id,
                )
            )

            if discrete_exposure is None:
                current_discrete_evidence_status = (
                    "vulnerability_not_found"
                )
            else:
                exposure_status = str(
                    discrete_exposure.get(
                        "status",
                        "resolved",
                    )
                )

                if exposure_status == "resolved":
                    current_discrete_evidence_status = (
                        "matched"
                    )
                else:
                    current_discrete_evidence_status = (
                        exposure_status
                    )
        else:
            discrete_exposure = None
            current_discrete_evidence_status = (
                discrete_evidence_status
            )

        if api_constraint_status != "resolved":
            overlap = {
                "status": (
                    f"api_constraint_"
                    f"{api_constraint_status}"
                ),
                "has_overlap": None,
                "intersection_specifier": "",
            }

        elif (
                vulnerability_constraint_status
                != "resolved"
        ):
            overlap = {
                "status": (
                    "vulnerability_constraint_"
                    f"{vulnerability_constraint_status}"
                ),
                "has_overlap": None,
                "intersection_specifier": "",
            }

        elif not str(s_vuln).strip():
            overlap = {
                "status":
                    "vulnerability_specifier_missing",
                "has_overlap": None,
                "intersection_specifier": "",
            }

        else:
            overlap = intersect_simple_specifiers(
                s_api,
                s_vuln,
            )

        if (
                discrete_exposure is not None
                and current_discrete_evidence_status
                == "matched"
        ):
            version_evidence_mode = (
                "discrete_confirmed_releases"
            )

            confirmed_api_compatible_release_count = (
                discrete_exposure.get(
                    "confirmed_api_compatible_release_count"
                )
            )

            confirmed_exposed_release_count = (
                discrete_exposure.get(
                    "confirmed_exposed_release_count"
                )
            )

            confirmed_not_affected_release_count = (
                discrete_exposure.get(
                    "confirmed_not_affected_release_count"
                )
            )

            confirmed_exposed_releases = (
                discrete_exposure.get(
                    "confirmed_exposed_releases",
                    [],
                )
            )

            time_unknown_exposed_release_labels = (
                discrete_exposure.get(
                    "time_unknown_exposed_release_labels",
                    [],
                )
            )

            has_version_exposure = (
                    confirmed_exposed_release_count is not None
                    and confirmed_exposed_release_count > 0
            )


        elif (
                current_discrete_evidence_status
                != "not_provided"
        ):
            version_evidence_mode = (
                "discrete_evidence_unresolved"
            )

            confirmed_api_compatible_release_count = None
            confirmed_exposed_release_count = None
            confirmed_not_affected_release_count = None
            confirmed_exposed_releases = []
            time_unknown_exposed_release_labels = []

            has_version_exposure = None

        else:
            version_evidence_mode = (
                "interval_fallback"
            )

            confirmed_api_compatible_release_count = None
            confirmed_exposed_release_count = None
            confirmed_not_affected_release_count = None
            confirmed_exposed_releases = []
            time_unknown_exposed_release_labels = []

            has_version_exposure = (
                overlap.get("has_overlap")
            )

        if (
            version_evidence_mode
            == "interval_fallback"
        ):
            intersection_semantics = (
                "decision_basis"
            )
        else:
            intersection_semantics = (
                "interval_summary_only"
            )

        trigger_conditions = vulnerability.get(
            "trigger_conditions",
            {},
        )

        if not isinstance(
                trigger_conditions,
                dict,
        ):
            trigger_conditions = {}

        trigger_api_symbols = set(
            trigger_conditions.get(
                "api_symbols",
                [],
            )
        )

        direct_api_rules = (
            trigger_conditions.get(
                "direct_api_rules",
                [],
            )
        )

        if not isinstance(
            direct_api_rules,
            list,
        ):
            direct_api_rules = []

        direct_api_rules = [
            rule
            for rule in direct_api_rules
            if isinstance(
                rule,
                dict,
            )
        ]

        conditional_trigger_rules = (
            trigger_conditions.get(
                "conditional_api_rules",
                [],
            )
        )

        if not isinstance(
                conditional_trigger_rules,
                list,
        ):
            conditional_trigger_rules = []

        conditional_trigger_rules = [
            rule
            for rule in conditional_trigger_rules
            if isinstance(
                rule,
                dict,
            )
        ]

        safe_api_symbols = set(
            vulnerability.get(
                "safe_api_symbols",
                [],
            )
        )

        safe_api_rules = (
            vulnerability.get(
                "safe_api_rules",
                [],
            )
        )

        if not isinstance(
                safe_api_rules,
                list,
        ):
            safe_api_rules = []

        safe_api_rules = [
            rule
            for rule in safe_api_rules
            if isinstance(
                rule,
                dict,
            )
        ]

        # --------------------------------------------------
        # 1. 直接 Trigger API
        #
        # 例如：
        #     yaml.full_load(...)
        #
        # 继续兼容原来的 legacy trigger seed。
        # --------------------------------------------------

        direct_trigger_rule_evaluations: list[
            dict[str, Any]
        ] = []

        direct_trigger_calls: list[
            dict[str, Any]
        ] = []

        # --------------------------------------------------
        # Real Trigger Evidence:
        # 有 direct_api_rules 时，
        # 必须同时满足 API symbol 和 version scope。
        # --------------------------------------------------

        if direct_api_rules:
            for call in observed_api_calls:
                call_api_symbol = str(
                    call.get(
                        "api_symbol",
                        "",
                    )
                )

                for rule in direct_api_rules:
                    rule_api_symbol = str(
                        rule.get(
                            "api_symbol",
                            "",
                        )
                    )

                    # 与 conditional rule 一样，
                    # 只记录真正与当前 API 有关的 rule。
                    if (
                            call_api_symbol
                            != rule_api_symbol
                    ):
                        continue

                    match_result = (
                        match_direct_trigger_rule(
                            call=call,
                            rule=rule,
                            confirmed_exposed_releases=(
                                confirmed_exposed_releases
                            ),
                        )
                    )

                    rule_evaluation = {
                        "api_symbol":
                            call_api_symbol,

                        "call_text":
                            call.get(
                                "call_text",
                                "",
                            ),

                        "location":
                            call.get(
                                "location",
                                {},
                            ),

                        "call_shape":
                            call.get(
                                "call_shape",
                                {},
                            ),

                        "trigger_rule_match":
                            match_result,
                    }

                    direct_trigger_rule_evaluations.append(
                        rule_evaluation
                    )

                    if not match_result.get(
                            "matched"
                    ):
                        continue

                    direct_trigger_calls.append(
                        {
                            "api_symbol":
                                call_api_symbol,

                            "call_text":
                                call.get(
                                    "call_text",
                                    "",
                                ),

                            "location":
                                call.get(
                                    "location",
                                    {},
                                ),

                            "call_shape":
                                call.get(
                                    "call_shape",
                                    {},
                                ),

                            "trigger_match_mode":
                                "direct_rule",

                            "trigger_rule_match":
                                match_result,
                        }
                    )

        # --------------------------------------------------
        # Legacy compatibility:
        #
        # 老的 curated trigger seed 没有 direct_api_rules，
        # 因此继续使用原来的 api_symbols 判定。
        # --------------------------------------------------

        else:
            for call in observed_api_calls:
                api_symbol = str(
                    call.get(
                        "api_symbol",
                        "",
                    )
                )

                if (
                        api_symbol
                        not in trigger_api_symbols
                ):
                    continue

                direct_trigger_calls.append(
                    {
                        "api_symbol":
                            api_symbol,

                        "call_text":
                            call.get(
                                "call_text",
                                "",
                            ),

                        "location":
                            call.get(
                                "location",
                                {},
                            ),

                        "call_shape":
                            call.get(
                                "call_shape",
                                {},
                            ),

                        "trigger_match_mode":
                            "legacy_direct_api",
                    }
                )

        # --------------------------------------------------
        # 2. 条件 Trigger rule
        #
        # 例如：
        #
        # yaml.load(..., Loader=yaml.FullLoader)
        #
        # yaml.load(...)
        # + historical default FullLoader
        # --------------------------------------------------

        conditional_trigger_rule_evaluations: list[
            dict[str, Any]
        ] = []

        conditional_trigger_calls: list[
            dict[str, Any]
        ] = []

        for call in observed_api_calls:
            call_api_symbol = str(
                call.get(
                    "api_symbol",
                    "",
                )
            )

            for rule in (
                    conditional_trigger_rules
            ):
                rule_api_symbol = str(
                    rule.get(
                        "api_symbol",
                        "",
                    )
                )

                # 只记录与当前 API symbol
                # 真正相关的 conditional rule，
                # 避免输出大量无意义
                # api_symbol_not_matched。
                if (
                        call_api_symbol
                        != rule_api_symbol
                ):
                    continue

                match_result = (
                    match_conditional_trigger_rule(
                        call=call,
                        rule=rule,
                        confirmed_exposed_releases=(
                            confirmed_exposed_releases
                        ),
                    )
                )

                rule_evaluation = {
                    "api_symbol":
                        call_api_symbol,

                    "call_text":
                        call.get(
                            "call_text",
                            "",
                        ),

                    "location":
                        call.get(
                            "location",
                            {},
                        ),

                    "call_shape":
                        call.get(
                            "call_shape",
                            {},
                        ),

                    "trigger_rule_match":
                        match_result,
                }

                conditional_trigger_rule_evaluations.append(
                    rule_evaluation
                )

                if not match_result.get(
                        "matched"
                ):
                    continue

                conditional_trigger_calls.append(
                    {
                        "api_symbol":
                            call_api_symbol,

                        "call_text":
                            call.get(
                                "call_text",
                                "",
                            ),

                        "location":
                            call.get(
                                "location",
                                {},
                            ),

                        "call_shape":
                            call.get(
                                "call_shape",
                                {},
                            ),

                        "trigger_match_mode":
                            "conditional_rule",

                        "trigger_rule_match":
                            match_result,
                    }
                )

        observed_trigger_calls = (
                direct_trigger_calls
                + conditional_trigger_calls
        )

        observed_trigger_apis = sorted(
            {
                str(
                    call.get(
                        "api_symbol",
                        "",
                    )
                )
                for call
                in observed_trigger_calls
                if call.get(
                "api_symbol"
            )
            }
        )

        # --------------------------------------------------
        # 3. 直接 Safe API
        #
        # 例如：
        #     yaml.safe_load(...)
        # --------------------------------------------------

        observed_safe_api_set = {
            str(symbol)
            for symbol
            in (
                    observed_api_symbols
                    & safe_api_symbols
            )
        }

        # --------------------------------------------------
        # 4. 参数级 Safe rule
        #
        # 例如：
        # yaml.load(..., Loader=yaml.SafeLoader)
        # --------------------------------------------------

        safe_rule_evaluations: list[
            dict[str, Any]
        ] = []

        observed_safe_rule_calls: list[
            dict[str, Any]
        ] = []

        for call in observed_api_calls:
            call_api_symbol = str(
                call.get(
                    "api_symbol",
                    "",
                )
            )

            for rule in safe_api_rules:
                rule_api_symbol = str(
                    rule.get(
                        "api_symbol",
                        "",
                    )
                )

                if (
                        call_api_symbol
                        != rule_api_symbol
                ):
                    continue

                safe_match = (
                    match_safe_api_rule(
                        call=call,
                        rule=rule,
                    )
                )

                safe_evaluation = {
                    "api_symbol":
                        call_api_symbol,

                    "call_text":
                        call.get(
                            "call_text",
                            "",
                        ),

                    "location":
                        call.get(
                            "location",
                            {},
                        ),

                    "call_shape":
                        call.get(
                            "call_shape",
                            {},
                        ),

                    "safe_rule_match":
                        safe_match,
                }

                safe_rule_evaluations.append(
                    safe_evaluation
                )

                if not safe_match.get(
                        "matched"
                ):
                    continue

                observed_safe_api_set.add(
                    call_api_symbol
                )

                observed_safe_rule_calls.append(
                    safe_evaluation
                )

        observed_safe_apis = sorted(
            observed_safe_api_set
        )

        requires_untrusted_input = bool(
            trigger_conditions.get(
                "requires_untrusted_input",
                False,
            )
        )

        # --------------------------------------------------
        # Environment Preconditions
        #
        # 某些漏洞即使已经满足：
        #
        #   1. vulnerable version
        #   2. Trigger API / call shape
        #
        # 仍然依赖运行环境中的额外条件。
        #
        # 例如：
        #
        #   credential file
        #   environment configuration
        #   runtime capability
        #
        # 当前这里只读取 Trigger Evidence
        # 已经声明的环境前提，不针对具体包
        # 编写特殊规则。
        # --------------------------------------------------

        environment_context = (
            get_environment_precondition_context(
                vulnerability
            )
        )

        requires_environment_review = bool(
            environment_context.get(
                "requires_review",
                False,
            )
        )

        version_overlap = overlap.get(
            "has_overlap"
        )

        risk_card_candidate = (
                api_constraint_status
                == "resolved"

                and
                vulnerability_constraint_status
                == "resolved"

                and
                has_version_exposure is True

                and
                bool(
                    observed_trigger_calls
                )
        )

        if api_constraint_status == "unresolved":
            assessment = "api_constraint_unresolved"
        elif api_constraint_status == "partial":
            assessment = (
                "api_constraint_partial_requires_review"
        )
        elif (
            vulnerability_constraint_status
            != "resolved"
            or not str(s_vuln).strip()
        ):
            assessment = (
                "vulnerability_constraint_requires_review"
            )
        elif (
                current_discrete_evidence_status
                not in (
                    "matched",
                    "not_provided",
                )
        ):
            assessment = (
                "discrete_evidence_requires_review"
            )
        elif has_version_exposure is None:
            assessment = "version_range_requires_review"
        elif has_version_exposure is not True:
            assessment = "no_version_overlap"
        elif not observed_trigger_apis:
            assessment = "trigger_api_not_observed"
        elif requires_environment_review:
            assessment = (
                "candidate_requires_environment_review"
            )
        elif requires_untrusted_input:
            assessment = (
                "candidate_requires_input_review"
            )
        else:
            assessment = "candidate_trigger_observed"

        evaluations.append(
            {
                "vulnerability_id": vulnerability.get(
                    "vulnerability_id",
                    "",
                ),
                "severity": vulnerability.get(
                    "severity",
                    "",
                ),
                "api_constraint_status": (
                    api_constraint_status
                ),

                "vulnerability_constraint_status": (
                    vulnerability_constraint_status
                ),

                "s_api": s_api,
                "s_vuln": s_vuln,
                "version_evidence_mode": (
                    version_evidence_mode
                ),
                "discrete_evidence_status": (
                    current_discrete_evidence_status
                ),

                "has_version_exposure": (
                    has_version_exposure
                ),

                "confirmed_api_compatible_release_count": (
                    confirmed_api_compatible_release_count
                ),

                "confirmed_exposed_release_count": (
                    confirmed_exposed_release_count
                ),

                "confirmed_not_affected_release_count": (
                    confirmed_not_affected_release_count
                ),

                "confirmed_exposed_releases": (
                    confirmed_exposed_releases
                ),

                "time_unknown_exposed_release_labels": (
                    time_unknown_exposed_release_labels
                ),
                "fixed_version_specifier": (
                    vulnerability.get(
                        "fixed_version_specifier",
                        "",
                    )
                ),
                "version_overlap": version_overlap,
                "intersection_specifier": overlap.get(
                    "intersection_specifier",
                    "",
                ),
                "intersection_semantics": (
                    intersection_semantics
                ),
                "overlap_status": overlap.get(
                    "status",
                    "",
                ),
                "observed_api_symbols": sorted(
                    observed_api_symbols
                ),
                "trigger_api_symbols": sorted(
                    trigger_api_symbols
                ),
                "direct_trigger_api_symbols": (
                    sorted(
                        {
                            str(
                                rule.get(
                                    "api_symbol",
                                    "",
                                )
                            )
                            for rule
                            in direct_api_rules
                            if rule.get(
                            "api_symbol"
                        )
                        }
                    )
                ),

                "direct_trigger_rule_evaluations": (
                    direct_trigger_rule_evaluations
                ),
                "conditional_trigger_api_symbols": (
                    sorted(
                        {
                            str(
                                rule.get(
                                    "api_symbol",
                                    "",
                                )
                            )
                            for rule
                            in conditional_trigger_rules
                            if rule.get(
                            "api_symbol"
                        )
                        }
                    )
                ),

                "conditional_trigger_rule_evaluations": (
                    conditional_trigger_rule_evaluations
                ),
                "observed_trigger_apis": (
                    observed_trigger_apis
                ),
                "observed_trigger_calls": (
                    observed_trigger_calls
                ),
                "observed_safe_apis": (
                    observed_safe_apis
                ),
                "safe_rule_evaluations": (
                    safe_rule_evaluations
                ),

                "observed_safe_rule_calls": (
                    observed_safe_rule_calls
                ),
                "requires_untrusted_input": (
                    requires_untrusted_input
                ),

                "environment_preconditions_present": (
                    environment_context.get(
                        "present",
                        False,
                    )
                ),

                "environment_preconditions_status": (
                    environment_context.get(
                        "evaluation_status",
                        "not_required",
                    )
                ),

                "environment_preconditions": (
                    environment_context.get(
                        "preconditions",
                        {},
                    )
                ),

                "requires_environment_review": (
                    requires_environment_review
                ),

                "assessment": assessment,
                "risk_card_candidate": (
                    risk_card_candidate
                ),
                "evidence_ref": vulnerability.get(
                    "evidence_ref",
                    "",
                ),
            }
        )

    candidate_count = sum(
        evaluation["risk_card_candidate"]
        for evaluation in evaluations
    )

    return {
        "schema_version": "avcs_evaluation_v0.1",
        "sample_id": sample_id,
        "sample_context_status": (
            sample_context_status
        ),
        "sample_context": sample_context,
        "distribution": distribution,
        "normalized_distribution": (
            normalized_distribution
        ),
        "status": "evaluated",
        "evaluation_count": len(evaluations),
        "risk_card_candidate_count": (
            candidate_count
        ),
        "evaluations": evaluations,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Evaluate AVCS version overlap and "
            "vulnerability trigger evidence."
        )
    )

    parser.add_argument(
        "--api-constraints",
        type=Path,
        required=True,
    )

    parser.add_argument(
        "--vulnerability-constraints",
        type=Path,
        required=True,
    )

    parser.add_argument(
        "--sample-records",
        type=Path,
        default=None,
    )

    parser.add_argument(
        "--exposed-releases",
        type=Path,
        default=None,
        help=(
            "Optional discrete AVCS exposed "
            "release evidence JSON."
        ),
    )

    parser.add_argument(
        "--out",
        type=Path,
        required=True,
    )

    args = parser.parse_args()

    result = evaluate_avcs(
        api_constraints_path=args.api_constraints,
        vulnerability_constraints_path=(
            args.vulnerability_constraints
        ),
        sample_records_path=args.sample_records,
        exposed_releases_path=(
            args.exposed_releases
        ),
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
        f"[OK] sample id: {result['sample_id']}"
    )
    print(
        f"[OK] evaluations: "
        f"{result.get('evaluation_count', 0)}"
    )
    print(
        f"[OK] Risk Card candidates: "
        f"{result['risk_card_candidate_count']}"
    )

    for evaluation in result.get(
        "evaluations",
        [],
    ):
        print(
            f"[OK] "
            f"{evaluation['vulnerability_id']} | "
            f"intersection: "
            f"{evaluation['intersection_specifier'] or '(none)'} | "
            f"assessment: "
            f"{evaluation['assessment']}"
        )

    print(
        f"[OK] result saved to: {args.out}"
    )


if __name__ == "__main__":
    main()