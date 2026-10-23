from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from packaging.version import (
    InvalidVersion,
    Version,
)


SCHEMA_VERSION = (
    "avcs_api_history_evidence_v0.1"
)


def read_json(
    path: Path,
) -> dict[str, Any]:
    return json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )


def normalize_boolean_observation(
    value: Any,
) -> str:
    """
    将 defined=True/False
    转换为统一的三态支持结果。
    """
    if value is True:
        return "supported"

    if value is False:
        return "unsupported"

    return "unknown"


def get_release_status(
    release: dict[str, Any],
    observation_key: str,
    observation_field: str,
) -> str:
    """
    从一个 release 的 raw observation 中，
    提取某项 API 能力的支持状态。
    """
    if (
        release.get("status")
        != "resolved"
    ):
        return "unknown"

    observations = release.get(
        "observations",
        {},
    )

    observation = observations.get(
        observation_key,
        {},
    )

    value = observation.get(
        observation_field
    )

    if isinstance(
            value,
            bool,
    ):
        return (
            normalize_boolean_observation(
                value
            )
        )

    if value in {
        "supported",
        "unsupported",
        "unknown",
    }:
        return str(value)

    return "unknown"


def derive_monotonic_lower_bound(
    releases: list[dict[str, Any]],
    observation_key: str,
    observation_field: str,
) -> dict[str, Any]:
    """
    从逐 release observation 中推导：

        unsupported ...
        unsupported
        supported
        supported ...
        supported

    这种单调支持历史的最小下界。

    例如：

        4.2b4 unsupported
        5.1b1 supported
        5.1b3 supported
        ...
        6.0.3 supported

    得到：

        >=5.1b1

    如果存在 unknown，
    或 supported 后又出现 unsupported，
    则不强行生成确定版本规则。
    """
    observations: list[
        dict[str, Any]
    ] = []

    for release in releases:
        version_text = str(
            release.get(
                "version",
                "",
            )
        )

        try:
            parsed_version = Version(
                version_text
            )
        except InvalidVersion:
            continue

        status = get_release_status(
            release=release,
            observation_key=(
                observation_key
            ),
            observation_field=(
                observation_field
            ),
        )

        observations.append(
            {
                "version":
                    version_text,

                "parsed_version":
                    parsed_version,

                "status":
                    status,

                "source_mode":
                    release.get(
                        "source_mode"
                    ),

                "source_path":
                    release.get(
                        "source_path"
                    ),

                "source_sha256":
                    release.get(
                        "source_sha256"
                    ),
            }
        )

    observations.sort(
        key=lambda row: (
            row["parsed_version"]
        )
    )

    if not observations:
        return {
            "status":
                "unresolved",

            "reason":
                "no_release_observations",

            "version_specifier":
                "",
        }

    unknown_rows = [
        row
        for row in observations
        if row["status"] == "unknown"
    ]

    supported_rows = [
        row
        for row in observations
        if row["status"] == "supported"
    ]

    unsupported_rows = [
        row
        for row in observations
        if row["status"] == "unsupported"
    ]

    if not supported_rows:
        return {
            "status":
                "unresolved",

            "reason":
                "no_supported_release_observed",

            "version_specifier":
                "",

            "observation_count":
                len(observations),

            "supported_count":
                0,

            "unsupported_count":
                len(unsupported_rows),

            "unknown_count":
                len(unknown_rows),
        }

    first_supported = min(
        supported_rows,
        key=lambda row: (
            row["parsed_version"]
        ),
    )

    first_supported_version = (
        first_supported["parsed_version"]
    )

    unsupported_after_support = [
        row
        for row in unsupported_rows
        if (
            row["parsed_version"]
            > first_supported_version
        )
    ]

    unknown_at_or_after_support = [
        row
        for row in unknown_rows
        if (
            row["parsed_version"]
            >= first_supported_version
        )
    ]

    unknown_before_support = [
        row
        for row in unknown_rows
        if (
            row["parsed_version"]
            < first_supported_version
        )
    ]

    prior_unsupported = [
        row
        for row in unsupported_rows
        if (
            row["parsed_version"]
            < first_supported_version
        )
    ]

    last_unsupported_before_support = (
        max(
            prior_unsupported,
            key=lambda row: (
                row["parsed_version"]
            ),
        )
        if prior_unsupported
        else None
    )

    if unsupported_after_support:
        return {
            "status":
                "non_monotonic",

            "reason":
                "unsupported_release_after_"
                "first_supported_release",

            "version_specifier":
                "",

            "first_supported_version":
                str(
                    first_supported[
                        "version"
                    ]
                ),

            "unsupported_after_support":
                [
                    row["version"]
                    for row
                    in unsupported_after_support
                ],
        }

    if (
        unknown_at_or_after_support
        or unknown_before_support
    ):
        return {
            "status":
                "partial",

            "reason":
                "unknown_release_observations",

            "version_specifier":
                "",

            "first_supported_version":
                str(
                    first_supported[
                        "version"
                    ]
                ),

            "unknown_versions":
                [
                    row["version"]
                    for row in unknown_rows
                ],
        }

    return {
        "status":
            "resolved",

        "version_specifier": (
            f">={first_supported['version']}"
        ),

        "first_supported_version":
            first_supported[
                "version"
            ],

        "last_unsupported_version": (
            last_unsupported_before_support[
                "version"
            ]
            if last_unsupported_before_support
            else None
        ),

        "observation_count":
            len(observations),

        "supported_count":
            len(supported_rows),

        "unsupported_count":
            len(unsupported_rows),

        "unknown_count":
            len(unknown_rows),

        "supported_versions": [
            row["version"]
            for row in supported_rows
        ],

        "unsupported_versions": [
            row["version"]
            for row in unsupported_rows
        ],

        "boundary_evidence": {
            "first_supported": {
                "version":
                    first_supported[
                        "version"
                    ],

                "source_mode":
                    first_supported.get(
                        "source_mode"
                    ),

                "source_path":
                    first_supported.get(
                        "source_path"
                    ),

                "source_sha256":
                    first_supported.get(
                        "source_sha256"
                    ),
            },

            "last_unsupported": (
                {
                    "version":
                        last_unsupported_before_support[
                            "version"
                        ],

                    "source_mode":
                        last_unsupported_before_support.get(
                            "source_mode"
                        ),

                    "source_path":
                        last_unsupported_before_support.get(
                            "source_path"
                        ),

                    "source_sha256":
                        last_unsupported_before_support.get(
                            "source_sha256"
                        ),
                }
                if last_unsupported_before_support
                else None
            ),
        },
    }

def derive_supported_window_before_transition(
    base_derivation: dict[str, Any],
    transition_derivation: dict[str, Any],
    transition_name: str,
) -> dict[str, Any]:
    """
    根据两个真实历史边界构造一个有限支持窗口。

    例如：

        yaml.load 存在
        >=3.01

    同时：

        Loader 从 6.0b1 起变成必填
        >=6.0b1

    那么：

        Loader omitted

    的真实支持窗口就是：

        >=3.01,<6.0b1
    """
    if (
        base_derivation.get(
            "status"
        )
        != "resolved"
    ):
        return {
            "status": "partial",
            "reason": (
                "base_derivation_"
                "not_resolved"
            ),
            "version_specifier": "",
        }

    if (
        transition_derivation.get(
            "status"
        )
        != "resolved"
    ):
        return {
            "status": "partial",
            "reason": (
                "transition_derivation_"
                "not_resolved"
            ),
            "version_specifier": "",
        }

    first_supported_version = str(
        base_derivation.get(
            "first_supported_version",
            "",
        )
    )

    first_transition_version = str(
        transition_derivation.get(
            "first_supported_version",
            "",
        )
    )

    if (
        not first_supported_version
        or not first_transition_version
    ):
        return {
            "status": "unresolved",
            "reason": (
                "boundary_version_missing"
            ),
            "version_specifier": "",
        }

    try:
        start_version = Version(
            first_supported_version
        )

        transition_version = Version(
            first_transition_version
        )

    except InvalidVersion as exc:
        return {
            "status": "unresolved",
            "reason": "invalid_boundary_version",
            "version_specifier": "",
            "error": str(exc),
        }

    if (
        transition_version
        <= start_version
    ):
        return {
            "status": "unresolved",
            "reason": (
                "invalid_transition_order"
            ),
            "version_specifier": "",
        }

    return {
        "status": "resolved",

        "version_specifier": (
            f">={first_supported_version},"
            f"<{first_transition_version}"
        ),

        "first_supported_version":
            first_supported_version,

        "first_excluded_version":
            first_transition_version,

        "transition_name":
            transition_name,

        "base_derivation":
            base_derivation,

        "transition_derivation":
            transition_derivation,
    }

def build_version_rule(
    *,
    rule_id: str,
    derivation: dict[str, Any],
    required_positional_args_min: int,
    required_positional_args_max: int,
    required_keyword_args: list[str],
    supported_keyword_args: list[str],
    forbidden_keyword_args: (
        list[str] | None
    ) = None,
) -> dict[str, Any]:
    """
    把 evidence derivation 转换为
    resolve_api_version_constraints.py
    可以直接消费的 version_rule。
    """
    if (
        derivation.get("status")
        != "resolved"
    ):
        return {
            "rule_id":
                rule_id,

            "status":
                derivation.get(
                    "status",
                    "unresolved",
                ),

            "version_specifier":
                "",

            "derivation":
                derivation,
        }

    return {
        "rule_id":
            rule_id,

        "status":
            "resolved",

        "version_specifier":
            derivation[
                "version_specifier"
            ],

        "required_positional_args_min":
            required_positional_args_min,

        "required_positional_args_max":
            required_positional_args_max,

        "required_keyword_args":
            required_keyword_args,

        "supported_keyword_args":
            supported_keyword_args,

        "forbidden_keyword_args": (
            forbidden_keyword_args
            or []
        ),

        "evidence_type":
            "real_api_history_evidence",

        "evidence_ref": (
            "PyYAML historical release "
            "source probe"
        ),

        "evidence_note": (
            "Version constraint derived "
            "from per-release official "
            "source evidence."
        ),

        "derivation":
            derivation,
    }


def normalize_history(
    raw_evidence: dict[str, Any],
    raw_path: Path,
) -> dict[str, Any]:
    releases = raw_evidence.get(
        "releases",
        [],
    )

    load_derivation = (
        derive_monotonic_lower_bound(
            releases=releases,
            observation_key=(
                "yaml.load"
            ),
            observation_field="defined",
        )
    )

    load_loader_keyword_derivation = (
        derive_monotonic_lower_bound(
            releases=releases,
            observation_key=(
                "yaml.load"
            ),
            observation_field=(
                "supports_loader_keyword"
            ),
        )
    )

    load_loader_required_derivation = (
        derive_monotonic_lower_bound(
            releases=releases,
            observation_key=(
                "yaml.load"
            ),
            observation_field=(
                "loader_parameter_required"
            ),
        )
    )

    load_loader_omitted_derivation = (
        derive_supported_window_before_transition(
            base_derivation=(
                load_derivation
            ),
            transition_derivation=(
                load_loader_required_derivation
            ),
            transition_name=(
                "loader_becomes_required"
            ),
        )
    )

    safe_load_derivation = (
        derive_monotonic_lower_bound(
            releases=releases,
            observation_key=(
                "yaml.safe_load"
            ),
            observation_field="defined",
        )
    )

    safe_dump_derivation = (
        derive_monotonic_lower_bound(
            releases=releases,
            observation_key=(
                "yaml.safe_dump"
            ),
            observation_field="defined",
        )
    )

    safe_dump_sort_keys_derivation = (
        derive_monotonic_lower_bound(
            releases=releases,
            observation_key=(
                "yaml.safe_dump"
                "(sort_keys=...)"
            ),
            observation_field="status",
        )
    )

    full_load_derivation = (
        derive_monotonic_lower_bound(
            releases=releases,
            observation_key=(
                "yaml.full_load"
            ),
            observation_field="defined",
        )
    )

    entries = [
        {
            "distribution":
                "PyYAML",

            "api_symbol":
                "yaml.load",

            "api_kind":
                "function",

            "version_rules": [
                build_version_rule(
                    rule_id=(
                        "pyyaml_load_"
                        "loader_omitted"
                    ),
                    derivation=(
                        load_loader_omitted_derivation
                    ),
                    required_positional_args_min=1,
                    required_positional_args_max=1,
                    required_keyword_args=[],
                    supported_keyword_args=[],
                    forbidden_keyword_args=[
                        "Loader"
                    ],
                ),

                build_version_rule(
                    rule_id=(
                        "pyyaml_load_"
                        "loader_keyword"
                    ),
                    derivation=(
                        load_loader_keyword_derivation
                    ),
                    required_positional_args_min=1,
                    required_positional_args_max=1,
                    required_keyword_args=[
                        "Loader"
                    ],
                    supported_keyword_args=[
                        "Loader"
                    ],
                ),
            ],
        },
        {
            "distribution":
                "PyYAML",

            "api_symbol":
                "yaml.safe_load",

            "api_kind":
                "function",

            "version_rules": [
                build_version_rule(
                    rule_id=(
                        "pyyaml_safe_load_basic"
                    ),
                    derivation=(
                        safe_load_derivation
                    ),
                    required_positional_args_min=1,
                    required_positional_args_max=1,
                    required_keyword_args=[],
                    supported_keyword_args=[],
                )
            ],
        },

        {
            "distribution":
                "PyYAML",

            "api_symbol":
                "yaml.safe_dump",

            "api_kind":
                "function",

            "version_rules": [
                build_version_rule(
                    rule_id=(
                        "pyyaml_safe_dump_basic"
                    ),
                    derivation=(
                        safe_dump_derivation
                    ),
                    required_positional_args_min=1,
                    required_positional_args_max=2,
                    required_keyword_args=[],
                    supported_keyword_args=[],
                ),

                build_version_rule(
                    rule_id=(
                        "pyyaml_safe_dump_"
                        "sort_keys"
                    ),
                    derivation=(
                        safe_dump_sort_keys_derivation
                    ),
                    required_positional_args_min=1,
                    required_positional_args_max=2,
                    required_keyword_args=[
                        "sort_keys"
                    ],
                    supported_keyword_args=[
                        "sort_keys"
                    ],
                ),
            ],
        },

        {
            "distribution":
                "PyYAML",

            "api_symbol":
                "yaml.full_load",

            "api_kind":
                "function",

            "version_rules": [
                build_version_rule(
                    rule_id=(
                        "pyyaml_full_load_basic"
                    ),
                    derivation=(
                        full_load_derivation
                    ),
                    required_positional_args_min=1,
                    required_positional_args_max=1,
                    required_keyword_args=[],
                    supported_keyword_args=[],
                )
            ],
        },
    ]

    derivation_statuses = [
        load_derivation.get(
            "status"
        ),
        load_loader_keyword_derivation.get(
            "status"
        ),

        load_loader_required_derivation.get(
            "status"
        ),

        load_loader_omitted_derivation.get(
            "status"
        ),
        safe_load_derivation.get(
            "status"
        ),
        safe_dump_derivation.get(
            "status"
        ),
        safe_dump_sort_keys_derivation.get(
            "status"
        ),
        full_load_derivation.get(
            "status"
        ),
    ]

    if all(
        status == "resolved"
        for status in derivation_statuses
    ):
        overall_status = "resolved"

    elif any(
        status == "resolved"
        for status in derivation_statuses
    ):
        overall_status = "partial"

    else:
        overall_status = "unresolved"

    return {
        "schema_version":
            SCHEMA_VERSION,

        "ecosystem":
            "pypi",

        "distribution":
            "PyYAML",

        "source_mode":
            "normalized_real_api_history",

        "source_raw_evidence_file":
            str(raw_path).replace(
                "\\",
                "/",
            ),

        "source_raw_schema_version":
            raw_evidence.get(
                "schema_version",
                "",
            ),

        "source_query_time":
            raw_evidence.get(
                "queried_at"
            ),

        "source_release_count":
            raw_evidence.get(
                "release_count"
            ),

        "status":
            overall_status,

        "entries":
            entries,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Normalize real PyYAML "
            "per-release API evidence "
            "into AVCS API history rules."
        )
    )

    parser.add_argument(
        "--raw",
        type=Path,
        default=Path(
            "output/"
            "pyyaml_api_history_"
            "raw_evidence_v0_3.json"
        ),
    )

    parser.add_argument(
        "--out",
        type=Path,
        default=Path(
            "output/"
            "pyyaml_api_history_"
            "evidence_v0.json"
        ),
    )

    args = parser.parse_args()

    raw_evidence = read_json(
        args.raw
    )

    result = normalize_history(
        raw_evidence=raw_evidence,
        raw_path=args.raw,
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
        f"[OK] status: "
        f"{result['status']}"
    )

    for entry in result["entries"]:
        api_symbol = entry[
            "api_symbol"
        ]

        for rule in entry[
            "version_rules"
        ]:
            print(
                f"[OK] {api_symbol}"
                f" | {rule['rule_id']}"
                f" | status="
                f"{rule.get('status')}"
                f" | S_api="
                f"{rule.get('version_specifier')}"
            )

    print(
        f"[OK] result saved to: "
        f"{args.out}"
    )


if __name__ == "__main__":
    main()