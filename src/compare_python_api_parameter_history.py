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
    "avcs_python_api_parameter_history_v0.1"
)


def read_json(
    path: Path,
) -> dict[str, Any]:
    return json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )


def build_refinement_map(
    paths: list[Path],
    normalized_distribution: str,
    api_symbol: str,
    parameter_name: str,
) -> dict[str, dict[str, Any]]:
    """
    将更强的历史语义分析证据按 version 建索引。

    当前主要接收：
        avcs_python_keyword_forwarding_v0.1

    例如：
        PyJWT 0.4.3
        algorithms
        unknown from signature
            ↓
        keyword forwarding analysis
            ↓
        unsupported

    这里不会静默接受来源不一致的 evidence。
    """

    result: dict[
        str,
        dict[str, Any],
    ] = {}

    for path in paths:
        evidence = read_json(
            path
        )

        evidence_distribution = str(
            evidence.get(
                "normalized_distribution",
                "",
            )
        ).strip()

        evidence_symbol = str(
            evidence.get(
                "api_symbol",
                "",
            )
        ).strip()

        evidence_keyword = str(
            evidence.get(
                "keyword",
                "",
            )
        ).strip()

        version = str(
            evidence.get(
                "version",
                "",
            )
        ).strip()

        if (
            evidence_distribution
            != normalized_distribution
        ):
            raise RuntimeError(
                "refinement evidence belongs "
                "to a different distribution: "
                f"{path}"
            )

        if evidence_symbol != api_symbol:
            raise RuntimeError(
                "refinement evidence refers "
                "to a different API symbol: "
                f"{path}"
            )

        if (
            evidence_keyword
            != parameter_name
        ):
            raise RuntimeError(
                "refinement evidence refers "
                "to a different parameter: "
                f"{path}"
            )

        if not version:
            raise RuntimeError(
                "refinement evidence has "
                f"no version: {path}"
            )

        if version in result:
            raise RuntimeError(
                "duplicate refinement evidence "
                f"for version {version}"
            )

        result[version] = evidence

    return result


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
        if not isinstance(
            parameter,
            dict,
        ):
            continue

        if (
            str(
                parameter.get(
                    "name",
                    "",
                )
            )
            == parameter_name
        ):
            return parameter

    return None


def classify_parameter_state(
    evidence: dict[str, Any],
    parameter_name: str,
    refinement_by_version: dict[
        str,
        dict[str, Any],
    ],
) -> dict[str, Any]:
    version = str(
        evidence.get(
            "version",
            "",
        )
    )

    status = str(
        evidence.get(
            "status",
            "",
        )
    )

    signature = evidence.get(
        "public_signature"
    )

    refinement = (
        refinement_by_version.get(
            version
        )
    )

    base = {
        "version":
            version,

        "api_symbol":
            evidence.get(
                "api_symbol",
                "",
            ),

        "resolution_status":
            status,

        "implementation":
            evidence.get(
                "implementation"
            ),

        "resolution_chain":
            evidence.get(
                "resolution_chain",
                [],
            ),

        "refinement_evidence":
            refinement,
    }

    if (
        status != "resolved"
        or not isinstance(
            signature,
            dict,
        )
    ):
        return {
            **base,

            "parameter":
                parameter_name,

            "parameter_explicit":
                None,

            "accepts_var_keyword":
                None,

            "support_status":
                "unknown",

            "support_reason":
                "public_signature_unresolved",

            "parameter_evidence":
                None,
        }

    parameter = find_parameter(
        signature,
        parameter_name,
    )

    accepts_var_keyword = bool(
        signature.get(
            "accepts_var_keyword",
            False,
        )
    )

    # 最强、最直接的证据：
    # public signature 明确包含参数。
    if parameter is not None:
        return {
            **base,

            "parameter":
                parameter_name,

            "parameter_explicit":
                True,

            "accepts_var_keyword":
                accepts_var_keyword,

            "support_status":
                "supported",

            "support_reason":
                "explicit_parameter",

            "parameter_evidence":
                parameter,
        }

    # 没有显式参数，但存在 **kwargs：
    # 仅凭 signature 不能判断。
    #
    # 如果有更强的 forwarding/body-analysis
    # evidence，则允许它把 unknown 收紧。
    if accepts_var_keyword:
        if isinstance(
            refinement,
            dict,
        ):
            refinement_status = str(
                refinement.get(
                    "support_status",
                    "",
                )
            )

            refinement_resolution = str(
                refinement.get(
                    "status",
                    "",
                )
            )

            if (
                refinement_resolution
                == "resolved"
                and refinement_status
                in {
                    "supported",
                    "unsupported",
                }
            ):
                return {
                    **base,

                    "parameter":
                        parameter_name,

                    "parameter_explicit":
                        False,

                    "accepts_var_keyword":
                        True,

                    "support_status":
                        refinement_status,

                    "support_reason":
                        (
                            "refined_by_"
                            "keyword_forwarding_evidence"
                        ),

                    "parameter_evidence":
                        None,

                    "refinement_reason":
                        refinement.get(
                            "support_reason"
                        ),

                    "refinement_assessment":
                        refinement.get(
                            "assessment"
                        ),
                }

        return {
            **base,

            "parameter":
                parameter_name,

            "parameter_explicit":
                False,

            "accepts_var_keyword":
                True,

            "support_status":
                "unknown",

            "support_reason":
                (
                    "parameter_not_explicit_"
                    "but_var_keyword_present"
                ),

            "parameter_evidence":
                None,
        }

    return {
        **base,

        "parameter":
            parameter_name,

        "parameter_explicit":
            False,

        "accepts_var_keyword":
            False,

        "support_status":
            "unsupported",

        "support_reason":
            (
                "parameter_absent_and_"
                "no_var_keyword"
            ),

        "parameter_evidence":
            None,
    }


def version_key(
    record: dict[str, Any],
) -> tuple[int, Any]:
    version_text = str(
        record.get(
            "version",
            "",
        )
    )

    try:
        return (
            0,
            Version(
                version_text
            ),
        )
    except InvalidVersion:
        return (
            1,
            version_text,
        )


def state_key(
    record: dict[str, Any],
) -> tuple[Any, ...]:
    parameter_evidence = (
        record.get(
            "parameter_evidence"
        )
    )

    if isinstance(
        parameter_evidence,
        dict,
    ):
        default = parameter_evidence.get(
            "default",
            {},
        )

        if not isinstance(
            default,
            dict,
        ):
            default = {}

        parameter_kind = (
            parameter_evidence.get(
                "kind"
            )
        )

        required = (
            parameter_evidence.get(
                "required"
            )
        )

        default_source = (
            default.get(
                "source_text"
            )
        )
    else:
        parameter_kind = None
        required = None
        default_source = None

    return (
        record.get(
            "support_status"
        ),

        record.get(
            "parameter_explicit"
        ),

        record.get(
            "accepts_var_keyword"
        ),

        parameter_kind,
        required,
        default_source,
    )


def build_transitions(
    records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    transitions: list[
        dict[str, Any]
    ] = []

    previous: (
        dict[str, Any]
        | None
    ) = None

    for record in records:
        if previous is None:
            previous = record
            continue

        if (
            state_key(previous)
            != state_key(record)
        ):
            transitions.append(
                {
                    "from_version":
                        previous.get(
                            "version"
                        ),

                    "to_version":
                        record.get(
                            "version"
                        ),

                    "from_support_status":
                        previous.get(
                            "support_status"
                        ),

                    "to_support_status":
                        record.get(
                            "support_status"
                        ),

                    "from_parameter_explicit":
                        previous.get(
                            "parameter_explicit"
                        ),

                    "to_parameter_explicit":
                        record.get(
                            "parameter_explicit"
                        ),

                    "from_accepts_var_keyword":
                        previous.get(
                            "accepts_var_keyword"
                        ),

                    "to_accepts_var_keyword":
                        record.get(
                            "accepts_var_keyword"
                        ),

                    "transition_reason":
                        "observable_signature_state_changed",
                }
            )

        previous = record

    return transitions


def derive_lower_bound_candidate(
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    supported_indexes = [
        index
        for index, record
        in enumerate(records)
        if record.get(
            "support_status"
        )
        == "supported"
    ]

    if not supported_indexes:
        return {
            "status":
                "no_supported_version_observed",

            "version_specifier":
                None,

            "boundary_version":
                None,
        }

    first_supported_index = (
        supported_indexes[0]
    )

    first_supported = records[
        first_supported_index
    ]

    earlier = records[
        :first_supported_index
    ]

    if any(
        record.get(
            "support_status"
        )
        == "unknown"
        for record in earlier
    ):
        return {
            "status":
                "blocked_by_unknown_predecessor",

            "version_specifier":
                None,

            "boundary_version":
                first_supported.get(
                    "version"
                ),

            "note":
                (
                    "At least one earlier release "
                    "has unresolved keyword support, "
                    "so a lower-bound version rule "
                    "cannot be safely compiled yet."
                ),
        }

    if any(
        record.get(
            "support_status"
        )
        == "supported"
        for record in earlier
    ):
        return {
            "status":
                "non_initial_supported_state",

            "version_specifier":
                None,

            "boundary_version":
                first_supported.get(
                    "version"
                ),
        }

    later = records[
        first_supported_index:
    ]

    if any(
        record.get(
            "support_status"
        )
        != "supported"
        for record in later
    ):
        return {
            "status":
                "non_monotonic_or_incomplete_history",

            "version_specifier":
                None,

            "boundary_version":
                first_supported.get(
                    "version"
                ),
        }

    boundary = str(
        first_supported.get(
            "version",
            "",
        )
    )

    if not boundary:
        return {
            "status":
                "boundary_version_missing",

            "version_specifier":
                None,

            "boundary_version":
                None,
        }

    return {
        "status":
            "candidate",

        "version_specifier":
            f">={boundary}",

        "boundary_version":
            boundary,

        "note":
            (
                "All observed earlier releases "
                "are explicitly unsupported and "
                "all observed releases from the "
                "boundary onward are supported. "
                "This remains an observed-history "
                "candidate, not benchmark truth."
            ),
    }


def compare_parameter_history(
    evidence_paths: list[Path],
    parameter_name: str,
    refinement_paths: list[Path],
) -> dict[str, Any]:
    if not evidence_paths:
        raise ValueError(
            "at least one evidence "
            "file is required"
        )

    evidence_rows = [
        read_json(path)
        for path in evidence_paths
    ]

    distributions = {
        str(
            row.get(
                "normalized_distribution",
                "",
            )
        )
        for row in evidence_rows
    }

    api_symbols = {
        str(
            row.get(
                "api_symbol",
                "",
            )
        )
        for row in evidence_rows
    }

    if len(distributions) != 1:
        raise RuntimeError(
            "evidence files belong to "
            "different distributions"
        )

    if len(api_symbols) != 1:
        raise RuntimeError(
            "evidence files refer to "
            "different API symbols"
        )

    normalized_distribution = next(
        iter(
            distributions
        )
    )

    api_symbol = next(
        iter(
            api_symbols
        )
    )

    refinement_by_version = (
        build_refinement_map(
            paths=refinement_paths,
            normalized_distribution=
                normalized_distribution,
            api_symbol=
                api_symbol,
            parameter_name=
                parameter_name,
        )
    )

    records = [
        classify_parameter_state(
            evidence=row,
            parameter_name=
            parameter_name,
            refinement_by_version=
            refinement_by_version,
        )
        for row in evidence_rows
    ]

    records.sort(
        key=version_key
    )

    supported_versions = [
        record["version"]
        for record in records
        if record.get(
            "support_status"
        )
        == "supported"
    ]

    unsupported_versions = [
        record["version"]
        for record in records
        if record.get(
            "support_status"
        )
        == "unsupported"
    ]

    unknown_versions = [
        record["version"]
        for record in records
        if record.get(
            "support_status"
        )
        == "unknown"
    ]

    lower_bound_candidate = (
        derive_lower_bound_candidate(
            records
        )
    )

    return {
        "schema_version":
            SCHEMA_VERSION,

        "distribution":
            evidence_rows[0].get(
                "distribution",
                "",
            ),

        "normalized_distribution":
            evidence_rows[0].get(
                "normalized_distribution",
                "",
            ),

        "api_symbol":
            evidence_rows[0].get(
                "api_symbol",
                "",
            ),

        "parameter":
            parameter_name,

        "refinement_evidence_count":
            len(
                refinement_by_version
            ),

        "refinement_versions":
            sorted(
                refinement_by_version
            ),

        "release_count":
            len(records),

        "supported_version_count":
            len(
                supported_versions
            ),

        "unsupported_version_count":
            len(
                unsupported_versions
            ),

        "unknown_version_count":
            len(
                unknown_versions
            ),

        "supported_versions":
            supported_versions,

        "unsupported_versions":
            unsupported_versions,

        "unknown_versions":
            unknown_versions,

        "records":
            records,

        "transitions":
            build_transitions(
                records
            ),

        "lower_bound_candidate":
            lower_bound_candidate,
    }


def main() -> None:
    parser = (
        argparse.ArgumentParser(
            description=(
                "Compare one public Python "
                "API parameter across historical "
                "release evidence files."
            )
        )
    )

    parser.add_argument(
        "--evidence",
        action="append",
        required=True,
        type=Path,
        help=(
            "Public API symbol evidence JSON. "
            "Repeat for multiple versions."
        ),
    )

    parser.add_argument(
        "--parameter",
        required=True,
    )

    parser.add_argument(
        "--refinement-evidence",
        action="append",
        default=[],
        type=Path,
        help=(
            "Optional stronger historical "
            "semantic evidence used to refine "
            "signature-level unknown states. "
            "Repeat for multiple versions."
        ),
    )

    parser.add_argument(
        "--out",
        required=True,
        type=Path,
    )

    args = parser.parse_args()

    result = compare_parameter_history(
        evidence_paths=
        args.evidence,

        parameter_name=
        args.parameter.strip(),

        refinement_paths=
        args.refinement_evidence,
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
        f"[OK] API symbol: "
        f"{result['api_symbol']}"
    )

    print(
        f"[OK] parameter: "
        f"{result['parameter']}"
    )

    print(
        f"[OK] releases: "
        f"{result['release_count']}"
    )

    print(
        f"[OK] supported: "
        f"{result['supported_version_count']}"
    )

    print(
        f"[OK] unsupported: "
        f"{result['unsupported_version_count']}"
    )

    print(
        f"[OK] unknown: "
        f"{result['unknown_version_count']}"
    )

    candidate = result[
        "lower_bound_candidate"
    ]

    print(
        f"[OK] lower-bound status: "
        f"{candidate['status']}"
    )

    print(
        f"[OK] version specifier: "
        f"{candidate.get('version_specifier')}"
    )

    print(
        f"[OK] result saved to: "
        f"{args.out}"
    )


if __name__ == "__main__":
    main()