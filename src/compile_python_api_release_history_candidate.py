from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from compare_python_api_parameter_history import (
    derive_lower_bound_candidate,
    version_key,
)


SCHEMA_VERSION = (
    "avcs_python_api_release_history_candidate_v0.1"
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


def build_support_transitions(
    records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
只记录与 API parameter compatibility
真正有关的 support-state transition。

例如：

    version_A unsupported
        ->
    version_B supported

这表示 API compatibility 在两个历史版本之间
发生了真实边界变化。

如果两个相邻版本最终 support state 相同，
即使底层 signature、forwarding evidence
或其他元数据发生变化，也不应被当作
新的 API compatibility boundary。
"""

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

        previous_status = str(
            previous.get(
                "support_status",
                "unknown",
            )
        )

        current_status = str(
            record.get(
                "support_status",
                "unknown",
            )
        )

        if (
            previous_status
            != current_status
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
                        previous_status,

                    "to_support_status":
                        current_status,

                    "from_analysis_mode":
                        previous.get(
                            "analysis_mode"
                        ),

                    "to_analysis_mode":
                        record.get(
                            "analysis_mode"
                        ),

                    "from_parameter_explicit":
                        previous.get(
                            "parameter_explicit"
                        ),

                    "to_parameter_explicit":
                        record.get(
                            "parameter_explicit"
                        ),

                    "transition_reason":
                        (
                            "release_support_"
                            "state_changed"
                        ),
                }
            )

        previous = record

    return transitions


def load_source_batch(
    refined: dict[str, Any],
) -> tuple[
    dict[str, Any] | None,
    Path | None,
]:
    path_text = str(
        refined.get(
            "release_history_batch_source",
            "",
        )
    ).strip()

    if not path_text:
        return None, None

    path = Path(
        path_text
    )

    if not path.exists():
        return None, path

    return (
        read_json(path),
        path,
    )


def load_release_history(
    source_batch: (
        dict[str, Any]
        | None
    ),
) -> tuple[
    dict[str, Any] | None,
    Path | None,
]:
    if not isinstance(
        source_batch,
        dict,
    ):
        return None, None

    path_text = str(
        source_batch.get(
            "release_history_source",
            "",
        )
    ).strip()

    if not path_text:
        return None, None

    path = Path(
        path_text
    )

    if not path.exists():
        return None, path

    return (
        read_json(path),
        path,
    )


def determine_coverage(
    source_batch: (
        dict[str, Any]
        | None
    ),
    release_history: (
        dict[str, Any]
        | None
    ),
) -> dict[str, Any]:
    """
    判断当前 candidate 到底基于：
    - 部分版本区间；
    - 全部 stable releases；
    - 全部 confirmed releases。

    这样不会把 4 个版本的实验
    错写成“完整历史已证明”。
    """

    if not isinstance(
        source_batch,
        dict,
    ):
        return {
            "coverage_status":
                "source_batch_unavailable",

            "coverage_complete":
                False,

            "coverage_scope":
                "unknown",
        }

    selection = source_batch.get(
        "selection",
        {},
    )

    if not isinstance(
        selection,
        dict,
    ):
        selection = {}

    start_version = selection.get(
        "start_version"
    )

    end_version = selection.get(
        "end_version"
    )

    limit = selection.get(
        "limit"
    )

    include_prereleases = bool(
        selection.get(
            "include_prereleases",
            False,
        )
    )

    selected_count = int(
        source_batch.get(
            "selected_release_count",
            0,
        )
        or 0
    )

    # 只要人为限制了 range / limit，
    # 就明确属于 subset。
    if (
        start_version is not None
        or end_version is not None
        or limit is not None
    ):
        return {
            "coverage_status":
                "partial_selection",

            "coverage_complete":
                False,

            "coverage_scope":
                "selected_release_subset",

            "selected_release_count":
                selected_count,

            "start_version":
                start_version,

            "end_version":
                end_version,

            "limit":
                limit,

            "include_prereleases":
                include_prereleases,
        }

    if not isinstance(
        release_history,
        dict,
    ):
        return {
            "coverage_status":
                "release_history_unavailable",

            "coverage_complete":
                False,

            "coverage_scope":
                "unknown",

            "selected_release_count":
                selected_count,

            "include_prereleases":
                include_prereleases,
        }

    confirmed_count = int(
        release_history.get(
            "confirmed_release_count_as_of_time_view",
            0,
        )
        or 0
    )

    prerelease_count = int(
        release_history.get(
            "confirmed_prerelease_count_as_of_time_view",
            0,
        )
        or 0
    )

    if include_prereleases:
        expected_count = (
            confirmed_count
        )

        scope = (
            "all_confirmed_releases"
        )
    else:
        expected_count = (
            confirmed_count
            - prerelease_count
        )

        scope = (
            "all_confirmed_stable_releases"
        )

    complete = (
        selected_count
        == expected_count
    )

    return {
        "coverage_status":
            (
                "complete"
                if complete
                else "count_mismatch"
            ),

        "coverage_complete":
            complete,

        "coverage_scope":
            scope,

        "selected_release_count":
            selected_count,

        "expected_release_count":
            expected_count,

        "confirmed_release_count":
            confirmed_count,

        "confirmed_prerelease_count":
            prerelease_count,

        "include_prereleases":
            include_prereleases,
    }


def classify_candidate_scope(
    lower_bound: dict[str, Any],
    coverage: dict[str, Any],
    unknown_count: int,
) -> str:
    if (
        lower_bound.get(
            "status"
        )
        != "candidate"
    ):
        return (
            "no_compilable_candidate"
        )

    if unknown_count > 0:
        return (
            "candidate_blocked_by_"
            "unresolved_history"
        )

    if not coverage.get(
        "coverage_complete",
        False,
    ):
        return (
            "observed_subset_candidate"
        )

    scope = coverage.get(
        "coverage_scope"
    )

    if (
        scope
        == "all_confirmed_releases"
    ):
        return (
            "full_release_history_candidate"
        )

    if (
        scope
        == "all_confirmed_stable_releases"
    ):
        return (
            "stable_release_history_candidate"
        )

    return (
        "observed_history_candidate"
    )


def compile_candidate(
    refined_history_path: Path,
) -> dict[str, Any]:
    refined = read_json(
        refined_history_path
    )

    records_raw = refined.get(
        "records",
        [],
    )

    if not isinstance(
        records_raw,
        list,
    ):
        raise RuntimeError(
            "refined release history has "
            "no valid records list"
        )

    records = [
        dict(record)
        for record in records_raw
        if isinstance(
            record,
            dict,
        )
    ]

    records.sort(
        key=version_key
    )

    if not records:
        raise RuntimeError(
            "refined release history "
            "contains no records"
        )

    source_batch, source_batch_path = (
        load_source_batch(
            refined
        )
    )

    (
        release_history,
        release_history_path,
    ) = load_release_history(
        source_batch
    )

    supported_count = sum(
        record.get(
            "support_status"
        )
        == "supported"
        for record in records
    )

    unsupported_count = sum(
        record.get(
            "support_status"
        )
        == "unsupported"
        for record in records
    )

    unknown_count = sum(
        record.get(
            "support_status"
        )
        == "unknown"
        for record in records
    )

    transitions = (
        build_support_transitions(
            records
        )
    )

    lower_bound = (
        derive_lower_bound_candidate(
            records
        )
    )

    coverage = determine_coverage(
        source_batch=
            source_batch,

        release_history=
            release_history,
    )

    candidate_scope = (
        classify_candidate_scope(
            lower_bound=
                lower_bound,

            coverage=
                coverage,

            unknown_count=
                unknown_count,
        )
    )

    return {
        "schema_version":
            SCHEMA_VERSION,

        "ecosystem":
            refined.get(
                "ecosystem",
                "pypi",
            ),

        "distribution":
            refined.get(
                "distribution",
                "",
            ),

        "normalized_distribution":
            refined.get(
                "normalized_distribution",
                "",
            ),

        "api_symbol":
            refined.get(
                "api_symbol",
                "",
            ),

        "support_target":
            refined.get(
                "support_target",
                "api_parameter_support",
            ),

        "parameter":
            refined.get(
                "parameter",
                "",
            ),

        "call_shape_evidence": (
            {
                "resolved_supported_release_count":
                    refined.get(
                        "call_shape_resolved_count",
                        0,
                    ),

                "unresolved_supported_release_count":
                    refined.get(
                        "call_shape_unresolved_count",
                        0,
                    ),

                "variant_count":
                    refined.get(
                        "supported_call_shape_variant_count",
                        0,
                    ),

                "uniform_supported_call_shape":
                    refined.get(
                        "uniform_supported_call_shape",
                        False,
                    ),

                "supported_call_shape":
                    refined.get(
                        "supported_call_shape"
                    ),
            }
            if refined.get(
                "support_target"
            ) == "api_symbol_presence"
            else None
        ),

        "refined_history_source":
            str(
                refined_history_path
            ).replace(
                "\\",
                "/",
            ),

        "release_history_batch_source":
            (
                str(
                    source_batch_path
                ).replace(
                    "\\",
                    "/",
                )
                if source_batch_path
                is not None
                else None
            ),

        "release_history_source":
            (
                str(
                    release_history_path
                ).replace(
                    "\\",
                    "/",
                )
                if release_history_path
                is not None
                else None
            ),

        "release_count":
            len(records),

        "supported_count":
            supported_count,

        "unsupported_count":
            unsupported_count,

        "unknown_count":
            unknown_count,

        "support_transition_count":
            len(
                transitions
            ),

        "coverage":
            coverage,

        "candidate_scope":
            candidate_scope,

        "lower_bound_candidate":
            lower_bound,

        "transitions":
            transitions,

        "records":
            records,

        "note":
            (
                "A compiled lower-bound remains "
                "evidence-derived candidate data. "
                "It is not benchmark truth until "
                "the intended release universe is "
                "covered and validation policy is "
                "satisfied."
            ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Compile refined release-level "
            "Python API support states into "
            "support transitions and a "
            "conservative lower-bound "
            "API-history candidate."
        )
    )

    parser.add_argument(
        "--refined-release-history",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--out",
        required=True,
        type=Path,
    )

    args = parser.parse_args()

    result = compile_candidate(
        refined_history_path=
            args.refined_release_history,
    )

    write_json(
        args.out,
        result,
    )

    lower_bound = result[
        "lower_bound_candidate"
    ]

    coverage = result[
        "coverage"
    ]

    print("")
    print("=" * 60)
    print("API HISTORY CANDIDATE SUMMARY")
    print("=" * 60)

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
        f"{result['supported_count']}"
    )

    print(
        f"[OK] unsupported: "
        f"{result['unsupported_count']}"
    )

    print(
        f"[OK] unknown: "
        f"{result['unknown_count']}"
    )

    print(
        f"[OK] support transitions: "
        f"{result['support_transition_count']}"
    )

    print(
        f"[OK] coverage status: "
        f"{coverage.get('coverage_status')}"
    )

    print(
        f"[OK] coverage scope: "
        f"{coverage.get('coverage_scope')}"
    )

    print(
        f"[OK] candidate scope: "
        f"{result['candidate_scope']}"
    )

    print(
        f"[OK] lower-bound status: "
        f"{lower_bound.get('status')}"
    )

    print(
        f"[OK] version specifier: "
        f"{lower_bound.get('version_specifier')}"
    )

    print(
        f"[OK] result saved to: "
        f"{args.out}"
    )


if __name__ == "__main__":
    main()