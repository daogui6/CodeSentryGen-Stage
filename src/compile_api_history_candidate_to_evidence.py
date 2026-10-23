from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any

from packaging.specifiers import (
    InvalidSpecifier,
    SpecifierSet,
)

from normalizer import pep503_normalize


OUTPUT_SCHEMA_VERSION = (
    "avcs_api_history_evidence_v0.1"
)

ALLOWED_CANDIDATE_SCOPES = {
    "stable_release_history_candidate",
    "full_release_history_candidate",
}


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


def normalized_path(
    path: Path,
) -> str:
    return str(
        path
    ).replace(
        "\\",
        "/",
    )


def rule_is_fully_automatic(
    rule: dict[str, Any],
) -> bool:
    derivation = rule.get(
        "derivation"
    )

    if not isinstance(
        derivation,
        dict,
    ):
        return False

    return (
        rule.get(
            "evidence_type"
        )
        == (
            "automatic_release_"
            "history_evidence"
        )
        and derivation.get(
            "status"
        )
        == "resolved"
        and derivation.get(
            "method"
        )
        == (
            "automatic_complete_"
            "release_history_candidate"
        )
    )


def derive_history_source_mode(
    history: dict[str, Any],
) -> str:
    rules: list[
        dict[str, Any]
    ] = []

    for entry in history.get(
        "entries",
        [],
    ):
        if not isinstance(
            entry,
            dict,
        ):
            continue

        for rule in entry.get(
            "version_rules",
            [],
        ):
            if isinstance(
                rule,
                dict,
            ):
                rules.append(
                    rule
                )

    if (
        rules
        and all(
            rule_is_fully_automatic(
                rule
            )
            for rule in rules
        )
    ):
        return (
            "automatic_release_history"
        )

    if any(
        rule_is_fully_automatic(
            rule
        )
        for rule in rules
    ):
        return (
            "mixed_curated_and_"
            "automatic_release_history"
        )

    return str(
        history.get(
            "source_mode",
            "curated_real_api_history",
        )
    )


def validate_symbol_presence_call_shape(
    candidate: dict[str, Any],
    target_rule: dict[str, Any],
    supported_count: int,
) -> dict[str, Any]:
    evidence = candidate.get(
        "call_shape_evidence"
    )

    if not isinstance(
        evidence,
        dict,
    ):
        raise RuntimeError(
            "symbol-presence candidate "
            "has no call-shape evidence"
        )

    resolved_count = int(
        evidence.get(
            "resolved_supported_release_count",
            0,
        )
        or 0
    )

    unresolved_count = int(
        evidence.get(
            "unresolved_supported_release_count",
            0,
        )
        or 0
    )

    variant_count = int(
        evidence.get(
            "variant_count",
            0,
        )
        or 0
    )

    uniform = bool(
        evidence.get(
            "uniform_supported_call_shape",
            False,
        )
    )

    if (
        resolved_count
        != supported_count
    ):
        raise RuntimeError(
            "call-shape evidence does not "
            "cover every supported release"
        )

    if unresolved_count != 0:
        raise RuntimeError(
            "call-shape evidence still "
            "contains unresolved supported "
            "releases"
        )

    if (
        variant_count != 1
        or not uniform
    ):
        raise RuntimeError(
            "supported releases do not "
            "have one uniform call shape"
        )

    shape = evidence.get(
        "supported_call_shape"
    )

    if not isinstance(
        shape,
        dict,
    ):
        raise RuntimeError(
            "uniform call shape is missing"
        )

    if (
        shape.get("kind")
        != "exact_zero_argument_call"
    ):
        raise RuntimeError(
            "only exact zero-argument "
            "symbol call shape is currently "
            "supported for automatic "
            "compilation"
        )

    expected_shape = {
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
    }

    for (
        field,
        expected_value,
    ) in expected_shape.items():
        if (
            shape.get(field)
            != expected_value
        ):
            raise RuntimeError(
                "candidate call shape is "
                "not exact zero-argument: "
                f"{field}"
            )

        if (
            target_rule.get(field)
            != expected_value
        ):
            raise RuntimeError(
                "candidate call shape does "
                "not match target rule: "
                f"{field}"
            )

    if bool(
        shape.get(
            "accepts_var_positional",
            False,
        )
    ):
        raise RuntimeError(
            "symbol call shape accepts "
            "variable positional arguments"
        )

    if bool(
        shape.get(
            "accepts_var_keyword",
            False,
        )
    ):
        raise RuntimeError(
            "symbol call shape accepts "
            "variable keyword arguments"
        )

    return copy.deepcopy(
        evidence
    )


def validate_candidate(
    candidate: dict[str, Any],
) -> dict[str, Any]:
    candidate_scope = str(
        candidate.get(
            "candidate_scope",
            "",
        )
    ).strip()

    if (
        candidate_scope
        not in ALLOWED_CANDIDATE_SCOPES
    ):
        raise RuntimeError(
            "candidate is not based on "
            "a complete supported release scope: "
            f"{candidate_scope!r}"
        )

    coverage = candidate.get(
        "coverage",
        {},
    )

    if not isinstance(
        coverage,
        dict,
    ):
        raise RuntimeError(
            "candidate has no valid "
            "coverage evidence"
        )

    if not coverage.get(
        "coverage_complete",
        False,
    ):
        raise RuntimeError(
            "candidate coverage is incomplete"
        )

    unknown_count = int(
        candidate.get(
            "unknown_count",
            0,
        )
        or 0
    )

    if unknown_count != 0:
        raise RuntimeError(
            "candidate still contains "
            f"{unknown_count} unknown releases"
        )

    lower_bound = candidate.get(
        "lower_bound_candidate",
        {},
    )

    if not isinstance(
        lower_bound,
        dict,
    ):
        raise RuntimeError(
            "candidate has no valid "
            "lower-bound evidence"
        )

    if (
        lower_bound.get(
            "status"
        )
        != "candidate"
    ):
        raise RuntimeError(
            "lower-bound result is not "
            "a compilable candidate"
        )

    version_specifier = str(
        lower_bound.get(
            "version_specifier",
            "",
        )
    ).strip()

    if not version_specifier:
        raise RuntimeError(
            "candidate version specifier "
            "is empty"
        )

    try:
        SpecifierSet(
            version_specifier
        )
    except InvalidSpecifier as exc:
        raise RuntimeError(
            "candidate contains invalid "
            "version specifier: "
            f"{version_specifier!r}"
        ) from exc

    boundary_version = str(
        lower_bound.get(
            "boundary_version",
            "",
        )
    ).strip()

    if not boundary_version:
        raise RuntimeError(
            "candidate boundary version "
            "is missing"
        )

    return {
        "candidate_scope":
            candidate_scope,

        "coverage":
            coverage,

        "version_specifier":
            version_specifier,

        "boundary_version":
            boundary_version,

        "unknown_count":
            unknown_count,
    }


def find_target_rule(
    history: dict[str, Any],
    normalized_distribution: str,
    api_symbol: str,
    rule_id: str,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
]:
    matches: list[
        tuple[
            dict[str, Any],
            dict[str, Any],
        ]
    ] = []

    for entry in history.get(
        "entries",
        [],
    ):
        if not isinstance(
            entry,
            dict,
        ):
            continue

        entry_distribution = (
            pep503_normalize(
                str(
                    entry.get(
                        "distribution",
                        "",
                    )
                )
            )
        )

        entry_symbol = str(
            entry.get(
                "api_symbol",
                "",
            )
        ).strip()

        if (
            entry_distribution
            != normalized_distribution
            or entry_symbol
            != api_symbol
        ):
            continue

        for rule in entry.get(
            "version_rules",
            [],
        ):
            if not isinstance(
                rule,
                dict,
            ):
                continue

            if (
                str(
                    rule.get(
                        "rule_id",
                        "",
                    )
                ).strip()
                == rule_id
            ):
                matches.append(
                    (
                        entry,
                        rule,
                    )
                )

    if len(matches) != 1:
        raise RuntimeError(
            "target rule must match exactly "
            "once, but matched "
            f"{len(matches)} times: "
            f"{normalized_distribution} "
            f"{api_symbol} "
            f"{rule_id}"
        )

    return matches[0]


def compile_candidate_to_history(
    candidate_path: Path,
    base_history_path: Path,
    rule_id: str,
) -> dict[str, Any]:
    candidate = read_json(
        candidate_path
    )

    base_history = read_json(
        base_history_path
    )

    validation = validate_candidate(
        candidate
    )

    output_history = copy.deepcopy(
        base_history
    )

    if (
        output_history.get(
            "schema_version"
        )
        != OUTPUT_SCHEMA_VERSION
    ):
        raise RuntimeError(
            "base history schema is not "
            f"{OUTPUT_SCHEMA_VERSION!r}"
        )

    candidate_distribution = str(
        candidate.get(
            "normalized_distribution",
            "",
        )
        or candidate.get(
            "distribution",
            "",
        )
    ).strip()

    normalized_distribution = (
        pep503_normalize(
            candidate_distribution
        )
    )

    api_symbol = str(
        candidate.get(
            "api_symbol",
            "",
        )
    ).strip()

    parameter = str(
        candidate.get(
            "parameter",
            "",
        )
    ).strip()

    support_target = str(
        candidate.get(
            "support_target",
            "api_parameter_support",
        )
    ).strip()

    if not support_target:
        support_target = (
            "api_parameter_support"
        )

    if support_target not in {
        "api_parameter_support",
        "api_symbol_presence",
    }:
        raise RuntimeError(
            "unsupported candidate "
            "support target: "
            f"{support_target!r}"
        )

    if not normalized_distribution:
        raise RuntimeError(
            "candidate distribution missing"
        )

    if not api_symbol:
        raise RuntimeError(
            "candidate API symbol missing"
        )

    (
        target_entry,
        target_rule,
    ) = find_target_rule(
        history=output_history,
        normalized_distribution=
            normalized_distribution,
        api_symbol=api_symbol,
        rule_id=rule_id,
    )

    if (
            support_target
            == "api_parameter_support"
    ):
        if not parameter:
            raise RuntimeError(
                "parameter-support candidate "
                "has no parameter"
            )

        required_keywords = {
            str(value)
            for value
            in target_rule.get(
                "required_keyword_args",
                [],
            )
        }

        if (
                parameter
                not in required_keywords
        ):
            raise RuntimeError(
                "candidate parameter is not "
                "represented by the target "
                "rule's required keyword "
                "arguments: "
                f"{parameter!r}"
            )

    elif (
            support_target
            == "api_symbol_presence"
    ):
        if parameter:
            raise RuntimeError(
                "symbol-presence candidate "
                "must not carry a parameter"
            )

    old_version_specifier = str(
        target_rule.get(
            "version_specifier",
            "",
        )
    ).strip()

    old_evidence_type = (
        target_rule.get(
            "evidence_type"
        )
    )

    old_evidence_ref = (
        target_rule.get(
            "evidence_ref"
        )
    )

    old_evidence_note = (
        target_rule.get(
            "evidence_note"
        )
    )

    old_derivation = copy.deepcopy(
        target_rule.get(
            "derivation"
        )
    )

    version_specifier = validation[
        "version_specifier"
    ]

    coverage = validation[
        "coverage"
    ]

    boundary_version = validation[
        "boundary_version"
    ]

    release_count = int(
        candidate.get(
            "release_count",
            0,
        )
        or 0
    )

    supported_count = int(
        candidate.get(
            "supported_count",
            0,
        )
        or 0
    )

    unsupported_count = int(
        candidate.get(
            "unsupported_count",
            0,
        )
        or 0
    )

    unknown_count = int(
        candidate.get(
            "unknown_count",
            0,
        )
        or 0
    )

    support_transition_count = int(
        candidate.get(
            "support_transition_count",
            0,
        )
        or 0
    )

    call_shape_evidence = None

    if (
            support_target
            == "api_symbol_presence"
    ):
        call_shape_evidence = (
            validate_symbol_presence_call_shape(
                candidate=candidate,
                target_rule=target_rule,
                supported_count=
                supported_count,
            )
        )

    target_rule[
        "version_specifier"
    ] = version_specifier

    target_rule[
        "evidence_type"
    ] = (
        "automatic_release_history_evidence"
    )

    target_rule[
        "evidence_ref"
    ] = normalized_path(
        candidate_path
    )

    if (
            support_target
            == "api_symbol_presence"
    ):
        target_rule[
            "evidence_note"
        ] = (
            "Automatically derived from "
            f"{release_count} releases in a "
            "complete release-history scope: "
            f"{unsupported_count} unsupported, "
            f"{supported_count} supported, "
            f"{unknown_count} unknown. "
            f"The conservative lower-bound "
            f"candidate is {version_specifier}. "
            f"All {supported_count} supported "
            "releases resolve to one exact "
            "zero-argument public call shape."
        )

    else:
        target_rule[
            "evidence_note"
        ] = (
            "Automatically derived from "
            f"{release_count} releases in a "
            "complete release-history scope: "
            f"{unsupported_count} unsupported, "
            f"{supported_count} supported, "
            f"{unknown_count} unknown. "
            f"The conservative lower-bound "
            f"candidate is {version_specifier}."
        )

    target_rule[
        "derivation"
    ] = {
        "status":
            "resolved",

        "support_target":
            support_target,

        "method":
            (
                "automatic_complete_"
                "release_history_candidate"
            ),

        "candidate_scope":
            validation[
                "candidate_scope"
            ],

        "version_specifier":
            version_specifier,

        "boundary_version":
            boundary_version,

        "source_candidate_file":
            normalized_path(
                candidate_path
            ),

        "coverage": {
            "coverage_complete":
                coverage.get(
                    "coverage_complete"
                ),

            "coverage_status":
                coverage.get(
                    "coverage_status"
                ),

            "coverage_scope":
                coverage.get(
                    "coverage_scope"
                ),

            "selected_release_count":
                coverage.get(
                    "selected_release_count"
                ),

            "expected_release_count":
                coverage.get(
                    "expected_release_count"
                ),

            "confirmed_release_count":
                coverage.get(
                    "confirmed_release_count"
                ),

            "confirmed_prerelease_count":
                coverage.get(
                    "confirmed_prerelease_count"
                ),

            "include_prereleases":
                coverage.get(
                    "include_prereleases"
                ),
        },

        "release_state_summary": {
            "release_count":
                release_count,

            "supported_count":
                supported_count,

            "unsupported_count":
                unsupported_count,

            "unknown_count":
                unknown_count,

            "support_transition_count":
                support_transition_count,
        },

        "call_shape_evidence":
            copy.deepcopy(
                call_shape_evidence
            ),

        "transitions":
            copy.deepcopy(
                candidate.get(
                    "transitions",
                    [],
                )
            ),
    }

    output_history[
        "source_mode"
    ] = (
        derive_history_source_mode(
            output_history
        )
    )

    output_history[
        "status"
    ] = "resolved"

    output_history[
        "automatic_compilation"
    ] = {
        "status":
            "resolved",

        "support_target":
            support_target,

        "base_history_file":
            normalized_path(
                base_history_path
            ),

        "candidate_file":
            normalized_path(
                candidate_path
            ),

        "target_distribution":
            normalized_distribution,

        "target_api_symbol":
            api_symbol,

        "target_parameter":
            parameter,

        "target_rule_id":
            rule_id,

        "old_version_specifier":
            old_version_specifier,

        "compiled_version_specifier":
            version_specifier,

        "candidate_scope":
            validation[
                "candidate_scope"
            ],

        "coverage_complete":
            coverage.get(
                "coverage_complete"
            ),

        "preserved_entry_count":
            len(
                output_history.get(
                    "entries",
                    [],
                )
            ),

        "replaced_curated_evidence": {
            "evidence_type":
                old_evidence_type,

            "evidence_ref":
                old_evidence_ref,

            "evidence_note":
                old_evidence_note,

            "derivation":
                old_derivation,
        },
    }

    sources = output_history.get(
        "sources",
        [],
    )

    if not isinstance(
        sources,
        list,
    ):
        sources = []

    source_id = (
        "automatic_"
        + rule_id
        + "_release_history"
    )

    sources = [
        source
        for source in sources
        if not (
            isinstance(
                source,
                dict,
            )
            and source.get(
                "source_id"
            )
            == source_id
        )
    ]

    sources.append(
        {
            "source_id":
                source_id,

            "source_type":
                (
                    "generated_release_"
                    "history_candidate"
                ),

            "path":
                normalized_path(
                    candidate_path
                ),

            "claim":
            (
                (
                    f"Complete release-history "
                    f"evidence derives "
                    f"{api_symbol} presence and "
                    "an exact zero-argument "
                    f"public call shape as "
                    f"{version_specifier}."
                )
                if support_target
                == "api_symbol_presence"
                else (
                    f"Complete release-history "
                    f"evidence derives "
                    f"{api_symbol} with "
                    f"{parameter!r} as "
                    f"{version_specifier}."
                )
            ),
        }
    )

    output_history[
        "sources"
    ] = sources

    # target_entry 本身不需要额外修改；
    # 保留它以及其他 API entries 的
    # call-shape 规则结构不变。
    _ = target_entry

    return output_history


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Compile a complete automatic "
            "API release-history candidate "
            "into an existing AVCS API "
            "History evidence template while "
            "preserving unrelated rules."
        )
    )

    parser.add_argument(
        "--candidate",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--base-history",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--rule-id",
        required=True,
    )

    parser.add_argument(
        "--out",
        required=True,
        type=Path,
    )

    args = parser.parse_args()

    result = (
        compile_candidate_to_history(
            candidate_path=
                args.candidate,

            base_history_path=
                args.base_history,

            rule_id=
                args.rule_id.strip(),
        )
    )

    write_json(
        args.out,
        result,
    )

    compilation = result[
        "automatic_compilation"
    ]

    print("")
    print("=" * 60)
    print(
        "API HISTORY EVIDENCE "
        "COMPILATION SUMMARY"
    )
    print("=" * 60)

    print(
        f"[OK] schema: "
        f"{result['schema_version']}"
    )

    print(
        f"[OK] target distribution: "
        f"{compilation['target_distribution']}"
    )

    print(
        f"[OK] target API symbol: "
        f"{compilation['target_api_symbol']}"
    )

    print(
        f"[OK] target parameter: "
        f"{compilation['target_parameter']}"
    )

    print(
        f"[OK] target rule: "
        f"{compilation['target_rule_id']}"
    )

    print(
        f"[OK] candidate scope: "
        f"{compilation['candidate_scope']}"
    )

    print(
        f"[OK] coverage complete: "
        f"{compilation['coverage_complete']}"
    )

    print(
        f"[OK] old specifier: "
        f"{compilation['old_version_specifier']}"
    )

    print(
        f"[OK] compiled specifier: "
        f"{compilation['compiled_version_specifier']}"
    )

    print(
        f"[OK] preserved entries: "
        f"{compilation['preserved_entry_count']}"
    )

    print(
        f"[OK] result saved to: "
        f"{args.out}"
    )


if __name__ == "__main__":
    main()