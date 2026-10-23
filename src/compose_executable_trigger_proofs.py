from __future__ import annotations

import argparse
import hashlib
import json
import re
from copy import deepcopy
from pathlib import Path
from typing import Any

from packaging.specifiers import (
    InvalidSpecifier,
    SpecifierSet,
)
from packaging.version import (
    InvalidVersion,
    Version,
)


ROOT = Path(
    __file__
).resolve().parents[1]


SCHEMA_VERSION = (
    "avcs_version_aware_trigger_evidence_draft_v0.1"
)

COMPOSER_VERSION = (
    "executable_trigger_proof_composer_v0.1"
)

EXPECTED_VERSION_DRAFT_SCHEMA = (
    "avcs_trigger_evidence_draft_v0.1"
)

EXPECTED_FACT_SCHEMA = (
    "avcs_trigger_candidate_fact_v0.1"
)

EXPECTED_VALIDATION_SCHEMA = (
    "avcs_trigger_candidate_fact_validation_v0.1"
)

EXPECTED_CORPUS_SCHEMA = (
    "avcs_trigger_candidate_evidence_corpus_v0.1"
)

EXPECTED_API_HISTORY_SCHEMA = (
    "avcs_api_history_evidence_v0.1"
)


SUPPORTED_PROPOSAL_KIND = (
    "keyword_call_condition"
)


def clean_text(
    value: Any,
) -> str:
    if value is None:
        return ""

    return str(
        value
    ).strip()


def load_json(
    path: Path,
) -> dict[str, Any]:
    data = json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )

    if not isinstance(
        data,
        dict,
    ):
        raise ValueError(
            f"Expected JSON object: {path}"
        )

    return data


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
        )
        + "\n",
        encoding="utf-8",
    )


def dict_rows(
    value: Any,
) -> list[dict[str, Any]]:
    if not isinstance(
        value,
        list,
    ):
        return []

    return [
        row
        for row in value
        if isinstance(
            row,
            dict,
        )
    ]


def normalized_ids(
    value: Any,
) -> tuple[str, ...]:
    if not isinstance(
        value,
        list,
    ):
        return tuple()

    return tuple(
        sorted(
            {
                clean_text(
                    item
                ).lower()
                for item in value
                if clean_text(
                    item
                )
            }
        )
    )


def normalized_distribution(
    value: Any,
) -> str:
    return clean_text(
        value
    ).lower()


def stable_json(
    value: Any,
) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(
            ",",
            ":",
        ),
    )


def make_id(
    prefix: str,
    payload: Any,
) -> str:
    digest = hashlib.sha256(
        stable_json(
            payload
        ).encode(
            "utf-8"
        )
    ).hexdigest()[:20]

    return (
        prefix
        + digest
    )


def case_key(
    row: dict[str, Any],
) -> tuple[
    str,
    tuple[str, ...],
]:
    return (
        normalized_distribution(
            row.get(
                "distribution"
            )
        ),
        normalized_ids(
            row.get(
                "vulnerability_ids"
            )
        ),
    )


def vulnerability_id_in_text(
    vulnerability_ids: tuple[
        str,
        ...,
    ],
    text: str,
) -> bool:
    lowered = clean_text(
        text
    ).lower()

    if not lowered:
        return False

    return any(
        vulnerability_id
        in lowered
        for vulnerability_id
        in vulnerability_ids
    )


def contains_keyword_assignment(
    text: str,
    keyword_name: str,
) -> bool:
    """
    Match an actual keyword argument such as:

        algorithms=

    but do not mistake attribute/module names such as:

        jwt.algorithms.get_default_algorithms()

    for the keyword argument itself.
    """

    normalized_keyword = clean_text(
        keyword_name
    )

    if (
        not normalized_keyword
        or not clean_text(
            text
        )
    ):
        return False

    pattern = (
        r"(?<![\w.])"
        + re.escape(
            normalized_keyword
        )
        + r"\s*="
    )

    return (
        re.search(
            pattern,
            text,
        )
        is not None
    )


def is_test_path(
    path: str,
) -> bool:
    normalized = (
        clean_text(
            path
        )
        .replace(
            "\\",
            "/",
        )
        .lower()
    )

    if not normalized:
        return False

    parts = [
        part
        for part in normalized.split(
            "/"
        )
        if part
    ]

    basename = (
        parts[-1]
        if parts
        else ""
    )

    return (
        "tests"
        in parts
        or "test"
        in parts
        or basename.startswith(
            "test_"
        )
        or basename.endswith(
            "_test.py"
        )
    )


def build_validation_index(
    validation_data: dict[str, Any],
) -> dict[
    str,
    dict[str, Any],
]:
    index = {}

    for row in dict_rows(
        validation_data.get(
            "validation_records"
        )
    ):
        fact_id = clean_text(
            row.get(
                "fact_id"
            )
        )

        if fact_id:
            index[
                fact_id
            ] = row

    return index


def build_fact_index(
    fact_data: dict[str, Any],
) -> dict[
    str,
    dict[str, Any],
]:
    index = {}

    for row in dict_rows(
        fact_data.get(
            "facts"
        )
    ):
        fact_id = clean_text(
            row.get(
                "fact_id"
            )
        )

        if fact_id:
            index[
                fact_id
            ] = row

    return index


def build_version_draft_index(
    version_data: dict[str, Any],
) -> dict[
    tuple[
        str,
        tuple[str, ...],
    ],
    dict[str, Any],
]:
    index = {}

    for row in dict_rows(
        version_data.get(
            "drafts"
        )
    ):
        key = case_key(
            row
        )

        if not key[0]:
            continue

        index[
            key
        ] = row

    return index


def build_corpus_case_index(
    corpus: dict[str, Any],
) -> dict[
    tuple[
        str,
        tuple[str, ...],
    ],
    list[
        dict[str, Any]
    ],
]:
    index = {}

    for entry in dict_rows(
        corpus.get(
            "entries"
        )
    ):
        key = case_key(
            entry
        )

        if not key[0]:
            continue

        index.setdefault(
            key,
            [],
        ).append(
            entry
        )

    return index


def proposal_signature(
    proposal: dict[str, Any],
) -> tuple[
    str,
    str,
    str,
    str,
]:
    keyword = proposal.get(
        "keyword_argument",
        {},
    )

    if not isinstance(
        keyword,
        dict,
    ):
        keyword = {}

    return (
        clean_text(
            proposal.get(
                "api_symbol"
            )
        ),
        clean_text(
            proposal.get(
                "kind"
            )
        ),
        clean_text(
            keyword.get(
                "name"
            )
        ),
        clean_text(
            keyword.get(
                "required_call_symbol"
            )
        ),
    )


def fact_matches_proposal(
    fact: dict[str, Any],
    proposal: dict[str, Any],
) -> bool:
    if (
        clean_text(
            fact.get(
                "fact_kind"
            )
        )
        != (
            "code_expression_"
            "keyword_call_candidate"
        )
    ):
        return False

    structured = fact.get(
        "structured_value",
        {},
    )

    if not isinstance(
        structured,
        dict,
    ):
        return False

    argument = structured.get(
        "argument_value",
        {},
    )

    if not isinstance(
        argument,
        dict,
    ):
        return False

    (
        api_symbol,
        kind,
        keyword_name,
        required_call_symbol,
    ) = proposal_signature(
        proposal
    )

    return (
        kind
        == SUPPORTED_PROPOSAL_KIND
        and clean_text(
            structured.get(
                "call_symbol"
            )
        )
        == api_symbol
        and clean_text(
            structured.get(
                "keyword_name"
            )
        )
        == keyword_name
        and clean_text(
            argument.get(
                "value_kind"
            )
        )
        == "call"
        and clean_text(
            argument.get(
                "call_symbol"
            )
        )
        == required_call_symbol
    )


def supported_fact(
    fact_id: str,
    validation_index: dict[
        str,
        dict[str, Any],
    ],
) -> bool:
    validation = (
        validation_index.get(
            fact_id
        )
    )

    if not isinstance(
        validation,
        dict,
    ):
        return False

    return (
        clean_text(
            validation.get(
                "validation_status"
            )
        )
        == "supported"
        and validation.get(
            "automatic_decision"
        )
        is True
        and validation.get(
            "review_required"
        )
        is not True
    )


def find_upstream_advisory_leg(
    *,
    proposal: dict[str, Any],
    case: tuple[
        str,
        tuple[str, ...],
    ],
    fact_index: dict[
        str,
        dict[str, Any],
    ],
    validation_index: dict[
        str,
        dict[str, Any],
    ],
) -> dict[str, Any] | None:
    distribution, vulnerability_ids = (
        case
    )

    candidates = []

    for fact_id, fact in (
        fact_index.items()
    ):
        if (
            normalized_distribution(
                fact.get(
                    "distribution"
                )
            )
            != distribution
        ):
            continue

        if (
            normalized_ids(
                fact.get(
                    "vulnerability_ids"
                )
            )
            != vulnerability_ids
        ):
            continue

        if (
            clean_text(
                fact.get(
                    "source_type"
                )
            )
            != (
                "upstream_security_"
                "advisory"
            )
        ):
            continue

        if not fact_matches_proposal(
            fact,
            proposal,
        ):
            continue

        if not supported_fact(
            fact_id,
            validation_index,
        ):
            continue

        candidates.append(
            fact
        )

    if len(
        candidates
    ) != 1:
        return None

    fact = candidates[0]

    return {
        "status":
            "supported",

        "fact_id":
            fact.get(
                "fact_id"
            ),

        "source_key":
            fact.get(
                "source_key"
            ),

        "source_type":
            fact.get(
                "source_type"
            ),

        "evidence_unit_id":
            fact.get(
                "evidence_unit_id"
            ),

        "evidence_excerpt":
            fact.get(
                "evidence_excerpt"
            ),

        "independence_note":
            (
                "OSV syndication of the same "
                "advisory text is not counted "
                "as a second semantic proof leg."
            ),
    }


def version_rule_covers(
    version_rule: dict[str, Any],
    versions: list[str],
) -> bool:
    if (
        clean_text(
            version_rule.get(
                "status"
            )
        )
        != "resolved"
    ):
        return False

    specifier_text = clean_text(
        version_rule.get(
            "version_specifier"
        )
    )

    if not specifier_text:
        return False

    try:
        specifier = SpecifierSet(
            specifier_text
        )

    except InvalidSpecifier:
        return False

    try:
        parsed_versions = [
            Version(
                value
            )
            for value in versions
        ]

    except InvalidVersion:
        return False

    return all(
        version
        in specifier
        for version in parsed_versions
    )


def find_api_history_entry(
    *,
    api_history: dict[str, Any],
    api_symbol: str,
    versions: list[str],
    require_zero_arg: bool,
    required_keyword_name: str | None = None,
) -> dict[str, Any] | None:
    matching_entries = [
        row
        for row in dict_rows(
            api_history.get(
                "entries"
            )
        )
        if clean_text(
            row.get(
                "api_symbol"
            )
        )
        == api_symbol
    ]

    if len(
        matching_entries
    ) != 1:
        return None

    entry = matching_entries[0]

    matching_rules = []

    for rule in dict_rows(
        entry.get(
            "version_rules"
        )
    ):
        if not version_rule_covers(
            rule,
            versions,
        ):
            continue

        if required_keyword_name:
            keyword_args = rule.get(
                "required_keyword_args",
                [],
            )

            if not isinstance(
                keyword_args,
                list,
            ):
                continue

            normalized_keywords = {
                clean_text(
                    value
                )
                for value in keyword_args
                if clean_text(
                    value
                )
            }

            if (
                required_keyword_name
                not in normalized_keywords
            ):
                continue

        if require_zero_arg:
            if (
                rule.get(
                    "required_positional_args_min"
                )
                != 0
                or rule.get(
                    "required_positional_args_max"
                )
                != 0
            ):
                continue

            if dict_rows(
                rule.get(
                    "required_keyword_args"
                )
            ):
                continue

            raw_keywords = rule.get(
                "required_keyword_args",
                [],
            )

            if (
                isinstance(
                    raw_keywords,
                    list,
                )
                and raw_keywords
            ):
                continue

        matching_rules.append(
            rule
        )

    if len(
        matching_rules
    ) != 1:
        return None

    return {
        "api_symbol":
            api_symbol,

        "api_kind":
            entry.get(
                "api_kind"
            ),

        "version_rule":
            deepcopy(
                matching_rules[0]
            ),
    }


FULLY_AUTOMATIC_API_HISTORY_SOURCE_MODE = (
    "automatic_release_history"
)

AUTOMATIC_API_HISTORY_EVIDENCE_TYPE = (
    "automatic_release_history_evidence"
)

AUTOMATIC_API_HISTORY_DERIVATION_METHOD = (
    "automatic_complete_release_history_candidate"
)


def api_history_rule_is_fully_automatic(
    matched_api: dict[str, Any],
) -> bool:
    """
    A matched API History rule is counted as fully automatic
    only when its actual rule-level provenance is automatic.

    Top-level source_mode alone is not sufficient.
    """

    version_rule = matched_api.get(
        "version_rule",
        {},
    )

    if not isinstance(
        version_rule,
        dict,
    ):
        return False

    if (
        clean_text(
            version_rule.get(
                "evidence_type"
            )
        )
        != AUTOMATIC_API_HISTORY_EVIDENCE_TYPE
    ):
        return False

    derivation = version_rule.get(
        "derivation",
        {},
    )

    if not isinstance(
        derivation,
        dict,
    ):
        return False

    if (
        clean_text(
            derivation.get(
                "status"
            )
        )
        != "resolved"
    ):
        return False

    if (
        clean_text(
            derivation.get(
                "method"
            )
        )
        != AUTOMATIC_API_HISTORY_DERIVATION_METHOD
    ):
        return False

    return True


def api_history_leg_is_fully_automatic(
    *,
    api_history: dict[str, Any],
    primary: dict[str, Any],
    nested: dict[str, Any],
) -> bool:
    """
    Final RQ1 automation eligibility requires BOTH:

    1. the artifact explicitly declares fully automatic
       release-history mode; and
    2. every API rule actually consumed by this proof
       carries automatic release-history provenance.

    Therefore a mixed curated/automatic artifact can support
    method validation, but cannot count toward the final
    fully automatic RQ1 rate.
    """

    if (
        clean_text(
            api_history.get(
                "source_mode"
            )
        )
        != FULLY_AUTOMATIC_API_HISTORY_SOURCE_MODE
    ):
        return False

    return (
        api_history_rule_is_fully_automatic(
            primary
        )
        and api_history_rule_is_fully_automatic(
            nested
        )
    )


def derive_single_osv_scope(
    version_evidence: dict[str, Any],
) -> dict[str, Any] | None:
    """
    Resolve one concrete PyPI affected-version interval.

    Multiple supported ECOSYSTEM records are allowed only
    when every record resolves to the same introduced/fixed
    interval. Agreement is treated as duplicate/consistent
    version evidence, not as independent semantic proof.

    GIT ranges are intentionally ignored because commit SHAs
    cannot be used as PyPI release-version matcher scope.
    """

    if (
        clean_text(
            version_evidence.get(
                "status"
            )
        )
        != "supported_version_evidence"
    ):
        return None

    if (
        clean_text(
            version_evidence.get(
                "fixed_release_status"
            )
        )
        != "supported"
    ):
        return None

    # v0 only supports a single release boundary.
    # Multi-branch version scopes remain unresolved.
    if (
        clean_text(
            version_evidence.get(
                "fixed_release_resolution_mode"
            )
        )
        != "single_release"
    ):
        return None


    ecosystem_ranges = [
        row
        for row in dict_rows(
            version_evidence.get(
                "osv_range_drafts"
            )
        )
        if (
            clean_text(
                row.get(
                    "range_type"
                )
            ).upper()
            == "ECOSYSTEM"
        )
    ]


    if not ecosystem_ranges:
        return None


    parsed_ranges: list[
        dict[str, Any]
    ] = []


    for range_draft in ecosystem_ranges:

        if (
            clean_text(
                range_draft.get(
                    "status"
                )
            )
            != "supported_atomic_range_events"
        ):
            return None


        introduced = []
        fixed = []
        unsupported_events = []


        for event in dict_rows(
            range_draft.get(
                "events"
            )
        ):

            event_kind = clean_text(
                event.get(
                    "event"
                )
            )

            version = clean_text(
                event.get(
                    "version"
                )
            )


            if event_kind == "introduced":
                if version:
                    introduced.append(
                        version
                    )

            elif event_kind == "fixed":
                if version:
                    fixed.append(
                        version
                    )

            else:
                unsupported_events.append(
                    event_kind
                )


        # v0 deliberately supports only a simple:
        #
        #   introduced -> fixed
        #
        # interval per ECOSYSTEM range.
        if unsupported_events:
            return None

        if (
            len(
                introduced
            )
            != 1
            or len(
                fixed
            )
            != 1
        ):
            return None


        lower_text = introduced[0]
        upper_text = fixed[0]


        # OSV's "0" means an open beginning.
        # v0 refuses to invent a concrete lower bound.
        if lower_text == "0":
            return None


        try:
            lower_version = Version(
                lower_text
            )

            upper_version = Version(
                upper_text
            )

        except InvalidVersion:
            return None


        if not (
            lower_version
            < upper_version
        ):
            return None


        parsed_ranges.append(
            {
                "lower_version":
                    lower_version,

                "upper_version":
                    upper_version,

                "lower_text":
                    lower_text,

                "upper_text":
                    upper_text,

                "range_draft":
                    deepcopy(
                        range_draft
                    ),
            }
        )


    # Multiple ECOSYSTEM records are acceptable only
    # when they are semantically the same release interval.
    distinct_intervals = {
        (
            row[
                "lower_version"
            ],
            row[
                "upper_version"
            ],
        )
        for row in parsed_ranges
    }


    if len(
        distinct_intervals
    ) != 1:
        return None


    (
        lower_version,
        upper_version,
    ) = next(
        iter(
            distinct_intervals
        )
    )


    fixed_release_text = clean_text(
        version_evidence.get(
            "fixed_release"
        )
    )


    if not fixed_release_text:
        return None


    try:
        fixed_release_version = Version(
            fixed_release_text
        )

    except InvalidVersion:
        return None


    if (
        fixed_release_version
        != upper_version
    ):
        return None


    # Prefer the spelling already present in the
    # supported ECOSYSTEM evidence.
    representative = (
        parsed_ranges[0]
    )

    introduced_text = (
        representative[
            "lower_text"
        ]
    )

    fixed_text = (
        representative[
            "upper_text"
        ]
    )


    source_keys = sorted(
        {
            clean_text(
                event.get(
                    "source_key"
                )
            )
            for row in ecosystem_ranges
            for event in dict_rows(
                row.get(
                    "events"
                )
            )
            if clean_text(
                event.get(
                    "source_key"
                )
            )
        }
    )


    return {
        "version_scope":
            (
                f">={introduced_text},"
                f"<{fixed_text}"
            ),

        "introduced_version":
            introduced_text,

        "fixed_version":
            fixed_text,

        # Backward-compatible representative field.
        "range_draft":
            deepcopy(
                representative[
                    "range_draft"
                ]
            ),

        # Preserve all agreeing provenance.
        "corroborating_range_drafts":
            [
                deepcopy(
                    row[
                        "range_draft"
                    ]
                )
                for row in parsed_ranges
            ],

        "ecosystem_range_count":
            len(
                ecosystem_ranges
            ),

        "ecosystem_range_source_keys":
            source_keys,

        "scope_resolution_mode":
            (
                "single_supported_ecosystem_range"
                if len(
                    ecosystem_ranges
                )
                == 1
                else (
                    "identical_supported_"
                    "ecosystem_range_consensus"
                )
            ),

        "semantic_boundary": {
            "duplicate_version_records_count_as_"
            "independent_trigger_semantics":
                False,

            "git_ranges_used_as_release_scope":
                False,

            "conflicting_ecosystem_ranges_accepted":
                False,
        },
    }


def find_fix_commit_leg(
    *,
    proposal: dict[str, Any],
    case: tuple[
        str,
        tuple[str, ...],
    ],
    corpus_entries: list[
        dict[str, Any]
    ],
) -> dict[str, Any] | None:
    (
        api_symbol,
        _,
        keyword_name,
        required_call_symbol,
    ) = proposal_signature(
        proposal
    )

    vulnerability_ids = case[1]

    matching = []

    for entry in corpus_entries:
        units = dict_rows(
            entry.get(
                "evidence_units"
            )
        )

        commit_messages = [
            unit
            for unit in units
            if clean_text(
                unit.get(
                    "unit_kind"
                )
            )
            == "github_commit_message"
        ]

        patches = [
            unit
            for unit in units
            if clean_text(
                unit.get(
                    "unit_kind"
                )
            )
            == "github_commit_patch"
        ]

        if (
            not commit_messages
            or not patches
        ):
            continue

        linked_messages = [
            unit
            for unit in commit_messages
            if vulnerability_id_in_text(
                vulnerability_ids,
                clean_text(
                    unit.get(
                        "text"
                    )
                ),
            )
        ]

        if not linked_messages:
            continue

        regression_patches = []

        implementation_patches = []

        for unit in patches:
            locator = unit.get(
                "locator",
                {},
            )

            if not isinstance(
                locator,
                dict,
            ):
                locator = {}

            filename = clean_text(
                locator.get(
                    "filename"
                )
            )

            text = clean_text(
                unit.get(
                    "text"
                )
            )

            if (
                is_test_path(
                    filename
                )
                and api_symbol
                in text
                and contains_keyword_assignment(
                    text,
                    keyword_name,
                )
                and required_call_symbol
                in text
            ):
                regression_patches.append(
                    unit
                )

            elif (
                filename.lower().endswith(
                    ".py"
                )
                and not is_test_path(
                    filename
                )
                and text
            ):
                implementation_patches.append(
                    unit
                )

        if (
            not regression_patches
            or not implementation_patches
        ):
            continue

        matching.append(
            {
                "source_key":
                    entry.get(
                        "source_key"
                    ),

                "source_type":
                    entry.get(
                        "source_type"
                    ),

                "canonical_identity":
                    deepcopy(
                        entry.get(
                            "canonical_identity",
                            {},
                        )
                    ),

                "commit_message_unit_ids":
                    [
                        row.get(
                            "unit_id"
                        )
                        for row
                        in linked_messages
                    ],

                "regression_test_patch_unit_ids":
                    [
                        row.get(
                            "unit_id"
                        )
                        for row
                        in regression_patches
                    ],

                "regression_test_files":
                    [
                        (
                            row.get(
                                "locator",
                                {},
                            )
                            or {}
                        ).get(
                            "filename"
                        )
                        for row
                        in regression_patches
                    ],

                "implementation_patch_unit_ids":
                    [
                        row.get(
                            "unit_id"
                        )
                        for row
                        in implementation_patches
                    ],

                "implementation_files":
                    [
                        (
                            row.get(
                                "locator",
                                {},
                            )
                            or {}
                        ).get(
                            "filename"
                        )
                        for row
                        in implementation_patches
                    ],
            }
        )

    if len(
        matching
    ) != 1:
        return None

    result = matching[0]

    result[
        "status"
    ] = (
        "supported"
    )

    return result


def build_api_history_leg(
    *,
    proposal: dict[str, Any],
    api_history: dict[str, Any],
    distribution: str,
    introduced_version: str,
    fixed_version: str,
) -> dict[str, Any] | None:
    if (
        clean_text(
            api_history.get(
                "schema_version"
            )
        )
        != EXPECTED_API_HISTORY_SCHEMA
    ):
        return None

    if (
        clean_text(
            api_history.get(
                "status"
            )
        )
        != "resolved"
    ):
        return None


    if (
        normalized_distribution(
            api_history.get(
                "distribution"
            )
        )
        != normalized_distribution(
            distribution
        )
    ):
        return None

    (
        api_symbol,
        _,
        keyword_name,
        required_call_symbol,
    ) = proposal_signature(
        proposal
    )

    versions = [
        introduced_version,
        fixed_version,
    ]

    primary = (
        find_api_history_entry(
            api_history=api_history,
            api_symbol=api_symbol,
            versions=versions,
            require_zero_arg=False,
            required_keyword_name=(
                keyword_name
            ),
        )
    )

    nested = (
        find_api_history_entry(
            api_history=api_history,
            api_symbol=(
                required_call_symbol
            ),
            versions=versions,
            require_zero_arg=True,
            required_keyword_name=None,
        )
    )

    if (
        primary is None
        or nested is None
    ):
        return None

    return {
        "status":
            "supported",

        "distribution":
            api_history.get(
                "distribution"
            ),

        "source_mode":
            api_history.get(
                "source_mode"
            ),

        "primary_api":
            primary,

        "nested_call_api":
            nested,

        "continuity_versions":
            versions,

        "final_rq1_automation_claim_eligible":
            api_history_leg_is_fully_automatic(
                api_history=api_history,
                primary=primary,
                nested=nested,
            ),

        "automation_note":
            (
                "Final RQ1 automation eligibility "
                "requires a fully automatic API "
                "History source mode and automatic "
                "rule-level provenance for every API "
                "History rule consumed by this proof. "
                "Curated or mixed artifacts may still "
                "support method validation."
            ),
    }


def compose_rule(
    *,
    proposal: dict[str, Any],
    version_scope: str,
    proof_id: str,
) -> dict[str, Any]:
    (
        api_symbol,
        kind,
        keyword_name,
        required_call_symbol,
    ) = proposal_signature(
        proposal
    )

    return {
        "trigger_id":
            proof_id,

        "api_symbol":
            api_symbol,

        "kind":
            kind,

        "keyword_argument": {
            "name":
                keyword_name,

            "required_call_symbol":
                required_call_symbol,
        },

        "version_scope":
            version_scope,
    }


def build_proof_draft(
    *,
    case: dict[str, Any],
    proposal: dict[str, Any],
    version_scope: dict[str, Any],
    advisory_leg: dict[str, Any],
    fix_commit_leg: dict[str, Any],
    api_history_leg: dict[str, Any],
) -> dict[str, Any]:
    payload = {
        "distribution":
            case.get(
                "distribution"
            ),

        "vulnerability_ids":
            normalized_ids(
                case.get(
                    "vulnerability_ids"
                )
            ),

        "proposal_signature":
            proposal_signature(
                proposal
            ),

        "version_scope":
            version_scope.get(
                "version_scope"
            ),
    }

    proof_id = make_id(
        "prooftrigger_",
        payload,
    )

    executable_rule = compose_rule(
        proposal=proposal,
        version_scope=clean_text(
            version_scope.get(
                "version_scope"
            )
        ),
        proof_id=proof_id,
    )

    return {
        "version_aware_trigger_draft_id":
            proof_id,

        "proof_composer_version":
            COMPOSER_VERSION,

        "proposal_type":
            (
                "proof_composed_"
                "version_aware_trigger_rule"
            ),

        "proposal_status":
            "proof_composed_executable",

        "review_required":
            False,

        "distribution":
            case.get(
                "distribution"
            ),

        "vulnerability_ids":
            deepcopy(
                case.get(
                    "vulnerability_ids",
                    [],
                )
            ),

        "semantic_trigger_hypothesis_id":
            None,

        "anchor":
            proposal.get(
                "api_symbol"
            ),

        "proof_path":
            (
                "vulnerability_specific_"
                "advisory_fix_regression_"
                "api_history_v0"
            ),

        "version_evidence":
            deepcopy(
                case.get(
                    "version_evidence",
                    {},
                )
            ),

        "version_scope_association": {
            "status":
                "proof_composed",

            "basis":
                (
                    "authoritative_vulnerability_"
                    "range_plus_vulnerability_"
                    "linked_fix_regression_plus_"
                    "api_history_continuity"
                ),

            "per_version_trigger_semantics_proven":
                True,
        },

        "executable_rule_ready":
            True,

        "matcher_rule_group":
            "conditional_api_rules",

        "executable_rule":
            executable_rule,

        "proof_bundle": {
            "structural_rule_proposal":
                deepcopy(
                    proposal
                ),

            "upstream_advisory_evidence":
                deepcopy(
                    advisory_leg
                ),

            "fix_commit_regression_evidence":
                deepcopy(
                    fix_commit_leg
                ),

            "version_scope_evidence":
                deepcopy(
                    version_scope
                ),

            "api_history_evidence":
                deepcopy(
                    api_history_leg
                ),
        },

        "review_reasons":
            [],

        "proposal_basis":
            (
                "The executable rule is promoted "
                "only because an automatically "
                "supported structural rule shape is "
                "present in a vulnerability-specific "
                "upstream advisory, the same "
                "vulnerability is linked to an "
                "upstream fix commit containing a "
                "regression-test use of the exact "
                "rule shape plus implementation "
                "changes, authoritative OSV evidence "
                "provides a single supported affected "
                "version interval, and API History "
                "shows that both API symbols remain "
                "available across the vulnerable and "
                "fixed boundaries."
            ),
    }


def assess_proposal(
    *,
    case: dict[str, Any],
    proposal: dict[str, Any],
    case_key_value: tuple[
        str,
        tuple[str, ...],
    ],
    fact_index: dict[
        str,
        dict[str, Any],
    ],
    validation_index: dict[
        str,
        dict[str, Any],
    ],
    corpus_entries: list[
        dict[str, Any]
    ],
    api_history: dict[str, Any],
) -> tuple[
    dict[str, Any] | None,
    list[str],
]:
    reasons = []

    (
        api_symbol,
        kind,
        keyword_name,
        required_call_symbol,
    ) = proposal_signature(
        proposal
    )

    if (
        kind
        != SUPPORTED_PROPOSAL_KIND
    ):
        reasons.append(
            "unsupported_proposal_kind"
        )

    if not api_symbol:
        reasons.append(
            "proposal_api_symbol_missing"
        )

    if not keyword_name:
        reasons.append(
            "proposal_keyword_name_missing"
        )

    if not required_call_symbol:
        reasons.append(
            "proposal_required_call_symbol_missing"
        )

    version_scope = (
        derive_single_osv_scope(
            case.get(
                "version_evidence",
                {},
            )
        )
    )

    if version_scope is None:
        reasons.append(
            "single_supported_osv_version_scope_missing"
        )

    advisory_leg = (
        find_upstream_advisory_leg(
            proposal=proposal,
            case=case_key_value,
            fact_index=fact_index,
            validation_index=(
                validation_index
            ),
        )
    )

    if advisory_leg is None:
        reasons.append(
            "upstream_advisory_exact_shape_missing"
        )

    fix_commit_leg = (
        find_fix_commit_leg(
            proposal=proposal,
            case=case_key_value,
            corpus_entries=(
                corpus_entries
            ),
        )
    )

    if fix_commit_leg is None:
        reasons.append(
            "vulnerability_linked_fix_regression_missing"
        )

    api_history_leg = None

    if version_scope is not None:
        api_history_leg = (
            build_api_history_leg(
                proposal=proposal,
                api_history=api_history,
                distribution=case_key_value[0],
                introduced_version=clean_text(
                    version_scope.get(
                        "introduced_version"
                    )
                ),
                fixed_version=clean_text(
                    version_scope.get(
                        "fixed_version"
                    )
                ),
            )
        )

    if api_history_leg is None:
        reasons.append(
            "api_history_continuity_missing"
        )

    if reasons:
        return (
            None,
            reasons,
        )

    assert version_scope is not None
    assert advisory_leg is not None
    assert fix_commit_leg is not None
    assert api_history_leg is not None

    return (
        build_proof_draft(
            case=case,
            proposal=proposal,
            version_scope=version_scope,
            advisory_leg=advisory_leg,
            fix_commit_leg=(
                fix_commit_leg
            ),
            api_history_leg=(
                api_history_leg
            ),
        ),
        [],
    )


def compose_proofs(
    *,
    version_aware_data: dict[str, Any],
    version_data: dict[str, Any],
    fact_data: dict[str, Any],
    validation_data: dict[str, Any],
    corpus_data: dict[str, Any],
    api_history_data: dict[str, Any],
) -> dict[str, Any]:
    if (
        clean_text(
            version_aware_data.get(
                "schema_version"
            )
        )
        != SCHEMA_VERSION
    ):
        raise ValueError(
            "Unexpected version-aware draft schema."
        )

    if (
        clean_text(
            version_data.get(
                "schema_version"
            )
        )
        != EXPECTED_VERSION_DRAFT_SCHEMA
    ):
        raise ValueError(
            "Unexpected version draft schema."
        )

    if (
        clean_text(
            corpus_data.get(
                "schema_version"
            )
        )
        != EXPECTED_CORPUS_SCHEMA
    ):
        raise ValueError(
            "Unexpected corpus schema."
        )

    output = deepcopy(
        version_aware_data
    )

    fact_index = build_fact_index(
        fact_data
    )

    validation_index = (
        build_validation_index(
            validation_data
        )
    )

    version_index = (
        build_version_draft_index(
            version_data
        )
    )

    corpus_index = (
        build_corpus_case_index(
            corpus_data
        )
    )

    proof_records = []

    composed_count = 0
    evaluated_count = 0

    cases = dict_rows(
        output.get(
            "cases"
        )
    )

    for case in cases:
        key = case_key(
            case
        )

        version_draft = (
            version_index.get(
                key
            )
        )

        proposals = []

        if isinstance(
            version_draft,
            dict,
        ):
            proposals = dict_rows(
                version_draft.get(
                    "structural_rule_proposals"
                )
            )

        corpus_entries = (
            corpus_index.get(
                key,
                [],
            )
        )

        existing_drafts = dict_rows(
            case.get(
                "version_aware_trigger_drafts"
            )
        )

        proof_drafts = []

        for proposal in proposals:
            evaluated_count += 1

            (
                draft,
                reasons,
            ) = assess_proposal(
                case=case,
                proposal=proposal,
                case_key_value=key,
                fact_index=fact_index,
                validation_index=(
                    validation_index
                ),
                corpus_entries=(
                    corpus_entries
                ),
                api_history=(
                    api_history_data
                ),
            )

            proof_records.append(
                {
                    "distribution":
                        case.get(
                            "distribution"
                        ),

                    "vulnerability_ids":
                        deepcopy(
                            case.get(
                                "vulnerability_ids",
                                [],
                            )
                        ),

                    "proposal_signature":
                        proposal_signature(
                            proposal
                        ),

                    "proof_status":
                        (
                            "composed"
                            if draft
                            is not None
                            else "unresolved"
                        ),

                    "reasons":
                        reasons,

                    "proof_id":
                        (
                            draft.get(
                                "version_aware_trigger_draft_id"
                            )
                            if draft
                            is not None
                            else None
                        ),
                }
            )

            if draft is not None:
                proof_drafts.append(
                    draft
                )

                composed_count += 1

        known_ids = {
            clean_text(
                row.get(
                    "version_aware_trigger_draft_id"
                )
            )
            for row in existing_drafts
            if clean_text(
                row.get(
                    "version_aware_trigger_draft_id"
                )
            )
        }

        for draft in proof_drafts:
            draft_id = clean_text(
                draft.get(
                    "version_aware_trigger_draft_id"
                )
            )

            if draft_id in known_ids:
                continue

            existing_drafts.append(
                draft
            )

            known_ids.add(
                draft_id
            )

        case[
            "version_aware_trigger_drafts"
        ] = existing_drafts

        case[
            "proof_composed_executable_rule_count"
        ] = len(
            proof_drafts
        )

    output[
        "proof_composer_version"
    ] = COMPOSER_VERSION

    output[
        "proof_composition_records"
    ] = proof_records

    output[
        "proof_composition_summary"
    ] = {
        "case_count":
            len(
                cases
            ),

        "structural_proposal_evaluated_count":
            evaluated_count,

        "proof_composed_executable_rule_count":
            composed_count,

        "unresolved_proposal_count":
            (
                evaluated_count
                - composed_count
            ),

        "proof_composition_rate":
            (
                composed_count
                / evaluated_count
                if evaluated_count
                else None
            ),

        "api_history_source_mode":
            api_history_data.get(
                "source_mode"
            ),

        "final_rq1_automation_claim_eligible":
            (
                bool(
                    composed_count
                )
                and all(
                    bool(
                        (
                            draft.get(
                                "proof_bundle",
                                {},
                            )
                            .get(
                                "api_history_evidence",
                                {},
                            )
                            .get(
                                "final_rq1_automation_claim_eligible",
                                False,
                            )
                        )
                    )
                    for case in cases
                    for draft in dict_rows(
                        case.get(
                            "version_aware_trigger_drafts"
                        )
                    )
                    if (
                        clean_text(
                            draft.get(
                                "proof_composer_version"
                            )
                        )
                        == COMPOSER_VERSION
                    )
                )
            ),
    }

    output[
        "proof_semantic_boundary"
    ] = {
        "osv_syndicated_advisory_counts_as_independent_semantic_leg":
            False,

        "requires_vulnerability_specific_upstream_advisory":
            True,

        "requires_vulnerability_linked_fix_commit":
            True,

        "requires_regression_test_exact_rule_shape":
            True,

        "requires_non_test_implementation_patch":
            True,

        "requires_single_supported_osv_version_interval":
            True,

        "requires_api_history_continuity":
            True,

        "uses_llm_judge":
            False,

        "uses_embedding_similarity":
            False,

        "relaxes_existing_admission_gate":
            False,

        "proof_composed_rule_means_full_exploit_proof":
            False,
    }

    return output


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Compose strictly proven executable "
            "Trigger rules from structural, "
            "vulnerability-specific, version, fix, "
            "and API History evidence."
        )
    )

    parser.add_argument(
        "--version-aware-drafts",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--version-drafts",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--facts",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--validation",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--corpus",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--api-history",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--out",
        required=True,
        type=Path,
    )

    args = parser.parse_args()

    result = compose_proofs(
        version_aware_data=load_json(
            args.version_aware_drafts
        ),
        version_data=load_json(
            args.version_drafts
        ),
        fact_data=load_json(
            args.facts
        ),
        validation_data=load_json(
            args.validation
        ),
        corpus_data=load_json(
            args.corpus
        ),
        api_history_data=load_json(
            args.api_history
        ),
    )

    write_json(
        args.out,
        result,
    )

    summary = result.get(
        "proof_composition_summary",
        {},
    )

    print(
        "[OK] composer:",
        COMPOSER_VERSION,
    )

    print(
        "[OK] cases:",
        summary.get(
            "case_count"
        ),
    )

    print(
        "[OK] structural proposals evaluated:",
        summary.get(
            "structural_proposal_evaluated_count"
        ),
    )

    print(
        "[OK] proof-composed executable rules:",
        summary.get(
            "proof_composed_executable_rule_count"
        ),
    )

    print(
        "[OK] unresolved proposals:",
        summary.get(
            "unresolved_proposal_count"
        ),
    )

    print(
        "[OK] final RQ1 automation claim eligible:",
        summary.get(
            "final_rq1_automation_claim_eligible"
        ),
    )

    print(
        "[OK] saved:",
        args.out,
    )


if __name__ == "__main__":
    main()
