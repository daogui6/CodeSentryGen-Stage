from __future__ import annotations

import argparse
import json
from collections import Counter
from copy import deepcopy
from pathlib import Path
from typing import Any


SCHEMA_VERSION = (
    "avcs_executable_trigger_admission_v0.1"
)

ADMITTER_VERSION = (
    "executable_trigger_admission_gate_v0.1"
)

EXPECTED_INPUT_SCHEMA = (
    "avcs_version_aware_trigger_evidence_draft_v0.1"
)

SUPPORTED_RULE_GROUPS = {
    "direct_api_rules",
    "conditional_api_rules",
}


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


def assess_draft(
    *,
    draft: dict[str, Any],
    version_evidence: dict[str, Any],
) -> dict[str, Any]:
    reasons: list[str] = []

    version_status = clean_text(
        version_evidence.get(
            "status"
        )
    )

    if (
        version_status
        != "supported_version_evidence"
    ):
        reasons.append(
            "version_evidence_not_fully_supported"
        )

    if (
        draft.get(
            "review_required"
        )
        is not False
    ):
        reasons.append(
            "draft_still_requires_review"
        )

    if (
        draft.get(
            "executable_rule_ready"
        )
        is not True
    ):
        reasons.append(
            "executable_rule_not_ready"
        )

    association = draft.get(
        "version_scope_association",
        {},
    )

    if not isinstance(
        association,
        dict,
    ):
        association = {}

    if (
        association.get(
            "per_version_trigger_semantics_proven"
        )
        is not True
    ):
        reasons.append(
            "per_version_trigger_semantics_not_proven"
        )

    rule_group = clean_text(
        draft.get(
            "matcher_rule_group"
        )
    )

    if (
        rule_group
        not in SUPPORTED_RULE_GROUPS
    ):
        reasons.append(
            "matcher_rule_group_not_available"
        )

    rule = draft.get(
        "executable_rule"
    )

    if not isinstance(
        rule,
        dict,
    ):
        reasons.append(
            "executable_rule_payload_missing"
        )
        rule = {}

    api_symbol = clean_text(
        rule.get(
            "api_symbol"
        )
    )

    kind = clean_text(
        rule.get(
            "kind"
        )
    )

    version_scope = clean_text(
        rule.get(
            "version_scope"
        )
    )

    if (
        isinstance(
            rule,
            dict,
        )
        and rule
    ):
        if not api_symbol:
            reasons.append(
                "executable_rule_api_symbol_missing"
            )

        if not kind:
            reasons.append(
                "executable_rule_kind_missing"
            )

        if not version_scope:
            reasons.append(
                "executable_rule_version_scope_missing"
            )

    admitted = not reasons

    return {
        "version_aware_trigger_draft_id":
            draft.get(
                "version_aware_trigger_draft_id"
            ),

        "semantic_trigger_hypothesis_id":
            draft.get(
                "semantic_trigger_hypothesis_id"
            ),

        "anchor":
            draft.get(
                "anchor"
            ),

        "admission_status":
            (
                "admitted"
                if admitted
                else "unresolved"
            ),

        "admitted":
            admitted,

        "reasons":
            reasons,

        "matcher_rule_group":
            (
                rule_group
                if rule_group
                else None
            ),

        "executable_rule":
            (
                deepcopy(
                    rule
                )
                if admitted
                else None
            ),
    }


def build_matcher_entry(
    *,
    case: dict[str, Any],
    admitted_records: list[
        dict[str, Any]
    ],
) -> dict[str, Any]:
    direct_rules = []

    conditional_rules = []

    for record in admitted_records:
        rule = record.get(
            "executable_rule"
        )

        if not isinstance(
            rule,
            dict,
        ):
            continue

        group = clean_text(
            record.get(
                "matcher_rule_group"
            )
        )

        if (
            group
            == "direct_api_rules"
        ):
            direct_rules.append(
                deepcopy(
                    rule
                )
            )

        elif (
            group
            == "conditional_api_rules"
        ):
            conditional_rules.append(
                deepcopy(
                    rule
                )
            )

    return {
        "distribution":
            case.get(
                "distribution"
            ),

        "normalized_distribution":
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

        "evidence_status":
            "executable_rule_admitted",

        "trigger_conditions": {
            "api_symbols":
                [],

            "direct_api_rules":
                direct_rules,

            "conditional_api_rules":
                conditional_rules,
        },

        "safe_api_symbols":
            [],

        "safe_api_rules":
            [],

        "source_mode":
            "review_gated_version_aware_trigger_draft",

        "admission_note":
            (
                "Only version-aware drafts that "
                "explicitly cleared review, contain "
                "an executable rule, and have "
                "per-version Trigger semantics "
                "marked as proven are exposed to "
                "the executable matcher."
            ),
    }


def build_admission(
    data: dict[str, Any],
) -> dict[str, Any]:
    if (
        clean_text(
            data.get(
                "schema_version"
            )
        )
        != EXPECTED_INPUT_SCHEMA
    ):
        raise ValueError(
            "Unexpected version-aware "
            "Trigger draft schema."
        )

    raw_cases = data.get(
        "cases",
        [],
    )

    if not isinstance(
        raw_cases,
        list,
    ):
        raise ValueError(
            "Input field 'cases' must be a list."
        )

    admission_records = []

    matcher_entries = []

    case_status_counts = Counter()

    total_drafts = 0
    admitted_drafts = 0

    for case in raw_cases:
        if not isinstance(
            case,
            dict,
        ):
            continue

        version_evidence = case.get(
            "version_evidence",
            {},
        )

        if not isinstance(
            version_evidence,
            dict,
        ):
            version_evidence = {}

        drafts = case.get(
            "version_aware_trigger_drafts",
            [],
        )

        if not isinstance(
            drafts,
            list,
        ):
            drafts = []

        drafts = [
            row
            for row in drafts
            if isinstance(
                row,
                dict,
            )
        ]

        total_drafts += len(
            drafts
        )

        case_records = []

        for draft in drafts:
            record = assess_draft(
                draft=draft,
                version_evidence=(
                    version_evidence
                ),
            )

            case_records.append(
                record
            )

            if record.get(
                "admitted"
            ):
                admitted_drafts += 1

        admitted_records = [
            row
            for row in case_records
            if row.get(
                "admitted"
            )
        ]

        if admitted_records:
            case_status = (
                "matcher_ready"
            )

            matcher_entries.append(
                build_matcher_entry(
                    case=case,
                    admitted_records=(
                        admitted_records
                    ),
                )
            )

        elif drafts:
            case_status = (
                "review_or_rule_resolution_required"
            )

        else:
            case_status = (
                "no_version_aware_trigger_draft"
            )

        case_status_counts[
            case_status
        ] += 1

        admission_records.append(
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

                "version_evidence_status":
                    version_evidence.get(
                        "status"
                    ),

                "version_aware_trigger_draft_count":
                    len(
                        drafts
                    ),

                "admitted_rule_count":
                    len(
                        admitted_records
                    ),

                "admission_status":
                    case_status,

                "draft_admissions":
                    case_records,
            }
        )

    return {
        "schema_version":
            SCHEMA_VERSION,

        "admitter_version":
            ADMITTER_VERSION,

        # Matcher can directly consume this artifact
        # once at least one entry has passed admission.
        "entries":
            matcher_entries,

        "admission_records":
            admission_records,

        "summary": {
            "case_count":
                len(
                    admission_records
                ),

            "version_aware_trigger_draft_count":
                total_drafts,

            "admitted_executable_rule_count":
                admitted_drafts,

            "matcher_ready_case_count":
                len(
                    matcher_entries
                ),

            "case_status_counts":
                dict(
                    sorted(
                        case_status_counts.items()
                    )
                ),

            "review_gated_draft_admission_rate":
                (
                    admitted_drafts
                    / total_drafts
                    if total_drafts
                    else None
                ),

            "review_gated_draft_admission_denominator":
                total_drafts,
        },

        "semantic_boundary": {
            "invents_executable_rules":
                False,

            "automatically_overrides_review":
                False,

            "requires_supported_version_evidence":
                True,

            "requires_review_cleared":
                True,

            "requires_per_version_semantics_proven":
                True,

            "matcher_ready_entry_means_full_exploit_proof":
                False,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Gate version-aware Trigger drafts "
            "before executable matcher admission."
        )
    )

    parser.add_argument(
        "--version-aware-drafts",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--out",
        required=True,
        type=Path,
    )

    args = parser.parse_args()

    data = load_json(
        args.version_aware_drafts
    )

    result = build_admission(
        data
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
        )
        + "\n",
        encoding="utf-8",
    )

    summary = result.get(
        "summary",
        {},
    )

    print(
        "[OK] admitter:",
        ADMITTER_VERSION,
    )

    print(
        "[OK] cases:",
        summary.get(
            "case_count"
        ),
    )

    print(
        "[OK] version-aware drafts:",
        summary.get(
            "version_aware_trigger_draft_count"
        ),
    )

    print(
        "[OK] admitted executable rules:",
        summary.get(
            "admitted_executable_rule_count"
        ),
    )

    print(
        "[OK] matcher-ready cases:",
        summary.get(
            "matcher_ready_case_count"
        ),
    )

    print(
        "[OK] saved:",
        args.out,
    )


if __name__ == "__main__":
    main()
