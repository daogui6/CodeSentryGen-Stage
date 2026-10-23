from __future__ import annotations

from build_executable_trigger_admission import (
    ADMITTER_VERSION,
    build_admission,
)


def base_case(
    distribution: str,
):
    return {
        "distribution":
            distribution,

        "vulnerability_ids": [
            "TEST-VULN"
        ],

        "version_evidence": {
            "status":
                "supported_version_evidence",
        },

        "version_aware_trigger_drafts":
            [],
    }


def main() -> None:

    # --------------------------------------------------
    # Case 1:
    # No semantic/version-aware draft.
    # Must NOT become not_matched or executable.
    # --------------------------------------------------

    no_draft = base_case(
        "no-draft-demo"
    )


    # --------------------------------------------------
    # Case 2:
    # This mirrors current automatic drafts:
    # review required + no executable rule.
    # --------------------------------------------------

    review_case = base_case(
        "review-demo"
    )

    review_case[
        "version_aware_trigger_drafts"
    ] = [
        {
            "version_aware_trigger_draft_id":
                "vatrigger_review",

            "semantic_trigger_hypothesis_id":
                "triggerhyp_review",

            "anchor":
                "demo.anchor",

            "review_required":
                True,

            "executable_rule_ready":
                False,

            "version_scope_association": {
                "per_version_trigger_semantics_proven":
                    False,
            },
        }
    ]


    # --------------------------------------------------
    # Case 3:
    # Synthetic future reviewed rule.
    # Demonstrates the only state allowed through.
    # --------------------------------------------------

    admitted_case = base_case(
        "requests"
    )

    admitted_case[
        "version_aware_trigger_drafts"
    ] = [
        {
            "version_aware_trigger_draft_id":
                "vatrigger_admitted",

            "semantic_trigger_hypothesis_id":
                "triggerhyp_admitted",

            "anchor":
                "requests.get",

            "review_required":
                False,

            "executable_rule_ready":
                True,

            "version_scope_association": {
                "per_version_trigger_semantics_proven":
                    True,
            },

            "matcher_rule_group":
                "conditional_api_rules",

            "executable_rule": {
                "trigger_id":
                    "requests_netrc_host_confusion",

                "api_symbol":
                    "requests.get",

                "kind":
                    "positional_url_condition",

                "positional_argument": {
                    "position":
                        0,

                    "url_condition":
                        (
                            "legacy_netrc_host_"
                            "differs_from_hostname"
                        ),
                },

                "version_scope":
                    "<2.32.4",
            },
        }
    ]


    artifact = {
        "schema_version":
            (
                "avcs_version_aware_"
                "trigger_evidence_draft_v0.1"
            ),

        "cases": [
            no_draft,
            review_case,
            admitted_case,
        ],
    }


    result = build_admission(
        artifact
    )

    assert (
        result.get(
            "admitter_version"
        )
        == ADMITTER_VERSION
    )

    summary = result.get(
        "summary",
        {},
    )

    assert (
        summary.get(
            "case_count"
        )
        == 3
    )

    assert (
        summary.get(
            "version_aware_trigger_draft_count"
        )
        == 2
    )

    assert (
        summary.get(
            "admitted_executable_rule_count"
        )
        == 1
    )

    assert (
        summary.get(
            "matcher_ready_case_count"
        )
        == 1
    )

    assert (
        summary.get(
            "review_gated_draft_admission_rate"
        )
        == 0.5
    )

    assert (
        summary.get(
            "review_gated_draft_admission_denominator"
        )
        == 2
    )

    records = {
        row.get(
            "distribution"
        ):
            row
        for row in result.get(
            "admission_records",
            []
        )
    }

    assert (
        records[
            "no-draft-demo"
        ][
            "admission_status"
        ]
        == "no_version_aware_trigger_draft"
    )

    assert (
        records[
            "review-demo"
        ][
            "admission_status"
        ]
        == "review_or_rule_resolution_required"
    )

    reasons = (
        records[
            "review-demo"
        ][
            "draft_admissions"
        ][0][
            "reasons"
        ]
    )

    assert (
        "draft_still_requires_review"
        in reasons
    )

    assert (
        "executable_rule_not_ready"
        in reasons
    )

    assert (
        "per_version_trigger_semantics_not_proven"
        in reasons
    )

    assert (
        records[
            "requests"
        ][
            "admission_status"
        ]
        == "matcher_ready"
    )

    entries = result.get(
        "entries",
        [],
    )

    assert len(
        entries
    ) == 1

    rules = (
        entries[0]
        .get(
            "trigger_conditions",
            {},
        )
        .get(
            "conditional_api_rules",
            [],
        )
    )

    assert len(
        rules
    ) == 1

    assert (
        rules[0].get(
            "trigger_id"
        )
        == "requests_netrc_host_confusion"
    )

    zero_denominator = build_admission(
        {
            "schema_version":
                (
                    "avcs_version_aware_"
                    "trigger_evidence_draft_v0.1"
                ),

            "cases": [
                base_case(
                    "zero-denominator-demo"
                )
            ],
        }
    )

    zero_summary = zero_denominator.get(
        "summary",
        {},
    )

    assert (
        zero_summary.get(
            "review_gated_draft_admission_rate"
        )
        is None
    )

    assert (
        zero_summary.get(
            "review_gated_draft_admission_denominator"
        )
        == 0
    )

    print(
        "[PASS] zero-draft denominator is "
        "reported as N/A rather than 0%."
    )


    print(
        "[PASS] unresolved automatic drafts "
        "cannot enter Matcher."
    )

    print(
        "[PASS] no-draft state remains "
        "explicitly non-executable."
    )

    print(
        "[PASS] only review-cleared, "
        "version-proven executable rules "
        "become matcher-ready."
    )

    print(
        "[PASS] Executable Trigger "
        "Admission Gate v0."
    )


if __name__ == "__main__":
    main()
