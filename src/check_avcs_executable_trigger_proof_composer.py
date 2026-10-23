from __future__ import annotations

from copy import deepcopy

from compose_executable_trigger_proofs import (
    COMPOSER_VERSION,
    compose_proofs,
)


VULNERABILITY_IDS = [
    "CVE-2022-29217",
    "GHSA-ffqj-6fqr-9h24",
]


def structural_proposal():
    return {
        "proposal_type":
            "conditional_trigger_rule_shape",

        "proposal_status":
            "proposed_requires_review",

        "review_required":
            True,

        "api_symbol":
            "jwt.decode",

        "kind":
            "keyword_call_condition",

        "keyword_argument": {
            "name":
                "algorithms",

            "required_call_symbol":
                (
                    "jwt.algorithms."
                    "get_default_algorithms"
                ),
        },

        "version_scope":
            None,

        "supporting_fact_ids": [
            "fact_advisory",
        ],
    }


def version_aware_input():
    return {
        "schema_version":
            (
                "avcs_version_aware_"
                "trigger_evidence_draft_v0.1"
            ),

        "cases": [
            {
                "distribution":
                    "pyjwt",

                "vulnerability_ids":
                    VULNERABILITY_IDS,

                "version_evidence": {
                    "status":
                        "supported_version_evidence",

                    "fixed_release_status":
                        "supported",

                    "fixed_release_resolution_mode":
                        "single_release",

                    "fixed_release":
                        "2.4.0",

                    "distinct_fixed_versions": [
                        "2.4.0"
                    ],

                    "osv_range_drafts": [
                        {
                            "range_type":
                                "ECOSYSTEM",

                            "status":
                                (
                                    "supported_atomic_"
                                    "range_events"
                                ),

                            "events": [
                                {
                                    "event":
                                        "introduced",

                                    "version":
                                        "1.5.0",
                                },

                                {
                                    "event":
                                        "fixed",

                                    "version":
                                        "2.4.0",
                                },
                            ],
                        }
                    ],
                },

                "version_aware_trigger_drafts":
                    [],
            }
        ],
    }


def version_input():
    return {
        "schema_version":
            "avcs_trigger_evidence_draft_v0.1",

        "drafts": [
            {
                "distribution":
                    "pyjwt",

                "vulnerability_ids":
                    VULNERABILITY_IDS,

                "structural_rule_proposals": [
                    structural_proposal()
                ],
            }
        ],
    }


def facts_input():
    return {
        "schema_version":
            "synthetic",

        "facts": [
            {
                "fact_id":
                    "fact_advisory",

                "distribution":
                    "pyjwt",

                "vulnerability_ids":
                    VULNERABILITY_IDS,

                "source_key":
                    "pyjwt::upstream_advisory",

                "source_type":
                    (
                        "upstream_security_"
                        "advisory"
                    ),

                "evidence_unit_id":
                    (
                        "pyjwt::upstream_"
                        "advisory::unit_002"
                    ),

                "fact_kind":
                    (
                        "code_expression_"
                        "keyword_call_candidate"
                    ),

                "structured_value": {
                    "call_symbol":
                        "jwt.decode",

                    "keyword_name":
                        "algorithms",

                    "argument_value": {
                        "value_kind":
                            "call",

                        "call_symbol":
                            (
                                "jwt.algorithms."
                                "get_default_algorithms"
                            ),
                    },
                },

                "evidence_excerpt":
                    (
                        "jwt.decode(token, key, "
                        "algorithms="
                        "jwt.algorithms."
                        "get_default_algorithms())"
                    ),
            }
        ],
    }


def validation_input():
    return {
        "schema_version":
            "synthetic",

        "validation_records": [
            {
                "fact_id":
                    "fact_advisory",

                "validation_status":
                    "supported",

                "automatic_decision":
                    True,

                "review_required":
                    False,
            }
        ],
    }


def corpus_input():
    return {
        "schema_version":
            (
                "avcs_trigger_candidate_"
                "evidence_corpus_v0.1"
            ),

        "entries": [
            {
                "distribution":
                    "pyjwt",

                "vulnerability_ids":
                    VULNERABILITY_IDS,

                "source_key":
                    "pyjwt::upstream_advisory",

                "source_type":
                    (
                        "upstream_security_"
                        "advisory"
                    ),

                "evidence_units":
                    [],
            },

            {
                "distribution":
                    "pyjwt",

                "vulnerability_ids":
                    VULNERABILITY_IDS,

                "source_key":
                    "pyjwt::fix_commit",

                "source_type":
                    "upstream_fix_commit",

                "canonical_identity": {
                    "canonical_commit_sha":
                        "9c528670",
                },

                "evidence_units": [
                    {
                        "unit_id":
                            (
                                "pyjwt::fix_commit::"
                                "unit_001"
                            ),

                        "unit_kind":
                            "github_commit_message",

                        "text":
                            (
                                "Security fix for "
                                "GHSA-ffqj-6fqr-9h24"
                            ),
                    },

                    {
                        "unit_id":
                            (
                                "pyjwt::fix_commit::"
                                "unit_002"
                            ),

                        "unit_kind":
                            "github_commit_patch",

                        "locator": {
                            "filename":
                                (
                                    "tests/"
                                    "test_advisory.py"
                                ),
                        },

                        "text":
                            (
                                "+ jwt.decode("
                                "encoded_bad, key, "
                                "algorithms="
                                "jwt.algorithms."
                                "get_default_algorithms()"
                                ")\n"
                                "+ with pytest.raises("
                                "InvalidKeyError):"
                            ),
                    },

                    {
                        "unit_id":
                            (
                                "pyjwt::fix_commit::"
                                "unit_003"
                            ),

                        "unit_kind":
                            "github_commit_patch",

                        "locator": {
                            "filename":
                                "jwt/algorithms.py",
                        },

                        "text":
                            (
                                "+ if is_pem_format(key) "
                                "or is_ssh_key(key):"
                            ),
                    },
                ],
            },
        ],
    }


def api_history_input():
    return {
        "schema_version":
            "avcs_api_history_evidence_v0.1",

        "distribution":
            "pyjwt",

        "source_mode":
            "curated_real_api_history",

        "status":
            "resolved",

        "entries": [
            {
                "api_symbol":
                    "jwt.decode",

                "api_kind":
                    "function",

                "version_rules": [
                    {
                        "status":
                            "resolved",

                        "version_specifier":
                            ">=1.0.0",

                        "required_positional_args_min":
                            2,

                        "required_positional_args_max":
                            2,

                        "required_keyword_args": [
                            "algorithms"
                        ],
                    }
                ],
            },

            {
                "api_symbol":
                    (
                        "jwt.algorithms."
                        "get_default_algorithms"
                    ),

                "api_kind":
                    "function",

                "version_rules": [
                    {
                        "status":
                            "resolved",

                        "version_specifier":
                            ">=1.0.0",

                        "required_positional_args_min":
                            0,

                        "required_positional_args_max":
                            0,

                        "required_keyword_args":
                            [],
                    }
                ],
            },
        ],
    }


def compose(
    *,
    corpus=None,
    api_history=None,
    version_aware=None,
):
    return compose_proofs(
        version_aware_data=(
            version_aware
            or version_aware_input()
        ),
        version_data=version_input(),
        fact_data=facts_input(),
        validation_data=validation_input(),
        corpus_data=(
            corpus
            or corpus_input()
        ),
        api_history_data=(
            api_history
            or api_history_input()
        ),
    )


def composed_count(
    result,
):
    return result[
        "proof_composition_summary"
    ][
        "proof_composed_executable_rule_count"
    ]


def main():
    assert (
        COMPOSER_VERSION
        == (
            "executable_trigger_"
            "proof_composer_v0.1"
        )
    )


    # --------------------------------------------------
    # Positive proof path.
    # --------------------------------------------------

    result = compose()

    summary = result[
        "proof_composition_summary"
    ]

    assert (
        summary[
            "structural_proposal_evaluated_count"
        ]
        == 1
    )

    assert (
        composed_count(
            result
        )
        == 1
    )

    assert (
        summary[
            "unresolved_proposal_count"
        ]
        == 0
    )

    assert (
        summary[
            "final_rq1_automation_claim_eligible"
        ]
        is False
    )


    draft = (
        result[
            "cases"
        ][0][
            "version_aware_trigger_drafts"
        ][0]
    )

    assert (
        draft[
            "review_required"
        ]
        is False
    )

    assert (
        draft[
            "executable_rule_ready"
        ]
        is True
    )

    assert (
        draft[
            "version_scope_association"
        ][
            "per_version_trigger_semantics_proven"
        ]
        is True
    )


    rule = draft[
        "executable_rule"
    ]

    assert (
        rule[
            "api_symbol"
        ]
        == "jwt.decode"
    )

    assert (
        rule[
            "kind"
        ]
        == "keyword_call_condition"
    )

    assert (
        rule[
            "keyword_argument"
        ][
            "name"
        ]
        == "algorithms"
    )

    assert (
        rule[
            "keyword_argument"
        ][
            "required_call_symbol"
        ]
        == (
            "jwt.algorithms."
            "get_default_algorithms"
        )
    )

    assert (
        rule[
            "version_scope"
        ]
        == ">=1.5.0,<2.4.0"
    )


    # --------------------------------------------------
    # Positive:
    # multiple identical supported ECOSYSTEM ranges
    # plus an unrelated GIT range are allowed.
    #
    # This mirrors the real PyJWT evidence shape:
    #
    # GHSA ECOSYSTEM  1.5.0 -> 2.4.0
    # PYSEC GIT       0 -> commit SHA
    # PYSEC ECOSYSTEM 1.5.0 -> 2.4.0
    # --------------------------------------------------

    duplicate_version = deepcopy(
        version_aware_input()
    )

    ranges = (
        duplicate_version[
            "cases"
        ][0][
            "version_evidence"
        ][
            "osv_range_drafts"
        ]
    )


    second_ecosystem = deepcopy(
        ranges[0]
    )

    second_ecosystem[
        "range_index"
    ] = 1

    for event in second_ecosystem[
        "events"
    ]:
        event[
            "source_key"
        ] = "pyjwt::pysec_2022_202"


    git_range = {
        "affected_index":
            0,

        "range_index":
            0,

        "range_type":
            "GIT",

        "package_name":
            "pyjwt",

        "ecosystem":
            "PyPI",

        "status":
            "supported_atomic_range_events",

        "events": [
            {
                "event_index":
                    0,

                "event":
                    "introduced",

                "version":
                    "0",

                "source_key":
                    "pyjwt::pysec_2022_202",
            },

            {
                "event_index":
                    1,

                "event":
                    "fixed",

                "version":
                    (
                        "9c528670c455b8d948"
                        "aff95ed50e22940d1ad3fc"
                    ),

                "source_key":
                    "pyjwt::pysec_2022_202",
            },
        ],
    }


    ranges.append(
        git_range
    )

    ranges.append(
        second_ecosystem
    )


    duplicate_result = compose(
        version_aware=duplicate_version
    )


    assert (
        composed_count(
            duplicate_result
        )
        == 1
    )


    duplicate_draft = (
        duplicate_result[
            "cases"
        ][0][
            "version_aware_trigger_drafts"
        ][0]
    )


    duplicate_scope = (
        duplicate_draft[
            "proof_bundle"
        ][
            "version_scope_evidence"
        ]
    )


    assert (
        duplicate_scope[
            "version_scope"
        ]
        == ">=1.5.0,<2.4.0"
    )

    assert (
        duplicate_scope[
            "ecosystem_range_count"
        ]
        == 2
    )

    assert (
        duplicate_scope[
            "scope_resolution_mode"
        ]
        == (
            "identical_supported_"
            "ecosystem_range_consensus"
        )
    )


    # --------------------------------------------------
    # Negative:
    # conflicting ECOSYSTEM ranges must remain
    # unresolved rather than being voted/merged.
    # --------------------------------------------------

    conflicting_version = deepcopy(
        duplicate_version
    )

    ecosystem_rows = [
        row
        for row
        in conflicting_version[
            "cases"
        ][0][
            "version_evidence"
        ][
            "osv_range_drafts"
        ]
        if row.get(
            "range_type"
        )
        == "ECOSYSTEM"
    ]


    assert len(
        ecosystem_rows
    ) == 2


    ecosystem_rows[1][
        "events"
    ][0][
        "version"
    ] = "1.6.0"


    conflicting_result = compose(
        version_aware=conflicting_version
    )


    assert (
        composed_count(
            conflicting_result
        )
        == 0
    )


    # --------------------------------------------------
    # Negative 1:
    # regression test is mandatory.
    # --------------------------------------------------

    no_regression = deepcopy(
        corpus_input()
    )

    no_regression[
        "entries"
    ][1][
        "evidence_units"
    ] = [
        row
        for row
        in no_regression[
            "entries"
        ][1][
            "evidence_units"
        ]
        if not (
            row.get(
                "unit_kind"
            )
            == "github_commit_patch"
            and "tests/"
            in str(
                row.get(
                    "locator",
                    {},
                ).get(
                    "filename",
                    "",
                )
            )
        )
    ]

    assert (
        composed_count(
            compose(
                corpus=no_regression
            )
        )
        == 0
    )


    # --------------------------------------------------
    # Negative 2:
    # API History must prove algorithms keyword.
    # --------------------------------------------------

    missing_keyword_history = deepcopy(
        api_history_input()
    )

    missing_keyword_history[
        "entries"
    ][0][
        "version_rules"
    ][0][
        "required_keyword_args"
    ] = []

    assert (
        composed_count(
            compose(
                api_history=(
                    missing_keyword_history
                )
            )
        )
        == 0
    )


    # --------------------------------------------------
    # Negative 3:
    # Attribute-name "algorithms" is NOT equivalent
    # to algorithms= keyword assignment.
    # --------------------------------------------------

    wrong_keyword_corpus = deepcopy(
        corpus_input()
    )

    regression_patch = (
        wrong_keyword_corpus[
            "entries"
        ][1][
            "evidence_units"
        ][1]
    )

    regression_patch[
        "text"
    ] = (
        "+ jwt.decode("
        "encoded_bad, key, "
        "options="
        "jwt.algorithms."
        "get_default_algorithms()"
        ")"
    )

    assert (
        composed_count(
            compose(
                corpus=wrong_keyword_corpus
            )
        )
        == 0
    )


    # --------------------------------------------------
    # Negative 4:
    # API History must span fixed boundary.
    # --------------------------------------------------

    bad_history = deepcopy(
        api_history_input()
    )

    for entry in bad_history[
        "entries"
    ]:
        for rule_row in entry[
            "version_rules"
        ]:
            rule_row[
                "version_specifier"
            ] = "<2.0.0"

    assert (
        composed_count(
            compose(
                api_history=bad_history
            )
        )
        == 0
    )


    # --------------------------------------------------
    # Negative 5:
    # API History must belong to same distribution.
    # --------------------------------------------------

    wrong_distribution = deepcopy(
        api_history_input()
    )

    wrong_distribution[
        "distribution"
    ] = "urllib3"

    assert (
        composed_count(
            compose(
                api_history=wrong_distribution
            )
        )
        == 0
    )


    # --------------------------------------------------
    # Negative 6:
    # OSV open-start 0 remains unresolved.
    # --------------------------------------------------

    bad_version = version_aware_input()

    bad_version[
        "cases"
    ][0][
        "version_evidence"
    ][
        "osv_range_drafts"
    ][0][
        "events"
    ][0][
        "version"
    ] = "0"

    assert (
        composed_count(
            compose(
                version_aware=bad_version
            )
        )
        == 0
    )


    print(
        "[PASS] exact keyword-call "
        "proof path is composed."
    )

    print(
        "[PASS] identical supported "
        "ECOSYSTEM ranges normalize to one "
        "release scope while GIT ranges stay "
        "out of release matching."
    )

    print(
        "[PASS] conflicting ECOSYSTEM ranges "
        "remain unresolved."
    )

    print(
        "[PASS] regression-test evidence "
        "is mandatory."
    )

    print(
        "[PASS] API History proves the "
        "required keyword and continuity."
    )

    print(
        "[PASS] attribute/module names cannot "
        "masquerade as keyword assignments."
    )

    print(
        "[PASS] API History must span both "
        "vulnerable and fixed boundaries."
    )

    print(
        "[PASS] API History must belong to "
        "the same distribution."
    )

    print(
        "[PASS] OSV open-start ranges remain "
        "unresolved."
    )

    print(
        "[PASS] curated API History is "
        "ineligible for final RQ1 automation "
        "rate claims."
    )

    print(
        "[PASS] Executable Trigger "
        "Proof Composer v0.1."
    )


if __name__ == "__main__":
    main()
