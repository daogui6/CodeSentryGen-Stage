from __future__ import annotations

from typing import Any

from check_avcs_trigger_rule_matching import (
    AIOHTTP_EXPOSED_RELEASES,
    AIOHTTP_FOLLOW_SYMLINKS_TRIGGER,
    DIRECT_FULL_LOAD_RULE,
    EXPOSED_RELEASES,
    NUMPY_EXPOSED_RELEASES,
    NUMPY_OMITTED_ALLOW_PICKLE_TRIGGER,
    PYJWT_DEFAULT_ALGORITHMS_TRIGGER,
    PYJWT_EXPOSED_RELEASES,
    REQUESTS_EXPOSED_RELEASES,
    REQUESTS_NETRC_HOST_CONFUSION_TRIGGER,
    SAFE_LOADER_RULE,
    TRIGGER_FULL_LOADER,
    TRIGGER_OMITTED_LOADER,
    URLLIB3_EXPOSED_RELEASES,
    URLLIB3_POOLMANAGER_RETRIES_TRIGGER,
    build_call,
    build_direct_call,
    build_literal_call,
    build_numpy_load_call,
    build_pyjwt_decode_call,
    build_requests_get_call,
    build_urllib3_request_call,
)

from run_avcs_trigger_matcher import (
    MATCHER_VERSION,
    match_trigger_entry,
)


def evidence(
    calls: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "schema_version":
            "api_call_evidence_v0.1",

        "sample_id":
            "executable_matcher_regression",

        "code_file":
            "synthetic.py",

        "parse_status":
            "ok",

        "api_calls":
            calls,
    }


def entry(
    distribution: str,
    *,
    direct_rules: (
        list[dict[str, Any]]
        | None
    ) = None,
    conditional_rules: (
        list[dict[str, Any]]
        | None
    ) = None,
    safe_rules: (
        list[dict[str, Any]]
        | None
    ) = None,
) -> dict[str, Any]:
    return {
        "distribution":
            distribution,

        "normalized_distribution":
            distribution,

        "vulnerability_ids": [
            "TEST-VULNERABILITY"
        ],

        "trigger_conditions": {
            "api_symbols":
                [],

            "direct_api_rules":
                direct_rules or [],

            "conditional_api_rules":
                conditional_rules or [],
        },

        "safe_api_symbols":
            [],

        "safe_api_rules":
            safe_rules or [],
    }


def run(
    *,
    distribution: str,
    calls: list[dict[str, Any]],
    exposed: list[dict[str, str]],
    direct_rules: (
        list[dict[str, Any]]
        | None
    ) = None,
    conditional_rules: (
        list[dict[str, Any]]
        | None
    ) = None,
    safe_rules: (
        list[dict[str, Any]]
        | None
    ) = None,
) -> dict[str, Any]:
    return match_trigger_entry(
        api_call_evidence=evidence(
            calls
        ),
        trigger_entry=entry(
            distribution,
            direct_rules=direct_rules,
            conditional_rules=(
                conditional_rules
            ),
            safe_rules=safe_rules,
        ),
        confirmed_exposed_releases=(
            exposed
        ),
    )


def status(
    result: dict[str, Any],
) -> str:
    return str(
        result.get(
            "summary",
            {},
        ).get(
            "overall_trigger_status"
        )
    )


def assert_status(
    name: str,
    result: dict[str, Any],
    expected: str,
) -> None:
    actual = status(
        result
    )

    assert (
        actual == expected
    ), (
        f"{name}: "
        f"expected={expected!r}, "
        f"actual={actual!r}"
    )

    print(
        f"[PASS] {name}: {actual}"
    )


def main() -> None:

    # --------------------------------------------------
    # 1. Direct API rule
    # yaml.full_load(...)
    # --------------------------------------------------

    direct = run(
        distribution="pyyaml",
        calls=[
            build_direct_call(
                "yaml.full_load"
            )
        ],
        exposed=EXPOSED_RELEASES,
        direct_rules=[
            DIRECT_FULL_LOAD_RULE
        ],
    )

    assert_status(
        "direct_api",
        direct,
        "matched",
    )


    # --------------------------------------------------
    # 2. Keyword symbol condition
    # yaml.load(..., Loader=yaml.FullLoader)
    # --------------------------------------------------

    keyword_symbol = run(
        distribution="pyyaml",
        calls=[
            build_call(
                "yaml.FullLoader"
            )
        ],
        exposed=EXPOSED_RELEASES,
        conditional_rules=[
            TRIGGER_FULL_LOADER
        ],
        safe_rules=[
            SAFE_LOADER_RULE
        ],
    )

    assert_status(
        "keyword_argument_condition",
        keyword_symbol,
        "matched",
    )


    # Safe alternative must remain separately observable.
    safe = run(
        distribution="pyyaml",
        calls=[
            build_call(
                "yaml.SafeLoader"
            )
        ],
        exposed=EXPOSED_RELEASES,
        conditional_rules=[
            TRIGGER_FULL_LOADER
        ],
        safe_rules=[
            SAFE_LOADER_RULE
        ],
    )

    assert (
        safe.get(
            "summary",
            {},
        ).get(
            "overall_safe_status"
        )
        == "matched"
    )

    assert_status(
        "safe_loader_trigger_side",
        safe,
        "not_matched",
    )

    print(
        "[PASS] safe rule remains independently visible"
    )


    # --------------------------------------------------
    # 3. Keyword literal
    # aiohttp.web.static(..., follow_symlinks=True)
    # --------------------------------------------------

    aiohttp = run(
        distribution="aiohttp",
        calls=[
            build_literal_call(
                True
            )
        ],
        exposed=AIOHTTP_EXPOSED_RELEASES,
        conditional_rules=[
            AIOHTTP_FOLLOW_SYMLINKS_TRIGGER
        ],
    )

    assert_status(
        "keyword_literal_condition",
        aiohttp,
        "matched",
    )


    aiohttp_unresolved = run(
        distribution="aiohttp",
        calls=[
            build_literal_call(
                True,
                resolved=False,
            )
        ],
        exposed=AIOHTTP_EXPOSED_RELEASES,
        conditional_rules=[
            AIOHTTP_FOLLOW_SYMLINKS_TRIGGER
        ],
    )

    assert_status(
        "keyword_literal_unresolved",
        aiohttp_unresolved,
        "unresolved",
    )


    # --------------------------------------------------
    # 4. Historical omitted keyword
    # numpy.load(...) historical allow_pickle=True
    # --------------------------------------------------

    numpy_result = run(
        distribution="numpy",
        calls=[
            build_numpy_load_call(
                include_allow_pickle=False
            )
        ],
        exposed=NUMPY_EXPOSED_RELEASES,
        conditional_rules=[
            NUMPY_OMITTED_ALLOW_PICKLE_TRIGGER
        ],
    )

    assert_status(
        "omitted_keyword_historical_default",
        numpy_result,
        "matched",
    )


    # Same rule family, PyYAML historical Loader.
    yaml_omitted = run(
        distribution="pyyaml",
        calls=[
            build_call(
                None
            )
        ],
        exposed=EXPOSED_RELEASES,
        conditional_rules=[
            TRIGGER_OMITTED_LOADER
        ],
    )

    assert_status(
        "pyyaml_historical_default",
        yaml_omitted,
        "matched",
    )


    # --------------------------------------------------
    # 5. Keyword call condition
    # jwt.decode(... algorithms=get_default_algorithms())
    # --------------------------------------------------

    pyjwt = run(
        distribution="pyjwt",
        calls=[
            build_pyjwt_decode_call(
                include_algorithms=True,
                resolved_call_symbol=(
                    "jwt.algorithms."
                    "get_default_algorithms"
                ),
            )
        ],
        exposed=PYJWT_EXPOSED_RELEASES,
        conditional_rules=[
            PYJWT_DEFAULT_ALGORITHMS_TRIGGER
        ],
    )

    assert_status(
        "keyword_call_condition",
        pyjwt,
        "matched",
    )


    pyjwt_unresolved = run(
        distribution="pyjwt",
        calls=[
            build_pyjwt_decode_call(
                include_algorithms=True,
                resolved_call_symbol=None,
            )
        ],
        exposed=PYJWT_EXPOSED_RELEASES,
        conditional_rules=[
            PYJWT_DEFAULT_ALGORITHMS_TRIGGER
        ],
    )

    assert_status(
        "keyword_call_unresolved",
        pyjwt_unresolved,
        "unresolved",
    )


    # --------------------------------------------------
    # 6. Positional URL condition
    # Requests
    # --------------------------------------------------

    requests_match = run(
        distribution="requests",
        calls=[
            build_requests_get_call(
                (
                    "http://github.com:"
                    "@evil.example.net"
                )
            )
        ],
        exposed=REQUESTS_EXPOSED_RELEASES,
        conditional_rules=[
            REQUESTS_NETRC_HOST_CONFUSION_TRIGGER
        ],
    )

    assert_status(
        "positional_url_condition",
        requests_match,
        "matched",
    )


    requests_normal = run(
        distribution="requests",
        calls=[
            build_requests_get_call(
                "https://example.com"
            )
        ],
        exposed=REQUESTS_EXPOSED_RELEASES,
        conditional_rules=[
            REQUESTS_NETRC_HOST_CONFUSION_TRIGGER
        ],
    )

    assert_status(
        "positional_url_not_matched",
        requests_normal,
        "not_matched",
    )


    requests_unresolved = run(
        distribution="requests",
        calls=[
            build_requests_get_call(
                "url",
                resolved=False,
            )
        ],
        exposed=REQUESTS_EXPOSED_RELEASES,
        conditional_rules=[
            REQUESTS_NETRC_HOST_CONFUSION_TRIGGER
        ],
    )

    assert_status(
        "positional_url_unresolved",
        requests_unresolved,
        "unresolved",
    )


    # --------------------------------------------------
    # 7. Receiver producer provenance
    # urllib3.PoolManager(retries=0).request(...)
    # --------------------------------------------------

    urllib3_result = run(
        distribution="urllib3",
        calls=[
            build_urllib3_request_call(
                retries_value=0,
            )
        ],
        exposed=URLLIB3_EXPOSED_RELEASES,
        conditional_rules=[
            URLLIB3_POOLMANAGER_RETRIES_TRIGGER
        ],
    )

    assert_status(
        (
            "receiver_producer_"
            "keyword_literal_condition"
        ),
        urllib3_result,
        "matched",
    )


    urllib3_unresolved = run(
        distribution="urllib3",
        calls=[
            build_urllib3_request_call(
                include_receiver_provenance=False
            )
        ],
        exposed=URLLIB3_EXPOSED_RELEASES,
        conditional_rules=[
            URLLIB3_POOLMANAGER_RETRIES_TRIGGER
        ],
    )

    assert_status(
        "receiver_provenance_unresolved",
        urllib3_unresolved,
        "unresolved",
    )


    # --------------------------------------------------
    # 8. Version evidence boundary
    # --------------------------------------------------

    no_version = run(
        distribution="requests",
        calls=[
            build_requests_get_call(
                (
                    "http://github.com:"
                    "@evil.example.net"
                )
            )
        ],
        exposed=[],
        conditional_rules=[
            REQUESTS_NETRC_HOST_CONFUSION_TRIGGER
        ],
    )

    assert_status(
        "missing_version_evidence",
        no_version,
        "unresolved",
    )


    # --------------------------------------------------
    # 9. Critical no-rule boundary
    #
    # No executable rule is NOT evidence that
    # code definitely does not trigger.
    # --------------------------------------------------

    no_rule = run(
        distribution="demo",
        calls=[],
        exposed=[],
    )

    assert_status(
        "no_executable_rule",
        no_rule,
        "unresolved",
    )

    assert (
        no_rule.get(
            "summary",
            {},
        ).get(
            "overall_trigger_reason"
        )
        == "no_executable_trigger_rule_available"
    )

    print(
        "[PASS] no-rule state is not "
        "misclassified as not_matched"
    )


    print()
    print(
        "[PASS] Executable Trigger Matcher v0 "
        "covers all frozen rule families."
    )

    print(
        "[PASS] tri-state semantics remain "
        "conservative."
    )

    print(
        "[PASS] matcher version:",
        MATCHER_VERSION,
    )


if __name__ == "__main__":
    main()
