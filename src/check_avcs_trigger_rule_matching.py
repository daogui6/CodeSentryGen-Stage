from __future__ import annotations

from typing import Any

from evaluate_avcs_overlap import (
    match_conditional_trigger_rule,
    match_direct_trigger_rule,
    match_safe_api_rule,
)


EXPOSED_RELEASES = [
    {
        "version": "5.1",
    },
    {
        "version": "5.3.1",
    },
    {
        "version": "5.4b1",
    },
]

DIRECT_FULL_LOAD_RULE = {
    "trigger_id":
        "pyyaml_full_load_untrusted",

    "api_symbol":
        "yaml.full_load",

    "kind":
        "direct_api",

    "requires_untrusted_input":
        True,

    "version_scope":
        ">=5.1,<5.4",

    "status":
        "resolved",

    "confidence":
        "high",
}


TRIGGER_FULL_LOADER = {
    "trigger_id":
        "pyyaml_load_explicit_full_loader",

    "api_symbol":
        "yaml.load",

    "kind":
        "keyword_argument_condition",

    "keyword_argument": {
        "name":
            "Loader",

        "required_symbol":
            "yaml.FullLoader",
    },

    "version_scope":
        ">=5.1,<5.4",
}


TRIGGER_OMITTED_LOADER = {
    "trigger_id":
        "pyyaml_load_default_full_loader",

    "api_symbol":
        "yaml.load",

    "kind":
        "omitted_keyword_historical_default",

    "keyword_argument": {
        "name":
            "Loader",

        "must_be_omitted":
            True,
    },

    "historical_default_symbol":
        "yaml.FullLoader",

    "version_scope":
        ">=5.1,<5.4",
}


SAFE_LOADER_RULE = {
    "alternative_id":
        "pyyaml_load_safe_loader",

    "api_symbol":
        "yaml.load",

    "keyword_argument": {
        "name":
            "Loader",

        "required_symbol":
            "yaml.SafeLoader",
    },
}

AIOHTTP_FOLLOW_SYMLINKS_TRIGGER = {
    "trigger_id":
        "aiohttp_static_follow_symlinks_true",

    "api_symbol":
        "aiohttp.web.static",

    "kind":
        "keyword_literal_condition",

    "keyword_argument": {
        "name":
            "follow_symlinks",

        "required_literal":
            True,
    },

    "version_scope":
        ">=3.1,<3.9.2",
}


AIOHTTP_EXPOSED_RELEASES = [
    {
        "version":
            "3.8.6",
    },
    {
        "version":
            "3.9.1",
    },
]

NUMPY_OMITTED_ALLOW_PICKLE_TRIGGER = {
    "trigger_id":
        "numpy_load_default_allow_pickle_true",

    "api_symbol":
        "numpy.load",

    "kind":
        "omitted_keyword_historical_default",

    "keyword_argument": {
        "name":
            "allow_pickle",

        "must_be_omitted":
            True,
    },

    "historical_default_literal":
        True,

    "version_scope":
        ">=1.10.0b1,<1.16.3",
}


NUMPY_EXPOSED_RELEASES = [
    {
        "version":
            "1.15.4",
    },
    {
        "version":
            "1.16.2",
    },
]

PYJWT_DEFAULT_ALGORITHMS_TRIGGER = {
    "trigger_id":
        "pyjwt_decode_default_algorithms",

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
        ">=1.5.0,<2.4.0",
}


PYJWT_EXPOSED_RELEASES = [
    {
        "version":
            "1.7.1",
    },
    {
        "version":
            "2.3.0",
    },
]

REQUESTS_NETRC_HOST_CONFUSION_TRIGGER = {
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
}


REQUESTS_EXPOSED_RELEASES = [
    {
        "version":
            "2.31.0",
    },
    {
        "version":
            "2.32.3",
    },
]

URLLIB3_POOLMANAGER_RETRIES_TRIGGER = {
    "trigger_id":
        "urllib3_poolmanager_retries_zero_request",

    "api_symbol":
        "urllib3.PoolManager.request",

    "kind":
        (
            "receiver_producer_"
            "keyword_literal_condition"
        ),

    "receiver_provenance": {
        "producer_api_symbol":
            "urllib3.PoolManager",

        "producer_keyword_argument": {
            "name":
                "retries",

            "required_literal":
                0,
        },
    },

    "version_scope":
        "<2.5.0",
}


URLLIB3_EXPOSED_RELEASES = [
    {
        "version":
            "2.4.0",
    },
]

def build_direct_call(
    api_symbol: str,
) -> dict[str, Any]:
    return {
        "api_symbol":
            api_symbol,

        "call_text":
            f"{api_symbol}(data)",

        "call_shape": {
            "explicit_positional_arg_count":
                1,

            "keyword_arg_names":
                [],

            "keyword_arg_values":
                {},

            "has_star_args":
                False,

            "has_star_kwargs":
                False,
        },
    }

def build_call(
    loader_symbol: str | None,
) -> dict[str, Any]:
    keyword_names: list[str] = []
    keyword_values: dict[
        str,
        dict[str, Any],
    ] = {}

    if loader_symbol is not None:
        keyword_names.append(
            "Loader"
        )

        keyword_values["Loader"] = {
            "source_text":
                loader_symbol,

            "resolved_symbol":
                loader_symbol,
        }

    return {
        "api_symbol":
            "yaml.load",

        "call_text":
            "synthetic yaml.load call",

        "call_shape": {
            "explicit_positional_arg_count":
                1,

            "keyword_arg_names":
                keyword_names,

            "keyword_arg_values":
                keyword_values,

            "has_star_args":
                False,

            "has_star_kwargs":
                False,
        },
    }

def build_literal_call(
    literal_value: Any,
    *,
    resolved: bool = True,
) -> dict[str, Any]:
    value_evidence: dict[
        str,
        Any,
    ] = {
        "source_text":
            repr(literal_value),

        "resolved_symbol":
            None,
    }

    if resolved:
        value_evidence[
            "literal_value"
        ] = literal_value

    return {
        "api_symbol":
            "aiohttp.web.static",

        "call_text":
            (
                "synthetic "
                "aiohttp.web.static call"
            ),

        "call_shape": {
            "explicit_positional_arg_count":
                2,

            "keyword_arg_names": [
                "follow_symlinks"
            ],

            "keyword_arg_values": {
                "follow_symlinks":
                    value_evidence,
            },

            "has_star_args":
                False,

            "has_star_kwargs":
                False,
        },
    }

def build_numpy_load_call(
    *,
    include_allow_pickle: bool,
    allow_pickle_value: bool = True,
) -> dict[str, Any]:
    keyword_names: list[str] = []

    keyword_values: dict[
        str,
        dict[str, Any],
    ] = {}

    if include_allow_pickle:
        keyword_names.append(
            "allow_pickle"
        )

        keyword_values[
            "allow_pickle"
        ] = {
            "source_text":
                repr(
                    allow_pickle_value
                ),

            "resolved_symbol":
                None,

            "literal_value":
                allow_pickle_value,
        }

    return {
        "api_symbol":
            "numpy.load",

        "call_text":
            "synthetic numpy.load call",

        "call_shape": {
            "explicit_positional_arg_count":
                1,

            "keyword_arg_names":
                keyword_names,

            "keyword_arg_values":
                keyword_values,

            "has_star_args":
                False,

            "has_star_kwargs":
                False,
        },
    }

def build_pyjwt_decode_call(
    *,
    include_algorithms: bool,
    resolved_call_symbol: str | None = None,
) -> dict[str, Any]:
    keyword_names: list[str] = []

    keyword_values: dict[
        str,
        dict[str, Any],
    ] = {}

    if include_algorithms:
        keyword_names.append(
            "algorithms"
        )

        value_evidence: dict[
            str,
            Any,
        ] = {
            "source_text":
                (
                    "synthetic algorithms "
                    "value"
                ),

            "resolved_symbol":
                None,
        }

        if (
            resolved_call_symbol
            is not None
        ):
            value_evidence[
                "resolved_call_symbol"
            ] = resolved_call_symbol

        keyword_values[
            "algorithms"
        ] = value_evidence

    return {
        "api_symbol":
            "jwt.decode",

        "call_text":
            "synthetic jwt.decode call",

        "call_shape": {
            "explicit_positional_arg_count":
                2,

            "keyword_arg_names":
                keyword_names,

            "keyword_arg_values":
                keyword_values,

            "has_star_args":
                False,

            "has_star_kwargs":
                False,
        },
    }

def build_requests_get_call(
    url_value: Any,
    *,
    resolved: bool = True,
) -> dict[str, Any]:
    positional_value: dict[
        str,
        Any,
    ] = {
        "position":
            0,

        "source_text":
            repr(
                url_value
            ),

        "resolved_symbol":
            None,
    }

    if resolved:
        positional_value[
            "literal_value"
        ] = url_value

    return {
        "api_symbol":
            "requests.get",

        "call_text":
            "synthetic requests.get call",

        "call_shape": {
            "explicit_positional_arg_count":
                1,

            "positional_arg_values": [
                positional_value
            ],

            "keyword_arg_names":
                [],

            "keyword_arg_values":
                {},

            "has_star_args":
                False,

            "has_star_kwargs":
                False,
        },
    }

def build_urllib3_request_call(
    *,
    retries_value: Any = 0,
    include_retries: bool = True,
    retries_resolved: bool = True,
    include_receiver_provenance: bool = True,
) -> dict[str, Any]:

    producer_keyword_names: list[
        str
    ] = []

    producer_keyword_values: dict[
        str,
        dict[str, Any],
    ] = {}

    if include_retries:
        producer_keyword_names.append(
            "retries"
        )

        retries_evidence: dict[
            str,
            Any,
        ] = {
            "source_text":
                repr(
                    retries_value
                ),

            "resolved_symbol":
                None,
        }

        if retries_resolved:
            retries_evidence[
                "literal_value"
            ] = retries_value

        producer_keyword_values[
            "retries"
        ] = retries_evidence

    call: dict[str, Any] = {
        "api_symbol":
            "urllib3.PoolManager.request",

        "call_text":
            (
                "synthetic "
                "PoolManager.request call"
            ),

        "call_shape": {
            "explicit_positional_arg_count":
                2,

            "positional_arg_values":
                [],

            "keyword_arg_names":
                [],

            "keyword_arg_values":
                {},

            "has_star_args":
                False,

            "has_star_kwargs":
                False,
        },
    }

    if include_receiver_provenance:
        call[
            "receiver_provenance"
        ] = {
            "receiver_name":
                "http",

            "producer_api_symbol":
                "urllib3.PoolManager",

            "producer_binding_type":
                "module_import",

            "producer_call_shape": {
                "explicit_positional_arg_count":
                    0,

                "positional_arg_values":
                    [],

                "keyword_arg_names":
                    producer_keyword_names,

                "keyword_arg_values":
                    producer_keyword_values,

                "has_star_args":
                    False,

                "has_star_kwargs":
                    False,
            },
        }

    return call

def check(
    name: str,
    expected: Any,
    actual: Any,
) -> bool:
    passed = (
        expected == actual
    )

    print(
        f"[{'PASS' if passed else 'FAIL'}] "
        f"{name} | "
        f"expected={expected!r} | "
        f"actual={actual!r}"
    )

    return passed


def main() -> None:
    full_loader_call = build_call(
        "yaml.FullLoader"
    )

    safe_loader_call = build_call(
        "yaml.SafeLoader"
    )

    omitted_loader_call = build_call(
        None
    )

    checks: list[bool] = []

    direct_full_load_call = (
        build_direct_call(
            "yaml.full_load"
        )
    )

    direct_match = (
        match_direct_trigger_rule(
            call=direct_full_load_call,
            rule=DIRECT_FULL_LOAD_RULE,
            confirmed_exposed_releases=(
                EXPOSED_RELEASES
            ),
        )
    )

    checks.append(
        check(
            "full_load direct trigger "
            "matches scoped exposure",
            True,
            direct_match[
                "matched"
            ],
        )
    )

    out_of_scope_match = (
        match_direct_trigger_rule(
            call=direct_full_load_call,
            rule=DIRECT_FULL_LOAD_RULE,
            confirmed_exposed_releases=[
                {
                    "version":
                        "5.1b1",
                },
            ],
        )
    )

    checks.append(
        check(
            "full_load does not trigger "
            "outside evidence scope",
            False,
            out_of_scope_match[
                "matched"
            ],
        )
    )

    wrong_direct_api = (
        match_direct_trigger_rule(
            call=build_direct_call(
                "yaml.safe_load"
            ),
            rule=DIRECT_FULL_LOAD_RULE,
            confirmed_exposed_releases=(
                EXPOSED_RELEASES
            ),
        )
    )

    checks.append(
        check(
            "different API does not "
            "match direct trigger",
            False,
            wrong_direct_api[
                "matched"
            ],
        )
    )

    full_loader_trigger = (
        match_conditional_trigger_rule(
            call=full_loader_call,
            rule=TRIGGER_FULL_LOADER,
            confirmed_exposed_releases=(
                EXPOSED_RELEASES
            ),
        )
    )

    checks.append(
        check(
            "FullLoader matches trigger",
            True,
            full_loader_trigger[
                "matched"
            ],
        )
    )

    safe_loader_trigger = (
        match_conditional_trigger_rule(
            call=safe_loader_call,
            rule=TRIGGER_FULL_LOADER,
            confirmed_exposed_releases=(
                EXPOSED_RELEASES
            ),
        )
    )

    checks.append(
        check(
            "SafeLoader does not match "
            "FullLoader trigger",
            False,
            safe_loader_trigger[
                "matched"
            ],
        )
    )

    omitted_trigger = (
        match_conditional_trigger_rule(
            call=omitted_loader_call,
            rule=TRIGGER_OMITTED_LOADER,
            confirmed_exposed_releases=(
                EXPOSED_RELEASES
            ),
        )
    )

    checks.append(
        check(
            "omitted Loader matches "
            "historical default trigger",
            True,
            omitted_trigger[
                "matched"
            ],
        )
    )

    explicit_full_not_omitted = (
        match_conditional_trigger_rule(
            call=full_loader_call,
            rule=TRIGGER_OMITTED_LOADER,
            confirmed_exposed_releases=(
                EXPOSED_RELEASES
            ),
        )
    )

    checks.append(
        check(
            "explicit Loader does not "
            "match omitted rule",
            False,
            explicit_full_not_omitted[
                "matched"
            ],
        )
    )

    safe_match = (
        match_safe_api_rule(
            call=safe_loader_call,
            rule=SAFE_LOADER_RULE,
        )
    )

    checks.append(
        check(
            "SafeLoader matches safe rule",
            True,
            safe_match[
                "matched"
            ],
        )
    )

    unsafe_not_safe = (
        match_safe_api_rule(
            call=full_loader_call,
            rule=SAFE_LOADER_RULE,
        )
    )

    checks.append(
        check(
            "FullLoader does not match "
            "safe rule",
            False,
            unsafe_not_safe[
                "matched"
            ],
        )
    )

    scoped_versions = (
        full_loader_trigger[
            "scoped_exposed_releases"
        ]
    )

    checks.append(
        check(
            "5.4b1 preserved in "
            "trigger version scope",
            True,
            "5.4b1"
            in scoped_versions,
        )
    )

    aiohttp_true_call = (
        build_literal_call(
            True
        )
    )

    aiohttp_true_match = (
        match_conditional_trigger_rule(
            call=aiohttp_true_call,
            rule=(
                AIOHTTP_FOLLOW_SYMLINKS_TRIGGER
            ),
            confirmed_exposed_releases=(
                AIOHTTP_EXPOSED_RELEASES
            ),
        )
    )

    checks.append(
        check(
            (
                "aiohttp True literal "
                "matches trigger"
            ),
            True,
            aiohttp_true_match[
                "matched"
            ],
        )
    )

    aiohttp_false_call = (
        build_literal_call(
            False
        )
    )

    aiohttp_false_match = (
        match_conditional_trigger_rule(
            call=aiohttp_false_call,
            rule=(
                AIOHTTP_FOLLOW_SYMLINKS_TRIGGER
            ),
            confirmed_exposed_releases=(
                AIOHTTP_EXPOSED_RELEASES
            ),
        )
    )

    checks.append(
        check(
            (
                "aiohttp False literal "
                "does not match trigger"
            ),
            False,
            aiohttp_false_match[
                "matched"
            ],
        )
    )

    aiohttp_unresolved_call = (
        build_literal_call(
            "flag",
            resolved=False,
        )
    )

    aiohttp_unresolved_match = (
        match_conditional_trigger_rule(
            call=aiohttp_unresolved_call,
            rule=(
                AIOHTTP_FOLLOW_SYMLINKS_TRIGGER
            ),
            confirmed_exposed_releases=(
                AIOHTTP_EXPOSED_RELEASES
            ),
        )
    )

    checks.append(
        check(
            (
                "aiohttp variable value "
                "remains unresolved"
            ),
            (
                "keyword_literal_"
                "unresolved"
            ),
            aiohttp_unresolved_match[
                "reason"
            ],
        )
    )

    numpy_omitted_call = (
        build_numpy_load_call(
            include_allow_pickle=False
        )
    )

    numpy_omitted_match = (
        match_conditional_trigger_rule(
            call=numpy_omitted_call,
            rule=(
                NUMPY_OMITTED_ALLOW_PICKLE_TRIGGER
            ),
            confirmed_exposed_releases=(
                NUMPY_EXPOSED_RELEASES
            ),
        )
    )

    checks.append(
        check(
            (
                "NumPy omitted allow_pickle "
                "matches vulnerable "
                "historical default"
            ),
            True,
            numpy_omitted_match[
                "matched"
            ],
        )
    )

    numpy_explicit_true_call = (
        build_numpy_load_call(
            include_allow_pickle=True,
            allow_pickle_value=True,
        )
    )

    numpy_explicit_not_omitted = (
        match_conditional_trigger_rule(
            call=numpy_explicit_true_call,
            rule=(
                NUMPY_OMITTED_ALLOW_PICKLE_TRIGGER
            ),
            confirmed_exposed_releases=(
                NUMPY_EXPOSED_RELEASES
            ),
        )
    )

    checks.append(
        check(
            (
                "NumPy explicit allow_pickle "
                "does not match omitted rule"
            ),
            False,
            numpy_explicit_not_omitted[
                "matched"
            ],
        )
    )

    numpy_fixed_only_match = (
        match_conditional_trigger_rule(
            call=numpy_omitted_call,
            rule=(
                NUMPY_OMITTED_ALLOW_PICKLE_TRIGGER
            ),
            confirmed_exposed_releases=[
                {
                    "version":
                        "1.16.3",
                },
            ],
        )
    )

    checks.append(
        check(
            (
                "NumPy omitted historical "
                "default does not match "
                "outside vulnerable scope"
            ),
            False,
            numpy_fixed_only_match[
                "matched"
            ],
        )
    )

    pyjwt_default_call = (
        build_pyjwt_decode_call(
            include_algorithms=True,
            resolved_call_symbol=(
                "jwt.algorithms."
                "get_default_algorithms"
            ),
        )
    )

    pyjwt_default_match = (
        match_conditional_trigger_rule(
            call=pyjwt_default_call,
            rule=(
                PYJWT_DEFAULT_ALGORITHMS_TRIGGER
            ),
            confirmed_exposed_releases=(
                PYJWT_EXPOSED_RELEASES
            ),
        )
    )

    checks.append(
        check(
            (
                "PyJWT default algorithms "
                "call matches trigger"
            ),
            True,
            pyjwt_default_match[
                "matched"
            ],
        )
    )

    pyjwt_wrong_call = (
        build_pyjwt_decode_call(
            include_algorithms=True,
            resolved_call_symbol=(
                "jwt.algorithms."
                "some_other_function"
            ),
        )
    )

    pyjwt_wrong_match = (
        match_conditional_trigger_rule(
            call=pyjwt_wrong_call,
            rule=(
                PYJWT_DEFAULT_ALGORITHMS_TRIGGER
            ),
            confirmed_exposed_releases=(
                PYJWT_EXPOSED_RELEASES
            ),
        )
    )

    checks.append(
        check(
            (
                "PyJWT different call "
                "does not match trigger"
            ),
            False,
            pyjwt_wrong_match[
                "matched"
            ],
        )
    )

    pyjwt_unresolved_call = (
        build_pyjwt_decode_call(
            include_algorithms=True,
            resolved_call_symbol=None,
        )
    )

    pyjwt_unresolved_match = (
        match_conditional_trigger_rule(
            call=pyjwt_unresolved_call,
            rule=(
                PYJWT_DEFAULT_ALGORITHMS_TRIGGER
            ),
            confirmed_exposed_releases=(
                PYJWT_EXPOSED_RELEASES
            ),
        )
    )

    checks.append(
        check(
            (
                "PyJWT unresolved "
                "algorithms value stays "
                "unresolved"
            ),
            "keyword_call_unresolved",
            pyjwt_unresolved_match[
                "reason"
            ],
        )
    )

    pyjwt_missing_keyword_call = (
        build_pyjwt_decode_call(
            include_algorithms=False,
        )
    )

    pyjwt_missing_keyword_match = (
        match_conditional_trigger_rule(
            call=pyjwt_missing_keyword_call,
            rule=(
                PYJWT_DEFAULT_ALGORITHMS_TRIGGER
            ),
            confirmed_exposed_releases=(
                PYJWT_EXPOSED_RELEASES
            ),
        )
    )

    checks.append(
        check(
            (
                "PyJWT missing algorithms "
                "does not match trigger"
            ),
            "required_keyword_not_observed",
            pyjwt_missing_keyword_match[
                "reason"
            ],
        )
    )

    requests_confusing_call = (
        build_requests_get_call(
            (
                "http://github.com:"
                "@evil.example.net"
            )
        )
    )

    requests_confusing_match = (
        match_conditional_trigger_rule(
            call=(
                requests_confusing_call
            ),
            rule=(
                REQUESTS_NETRC_HOST_CONFUSION_TRIGGER
            ),
            confirmed_exposed_releases=(
                REQUESTS_EXPOSED_RELEASES
            ),
        )
    )

    checks.append(
        check(
            (
                "Requests confusing URL "
                "matches trigger"
            ),
            True,
            requests_confusing_match[
                "matched"
            ],
        )
    )


    requests_normal_call = (
        build_requests_get_call(
            "https://api.example.net/data"
        )
    )

    requests_normal_match = (
        match_conditional_trigger_rule(
            call=(
                requests_normal_call
            ),
            rule=(
                REQUESTS_NETRC_HOST_CONFUSION_TRIGGER
            ),
            confirmed_exposed_releases=(
                REQUESTS_EXPOSED_RELEASES
            ),
        )
    )

    checks.append(
        check(
            (
                "Requests normal URL "
                "does not match trigger"
            ),
            False,
            requests_normal_match[
                "matched"
            ],
        )
    )


    requests_unresolved_call = (
        build_requests_get_call(
            "dynamic_url",
            resolved=False,
        )
    )

    requests_unresolved_match = (
        match_conditional_trigger_rule(
            call=(
                requests_unresolved_call
            ),
            rule=(
                REQUESTS_NETRC_HOST_CONFUSION_TRIGGER
            ),
            confirmed_exposed_releases=(
                REQUESTS_EXPOSED_RELEASES
            ),
        )
    )

    checks.append(
        check(
            (
                "Requests unresolved URL "
                "stays conservative"
            ),
            False,
            requests_unresolved_match[
                "matched"
            ],
        )
    )


    requests_fixed_only_match = (
        match_conditional_trigger_rule(
            call=(
                requests_confusing_call
            ),
            rule=(
                REQUESTS_NETRC_HOST_CONFUSION_TRIGGER
            ),
            confirmed_exposed_releases=[
                {
                    "version":
                        "2.32.4",
                },
            ],
        )
    )

    checks.append(
        check(
            (
                "Requests fixed release "
                "is outside trigger scope"
            ),
            False,
            requests_fixed_only_match[
                "matched"
            ],
        )
    )

    requests_ipv6_call = (
        build_requests_get_call(
            "http://[::1]/resource"
        )
    )

    requests_ipv6_match = (
        match_conditional_trigger_rule(
            call=(
                requests_ipv6_call
            ),
            rule=(
                REQUESTS_NETRC_HOST_CONFUSION_TRIGGER
            ),
            confirmed_exposed_releases=(
                REQUESTS_EXPOSED_RELEASES
            ),
        )
    )

    checks.append(
        check(
            (
                "Requests ordinary IPv6 URL "
                "does not match trigger"
            ),
            False,
            requests_ipv6_match[
                "matched"
            ],
        )
    )

    requests_non_http_call = (
        build_requests_get_call(
            (
                "ftp://github.com:"
                "@evil.example.net"
            )
        )
    )

    requests_non_http_match = (
        match_conditional_trigger_rule(
            call=(
                requests_non_http_call
            ),
            rule=(
                REQUESTS_NETRC_HOST_CONFUSION_TRIGGER
            ),
            confirmed_exposed_releases=(
                REQUESTS_EXPOSED_RELEASES
            ),
        )
    )

    checks.append(
        check(
            (
                "Requests non-HTTP URL "
                "does not match trigger"
            ),
            False,
            requests_non_http_match[
                "matched"
            ],
        )
    )

    urllib3_true_call = (
        build_urllib3_request_call(
            retries_value=0,
        )
    )

    urllib3_true_match = (
        match_conditional_trigger_rule(
            call=urllib3_true_call,
            rule=(
                URLLIB3_POOLMANAGER_RETRIES_TRIGGER
            ),
            confirmed_exposed_releases=(
                URLLIB3_EXPOSED_RELEASES
            ),
        )
    )

    checks.append(
        check(
            (
                "urllib3 PoolManager "
                "retries=0 receiver "
                "matches trigger"
            ),
            True,
            urllib3_true_match[
                "matched"
            ],
        )
    )


    urllib3_false_literal_call = (
        build_urllib3_request_call(
            retries_value=False,
        )
    )

    urllib3_false_literal_match = (
        match_conditional_trigger_rule(
            call=urllib3_false_literal_call,
            rule=(
                URLLIB3_POOLMANAGER_RETRIES_TRIGGER
            ),
            confirmed_exposed_releases=(
                URLLIB3_EXPOSED_RELEASES
            ),
        )
    )

    checks.append(
        check(
            (
                "urllib3 retries=False "
                "does not silently match "
                "the retries=0 v0 rule"
            ),
            (
                "producer_keyword_literal_"
                "not_matched"
            ),
            urllib3_false_literal_match[
                "reason"
            ],
        )
    )


    urllib3_missing_keyword_call = (
        build_urllib3_request_call(
            include_retries=False,
        )
    )

    urllib3_missing_keyword_match = (
        match_conditional_trigger_rule(
            call=urllib3_missing_keyword_call,
            rule=(
                URLLIB3_POOLMANAGER_RETRIES_TRIGGER
            ),
            confirmed_exposed_releases=(
                URLLIB3_EXPOSED_RELEASES
            ),
        )
    )

    checks.append(
        check(
            (
                "urllib3 missing producer "
                "retries stays conservative"
            ),
            (
                "producer_required_keyword_"
                "not_observed"
            ),
            urllib3_missing_keyword_match[
                "reason"
            ],
        )
    )


    urllib3_no_provenance_call = (
        build_urllib3_request_call(
            include_receiver_provenance=False,
        )
    )

    urllib3_no_provenance_match = (
        match_conditional_trigger_rule(
            call=urllib3_no_provenance_call,
            rule=(
                URLLIB3_POOLMANAGER_RETRIES_TRIGGER
            ),
            confirmed_exposed_releases=(
                URLLIB3_EXPOSED_RELEASES
            ),
        )
    )

    checks.append(
        check(
            (
                "urllib3 unresolved receiver "
                "provenance stays conservative"
            ),
            (
                "receiver_provenance_"
                "unresolved"
            ),
            urllib3_no_provenance_match[
                "reason"
            ],
        )
    )


    urllib3_fixed_only_match = (
        match_conditional_trigger_rule(
            call=urllib3_true_call,
            rule=(
                URLLIB3_POOLMANAGER_RETRIES_TRIGGER
            ),
            confirmed_exposed_releases=[
                {
                    "version":
                        "2.5.0",
                },
            ],
        )
    )

    checks.append(
        check(
            (
                "urllib3 fixed release "
                "is outside trigger scope"
            ),
            (
                "no_exposed_release_"
                "within_trigger_version_scope"
            ),
            urllib3_fixed_only_match[
                "reason"
            ],
        )
    )

    passed = sum(checks)
    failed = (
        len(checks)
        - passed
    )

    print("")
    print(
        f"[OK] total checks: "
        f"{len(checks)}"
    )
    print(
        f"[OK] passed: {passed}"
    )
    print(
        f"[OK] failed: {failed}"
    )

    if failed:
        raise SystemExit(1)

    print(
        "[OK] AVCS trigger rule "
        "matching ALL PASS"
    )


if __name__ == "__main__":
    main()