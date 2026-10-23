from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from normalizer import pep503_normalize


SCHEMA_VERSION = (
    "avcs_vulnerability_trigger_evidence_v0.2"
)

NORMALIZER_VERSION = (
    "avcs_trigger_evidence_normalizer_v0.2"
)


def load_json(
    path: Path,
) -> dict[str, Any]:
    return json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )


def sha256_file(
    path: Path,
) -> str:
    digest = hashlib.sha256()

    with path.open(
        "rb"
    ) as file:
        for chunk in iter(
            lambda: file.read(
                1024 * 1024
            ),
            b"",
        ):
            digest.update(chunk)

    return (
        f"sha256:{digest.hexdigest()}"
    )


def unique_preserve_order(
    values: list[str],
) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []

    for value in values:
        value = str(value).strip()

        if (
            value
            and value not in seen
        ):
            seen.add(value)
            result.append(value)

    return result


def source_ids_from_rules(
    rules: list[dict[str, Any]],
) -> list[str]:
    result: list[str] = []

    for rule in rules:
        refs = rule.get(
            "evidence_refs",
            [],
        )

        if not isinstance(
            refs,
            list,
        ):
            continue

        result.extend(
            str(ref)
            for ref in refs
            if str(ref).strip()
        )

    return unique_preserve_order(
        result
    )


def normalize_trigger_evidence(
    raw_evidence: dict[str, Any],
    raw_path: Path,
) -> dict[str, Any]:
    distribution = str(
        raw_evidence.get(
            "distribution",
            "",
        )
    ).strip()

    ecosystem = str(
        raw_evidence.get(
            "ecosystem",
            "",
        )
    ).strip()

    normalized_distribution = (
        pep503_normalize(
            distribution
        )
        if distribution
        else ""
    )

    vulnerability_ids_raw = (
        raw_evidence.get(
            "vulnerability_ids",
            [],
        )
    )

    if not isinstance(
        vulnerability_ids_raw,
        list,
    ):
        vulnerability_ids_raw = []

    vulnerability_ids = (
        unique_preserve_order(
            [
                str(value)
                for value
                in vulnerability_ids_raw
            ]
        )
    )

    trigger_candidates = (
        raw_evidence.get(
            "trigger_candidates",
            [],
        )
    )

    if not isinstance(
        trigger_candidates,
        list,
    ):
        trigger_candidates = []

    trigger_candidates = [
        rule
        for rule in trigger_candidates
        if isinstance(
            rule,
            dict,
        )
    ]

    safe_alternatives = (
        raw_evidence.get(
            "safe_alternatives",
            [],
        )
    )

    if not isinstance(
        safe_alternatives,
        list,
    ):
        safe_alternatives = []

    safe_alternatives = [
        rule
        for rule in safe_alternatives
        if isinstance(
            rule,
            dict,
        )
    ]

    sources = raw_evidence.get(
        "sources",
        [],
    )

    if not isinstance(
        sources,
        list,
    ):
        sources = []

    sources = [
        source
        for source in sources
        if isinstance(
            source,
            dict,
        )
    ]

    source_ids = {
        str(
            source.get(
                "source_id",
                "",
            )
        ).strip()
        for source in sources
        if str(
            source.get(
                "source_id",
                "",
            )
        ).strip()
    }

    direct_api_symbols: list[str] = []

    direct_api_rules: list[
        dict[str, Any]
    ] = []

    conditional_api_rules: list[
        dict[str, Any]
    ] = []

    loader_symbols: list[str] = []

    for trigger in trigger_candidates:
        if (
            trigger.get("status")
            != "resolved"
        ):
            continue

        api_symbol = str(
            trigger.get(
                "api_symbol",
                "",
            )
        ).strip()

        if not api_symbol:
            continue

        kind = str(
            trigger.get(
                "kind",
                "",
            )
        ).strip()

        keyword_argument = (
            trigger.get(
                "keyword_argument",
                {}
            )
        )

        if not isinstance(
            keyword_argument,
            dict,
        ):
            keyword_argument = {}

        # positional_argument 用于描述
        # 基于位置参数的 Trigger 条件。
        #
        # 例如 Requests：
        #
        # requests.get(
        #     "http://github.com:@evil.example.net"
        # )
        #
        # URL 位于 position=0。
        #
        # normalizer 这里只保留 raw evidence
        # 已经声明的规则结构，不重新判断
        # 漏洞语义。
        positional_argument = (
            trigger.get(
                "positional_argument",
                {},
            )
        )

        if not isinstance(
            positional_argument,
            dict,
        ):
            positional_argument = {}

        receiver_provenance = (
            trigger.get(
                "receiver_provenance",
                {},
            )
        )

        if not isinstance(
            receiver_provenance,
            dict,
        ):
            receiver_provenance = {}

        required_symbol = str(
            keyword_argument.get(
                "required_symbol",
                "",
            )
        ).strip()

        historical_default_symbol = str(
            trigger.get(
                "historical_default_symbol",
                "",
            )
        ).strip()

        has_historical_default_literal = (
            "historical_default_literal"
            in trigger
        )

        historical_default_literal = (
            trigger.get(
                "historical_default_literal"
            )
        )

        if required_symbol:
            loader_symbols.append(
                required_symbol
            )

        if historical_default_symbol:
            loader_symbols.append(
                historical_default_symbol
            )

        if kind == "direct_api":
            direct_api_symbols.append(
                api_symbol
            )

            direct_api_rules.append(
                {
                    "trigger_id":
                        trigger.get(
                            "trigger_id"
                        ),

                    "api_symbol":
                        api_symbol,

                    "kind":
                        kind,

                    "requires_untrusted_input":
                        bool(
                            trigger.get(
                                "requires_untrusted_input",
                                False,
                            )
                        ),

                    "version_scope":
                        trigger.get(
                            "version_scope"
                        ),

                    "status":
                        trigger.get(
                            "status"
                        ),

                    "confidence":
                        trigger.get(
                            "confidence"
                        ),

                    "evidence_refs":
                        trigger.get(
                            "evidence_refs",
                            [],
                        ),
                }
            )

            continue

        conditional_api_rules.append(
            {
                "trigger_id":
                    trigger.get(
                        "trigger_id"
                    ),

                "api_symbol":
                    api_symbol,

                "kind":
                    kind,

                "requires_untrusted_input":
                    bool(
                        trigger.get(
                            "requires_untrusted_input",
                            False,
                        )
                    ),

                "keyword_argument":
                    keyword_argument,

                # 为了保持已有 PyYAML / aiohttp /
                # NumPy / PyJWT normalized output
                # 尽量稳定，只有 raw rule 真正声明了
                # positional_argument 时才输出。
                **(
                    {
                        "positional_argument":
                            positional_argument,
                    }
                    if positional_argument
                    else {}
                ),

                **(
                    {
                        "receiver_provenance":
                            receiver_provenance,
                    }
                    if receiver_provenance
                    else {}
                ),

                "historical_default_symbol":
                    (
                        historical_default_symbol
                        or None
                    ),

                **(
                    {
                        "historical_default_literal":
                            historical_default_literal,
                    }
                    if has_historical_default_literal
                    else {}
                ),

                "version_scope":
                    trigger.get(
                        "version_scope"
                    ),

                "status":
                    trigger.get(
                        "status"
                    ),

                "confidence":
                    trigger.get(
                        "confidence"
                    ),

                "evidence_refs":
                    trigger.get(
                        "evidence_refs",
                        [],
                    ),
            }
        )

    direct_api_symbols = (
        unique_preserve_order(
            direct_api_symbols
        )
    )

    loader_symbols = (
        unique_preserve_order(
            loader_symbols
        )
    )

    safe_api_symbols: list[str] = []
    safe_api_rules: list[
        dict[str, Any]
    ] = []

    for alternative in safe_alternatives:
        if (
            alternative.get("status")
            != "resolved"
        ):
            continue

        api_symbol = str(
            alternative.get(
                "api_symbol",
                "",
            )
        ).strip()

        if not api_symbol:
            continue

        keyword_argument = (
            alternative.get(
                "keyword_argument",
                {}
            )
        )

        if not isinstance(
            keyword_argument,
            dict,
        ):
            keyword_argument = {}

        if keyword_argument:
            safe_api_rules.append(
                {
                    "alternative_id":
                        alternative.get(
                            "alternative_id"
                        ),

                    "api_symbol":
                        api_symbol,

                    "keyword_argument":
                        keyword_argument,

                    "loader_semantics":
                        alternative.get(
                            "loader_semantics"
                        ),

                    "suitable_for_untrusted_input":
                        bool(
                            alternative.get(
                                "suitable_for_untrusted_input",
                                False,
                            )
                        ),

                    "status":
                        alternative.get(
                            "status"
                        ),

                    "confidence":
                        alternative.get(
                            "confidence"
                        ),

                    "evidence_refs":
                        alternative.get(
                            "evidence_refs",
                            [],
                        ),
                }
            )

        else:
            safe_api_symbols.append(
                api_symbol
            )

    safe_api_symbols = (
        unique_preserve_order(
            safe_api_symbols
        )
    )

    referenced_source_ids = (
        source_ids_from_rules(
            trigger_candidates
        )
        + source_ids_from_rules(
            safe_alternatives
        )
    )

    fix_evidence = (
        raw_evidence.get(
            "fix_evidence",
            {},
        )
    )

    if not isinstance(
        fix_evidence,
        dict,
    ):
        fix_evidence = {}

    fix_refs = fix_evidence.get(
        "evidence_refs",
        [],
    )

    if isinstance(
        fix_refs,
        list,
    ):
        referenced_source_ids.extend(
            str(ref)
            for ref in fix_refs
            if str(ref).strip()
        )

    referenced_source_ids = (
        unique_preserve_order(
            referenced_source_ids
        )
    )

    missing_source_refs = [
        source_id
        for source_id
        in referenced_source_ids
        if source_id
        not in source_ids
    ]

    scope = raw_evidence.get(
        "scope",
        {},
    )

    if not isinstance(
        scope,
        dict,
    ):
        scope = {}

    scope_status = str(
        scope.get(
            "status",
            "unknown",
        )
    )

    if (
        not distribution
        or not vulnerability_ids
        or not trigger_candidates
    ):
        evidence_status = (
            "malformed_record"
        )

    elif missing_source_refs:
        evidence_status = "partial"

    elif scope_status.startswith(
        "resolved"
    ):
        evidence_status = (
            "resolved_with_scope"
        )

    else:
        evidence_status = (
            "partial"
        )

    requires_untrusted_input = any(
        bool(
            trigger.get(
                "requires_untrusted_input",
                False,
            )
        )
        for trigger in trigger_candidates
        if trigger.get("status")
        == "resolved"
    )

    entry = {
        "distribution":
            distribution,

        "normalized_distribution":
            normalized_distribution,

        "vulnerability_ids":
            vulnerability_ids,

        "evidence_status":
            evidence_status,

        "scope":
            scope,

        "trigger_conditions": {
            "api_symbols":
                direct_api_symbols,

            "direct_api_rules":
                direct_api_rules,

            "conditional_api_rules":
                conditional_api_rules,

            "loader_symbols":
                loader_symbols,

            "requires_untrusted_input":
                requires_untrusted_input,

            "version_scope":
                scope.get(
                    "trigger_semantics_version_scope"
                ),
        },

        "safe_api_symbols":
            safe_api_symbols,

        "safe_api_rules":
            safe_api_rules,

        "fix_evidence":
            fix_evidence,

        "evidence_type":
            "normalized_real_trigger_evidence",

                "evidence_ref":
            str(
                raw_evidence.get(
                    "evidence_ref",
                    "",
                )
            ),

        "evidence_note":
            str(
                raw_evidence.get(
                    "evidence_note",
                    "",
                )
            ),

        "confidence":
            (
                "high"
                if (
                    evidence_status
                    == "resolved_with_scope"
                )
                else "partial"
            ),

        "provenance": {
            "source_ids":
                sorted(source_ids),

            "referenced_source_ids":
                referenced_source_ids,

            "missing_source_refs":
                missing_source_refs,

            "sources":
                sources,
        },
    }

    return {
        "schema_version":
            SCHEMA_VERSION,

        "normalizer_version":
            NORMALIZER_VERSION,

        "ecosystem":
            ecosystem,

        "distribution":
            distribution,

        "normalized_distribution":
            normalized_distribution,

        "source_mode":
            "normalized_real_trigger_evidence",

        "source_raw_schema_version":
            raw_evidence.get(
                "schema_version",
                "",
            ),

        "source_raw_evidence_file":
            str(raw_path).replace(
                "\\",
                "/",
            ),

        "source_raw_evidence_hash":
            sha256_file(
                raw_path
            ),

        "status":
            evidence_status,

        "trigger_candidate_count":
            len(
                trigger_candidates
            ),

        "direct_trigger_api_count":
            len(
                direct_api_symbols
            ),

        "direct_trigger_rule_count":
            len(
                direct_api_rules
            ),

        "conditional_trigger_rule_count":
            len(
                conditional_api_rules
            ),

        "safe_api_count":
            len(
                safe_api_symbols
            ),

        "safe_api_rule_count":
            len(
                safe_api_rules
            ),

        "source_count":
            len(sources),

        "entries": [
            entry
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Normalize real PyYAML "
            "vulnerability trigger evidence "
            "into AVCS trigger rules."
        )
    )

    parser.add_argument(
        "--raw",
        type=Path,
        required=True,
    )

    parser.add_argument(
        "--out",
        type=Path,
        required=True,
    )

    args = parser.parse_args()

    raw_evidence = load_json(
        args.raw
    )

    result = (
        normalize_trigger_evidence(
            raw_evidence=raw_evidence,
            raw_path=args.raw,
        )
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
        f"[OK] distribution: "
        f"{result.get('distribution')}"
    )

    print(
        f"[OK] status: "
        f"{result.get('status')}"
    )

    print(
        f"[OK] direct trigger APIs: "
        f"{result.get('direct_trigger_api_count')}"
    )

    print(
        f"[OK] conditional trigger rules: "
        f"{result.get('conditional_trigger_rule_count')}"
    )

    print(
        f"[OK] safe APIs: "
        f"{result.get('safe_api_count')}"
    )

    print(
        f"[OK] safe API rules: "
        f"{result.get('safe_api_rule_count')}"
    )

    print(
        f"[OK] sources: "
        f"{result.get('source_count')}"
    )

    print(
        f"[OK] result saved to: "
        f"{args.out}"
    )


if __name__ == "__main__":
    main()