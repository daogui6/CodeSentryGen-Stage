from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


BUILDER_ID = "trigger_hitl_candidate_builder_v0.1"
SCHEMA_VERSION = "avcs_trigger_hitl_candidate_v0.1"

DEFAULT_PROTOCOL = Path(
    "schemas/avcs_trigger_eligibility_protocol_v0.json"
)


def load_json(path: Path) -> dict[str, Any]:
    data = json.loads(
        path.read_text(encoding="utf-8")
    )

    if not isinstance(data, dict):
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


def clean_text(value: Any) -> str:
    return str(
        value
        if value is not None
        else ""
    ).strip()


def unique_strings(
    values: Any,
) -> list[str]:
    if not isinstance(values, list):
        return []

    result: list[str] = []

    for value in values:
        text = clean_text(value)

        if (
            text
            and text not in result
        ):
            result.append(text)

    return result


def slug(value: str) -> str:
    cleaned = re.sub(
        r"[^a-zA-Z0-9]+",
        "_",
        value,
    ).strip("_")

    return cleaned.lower()


def find_vulnerability(
    kb: dict[str, Any],
    requested_id: str,
) -> dict[str, Any]:
    requested_lower = (
        requested_id.lower()
    )

    matches: list[
        dict[str, Any]
    ] = []

    for record in kb.get(
        "vulnerability_catalog",
        [],
    ):
        if not isinstance(
            record,
            dict,
        ):
            continue

        ids = {
            clean_text(
                record.get(
                    "vulnerability_id"
                )
            ).lower()
        }

        ids.update(
            value.lower()
            for value in unique_strings(
                record.get(
                    "aliases",
                    [],
                )
            )
        )

        if requested_lower in ids:
            matches.append(record)

    if not matches:
        raise ValueError(
            "Vulnerability not found in Package KB: "
            + requested_id
        )

    if len(matches) != 1:
        raise ValueError(
            "Vulnerability ID is ambiguous in Package KB: "
            + requested_id
        )

    return matches[0]


def build_source_index(
    kb: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    provenance = kb.get(
        "provenance",
        {},
    )

    if not isinstance(
        provenance,
        dict,
    ):
        return {}

    index: dict[
        str,
        dict[str, Any],
    ] = {}

    for source in provenance.get(
        "sources",
        [],
    ):
        if not isinstance(
            source,
            dict,
        ):
            continue

        source_id = clean_text(
            source.get(
                "source_id"
            )
        )

        if not source_id:
            continue

        if source_id in index:
            raise ValueError(
                "Duplicate provenance source_id: "
                + source_id
            )

        index[source_id] = source

    return index


def normalize_evidence_source(
    source: dict[str, Any],
) -> dict[str, Any]:
    # Candidate Schema 只接收这些字段，
    # 不把 Package KB 的额外元数据整包复制进来。
    return {
        "source_id":
            clean_text(
                source.get(
                    "source_id"
                )
            ),

        "source_type":
            clean_text(
                source.get(
                    "source_type"
                )
            ),

        "url":
            source.get("url"),

        "path":
            source.get("path"),

        "locator":
            source.get("locator"),

        "claim":
            source.get("claim"),
    }


def derive_affected_scope(
    vulnerability: dict[str, Any],
) -> tuple[
    str | None,
    list[str],
]:
    specifiers: list[str] = []

    for affected_range in vulnerability.get(
        "affected_ranges",
        [],
    ):
        if not isinstance(
            affected_range,
            dict,
        ):
            continue

        specifier = clean_text(
            affected_range.get(
                "version_specifier"
            )
        )

        if (
            specifier
            and specifier not in specifiers
        ):
            specifiers.append(
                specifier
            )

    if not specifiers:
        return None, []

    if len(specifiers) == 1:
        return specifiers[0], specifiers

    # 这里只用于 Case Packet 展示，
    # 不把多个范围错误地解释为一个 SpecifierSet。
    display = " OR ".join(
        f"({value})"
        for value in specifiers
    )

    return display, specifiers


def build_claim_map(
    *,
    vulnerability_id: str,
    aliases: list[str],
    affected_scope: str | None,
    fixed_versions: list[str],
    source_refs: list[str],
) -> list[dict[str, Any]]:
    # 没有 provenance source 时，不凭空创造 claim evidence。
    if not source_refs:
        return []

    claims: list[
        dict[str, Any]
    ] = []

    identity_text = vulnerability_id

    if aliases:
        identity_text += (
            " with aliases "
            + ", ".join(aliases)
        )

    claims.append(
        {
            "claim_id":
                "vulnerability_identity",

            "claim":
                (
                    "The vulnerability identity is "
                    + identity_text
                    + "."
                ),

            "evidence_refs":
                list(source_refs),
        }
    )

    if affected_scope:
        claims.append(
            {
                "claim_id":
                    "affected_version_range",

                "claim":
                    (
                        "The recorded affected "
                        "version scope is "
                        + affected_scope
                        + "."
                    ),

                "evidence_refs":
                    list(source_refs),
            }
        )

    if fixed_versions:
        claims.append(
            {
                "claim_id":
                    "fixed_versions",

                "claim":
                    (
                        "The recorded fixed "
                        "version(s) are "
                        + ", ".join(
                            fixed_versions
                        )
                        + "."
                    ),

                "evidence_refs":
                    list(source_refs),
            }
        )

    return claims


def build_candidate(
    *,
    kb: dict[str, Any],
    protocol: dict[str, Any],
    vulnerability: dict[str, Any],
    case_id: str | None,
) -> dict[str, Any]:
    protocol_version = clean_text(
        protocol.get(
            "x-protocol-id"
        )
    )

    if not protocol_version:
        raise ValueError(
            "Eligibility protocol has no x-protocol-id"
        )

    vulnerability_id = clean_text(
        vulnerability.get(
            "vulnerability_id"
        )
    )

    aliases = unique_strings(
        vulnerability.get(
            "aliases",
            [],
        )
    )

    fixed_versions = unique_strings(
        vulnerability.get(
            "fixed_versions",
            [],
        )
    )

    source_refs = unique_strings(
        vulnerability.get(
            "source_refs",
            [],
        )
    )

    source_index = (
        build_source_index(kb)
    )

    missing_source_refs = [
        source_ref
        for source_ref in source_refs
        if source_ref not in source_index
    ]

    if missing_source_refs:
        raise ValueError(
            "Vulnerability source_refs do not resolve "
            "to Package KB provenance.sources: "
            + repr(
                missing_source_refs
            )
        )

    evidence_sources = [
        normalize_evidence_source(
            source_index[source_ref]
        )
        for source_ref in source_refs
    ]

    (
        affected_scope,
        raw_scopes,
    ) = derive_affected_scope(
        vulnerability
    )

    distribution = clean_text(
        kb.get(
            "distribution"
        )
    )

    ecosystem = clean_text(
        kb.get(
            "ecosystem"
        )
    )

    if not distribution:
        raise ValueError(
            "Package KB distribution is empty"
        )

    if not ecosystem:
        raise ValueError(
            "Package KB ecosystem is empty"
        )

    resolved_case_id = (
        clean_text(case_id)
        if case_id
        else (
            "hitl_"
            + slug(distribution)
            + "_"
            + slug(vulnerability_id)
            + "_v0"
        )
    )

    unresolved_questions = [
        (
            "Trigger semantics have not yet been "
            "proposed or human-reviewed."
        )
    ]

    if len(raw_scopes) > 1:
        unresolved_questions.append(
            (
                "Multiple affected version ranges are "
                "recorded and must remain distinct "
                "during Trigger review."
            )
        )

    if not source_refs:
        unresolved_questions.append(
            (
                "No vulnerability provenance sources "
                "are currently attached."
            )
        )

    proposal = {
        "proposer_type":
            "automatic",

        "proposer_id":
            BUILDER_ID,

        "proposed_status":
            "requires_review",

        "candidate_rule":
            None,

        "claim_evidence_map":
            build_claim_map(
                vulnerability_id=
                    vulnerability_id,
                aliases=
                    aliases,
                affected_scope=
                    affected_scope,
                fixed_versions=
                    fixed_versions,
                source_refs=
                    source_refs,
            ),

        "unresolved_questions":
            unresolved_questions,

        "notes":
            (
                "Evidence-grounded HITL case packet "
                "assembled from Package KB. No "
                "Trigger semantics were copied from "
                "existing trigger_rules."
            ),
    }

    return {
        "schema_version":
            SCHEMA_VERSION,

        "protocol_version":
            protocol_version,

        "case_id":
            resolved_case_id,

        "ecosystem":
            ecosystem,

        "distribution":
            distribution,

        "vulnerability": {
            "vulnerability_id":
                vulnerability_id,

            "aliases":
                aliases,

            "affected_version_scope":
                affected_scope,

            "fixed_versions":
                fixed_versions,

            "source_refs":
                source_refs,
        },

        "evidence_sources":
            evidence_sources,

        "proposal":
            proposal,

        "review_gate": {
            "status":
                "requires_review",

            "review_required":
                True,

            "final_truth_created":
                False,

            "reviewer":
                None,

            "reviewed_at":
                None,

            "notes":
                (
                    "Candidate packet only. "
                    "Human review is mandatory "
                    "before any Trigger knowledge "
                    "can enter the formal Package KB."
                ),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Build an evidence-grounded AVCS "
            "HITL Trigger candidate packet "
            "from a unified Package KB."
        )
    )

    parser.add_argument(
        "--kb",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--vulnerability-id",
        required=True,
    )

    parser.add_argument(
        "--protocol",
        type=Path,
        default=DEFAULT_PROTOCOL,
    )

    parser.add_argument(
        "--case-id",
        default=None,
    )

    parser.add_argument(
        "--out",
        required=True,
        type=Path,
    )

    args = parser.parse_args()

    kb = load_json(
        args.kb
    )

    protocol = load_json(
        args.protocol
    )

    vulnerability = find_vulnerability(
        kb,
        args.vulnerability_id,
    )

    candidate = build_candidate(
        kb=kb,
        protocol=protocol,
        vulnerability=vulnerability,
        case_id=args.case_id,
    )

    write_json(
        args.out,
        candidate,
    )

    print(
        "HITL TRIGGER CANDIDATE PACKET BUILT"
    )

    print(
        "case_id:",
        candidate["case_id"],
    )

    print(
        "distribution:",
        candidate["distribution"],
    )

    print(
        "vulnerability_id:",
        candidate[
            "vulnerability"
        ][
            "vulnerability_id"
        ],
    )

    print(
        "evidence_source_count:",
        len(
            candidate[
                "evidence_sources"
            ]
        ),
    )

    print(
        "proposed_status:",
        candidate[
            "proposal"
        ][
            "proposed_status"
        ],
    )

    print(
        "candidate_rule_present:",
        isinstance(
            candidate[
                "proposal"
            ].get(
                "candidate_rule"
            ),
            dict,
        ),
    )

    print(
        "review_required:",
        candidate[
            "review_gate"
        ][
            "review_required"
        ],
    )

    print(
        "saved:",
        args.out,
    )


if __name__ == "__main__":
    main()
