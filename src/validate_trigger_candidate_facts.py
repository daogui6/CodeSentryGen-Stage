from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

SCHEMA_VERSION = "avcs_trigger_candidate_fact_validation_v0.1"
VALIDATOR_VERSION = "trigger_candidate_fact_validator_v0.2"

DEFAULT_CORPUS = (
    ROOT / "output" / "avcs_trigger_candidate_evidence_corpus_v0.json"
)
DEFAULT_FACTS = (
    ROOT / "output" / "avcs_trigger_candidate_facts_v0.json"
)
DEFAULT_OUTPUT = (
    ROOT / "output" / "avcs_trigger_candidate_fact_validation_v0.json"
)


SEMANTIC_RELATION_FACT_KIND = (
    "security_context_relation_candidate"
)


SUPPORTED = "supported"
REJECTED = "rejected"
CONFLICTED = "conflicted"
UNRESOLVED = "unresolved"

ALLOWED_STATUSES = {
    SUPPORTED,
    REJECTED,
    CONFLICTED,
    UNRESOLVED,
}


def clean_text(value: Any) -> str:
    return str(value if value is not None else "").strip()


def load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))

    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object: {path}")

    return data


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    path.write_text(
        json.dumps(
            data,
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def dict_rows(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []

    return [
        row
        for row in value
        if isinstance(row, dict)
    ]


def normalized_ids(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return tuple()

    return tuple(
        sorted(
            {
                clean_text(item).lower()
                for item in value
                if clean_text(item)
            }
        )
    )


def evidence_group_key(
    row: dict[str, Any],
) -> tuple[str, tuple[str, ...]]:
    return (
        clean_text(
            row.get("distribution")
        ).lower(),
        normalized_ids(
            row.get("vulnerability_ids")
        ),
    )


def stable_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def exact_fact_signature(
    fact: dict[str, Any],
) -> str:
    return stable_json(
        {
            "fact_kind": clean_text(
                fact.get("fact_kind")
            ),
            "structured_value": fact.get(
                "structured_value"
            ),
        }
    )


def build_corpus_indices(
    corpus: dict[str, Any],
) -> tuple[
    dict[str, dict[str, Any]],
    dict[
        str,
        tuple[
            dict[str, Any],
            dict[str, Any],
        ],
    ],
]:
    source_index: dict[
        str,
        dict[str, Any],
    ] = {}

    unit_index: dict[
        str,
        tuple[
            dict[str, Any],
            dict[str, Any],
        ],
    ] = {}

    for entry in dict_rows(
        corpus.get("entries")
    ):
        source_key = clean_text(
            entry.get("source_key")
        )

        if source_key:
            source_index[source_key] = entry

        for unit in dict_rows(
            entry.get("evidence_units")
        ):
            unit_id = clean_text(
                unit.get("unit_id")
            )

            if unit_id:
                unit_index[unit_id] = (
                    entry,
                    unit,
                )

    return source_index, unit_index


def provenance_issues(
    fact: dict[str, Any],
    source_index: dict[str, dict[str, Any]],
    unit_index: dict[
        str,
        tuple[
            dict[str, Any],
            dict[str, Any],
        ],
    ],
) -> list[str]:
    issues: list[str] = []

    if fact.get("candidate_status") != "candidate":
        issues.append(
            "candidate_status_not_candidate"
        )

    fact_id = clean_text(
        fact.get("fact_id")
    )

    if not fact_id:
        issues.append("missing_fact_id")

    source_key = clean_text(
        fact.get("source_key")
    )

    source_entry = source_index.get(
        source_key
    )

    if source_entry is None:
        issues.append(
            "source_key_not_found_in_corpus"
        )

    unit_id = clean_text(
        fact.get("evidence_unit_id")
    )

    unit_pair = unit_index.get(unit_id)

    if unit_pair is None:
        issues.append(
            "evidence_unit_not_found_in_corpus"
        )

        return issues

    unit_entry, unit = unit_pair

    if (
        clean_text(
            unit_entry.get("source_key")
        )
        != source_key
    ):
        issues.append(
            "evidence_unit_source_mismatch"
        )

    if (
        fact.get("text_sha256")
        != unit.get("text_sha256")
    ):
        issues.append(
            "evidence_text_hash_mismatch"
        )

    if (
        fact.get("unit_kind")
        != unit.get("unit_kind")
    ):
        issues.append(
            "evidence_unit_kind_mismatch"
        )

    if source_entry is not None:
        if (
            clean_text(
                fact.get("distribution")
            ).lower()
            != clean_text(
                source_entry.get(
                    "distribution"
                )
            ).lower()
        ):
            issues.append(
                "distribution_mismatch"
            )

        if (
            normalized_ids(
                fact.get("vulnerability_ids")
            )
            != normalized_ids(
                source_entry.get(
                    "vulnerability_ids"
                )
            )
        ):
            issues.append(
                "vulnerability_ids_mismatch"
            )

    return issues


def is_structured_osv_fact(
    fact: dict[str, Any],
) -> bool:
    fact_kind = clean_text(
        fact.get("fact_kind")
    )

    return (
        fact_kind.startswith("osv_")
        and fact_kind.endswith(
            "_version_candidate"
        )
        and clean_text(
            fact.get("extraction_method")
        )
        == "structured_osv_range_event"
        and clean_text(
            fact.get("unit_kind")
        )
        == "structured_json_record"
        and clean_text(
            fact.get("confidence_level")
        )
        == "high"
    )


def is_supported_python_ast_fact(
    fact: dict[str, Any],
) -> bool:
    fact_kind = clean_text(
        fact.get("fact_kind")
    )

    if not fact_kind.startswith("python_"):
        return False

    if clean_text(
        fact.get("source_type")
    ) != "upstream_release_source":
        return False

    if clean_text(
        fact.get("unit_kind")
    ) != "github_source_file_text":
        return False

    if not clean_text(
        fact.get("extraction_method")
    ).startswith("python_ast_"):
        return False

    if clean_text(
        fact.get("confidence_level")
    ) != "high":
        return False

    relevance_gate = fact.get(
        "relevance_gate",
        {},
    )

    if not isinstance(
        relevance_gate,
        dict,
    ):
        return False

    return (
        relevance_gate.get("status")
        == "supported"
        and relevance_gate.get(
            "support_is_cross_source"
        )
        is True
        and relevance_gate.get(
            "support_excludes_python_release_source"
        )
        is True
        and relevance_gate.get(
            "support_excludes_commit_patch"
        )
        is True
    )


def is_semantic_relation_fact(
    fact: dict[str, Any],
) -> bool:
    return (
        clean_text(
            fact.get(
                "fact_kind"
            )
        )
        == SEMANTIC_RELATION_FACT_KIND
    )


def normalized_semantic_excerpt(
    fact: dict[str, Any],
) -> str:
    """
    Normalize superficial presentation differences
    before semantic evidence-independence checks.

    Deliberately limited to deterministic lexical
    normalization. No embedding or LLM judgment.
    """
    text = clean_text(
        fact.get(
            "evidence_excerpt"
        )
    )

    if not text:
        return ""

    text = text.lower()

    # Markdown presentation must not manufacture
    # evidence independence.
    text = re.sub(
        r"[`*_~]+",
        "",
        text,
    )

    # Some corpus excerpts contain a literal "\\n".
    text = re.sub(
        r"\\n",
        " ",
        text,
    )

    text = re.sub(
        r"\s+",
        " ",
        text,
    ).strip()

    text = text.strip(
        " \t\r\n"
        "\"'"
        "()[]{}"
        ".,;:"
    )

    return text


def semantic_excerpt_is_independent(
    fact: dict[str, Any],
    peer: dict[str, Any],
) -> bool:
    """
    Conservative semantic-evidence independence gate.

    For semantic relation facts, two excerpts are not
    considered independent when:

    1. their normalized text is identical; or
    2. one normalized excerpt is substantially contained
       in the other, indicating the same syndicated claim
       with additional heading/preamble/context.

    Missing excerpts are conservatively insufficient to
    establish semantic independence.

    Non-semantic atomic facts retain the frozen validator
    behavior.
    """
    if not (
        is_semantic_relation_fact(
            fact
        )
        and is_semantic_relation_fact(
            peer
        )
    ):
        return True

    fact_excerpt = (
        normalized_semantic_excerpt(
            fact
        )
    )

    peer_excerpt = (
        normalized_semantic_excerpt(
            peer
        )
    )

    if (
        not fact_excerpt
        or not peer_excerpt
    ):
        return False

    if (
        fact_excerpt
        == peer_excerpt
    ):
        return False

    shorter = min(
        (
            fact_excerpt,
            peer_excerpt,
        ),
        key=len,
    )

    longer = max(
        (
            fact_excerpt,
            peer_excerpt,
        ),
        key=len,
    )

    # Avoid treating tiny coincidental fragments as
    # meaningful containment.
    if (
        len(
            shorter
        )
        >= 40
        and shorter
        in longer
    ):
        return False

    return True


def build_exact_support_index(
    facts: list[dict[str, Any]],
) -> dict[
    tuple[
        tuple[str, tuple[str, ...]],
        str,
    ],
    list[dict[str, Any]],
]:
    index: dict[
        tuple[
            tuple[str, tuple[str, ...]],
            str,
        ],
        list[dict[str, Any]],
    ] = defaultdict(list)

    for fact in facts:
        key = (
            evidence_group_key(fact),
            exact_fact_signature(fact),
        )

        index[key].append(fact)

    return index


def find_exact_cross_source_peers(
    fact: dict[str, Any],
    exact_support_index: dict[
        tuple[
            tuple[str, tuple[str, ...]],
            str,
        ],
        list[dict[str, Any]],
    ],
) -> list[dict[str, Any]]:
    key = (
        evidence_group_key(fact),
        exact_fact_signature(fact),
    )

    fact_id = clean_text(
        fact.get("fact_id")
    )
    source_key = clean_text(
        fact.get("source_key")
    )
    source_type = clean_text(
        fact.get("source_type")
    )

    peers: list[dict[str, Any]] = []

    for peer in exact_support_index.get(
        key,
        [],
    ):
        if clean_text(
            peer.get("fact_id")
        ) == fact_id:
            continue

        peer_source_key = clean_text(
            peer.get("source_key")
        )
        peer_source_type = clean_text(
            peer.get("source_type")
        )

        if not peer_source_key:
            continue

        if peer_source_key == source_key:
            continue

        # v0 deliberately requires source-type
        # diversity as well as a different source.
        if (
            not source_type
            or not peer_source_type
            or peer_source_type
            == source_type
        ):
            continue

        # Semantic relations additionally require
        # evidence-content independence. Different
        # databases may syndicate the same advisory text,
        # so source-key/source-type diversity alone is not
        # sufficient semantic corroboration.
        if not semantic_excerpt_is_independent(
            fact,
            peer,
        ):
            continue

        peers.append(peer)

    return peers


def build_osv_fixed_index(
    facts: list[dict[str, Any]],
) -> dict[
    tuple[
        tuple[str, tuple[str, ...]],
        str,
    ],
    list[dict[str, Any]],
]:
    index: dict[
        tuple[
            tuple[str, tuple[str, ...]],
            str,
        ],
        list[dict[str, Any]],
    ] = defaultdict(list)

    for fact in facts:
        if (
            clean_text(
                fact.get("fact_kind")
            )
            != "osv_fixed_version_candidate"
        ):
            continue

        structured_value = fact.get(
            "structured_value",
            {},
        )

        if not isinstance(
            structured_value,
            dict,
        ):
            continue

        version = clean_text(
            structured_value.get("version")
        )

        if not version:
            continue

        key = (
            evidence_group_key(fact),
            version,
        )

        index[key].append(fact)

    return index


def validation_record(
    *,
    fact: dict[str, Any],
    status: str,
    review_required: bool,
    rule: str,
    basis: str,
    supporting_fact_ids: list[str] | None = None,
    supporting_evidence_unit_ids: list[str] | None = None,
    issues: list[str] | None = None,
) -> dict[str, Any]:
    if status not in ALLOWED_STATUSES:
        raise ValueError(
            f"Unsupported validation status: {status}"
        )

    return {
        "fact_id": fact.get("fact_id"),
        "distribution": fact.get(
            "distribution"
        ),
        "vulnerability_ids": fact.get(
            "vulnerability_ids",
            [],
        ),
        "fact_kind": fact.get(
            "fact_kind"
        ),
        "source_key": fact.get(
            "source_key"
        ),
        "validation_status": status,
        "review_required": review_required,
        "automatic_decision": (
            status
            in {
                SUPPORTED,
                REJECTED,
            }
            and not review_required
        ),
        "validation_rule": rule,
        "validation_basis": basis,
        "supporting_fact_ids": sorted(
            set(
                supporting_fact_ids
                or []
            )
        ),
        "supporting_evidence_unit_ids": sorted(
            set(
                supporting_evidence_unit_ids
                or []
            )
        ),
        "issues": issues or [],
    }


def validate_fact(
    *,
    fact: dict[str, Any],
    source_index: dict[str, dict[str, Any]],
    unit_index: dict[
        str,
        tuple[
            dict[str, Any],
            dict[str, Any],
        ],
    ],
    exact_support_index: dict[
        tuple[
            tuple[str, tuple[str, ...]],
            str,
        ],
        list[dict[str, Any]],
    ],
    osv_fixed_index: dict[
        tuple[
            tuple[str, tuple[str, ...]],
            str,
        ],
        list[dict[str, Any]],
    ],
) -> dict[str, Any]:
    issues = provenance_issues(
        fact,
        source_index,
        unit_index,
    )

    if issues:
        return validation_record(
            fact=fact,
            status=REJECTED,
            review_required=False,
            rule="provenance_integrity_failure",
            basis=(
                "The candidate fact violates the "
                "frozen corpus/fact provenance "
                "contract and is deterministically "
                "rejected as an invalid candidate."
            ),
            issues=issues,
        )

    if is_structured_osv_fact(fact):
        return validation_record(
            fact=fact,
            status=SUPPORTED,
            review_required=False,
            rule=(
                "authoritative_osv_structured_event"
            ),
            basis=(
                "The atomic version event is "
                "preserved directly from a "
                "machine-readable OSV range event. "
                "This validates the atomic version "
                "fact only; it does not construct "
                "Trigger Evidence."
            ),
            supporting_evidence_unit_ids=[
                clean_text(
                    fact.get(
                        "evidence_unit_id"
                    )
                )
            ],
        )

    if is_supported_python_ast_fact(
        fact
    ):
        gate = fact.get(
            "relevance_gate",
            {},
        )

        support_ids: list[str] = []

        if isinstance(gate, dict):
            raw_support = gate.get(
                "supporting_evidence_unit_ids",
                [],
            )

            if isinstance(
                raw_support,
                list,
            ):
                support_ids = [
                    clean_text(value)
                    for value in raw_support
                    if clean_text(value)
                ]

        return validation_record(
            fact=fact,
            status=SUPPORTED,
            review_required=False,
            rule=(
                "official_python_ast_with_"
                "cross_source_relevance"
            ),
            basis=(
                "The syntactic fact is directly "
                "resolved by Python AST from an "
                "upstream release source and has "
                "already passed the frozen "
                "cross-source identifier relevance "
                "gate. Support applies to the "
                "atomic source-code fact, not to "
                "vulnerability trigger semantics."
            ),
            supporting_evidence_unit_ids=(
                support_ids
            ),
        )

    fact_kind = clean_text(
        fact.get("fact_kind")
    )

    if (
        fact_kind
        == "text_fixed_version_phrase_candidate"
    ):
        structured_value = fact.get(
            "structured_value",
            {},
        )

        if isinstance(
            structured_value,
            dict,
        ):
            version = clean_text(
                structured_value.get(
                    "version"
                )
            )

            key = (
                evidence_group_key(fact),
                version,
            )

            osv_peers = osv_fixed_index.get(
                key,
                [],
            )

            cross_source_peers = [
                peer
                for peer in osv_peers
                if clean_text(
                    peer.get(
                        "source_key"
                    )
                )
                != clean_text(
                    fact.get(
                        "source_key"
                    )
                )
            ]

            if cross_source_peers:
                return validation_record(
                    fact=fact,
                    status=SUPPORTED,
                    review_required=False,
                    rule=(
                        "text_fixed_version_"
                        "corroborated_by_osv"
                    ),
                    basis=(
                        "The explicit fixed-version "
                        "phrase agrees with a "
                        "machine-readable OSV fixed "
                        "event for the same "
                        "package-vulnerability group."
                    ),
                    supporting_fact_ids=[
                        clean_text(
                            peer.get(
                                "fact_id"
                            )
                        )
                        for peer
                        in cross_source_peers
                    ],
                    supporting_evidence_unit_ids=[
                        clean_text(
                            peer.get(
                                "evidence_unit_id"
                            )
                        )
                        for peer
                        in cross_source_peers
                    ],
                )

    peers = find_exact_cross_source_peers(
        fact,
        exact_support_index,
    )

    if peers:
        semantic_relation = (
            is_semantic_relation_fact(
                fact
            )
        )

        return validation_record(
            fact=fact,
            status=SUPPORTED,
            review_required=False,
            rule=(
                (
                    "exact_cross_source_"
                    "corroboration_with_"
                    "excerpt_independence"
                )
                if semantic_relation
                else (
                    "exact_cross_source_"
                    "corroboration"
                )
            ),
            basis=(
                (
                    "The same semantic relation "
                    "structure is extracted from "
                    "a different source key and "
                    "source type, and at least one "
                    "supporting excerpt is not an "
                    "identical or contained copy of "
                    "the candidate excerpt."
                )
                if semantic_relation
                else (
                    "The same atomic fact structure "
                    "is independently extracted from "
                    "a different source key and a "
                    "different source type within the "
                    "same package-vulnerability group."
                )
            ),
            supporting_fact_ids=[
                clean_text(
                    peer.get("fact_id")
                )
                for peer in peers
            ],
            supporting_evidence_unit_ids=[
                clean_text(
                    peer.get(
                        "evidence_unit_id"
                    )
                )
                for peer in peers
            ],
        )

    return validation_record(
        fact=fact,
        status=UNRESOLVED,
        review_required=True,
        rule="insufficient_conservative_support",
        basis=(
            "The current v0 validator does not "
            "have enough conservative evidence to "
            "support or reject this candidate fact "
            "without additional semantic review."
        ),
    )


def rate(
    numerator: int,
    denominator: int,
) -> float:
    if denominator <= 0:
        return 0.0

    return round(
        numerator / denominator,
        6,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Conservatively validate AVCS Trigger "
            "Evidence candidate facts."
        )
    )

    parser.add_argument(
        "--corpus",
        type=Path,
        default=DEFAULT_CORPUS,
    )

    parser.add_argument(
        "--facts",
        type=Path,
        default=DEFAULT_FACTS,
    )

    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUTPUT,
    )

    args = parser.parse_args()

    corpus = load_json(args.corpus)
    candidate_data = load_json(
        args.facts
    )

    if (
        candidate_data.get("status")
        not in {
            "resolved",
            "partial",
        }
    ):
        raise ValueError(
            "Candidate fact input must be "
            "resolved or partial."
        )

    facts = dict_rows(
        candidate_data.get("facts")
    )

    source_index, unit_index = (
        build_corpus_indices(corpus)
    )

    exact_support_index = (
        build_exact_support_index(
            facts
        )
    )

    osv_fixed_index = (
        build_osv_fixed_index(
            facts
        )
    )

    records = [
        validate_fact(
            fact=fact,
            source_index=source_index,
            unit_index=unit_index,
            exact_support_index=(
                exact_support_index
            ),
            osv_fixed_index=(
                osv_fixed_index
            ),
        )
        for fact in facts
    ]

    status_counts = Counter(
        clean_text(
            record.get(
                "validation_status"
            )
        )
        for record in records
    )

    rule_counts = Counter(
        clean_text(
            record.get(
                "validation_rule"
            )
        )
        for record in records
    )

    review_required_count = sum(
        1
        for record in records
        if record.get(
            "review_required"
        )
        is True
    )

    automatic_decision_count = sum(
        1
        for record in records
        if record.get(
            "automatic_decision"
        )
        is True
    )

    total = len(records)

    result = {
        "schema_version": SCHEMA_VERSION,
        "validator_version": (
            VALIDATOR_VERSION
        ),
        "status": "resolved",
        "source_mode": (
            "conservative_candidate_fact_"
            "validation"
        ),
        "input": {
            "corpus_path": str(
                args.corpus.resolve()
            ),
            "candidate_fact_path": str(
                args.facts.resolve()
            ),
            "candidate_fact_schema_version": (
                candidate_data.get(
                    "schema_version"
                )
            ),
            "candidate_fact_extractor_version": (
                candidate_data.get(
                    "extractor_version"
                )
            ),
        },
        "semantic_boundary": {
            "consumes_candidate_facts": True,
            "consumes_candidate_evidence_corpus": (
                True
            ),
            "consumes_trigger_raw_ground_truth": (
                False
            ),
            "uses_llm_semantic_inference": False,
            "modifies_candidate_fact_artifact": (
                False
            ),
            "creates_validation_sidecar": True,
            "creates_resolved_trigger_rules": False,
            "supported_means_atomic_fact_support": (
                True
            ),
            "supported_means_trigger_semantics": (
                False
            ),
            "unresolved_is_valid_outcome": True,
            "intended_next_stage": (
                "validated_atomic_fact_to_"
                "trigger_evidence_draft"
            ),
        },
        "validation_policy": {
            "authoritative_osv_structured_event": (
                True
            ),
            "official_python_ast_with_cross_source_relevance": (
                True
            ),
            "text_fixed_version_corroborated_by_osv": (
                True
            ),
            "exact_cross_source_corroboration": (
                True
            ),
            "natural_language_trigger_inference": (
                False
            ),
            "runtime_dataflow_inference": False,
            "cross_source_trigger_rule_composition": (
                False
            ),
            "automatic_conflict_resolution": False,
        },
        "summary": {
            "candidate_fact_count": total,
            "supported_fact_count": (
                status_counts[SUPPORTED]
            ),
            "rejected_fact_count": (
                status_counts[REJECTED]
            ),
            "conflicted_fact_count": (
                status_counts[CONFLICTED]
            ),
            "unresolved_fact_count": (
                status_counts[UNRESOLVED]
            ),
            "automatic_decision_count": (
                automatic_decision_count
            ),
            "review_required_fact_count": (
                review_required_count
            ),
            "automatic_decision_rate": rate(
                automatic_decision_count,
                total,
            ),
            "manual_review_rate": rate(
                review_required_count,
                total,
            ),
            "validation_status_counts": dict(
                sorted(
                    status_counts.items()
                )
            ),
            "validation_rule_counts": dict(
                sorted(
                    rule_counts.items()
                )
            ),
        },
        "validation_records": records,
    }

    write_json(
        args.out,
        result,
    )

    print("=" * 60)
    print(
        "TRIGGER CANDIDATE FACT VALIDATION SUMMARY"
    )
    print("=" * 60)
    print(
        "[OK] schema:",
        SCHEMA_VERSION,
    )
    print(
        "[OK] candidate facts:",
        total,
    )
    print(
        "[OK] supported:",
        status_counts[SUPPORTED],
    )
    print(
        "[OK] rejected:",
        status_counts[REJECTED],
    )
    print(
        "[OK] conflicted:",
        status_counts[CONFLICTED],
    )
    print(
        "[OK] unresolved:",
        status_counts[UNRESOLVED],
    )
    print(
        "[OK] automatic decision rate:",
        result["summary"][
            "automatic_decision_rate"
        ],
    )
    print(
        "[OK] manual review rate:",
        result["summary"][
            "manual_review_rate"
        ],
    )
    print(
        "[OK] saved:",
        args.out.resolve(),
    )


if __name__ == "__main__":
    main()