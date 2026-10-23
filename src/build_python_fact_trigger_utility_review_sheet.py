from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

SCHEMA_VERSION = (
    "python_fact_trigger_utility_review_sheet_v0.2"
)

BUILDER_VERSION = (
    "python_fact_trigger_utility_review_sheet_builder_v0.2"
)

DEFAULT_SAMPLE = (
    ROOT
    / "data"
    / "avcs_validation"
    / "rq1_review"
    / "python_fact_trigger_utility_sample_v0.json"
)

DEFAULT_CORPUS = (
    ROOT
    / "output"
    / "avcs_trigger_candidate_evidence_corpus_v0.json"
)

DEFAULT_JSON_OUTPUT = (
    ROOT
    / "data"
    / "avcs_validation"
    / "rq1_review"
    / "python_fact_trigger_utility_review_sheet_v0.json"
)

DEFAULT_CSV_OUTPUT = (
    ROOT
    / "data"
    / "avcs_validation"
    / "rq1_review"
    / "python_fact_trigger_utility_review_sheet_v0.csv"
)


ATOMIC_CORRECTNESS_OPTIONS = [
    "correct",
    "incorrect",
    "uncertain",
]

TRIGGER_UTILITY_OPTIONS = [
    "A",
    "B",
    "C",
    "U",
]


def clean_text(value: Any) -> str:
    return str(
        value
        if value is not None
        else ""
    ).strip()


def load_json(path: Path) -> dict[str, Any]:
    data = json.loads(
        path.read_text(
            encoding="utf-8"
        )
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


def dict_rows(
    value: Any,
) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []

    return [
        row
        for row in value
        if isinstance(row, dict)
    ]


def evidence_text(
    unit: dict[str, Any],
) -> str:
    for key in (
        "text",
        "evidence_text",
        "content",
        "excerpt",
    ):
        text = unit.get(key)

        if isinstance(text, str) and text:
            return text

    return ""


def build_case_contexts(
    *,
    corpus: dict[str, Any],
    distributions: set[str],
) -> dict[str, Any]:
    contexts: dict[str, Any] = {}

    for entry in dict_rows(
        corpus.get("entries")
    ):
        distribution = clean_text(
            entry.get("distribution")
        )

        if distribution not in distributions:
            continue

        source_type = clean_text(
            entry.get("source_type")
        )

        # Candidate Fact 自己已经携带源码位置。
        # 这里单独保存漏洞语义/修复上下文，
        # 避免把整份 release source 重复塞进审核材料。
        if source_type == "upstream_release_source":
            continue

        source_key = clean_text(
            entry.get("source_key")
        )

        units = []

        for unit in dict_rows(
            entry.get("evidence_units")
        ):
            units.append(
                {
                    "unit_id": unit.get(
                        "unit_id"
                    ),
                    "unit_kind": unit.get(
                        "unit_kind"
                    ),
                    "text": evidence_text(
                        unit
                    ),
                }
            )

        if distribution not in contexts:
            contexts[distribution] = {
                "distribution": distribution,
                "sources": [],
            }

        contexts[
            distribution
        ]["sources"].append(
            {
                "source_key": source_key,
                "source_id": entry.get(
                    "source_id"
                ),
                "source_type": source_type,
                "evidence_units": units,
            }
        )

    for context in contexts.values():
        context["sources"].sort(
            key=lambda source: (
                clean_text(
                    source.get("source_type")
                ),
                clean_text(
                    source.get("source_key")
                ),
            )
        )

    return dict(
        sorted(
            contexts.items()
        )
    )


def build_candidate_source_contexts(
    *,
    corpus: dict[str, Any],
    source_keys: set[str],
) -> dict[str, Any]:
    contexts: dict[str, Any] = {}

    for entry in dict_rows(
        corpus.get("entries")
    ):
        source_key = clean_text(
            entry.get("source_key")
        )

        if source_key not in source_keys:
            continue

        if clean_text(
            entry.get("source_type")
        ) != "upstream_release_source":
            continue

        units = []

        for unit in dict_rows(
            entry.get("evidence_units")
        ):
            units.append(
                {
                    "unit_id": unit.get(
                        "unit_id"
                    ),
                    "unit_kind": unit.get(
                        "unit_kind"
                    ),
                    "text": evidence_text(
                        unit
                    ),
                }
            )

        contexts[source_key] = {
            "distribution": entry.get(
                "distribution"
            ),
            "source_key": source_key,
            "source_id": entry.get(
                "source_id"
            ),
            "source_type": entry.get(
                "source_type"
            ),
            "evidence_units": units,
        }

    return dict(
        sorted(
            contexts.items()
        )
    )


def compact_candidate_fact(
    fact: dict[str, Any],
) -> dict[str, Any]:
    return {
        "fact_id": fact.get(
            "fact_id"
        ),
        "fact_kind": fact.get(
            "fact_kind"
        ),
        "distribution": fact.get(
            "distribution"
        ),
        "vulnerability_ids": fact.get(
            "vulnerability_ids",
            [],
        ),
        "structured_value": fact.get(
            "structured_value"
        ),
        "evidence_excerpt": fact.get(
            "evidence_excerpt"
        ),
        "evidence_locator": fact.get(
            "evidence_locator"
        ),
        "line_number": fact.get(
            "line_number"
        ),
        "source_key": fact.get(
            "source_key"
        ),
        "source_type": fact.get(
            "source_type"
        ),
        "extraction_method": fact.get(
            "extraction_method"
        ),
        "confidence_level": fact.get(
            "confidence_level"
        ),
        "confidence_basis": fact.get(
            "confidence_basis"
        ),
    }


def build_reviews(
    sample_data: dict[str, Any],
    case_contexts: dict[str, Any],
) -> list[dict[str, Any]]:
    reviews: list[dict[str, Any]] = []

    for sample in dict_rows(
        sample_data.get("samples")
    ):
        fact = sample.get(
            "fact",
            {},
        )

        if not isinstance(fact, dict):
            raise ValueError(
                "Sample contains invalid fact."
            )

        distribution = clean_text(
            sample.get("distribution")
        )

        context = case_contexts.get(
            distribution,
            {},
        )

        available_source_keys = [
            clean_text(
                source.get("source_key")
            )
            for source in dict_rows(
                context.get("sources")
            )
            if clean_text(
                source.get("source_key")
            )
        ]

        reviews.append(
            {
                "sample_index": sample.get(
                    "sample_index"
                ),
                "review_id": sample.get(
                    "review_id"
                ),
                "fact_id": sample.get(
                    "fact_id"
                ),
                "distribution": distribution,
                "vulnerability_ids": fact.get(
                    "vulnerability_ids",
                    [],
                ),
                "fact_kind": sample.get(
                    "fact_kind"
                ),

                "sampling": sample.get(
                    "sampling"
                ),

                "candidate_fact": (
                    compact_candidate_fact(
                        fact
                    )
                ),

                "context_distribution": (
                    distribution
                ),

                "available_source_keys": (
                    available_source_keys
                ),

                "review_status": "pending",

                "atomic_correctness_options": (
                    ATOMIC_CORRECTNESS_OPTIONS
                ),

                "atomic_correctness": "",

                "trigger_utility_options": (
                    TRIGGER_UTILITY_OPTIONS
                ),

                "trigger_utility": "",

                "reviewed_source_keys": [],

                "source_lookup_count": None,

                "review_seconds": None,

                "review_reason": "",

                "additional_evidence_required": (
                    None
                ),

                "additional_evidence_note": "",
            }
        )

    reviews.sort(
        key=lambda row: int(
            row.get("sample_index")
            or 0
        )
    )

    return reviews


def build_review_sheet(
    *,
    sample_data: dict[str, Any],
    corpus: dict[str, Any],
) -> dict[str, Any]:
    samples = dict_rows(
        sample_data.get("samples")
    )

    candidate_source_keys = set()

    for sample in samples:
        fact = sample.get(
            "fact",
            {},
        )

        if not isinstance(
                fact,
                dict,
        ):
            continue

        source_key = clean_text(
            fact.get("source_key")
        )

        if source_key:
            candidate_source_keys.add(
                source_key
            )

    candidate_source_contexts = (
        build_candidate_source_contexts(
            corpus=corpus,
            source_keys=(
                candidate_source_keys
            ),
        )
    )

    missing_candidate_sources = sorted(
        source_key
        for source_key
        in candidate_source_keys
        if source_key
        not in candidate_source_contexts
    )

    if missing_candidate_sources:
        raise ValueError(
            "Missing Candidate Fact source "
            "context for: "
            + ", ".join(
                missing_candidate_sources
            )
        )

    distributions = {
        clean_text(
            row.get("distribution")
        )
        for row in samples
        if clean_text(
            row.get("distribution")
        )
    }

    case_contexts = (
        build_case_contexts(
            corpus=corpus,
            distributions=distributions,
        )
    )

    missing_contexts = sorted(
        distribution
        for distribution in distributions
        if distribution
        not in case_contexts
    )

    if missing_contexts:
        raise ValueError(
            "Missing vulnerability context for: "
            + ", ".join(
                missing_contexts
            )
        )

    reviews = build_reviews(
        sample_data,
        case_contexts,
    )

    review_ids = [
        clean_text(
            row.get("review_id")
        )
        for row in reviews
    ]

    fact_ids = [
        clean_text(
            row.get("fact_id")
        )
        for row in reviews
    ]

    if len(review_ids) != len(
        set(review_ids)
    ):
        raise ValueError(
            "Duplicate review_id detected."
        )

    if len(fact_ids) != len(
        set(fact_ids)
    ):
        raise ValueError(
            "Duplicate fact_id detected."
        )

    fact_kind_counts = Counter(
        clean_text(
            row.get("fact_kind")
        )
        for row in reviews
    )

    distribution_counts = Counter(
        clean_text(
            row.get("distribution")
        )
        for row in reviews
    )

    context_source_count = sum(
        len(
            dict_rows(
                context.get("sources")
            )
        )
        for context
        in case_contexts.values()
    )

    return {
        "schema_version": SCHEMA_VERSION,
        "builder_version": BUILDER_VERSION,

        "status": (
            "pending_human_review"
        ),

        "source_mode": (
            "stratified_python_candidate_"
            "fact_trigger_utility_review"
        ),

        "input": {
            "sample_schema_version": (
                sample_data.get(
                    "schema_version"
                )
            ),
            "sample_population_size": (
                sample_data.get(
                    "sampling",
                    {},
                ).get(
                    "population_size"
                )
            ),
            "sample_size": (
                sample_data.get(
                    "sampling",
                    {},
                ).get(
                    "sample_size"
                )
            ),
            "random_seed": (
                sample_data.get(
                    "sampling",
                    {},
                ).get(
                    "random_seed"
                )
            ),
        },

        "semantic_boundary": {
            "review_sheet_is_ground_truth": (
                False
            ),
            "prepopulates_human_labels": (
                False
            ),
            "requires_human_decisions": (
                True
            ),
            "atomic_correctness_is_distinct_from_trigger_utility": (
                True
            ),
            "downstream_pipeline_usage_is_not_used_as_human_truth": (
                True
            ),
            "unresolved_human_judgment_is_allowed": (
                True
            ),
            "sampling_weights_must_be_used_for_population_estimates": (
                True
            ),
        },

        "review_protocol": {
            "atomic_correctness": {
                "correct": (
                    "Candidate Fact accurately "
                    "represents the cited source-code "
                    "fact."
                ),
                "incorrect": (
                    "Candidate Fact does not "
                    "accurately represent the cited "
                    "source-code fact."
                ),
                "uncertain": (
                    "Available source information is "
                    "insufficient to judge atomic "
                    "correctness reliably."
                ),
            },

            "trigger_utility": {
                "A": (
                    "Trigger-critical: directly "
                    "expresses a vulnerability-specific "
                    "condition needed to characterize "
                    "the Trigger."
                ),
                "B": (
                    "Trigger-supporting: materially "
                    "supports explanation or proof of "
                    "the Trigger, but is not itself a "
                    "decisive Trigger condition."
                ),
                "C": (
                    "Non-material: the code fact may "
                    "be correct or superficially "
                    "related, but provides no material "
                    "value for the vulnerability "
                    "Trigger."
                ),
                "U": (
                    "Uncertain: available evidence is "
                    "insufficient for a reliable "
                    "Trigger-utility judgment."
                ),
            },

            "evidence_policy": {
                "candidate_source": (
                    "Use the Candidate Fact's release "
                    "source and locator for atomic "
                    "correctness."
                ),
                "vulnerability_context": (
                    "Use same-distribution non-release-"
                    "source evidence such as advisory, "
                    "security issue, fix commit, fix "
                    "PR, changelog, release notes, and "
                    "conflicting advisory evidence."
                ),
                "do_not_infer_from_pipeline_outcome": (
                    True
                ),
            },
        },

        "summary": {
            "review_count": len(
                reviews
            ),
            "pending_review_count": len(
                reviews
            ),
            "case_context_count": len(
                case_contexts
            ),
            "context_source_count": (
                context_source_count
            ),
            "review_counts_by_distribution": (
                dict(
                    sorted(
                        distribution_counts.items()
                    )
                )
            ),
            "review_counts_by_fact_kind": (
                dict(
                    sorted(
                        fact_kind_counts.items()
                    )
                )
            ),
            "candidate_source_context_count": (
                len(
                    candidate_source_contexts
                )
            ),
        },

        "case_contexts": case_contexts,

        "candidate_source_contexts": (
            candidate_source_contexts
        ),

        "reviews": reviews,
    }


def csv_value(value: Any) -> Any:
    if isinstance(
        value,
        (dict, list),
    ):
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
        )

    if value is None:
        return ""

    return value


def write_csv(
    path: Path,
    reviews: list[dict[str, Any]],
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fieldnames = [
        "sample_index",
        "review_id",
        "fact_id",
        "distribution",
        "vulnerability_ids",
        "fact_kind",
        "sampling",
        "candidate_fact",
        "available_source_keys",
        "review_status",
        "atomic_correctness",
        "trigger_utility",
        "reviewed_source_keys",
        "source_lookup_count",
        "review_seconds",
        "review_reason",
        "additional_evidence_required",
        "additional_evidence_note",
    ]

    with path.open(
        "w",
        encoding="utf-8-sig",
        newline="",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
            extrasaction="ignore",
        )

        writer.writeheader()

        for review in reviews:
            writer.writerow(
                {
                    field: csv_value(
                        review.get(field)
                    )
                    for field
                    in fieldnames
                }
            )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Build the human-review sheet "
            "for retained Python Candidate "
            "Fact Trigger utility."
        )
    )

    parser.add_argument(
        "--sample",
        type=Path,
        default=DEFAULT_SAMPLE,
    )

    parser.add_argument(
        "--corpus",
        type=Path,
        default=DEFAULT_CORPUS,
    )

    parser.add_argument(
        "--json-out",
        type=Path,
        default=DEFAULT_JSON_OUTPUT,
    )

    parser.add_argument(
        "--csv-out",
        type=Path,
        default=DEFAULT_CSV_OUTPUT,
    )

    args = parser.parse_args()

    sample_data = load_json(
        args.sample
    )

    corpus = load_json(
        args.corpus
    )

    result = build_review_sheet(
        sample_data=sample_data,
        corpus=corpus,
    )

    write_json(
        args.json_out,
        result,
    )

    write_csv(
        args.csv_out,
        dict_rows(
            result.get("reviews")
        ),
    )

    summary = result["summary"]

    print("=" * 72)
    print(
        "PYTHON FACT TRIGGER UTILITY "
        "REVIEW SHEET"
    )
    print("=" * 72)

    print(
        "[OK] schema:",
        SCHEMA_VERSION,
    )

    print(
        "[OK] reviews:",
        summary["review_count"],
    )

    print(
        "[OK] pending:",
        summary[
            "pending_review_count"
        ],
    )

    print(
        "[OK] case contexts:",
        summary[
            "case_context_count"
        ],
    )

    print(
        "[OK] context sources:",
        summary[
            "context_source_count"
        ],
    )

    print(
        "[OK] JSON saved:",
        args.json_out.resolve(),
    )

    print(
        "[OK] CSV saved:",
        args.csv_out.resolve(),
    )


if __name__ == "__main__":
    main()