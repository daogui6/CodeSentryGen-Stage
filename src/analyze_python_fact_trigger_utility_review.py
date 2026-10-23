from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


DEFAULT_RESULTS = Path(
    "data/avcs_validation/rq1_review/"
    "python_fact_trigger_utility_review_results_v0.json"
)
DEFAULT_SHEET = Path(
    "data/avcs_validation/rq1_review/"
    "python_fact_trigger_utility_review_sheet_v0.json"
)
DEFAULT_SAMPLE = Path(
    "data/avcs_validation/rq1_review/"
    "python_fact_trigger_utility_sample_v0.json"
)
DEFAULT_BACKUP = Path(
    "data/avcs_validation/rq1_review/"
    "python_fact_trigger_utility_review_results_v0_pre_codex_batch.json"
)

ATOMIC_VALUES = {"correct", "incorrect", "uncertain"}
UTILITY_VALUES = {"A", "B", "C", "U"}
CONFIDENCE_VALUES = {"high", "medium", "low"}
EVALUATION_POPULATION = 363


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def rows(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def sampling_weight(review: dict[str, Any]) -> float:
    sampling = review.get("sampling")
    if not isinstance(sampling, dict):
        raise ValueError(f"{review.get('fact_id')} has no sampling object")

    weight = sampling.get("sampling_weight")
    if not isinstance(weight, (int, float)):
        raise ValueError(f"{review.get('fact_id')} has no sampling_weight")

    return float(weight)


def counter_with_all(
    counter: Counter[str],
    keys: list[str],
) -> dict[str, int]:
    return {key: counter.get(key, 0) for key in keys}


def validate_review(
    *,
    results: dict[str, Any],
    sheet: dict[str, Any],
    sample: dict[str, Any],
    backup: dict[str, Any] | None,
) -> list[str]:
    errors: list[str] = []
    reviews = rows(results.get("reviews"))
    sheet_reviews = rows(sheet.get("reviews"))
    sample_rows = rows(sample.get("samples"))

    if len(reviews) != 80:
        errors.append(f"reviews != 80: {len(reviews)}")

    completed = [
        review for review in reviews
        if review.get("review_status") == "completed"
    ]
    pending = len(reviews) - len(completed)
    expected_atomic_counts = dict(
        sorted(
            Counter(
                review.get("atomic_correctness")
                for review in completed
                if review.get("atomic_correctness")
            ).items()
        )
    )

    expected_utility_counts = dict(
        sorted(
            Counter(
                review.get("trigger_utility")
                for review in completed
                if review.get("trigger_utility")
            ).items()
        )
    )

    summary = results.get("summary")
    if not isinstance(summary, dict):
        errors.append("summary missing or invalid")
    else:
        if (
            summary.get("atomic_correctness_counts")
            != expected_atomic_counts
        ):
            errors.append(
                "summary atomic_correctness_counts "
                "does not match reviews"
            )

        if (
            summary.get("trigger_utility_counts")
            != expected_utility_counts
        ):
            errors.append(
                "summary trigger_utility_counts "
                "does not match reviews"
            )

    if len(completed) != 80:
        errors.append(f"completed != 80: {len(completed)}")
    if pending != 0:
        errors.append(f"pending != 0: {pending}")

    if len({review.get("fact_id") for review in reviews}) != 80:
        errors.append("unique fact_id != 80")
    if len({review.get("review_id") for review in reviews}) != 80:
        errors.append("unique review_id != 80")

    calibration_ids = set(
        sample.get("sampling", {}).get("calibration_fact_ids", [])
    )
    replacement_ids = set(
        sample.get("sampling", {}).get("replacement_fact_ids", [])
    )
    review_ids = {review.get("fact_id") for review in reviews}

    if calibration_ids & review_ids:
        errors.append("calibration fact appears in formal reviews")
    if not replacement_ids <= review_ids:
        errors.append("replacement fact missing from formal reviews")

    for review in reviews:
        fact_id = review.get("fact_id")
        if review.get("atomic_correctness") not in ATOMIC_VALUES:
            errors.append(f"{fact_id}: invalid atomic_correctness")
        if review.get("trigger_utility") not in UTILITY_VALUES:
            errors.append(f"{fact_id}: invalid trigger_utility")
        if not review.get("review_reason"):
            errors.append(f"{fact_id}: missing review_reason")
        try:
            sampling_weight(review)
        except ValueError as exc:
            errors.append(str(exc))

    first = reviews[0] if reviews else {}
    if first.get("annotation_source") != "human":
        errors.append("first annotation_source is not human")

    if backup is not None:
        backup_reviews = rows(backup.get("reviews"))
        if backup_reviews:
            backup_first = backup_reviews[0]
            protected = [
                "atomic_correctness",
                "trigger_utility",
                "review_reason",
                "reviewed_source_keys",
                "review_seconds",
                "completed_at_utc",
            ]
            for key in protected:
                if first.get(key) != backup_first.get(key):
                    errors.append(f"first human field changed: {key}")

    codex_reviews = reviews[1:]
    if len(codex_reviews) != 79:
        errors.append(f"codex review count != 79: {len(codex_reviews)}")

    for review in codex_reviews:
        fact_id = review.get("fact_id")
        if review.get("annotation_source") != "codex_assisted":
            errors.append(f"{fact_id}: annotation_source not codex_assisted")
        if review.get("confidence") not in CONFIDENCE_VALUES:
            errors.append(f"{fact_id}: invalid or missing confidence")
        reason = str(review.get("review_reason", "")).strip()
        if len(reason) < 40:
            errors.append(f"{fact_id}: review_reason too short")
        basis = review.get("reasoning_basis")
        if not isinstance(basis, dict):
            errors.append(f"{fact_id}: missing reasoning_basis")
            continue
        if not basis.get("candidate_source"):
            errors.append(f"{fact_id}: missing candidate_source basis")
        if not basis.get("vulnerability_sources"):
            errors.append(f"{fact_id}: missing vulnerability_sources basis")
        if not basis.get("fix_sources"):
            errors.append(f"{fact_id}: missing fix_sources basis")

    sheet_fact_ids = [review.get("fact_id") for review in sheet_reviews]
    sample_fact_ids = [review.get("fact_id") for review in sample_rows]
    if [review.get("fact_id") for review in reviews] != sheet_fact_ids:
        errors.append("results fact_id order differs from review sheet")
    if [review.get("fact_id") for review in reviews] != sample_fact_ids:
        errors.append("results fact_id order differs from sample")

    return errors


def analyze(results: dict[str, Any]) -> dict[str, Any]:
    reviews = rows(results.get("reviews"))

    atomic_counts = Counter(
        review.get("atomic_correctness")
        for review in reviews
    )
    utility_counts = Counter(
        review.get("trigger_utility")
        for review in reviews
    )
    confidence_counts = Counter(
        review.get("confidence")
        for review in reviews[1:]
    )

    weighted_counts = {key: 0.0 for key in ["A", "B", "C", "U"]}
    for review in reviews:
        utility = review.get("trigger_utility")
        if utility in weighted_counts:
            weighted_counts[utility] += sampling_weight(review)

    weighted_total = sum(weighted_counts.values())
    weighted_proportions = {
        key: (
            weighted_counts[key] / weighted_total
            if weighted_total
            else 0.0
        )
        for key in ["A", "B", "C", "U"]
    }

    strata: dict[tuple[str, str], dict[str, Any]] = defaultdict(
        lambda: {
            "sample_count": 0,
            "counts": Counter(),
            "weighted_contribution": 0.0,
        }
    )
    for review in reviews:
        key = (
            str(review.get("distribution")),
            str(review.get("fact_kind")),
        )
        weight = sampling_weight(review)
        item = strata[key]
        item["sample_count"] += 1
        item["counts"][str(review.get("trigger_utility"))] += 1
        item["weighted_contribution"] += weight

    strata_rows = []
    for (distribution, fact_kind), item in sorted(strata.items()):
        strata_rows.append(
            {
                "distribution": distribution,
                "fact_kind": fact_kind,
                "sample_count": item["sample_count"],
                "A": item["counts"].get("A", 0),
                "B": item["counts"].get("B", 0),
                "C": item["counts"].get("C", 0),
                "U": item["counts"].get("U", 0),
                "weighted_contribution": item["weighted_contribution"],
            }
        )

    return {
        "atomic_counts": counter_with_all(
            atomic_counts,
            ["correct", "incorrect", "uncertain"],
        ),
        "utility_counts": counter_with_all(
            utility_counts,
            ["A", "B", "C", "U"],
        ),
        "confidence_counts": counter_with_all(
            confidence_counts,
            ["high", "medium", "low"],
        ),
        "weighted_total": weighted_total,
        "weighted_counts": weighted_counts,
        "weighted_proportions": weighted_proportions,
        "strict_trigger_relevance_estimate": weighted_proportions["A"],
        "broader_trigger_evidence_utility_estimate": (
            weighted_proportions["A"] + weighted_proportions["B"]
        ),
        "non_material_noise_estimate": weighted_proportions["C"],
        "uncertainty_estimate": weighted_proportions["U"],
        "strata": strata_rows,
    }


def print_report(report: dict[str, Any]) -> None:
    print("Raw sample counts")
    print("Atomic:")
    for key, value in report["atomic_counts"].items():
        print(f"  {key}: {value}")
    print("Trigger Utility:")
    for key, value in report["utility_counts"].items():
        print(f"  {key}: {value}")

    print()
    print("Weighted population estimates")
    print(f"  weighted total: {report['weighted_total']:.6f}")
    for key in ["A", "B", "C", "U"]:
        proportion = report["weighted_proportions"][key]
        estimated = report["weighted_counts"][key]
        print(
            f"  {key}: proportion={proportion:.6f}, "
            f"estimated_count={estimated:.6f}"
        )

    print()
    print("Derived estimates")
    print(
        "  strict Trigger relevance estimate: "
        f"{report['strict_trigger_relevance_estimate']:.6f}"
    )
    print(
        "  broader Trigger evidence utility estimate: "
        f"{report['broader_trigger_evidence_utility_estimate']:.6f}"
    )
    print(
        "  non-material/noise estimate: "
        f"{report['non_material_noise_estimate']:.6f}"
    )
    print(
        "  uncertainty estimate: "
        f"{report['uncertainty_estimate']:.6f}"
    )

    print()
    print("Distribution x fact_kind strata")
    for row in report["strata"]:
        print(
            "  {distribution} | {fact_kind}: "
            "n={sample_count}, A={A}, B={B}, C={C}, U={U}, "
            "weighted_contribution={weighted_contribution:.6f}".format(
                **row
            )
        )

    print()
    print("Confidence")
    for key, value in report["confidence_counts"].items():
        print(f"  {key}: {value}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Analyze the RQ1 Python Candidate Fact Trigger Utility review."
        )
    )
    parser.add_argument("--results", type=Path, default=DEFAULT_RESULTS)
    parser.add_argument("--sheet", type=Path, default=DEFAULT_SHEET)
    parser.add_argument("--sample", type=Path, default=DEFAULT_SAMPLE)
    parser.add_argument("--backup", type=Path, default=DEFAULT_BACKUP)
    args = parser.parse_args()

    results = load_json(args.results)
    sheet = load_json(args.sheet)
    sample = load_json(args.sample)
    backup = load_json(args.backup) if args.backup.exists() else None

    errors = validate_review(
        results=results,
        sheet=sheet,
        sample=sample,
        backup=backup,
    )
    if errors:
        print("Integrity validation: FAILED")
        for error in errors:
            print(f"  - {error}")
        raise SystemExit(1)

    print("Integrity validation: PASSED")
    print(
        "Note: estimates are weighted sample estimates for the "
        f"{EVALUATION_POPULATION}-fact evaluation population, not exact "
        "counts over the original 364 retained facts."
    )
    print()
    print_report(analyze(results))


if __name__ == "__main__":
    main()
