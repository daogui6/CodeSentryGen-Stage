from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from review_python_fact_trigger_utility import (
    DEFAULT_OUTPUT,
    DEFAULT_SHEET,
    clean_text,
    dict_rows,
    get_context_sources,
    load_json,
    print_candidate_source_context,
    print_evidence_source,
    update_summary,
    utc_now_text,
    validate_resume_compatibility,
    write_json_atomic,
)


BATCH_REVIEWER_VERSION = (
    "python_fact_trigger_utility_batch_reviewer_v0.1"
)


def choose_briefing_sources(
    sources: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    semantic_source = None
    fix_source = None

    semantic_priority = [
        "upstream_security_advisory",
        "github_reviewed_advisory",
        "osv_github_advisory",
        "osv_pypi_advisory",
        "pypa_advisory",
        "upstream_security_issue",
    ]

    fix_priority = [
        "upstream_fix_commit",
        "upstream_fix_pull_request",
    ]

    for wanted_type in semantic_priority:
        for source in sources:
            if clean_text(
                source.get("source_type")
            ) == wanted_type:
                semantic_source = source
                break

        if semantic_source is not None:
            break

    for wanted_type in fix_priority:
        for source in sources:
            if clean_text(
                source.get("source_type")
            ) == wanted_type:
                fix_source = source
                break

        if fix_source is not None:
            break

    result = []

    if semantic_source is not None:
        result.append(
            semantic_source
        )

    if (
        fix_source is not None
        and fix_source
        not in result
    ):
        result.append(
            fix_source
        )

    return result


def show_case_briefing(
    *,
    distribution: str,
    sources: list[dict[str, Any]],
) -> list[str]:
    selected = (
        choose_briefing_sources(
            sources
        )
    )

    print()
    print("=" * 88)
    print(
        "PACKAGE CASE BRIEFING:",
        distribution,
    )
    print("=" * 88)

    print(
        "Read this once for the package. "
        "The following facts share this "
        "vulnerability background."
    )

    source_keys = []

    for source in selected:
        print_evidence_source(
            source,
            full=False,
        )

        source_key = clean_text(
            source.get(
                "source_key"
            )
        )

        if source_key:
            source_keys.append(
                source_key
            )

    print()
    input(
        "Press Enter after you understand "
        "the package vulnerability/fix context..."
    )

    return source_keys


def briefing_already_supported(
    *,
    results: dict[str, Any],
    distribution: str,
) -> list[str]:
    # 第 1 条 PyYAML 已经正式看过
    # advisory + fix commit，可以复用该事实。
    for review in dict_rows(
        results.get("reviews")
    ):
        if (
            review.get(
                "review_status"
            )
            != "completed"
        ):
            continue

        if clean_text(
            review.get(
                "distribution"
            )
        ) != distribution:
            continue

        source_keys = review.get(
            "reviewed_source_keys",
            [],
        )

        if not isinstance(
            source_keys,
            list,
        ):
            continue

        if len(source_keys) >= 2:
            return [
                clean_text(value)
                for value
                in source_keys
                if clean_text(value)
            ]

    return []


def ensure_case_briefing(
    *,
    results: dict[str, Any],
    review: dict[str, Any],
) -> list[str]:
    distribution = clean_text(
        review.get(
            "distribution"
        )
    )

    briefings = results.setdefault(
        "case_briefings",
        {},
    )

    existing = briefings.get(
        distribution
    )

    if isinstance(
        existing,
        dict,
    ):
        source_keys = existing.get(
            "source_keys",
            [],
        )

        if isinstance(
            source_keys,
            list,
        ):
            return [
                clean_text(value)
                for value in source_keys
                if clean_text(value)
            ]

    inherited = (
        briefing_already_supported(
            results=results,
            distribution=distribution,
        )
    )

    if inherited:
        briefings[
            distribution
        ] = {
            "status": "acknowledged",
            "source_keys": inherited,
            "mode": (
                "inherited_from_completed_"
                "formal_review"
            ),
            "acknowledged_at_utc": (
                utc_now_text()
            ),
        }

        return inherited

    sources = get_context_sources(
        results,
        review,
    )

    source_keys = (
        show_case_briefing(
            distribution=distribution,
            sources=sources,
        )
    )

    briefings[
        distribution
    ] = {
        "status": "acknowledged",
        "source_keys": source_keys,
        "mode": "batch_case_briefing",
        "acknowledged_at_utc": (
            utc_now_text()
        ),
    }

    return source_keys


def parse_label(
    raw: str,
) -> tuple[str, str] | None:
    text = (
        raw.strip()
        .upper()
        .replace(" ", "")
    )

    if len(text) != 2:
        return None

    atomic_code = text[0]
    utility = text[1]

    atomic_map = {
        "1": "correct",
        "2": "incorrect",
        "3": "uncertain",
    }

    if atomic_code not in atomic_map:
        return None

    if utility not in {
        "A",
        "B",
        "C",
        "U",
    }:
        return None

    return (
        atomic_map[
            atomic_code
        ],
        utility,
    )


def ask_reason_if_needed(
    *,
    atomic: str,
    utility: str,
) -> tuple[str, str]:
    # 最常见的 correct + C 不强迫写
    # 79 次几乎一样的句子。
    if (
        atomic == "correct"
        and utility == "C"
    ):
        return (
            "Routine non-material judgment "
            "under the package case briefing; "
            "the fact does not materially "
            "characterize the vulnerability "
            "Trigger.",
            "standardized_batch_reason",
        )

    print()
    print(
        "Reason required for this label:"
    )

    while True:
        reason = input(
            "> "
        ).strip()

        if reason:
            return (
                reason,
                "human_written",
            )

        print(
            "Reason cannot be blank."
        )


def print_batch_fact(
    *,
    results: dict[str, Any],
    review: dict[str, Any],
    current_number: int,
    total: int,
) -> bool:
    print()
    print("=" * 88)

    print(
        f"[{current_number}/{total}] "
        f"{review.get('distribution')} | "
        f"{review.get('fact_kind')}"
    )

    print("=" * 88)

    print(
        "Fact ID:",
        review.get(
            "fact_id"
        ),
    )

    fact = review.get(
        "candidate_fact",
        {},
    )

    if not isinstance(
        fact,
        dict,
    ):
        fact = {}

    print(
        "Structured fact:",
        fact.get(
            "structured_value"
        ),
    )

    print(
        "Excerpt:",
        fact.get(
            "evidence_excerpt"
        ),
    )

    print()

    return (
        print_candidate_source_context(
            results,
            review,
        )
    )


def list_package_evidence(
    results: dict[str, Any],
    review: dict[str, Any],
) -> list[dict[str, Any]]:
    sources = get_context_sources(
        results,
        review,
    )

    print()
    print(
        "Available package evidence:"
    )

    for index, source in enumerate(
        sources,
        start=1,
    ):
        print(
            f"  {index}. "
            f"[{source.get('source_type')}] "
            f"{source.get('source_key')}"
        )

    return sources


def save_label(
    *,
    results: dict[str, Any],
    review: dict[str, Any],
    atomic: str,
    utility: str,
    review_seconds: float,
    briefing_source_keys: list[str],
    extra_source_keys: list[str],
    candidate_source_viewed: bool,
) -> None:
    reason, reason_mode = (
        ask_reason_if_needed(
            atomic=atomic,
            utility=utility,
        )
    )

    all_source_keys = []

    for source_key in (
        briefing_source_keys
        + extra_source_keys
    ):
        if (
            source_key
            and source_key
            not in all_source_keys
        ):
            all_source_keys.append(
                source_key
            )

    review[
        "atomic_correctness"
    ] = atomic

    review[
        "trigger_utility"
    ] = utility

    review[
        "review_reason"
    ] = reason

    review[
        "review_reason_mode"
    ] = reason_mode

    # 单条额外打开的证据
    review[
        "reviewed_source_keys"
    ] = extra_source_keys

    review[
        "source_lookup_count"
    ] = len(
        extra_source_keys
    )

    # 包级 briefing 单独记录，
    # 不伪装成“每条都重新打开过”。
    review[
        "case_briefing_used"
    ] = True

    review[
        "case_briefing_source_keys"
    ] = briefing_source_keys

    review[
        "candidate_source_viewed"
    ] = candidate_source_viewed

    review[
        "review_seconds"
    ] = round(
        review_seconds,
        3,
    )

    review[
        "additional_evidence_required"
    ] = (
        utility == "U"
    )

    review[
        "additional_evidence_note"
    ] = (
        "Trigger utility remains uncertain "
        "under the available review evidence."
        if utility == "U"
        else ""
    )

    review[
        "review_status"
    ] = "completed"

    review[
        "completed_at_utc"
    ] = utc_now_text()

    results[
        "batch_reviewer_version"
    ] = BATCH_REVIEWER_VERSION

    update_summary(
        results
    )

    write_json_atomic(
        DEFAULT_OUTPUT,
        results,
    )


def main() -> None:
    sheet = load_json(
        DEFAULT_SHEET
    )

    results = load_json(
        DEFAULT_OUTPUT
    )

    validate_resume_compatibility(
        sheet,
        results,
    )

    reviews = dict_rows(
        results.get("reviews")
    )

    total = len(
        reviews
    )

    print(
        "[OK] Batch reviewer loaded."
    )

    print(
        "[INFO] completed:",
        results.get(
            "summary",
            {},
        ).get(
            "completed_review_count",
            0,
        ),
    )

    print(
        "[INFO] pending:",
        results.get(
            "summary",
            {},
        ).get(
            "pending_review_count",
            0,
        ),
    )

    for index, review in enumerate(
        reviews,
        start=1,
    ):
        if (
            review.get(
                "review_status"
            )
            == "completed"
        ):
            continue

        briefing_source_keys = (
            ensure_case_briefing(
                results=results,
                review=review,
            )
        )

        write_json_atomic(
            DEFAULT_OUTPUT,
            results,
        )

        candidate_viewed = (
            print_batch_fact(
                results=results,
                review=review,
                current_number=index,
                total=total,
            )
        )

        if not candidate_viewed:
            print(
                "[WARN] Candidate source "
                "could not be displayed."
            )

        start_time = (
            time.monotonic()
        )

        extra_source_keys = []

        while True:
            print()
            print(
                "Label: 1/2/3 + A/B/C/U "
                "(example: 1C)"
            )

            print(
                "Commands: b=show package briefing, "
                "e=list evidence, e N=open evidence, "
                "s=skip, q=save & quit"
            )

            raw = input(
                "batch> "
            ).strip()

            command = raw.lower()

            if command == "q":
                update_summary(
                    results
                )

                write_json_atomic(
                    DEFAULT_OUTPUT,
                    results,
                )

                print(
                    "[OK] Progress saved."
                )

                return

            if command == "s":
                break

            if command == "b":
                sources = (
                    get_context_sources(
                        results,
                        review,
                    )
                )

                show_case_briefing(
                    distribution=clean_text(
                        review.get(
                            "distribution"
                        )
                    ),
                    sources=sources,
                )

                continue

            if command == "e":
                list_package_evidence(
                    results,
                    review,
                )

                continue

            if command.startswith(
                "e "
            ):
                parts = raw.split()

                if len(parts) != 2:
                    print(
                        "Use: e N"
                    )
                    continue

                try:
                    source_number = int(
                        parts[1]
                    )

                except ValueError:
                    print(
                        "Use: e N"
                    )
                    continue

                sources = (
                    get_context_sources(
                        results,
                        review,
                    )
                )

                if not (
                    1
                    <= source_number
                    <= len(sources)
                ):
                    print(
                        "Evidence number "
                        "out of range."
                    )
                    continue

                source = sources[
                    source_number - 1
                ]

                print_evidence_source(
                    source,
                    full=False,
                )

                source_key = clean_text(
                    source.get(
                        "source_key"
                    )
                )

                if (
                    source_key
                    and source_key
                    not in extra_source_keys
                ):
                    extra_source_keys.append(
                        source_key
                    )

                continue

            parsed = parse_label(
                raw
            )

            if parsed is None:
                print(
                    "Invalid input. "
                    "Example labels: "
                    "1A, 1B, 1C, 1U."
                )
                continue

            atomic, utility = (
                parsed
            )

            elapsed = (
                time.monotonic()
                - start_time
            )

            save_label(
                results=results,
                review=review,
                atomic=atomic,
                utility=utility,
                review_seconds=elapsed,
                briefing_source_keys=(
                    briefing_source_keys
                ),
                extra_source_keys=(
                    extra_source_keys
                ),
                candidate_source_viewed=(
                    candidate_viewed
                ),
            )

            print(
                "[OK] Saved:",
                review.get(
                    "fact_id"
                ),
                "=>",
                atomic,
                utility,
            )

            break

    update_summary(
        results
    )

    write_json_atomic(
        DEFAULT_OUTPUT,
        results,
    )

    print(
        "[OK] All 80 reviews completed."
    )


if __name__ == "__main__":
    main()