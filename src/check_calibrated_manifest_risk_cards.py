import json
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

INPUT_PATH = (
    ROOT
    / "output"
    / "auto_qwen37_100_temporal_risk_cards_calibrated.jsonl"
)


EXPECTED_SUBTYPES = {
    "manifest_only_transitive_backed": 3,
    "manifest_only_optional_extra": 1,
    "manifest_only_unexplained": 1,
}

EXPECTED_SEVERITIES = {
    "low": 4,
    "medium": 1,
}

EXPECTED_EVIDENCE_LEVELS = {
    "strong": 3,
    "moderate": 1,
    "none": 1,
}

EXPECTED_REVIEW_PRIORITIES = {
    "low": 3,
    "medium": 1,
    "high": 1,
}


def read_jsonl(
    path: Path,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []

    with path.open(
        "r",
        encoding="utf-8",
    ) as file:
        for line_number, raw_line in enumerate(
            file,
            start=1,
        ):
            line = raw_line.strip()

            if not line:
                continue

            try:
                records.append(
                    json.loads(line)
                )
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON at line "
                    f"{line_number}: {exc}"
                ) from exc

    return records


def main() -> None:
    if not INPUT_PATH.exists():
        raise FileNotFoundError(
            f"Input file not found: {INPUT_PATH}"
        )

    cards = read_jsonl(INPUT_PATH)

    subtype_counts = Counter(
        str(card.get("subtype", ""))
        for card in cards
    )

    severity_counts = Counter(
        str(card.get("severity", ""))
        for card in cards
    )

    evidence_level_counts = Counter(
        str(
            card.get(
                "evidence_level",
                "",
            )
        )
        for card in cards
    )

    review_priority_counts = Counter(
        str(
            card.get(
                "review_priority",
                "",
            )
        )
        for card in cards
    )

    errors: list[str] = []

    if len(cards) != 5:
        errors.append(
            f"Expected 5 cards, got {len(cards)}"
        )

    for subtype, expected in (
        EXPECTED_SUBTYPES.items()
    ):
        actual = subtype_counts.get(
            subtype,
            0,
        )

        if actual != expected:
            errors.append(
                f"{subtype}: expected "
                f"{expected}, got {actual}"
            )

    for severity, expected in (
        EXPECTED_SEVERITIES.items()
    ):
        actual = severity_counts.get(
            severity,
            0,
        )

        if actual != expected:
            errors.append(
                f"severity {severity}: expected "
                f"{expected}, got {actual}"
            )

    for evidence_level, expected in (
            EXPECTED_EVIDENCE_LEVELS.items()
    ):
        actual = evidence_level_counts.get(
            evidence_level,
            0,
        )

        if actual != expected:
            errors.append(
                f"evidence_level {evidence_level}: "
                f"expected {expected}, got {actual}"
            )

    for review_priority, expected in (
            EXPECTED_REVIEW_PRIORITIES.items()
    ):
        actual = review_priority_counts.get(
            review_priority,
            0,
        )

        if actual != expected:
            errors.append(
                f"review_priority {review_priority}: "
                f"expected {expected}, got {actual}"
            )

    print(
        "============================================================"
    )
    print(
        "Calibrated manifest Risk Card check"
    )
    print(
        "============================================================"
    )

    for card in cards:
        sample_id = card.get(
            "sample_id",
            "",
        )

        package = (
            card.get(
                "introduced_by",
                {},
            ).get(
                "entity",
                "",
            )
        )

        subtype = card.get(
            "subtype",
            "",
        )

        severity = card.get(
            "severity",
            "",
        )

        evidence_level = card.get(
            "evidence_level",
            "",
        )

        review_priority = card.get(
            "review_priority",
            "",
        )

        if "confidence" in card:
            errors.append(
                f"{sample_id}/{package}: "
                "unexpected numeric confidence "
                "in manifest-only Risk Card"
            )

        manifest_evidence = (
            card.get(
                "evidence",
                {},
            ).get(
                "manifest_only"
            )
        )

        if not isinstance(
            manifest_evidence,
            dict,
        ):
            errors.append(
                f"{sample_id}/{package}: "
                "missing manifest_only evidence"
            )

        observable_labels = (
            card.get(
                "attribution",
                {},
            ).get(
                "observable_labels",
                [],
            )
        )

        evidence_label = ""

        if isinstance(
            manifest_evidence,
            dict,
        ):
            evidence_label = str(
                manifest_evidence.get(
                    "label",
                    "",
                )
            )

        if (
            evidence_label
            and evidence_label
            not in observable_labels
        ):
            errors.append(
                f"{sample_id}/{package}: "
                "evidence label missing from "
                "observable_labels"
            )

        print(
            f"[OK] {sample_id} | "
            f"{package} | "
            f"{subtype} | "
            f"severity={severity} | "
            f"evidence_level={evidence_level} | "
            f"review_priority={review_priority}"
        )

    # direct_import_backed 不应该出现在 Risk Card 中。
    for card in cards:
        manifest_evidence = (
            card.get(
                "evidence",
                {},
            ).get(
                "manifest_only"
            )
        )

        if (
            isinstance(
                manifest_evidence,
                dict,
            )
            and manifest_evidence.get(
                "label"
            )
            == "direct_import_backed"
        ):
            errors.append(
                "A direct_import_backed record "
                "was incorrectly emitted as a Risk Card"
            )

    print("")
    print("Subtype counts:")

    for subtype, count in sorted(
        subtype_counts.items()
    ):
        print(
            f"  {subtype} = {count}"
        )

    print("")
    print("Severity counts:")

    for severity, count in sorted(
        severity_counts.items()
    ):
        print(
            f"  {severity} = {count}"
        )

    print("")
    print("Evidence level counts:")

    for evidence_level, count in sorted(
            evidence_level_counts.items()
    ):
        print(
            f"  {evidence_level} = {count}"
        )

    print("")
    print("Review priority counts:")

    for review_priority, count in sorted(
            review_priority_counts.items()
    ):
        print(
            f"  {review_priority} = {count}"
        )

    print("")
    print(
        f"total_cards = {len(cards)}"
    )
    print(
        f"errors = {len(errors)}"
    )

    if errors:
        print("")
        print("Validation errors:")

        for error in errors:
            print(
                f"  - {error}"
            )

    all_pass = not errors

    print(
        f"ALL_PASS = {all_pass}"
    )
    print(
        "============================================================"
    )

    if not all_pass:
        raise SystemExit(1)


if __name__ == "__main__":
    main()