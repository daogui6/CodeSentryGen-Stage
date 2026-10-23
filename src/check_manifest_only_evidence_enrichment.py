import json
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

INPUT_PATH = (
    ROOT
    / "output"
    / "auto_qwen37_100_manifest_evidence_enriched.jsonl"
)


EXPECTED_COUNTS = {
    "direct_import_backed": 15,
    "transitive_dependency_backed": 3,
    "optional_extra_dependency": 1,
    "no_dependency_evidence": 1,
}


EXPECTED_POLICY: dict[str, dict[str, Any]] = {
    "direct_import_backed": {
        "risk_candidate": False,
        "confidence": 0.0,
        "status": "resolved",
        "severity": "none",
    },
    "transitive_dependency_backed": {
        "risk_candidate": True,
        "confidence": 0.35,
        "status": "weak",
        "severity": "low",
    },
    "optional_extra_dependency": {
        "risk_candidate": True,
        "confidence": 0.45,
        "status": "weak",
        "severity": "low",
    },
    "no_dependency_evidence": {
        "risk_candidate": True,
        "confidence": 0.80,
        "status": "probable",
        "severity": "medium",
    },
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


def approximately_equal(
    left: Any,
    right: float,
) -> bool:
    try:
        return abs(
            float(left) - right
        ) < 1e-9
    except (
        TypeError,
        ValueError,
    ):
        return False


def main() -> None:
    if not INPUT_PATH.exists():
        raise FileNotFoundError(
            f"Input not found: {INPUT_PATH}"
        )

    records = read_jsonl(
        INPUT_PATH
    )

    enriched_records = [
        record
        for record in records
        if record.get(
            "manifest_only_evidence_label"
        )
    ]

    label_counts = Counter(
        str(
            record.get(
                "manifest_only_evidence_label",
                "",
            )
        )
        for record in enriched_records
    )

    errors: list[str] = []

    if len(records) != 260:
        errors.append(
            f"Expected 260 total records, "
            f"got {len(records)}"
        )

    if len(enriched_records) != 20:
        errors.append(
            f"Expected 20 enriched records, "
            f"got {len(enriched_records)}"
        )

    for label, expected_count in (
        EXPECTED_COUNTS.items()
    ):
        actual_count = label_counts.get(
            label,
            0,
        )

        if actual_count != expected_count:
            errors.append(
                f"{label}: expected "
                f"{expected_count}, got "
                f"{actual_count}"
            )

    print(
        "============================================================"
    )
    print(
        "Manifest-only evidence enrichment check"
    )
    print(
        "============================================================"
    )

    for record in enriched_records:
        sample_id = str(
            record.get(
                "sample_id",
                "",
            )
        )

        package = str(
            record.get(
                "package",
                "",
            )
        )

        source_type = str(
            record.get(
                "source_type",
                "",
            )
        )

        label = str(
            record.get(
                "manifest_only_evidence_label",
                "",
            )
        )

        risk_candidate = record.get(
            "manifest_only_risk_candidate"
        )

        confidence = record.get(
            "manifest_only_risk_confidence"
        )

        evidence = record.get(
            "manifest_only_evidence",
            {},
        )

        if label not in EXPECTED_POLICY:
            errors.append(
                f"{sample_id}/{package}: "
                f"unsupported label {label}"
            )
            continue

        policy = EXPECTED_POLICY[
            label
        ]

        if source_type not in {
            "manifest",
            "requirements",
        }:
            errors.append(
                f"{sample_id}/{package}: "
                f"unexpected source_type "
                f"{source_type}"
            )

        if (
            risk_candidate
            is not policy["risk_candidate"]
        ):
            errors.append(
                f"{sample_id}/{package}: "
                f"risk_candidate should be "
                f"{policy['risk_candidate']}, "
                f"got {risk_candidate}"
            )

        if not approximately_equal(
            confidence,
            policy["confidence"],
        ):
            errors.append(
                f"{sample_id}/{package}: "
                f"confidence should be "
                f"{policy['confidence']}, "
                f"got {confidence}"
            )

        if not isinstance(
            evidence,
            dict,
        ):
            errors.append(
                f"{sample_id}/{package}: "
                "manifest_only_evidence "
                "is not an object"
            )
            continue

        if evidence.get("label") != label:
            errors.append(
                f"{sample_id}/{package}: "
                "nested evidence label mismatch"
            )

        if (
            evidence.get(
                "recommended_status"
            )
            != policy["status"]
        ):
            errors.append(
                f"{sample_id}/{package}: "
                "recommended_status mismatch"
            )

        if (
            evidence.get(
                "recommended_severity"
            )
            != policy["severity"]
        ):
            errors.append(
                f"{sample_id}/{package}: "
                "recommended_severity mismatch"
            )

        if not approximately_equal(
            evidence.get(
                "recommended_confidence"
            ),
            policy["confidence"],
        ):
            errors.append(
                f"{sample_id}/{package}: "
                "nested confidence mismatch"
            )

        print(
            f"[OK] {sample_id} | "
            f"{package} | "
            f"{label} | "
            f"confidence={confidence}"
        )

    print("")
    print("Label counts:")

    for label, count in sorted(
        label_counts.items()
    ):
        print(
            f"  {label} = {count}"
        )

    print("")
    print(
        f"total_records = {len(records)}"
    )
    print(
        f"enriched_records = "
        f"{len(enriched_records)}"
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