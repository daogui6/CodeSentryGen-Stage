from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from build_trigger_hitl_candidate import (
    build_candidate,
    find_vulnerability,
    load_json,
    write_json,
)
from validate_trigger_hitl_candidate import (
    validate_hitl_candidate,
)


BATCH_BUILDER_ID = (
    "step7_hitl_batch_builder_v0.1"
)

SUMMARY_SCHEMA_VERSION = (
    "step7_hitl_batch_summary_v0.1"
)


def clean_text(value: Any) -> str:
    return str(
        value
        if value is not None
        else ""
    ).strip()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as f:
        for chunk in iter(
            lambda: f.read(1024 * 1024),
            b"",
        ):
            digest.update(chunk)

    return digest.hexdigest()


def safe_case_id(value: str) -> str:
    case_id = clean_text(value)

    if not case_id:
        raise ValueError(
            "Empty case_id"
        )

    if (
        "/" in case_id
        or "\\" in case_id
        or case_id in {".", ".."}
        or ".." in case_id
    ):
        raise ValueError(
            "Unsafe case_id path component: "
            + repr(case_id)
        )

    return case_id


def normalized_repo_path(
    value: Any,
) -> str:
    return clean_text(
        value
    ).replace(
        "\\",
        "/",
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Build a batch of Step7 HITL "
            "candidate packets by reusing the "
            "existing single-case candidate "
            "builder and validator."
        )
    )

    parser.add_argument(
        "--case-plan",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--schema",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--protocol",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--repo-root",
        default=Path("."),
        type=Path,
    )

    parser.add_argument(
        "--out-dir",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--lane",
        default="formal_kb_ready",
    )

    parser.add_argument(
        "--expected-count",
        type=int,
        default=None,
    )

    args = parser.parse_args()

    if args.out_dir.exists():
        raise ValueError(
            "Output directory already exists: "
            + str(args.out_dir)
        )

    case_plan = load_json(
        args.case_plan
    )

    schema = load_json(
        args.schema
    )

    protocol = load_json(
        args.protocol
    )

    Draft202012Validator.check_schema(
        schema
    )

    pending_cases = [
        row
        for row in case_plan.get(
            "pending_cases",
            [],
        )
        if isinstance(
            row,
            dict,
        )
    ]

    selected_cases = [
        row
        for row in pending_cases
        if clean_text(
            row.get("lane")
        )
        == args.lane
    ]

    if not selected_cases:
        raise ValueError(
            "No Case Plan cases selected for lane: "
            + args.lane
        )

    if (
        args.expected_count is not None
        and len(selected_cases)
        != args.expected_count
    ):
        raise ValueError(
            "Selected case count mismatch: "
            f"{len(selected_cases)} "
            f"!= {args.expected_count}"
        )

    case_ids = [
        safe_case_id(
            row.get("case_id")
        )
        for row in selected_cases
    ]

    if len(case_ids) != len(set(case_ids)):
        raise ValueError(
            "Duplicate case_id in selected batch"
        )

    repo_root = args.repo_root.resolve()

    kb_cache: dict[
        str,
        dict[str, Any],
    ] = {}

    kb_hashes: dict[
        str,
        str,
    ] = {}

    built_candidates: list[
        tuple[
            dict[str, Any],
            dict[str, Any],
            str,
            str,
        ]
    ] = []

    failures: list[str] = []

    package_counts: Counter[str] = (
        Counter()
    )

    #
    # Phase A:
    # Build and validate everything in memory.
    # Nothing is written yet.
    #
    for batch_order, case in enumerate(
        selected_cases,
        start=1,
    ):
        case_id = safe_case_id(
            case.get("case_id")
        )

        package = clean_text(
            case.get(
                "normalized_package"
            )
            or case.get("package")
        ).lower()

        if not package:
            failures.append(
                f"{case_id}: empty package"
            )
            continue

        package_counts[
            package
        ] += 1

        if (
            case.get(
                "eligibility_created"
            )
            is not False
        ):
            failures.append(
                f"{case_id}: "
                "eligibility_created must be false"
            )
            continue

        if (
            case.get(
                "package_kb_mutated"
            )
            is not False
        ):
            failures.append(
                f"{case_id}: "
                "package_kb_mutated must be false"
            )
            continue

        kb_path_text = normalized_repo_path(
            case.get(
                "formal_kb_path"
            )
        )

        if not kb_path_text:
            failures.append(
                f"{case_id}: "
                "formal_kb_path is empty"
            )
            continue

        kb_path = (
            repo_root
            / kb_path_text
        )

        if not kb_path.exists():
            failures.append(
                f"{case_id}: "
                "formal Package KB missing: "
                + kb_path_text
            )
            continue

        if kb_path_text not in kb_cache:
            kb_cache[
                kb_path_text
            ] = load_json(
                kb_path
            )

            kb_hashes[
                kb_path_text
            ] = sha256_file(
                kb_path
            )

        kb = kb_cache[
            kb_path_text
        ]

        current_matches = case.get(
            "current_curated_match",
            [],
        )

        if (
            not isinstance(
                current_matches,
                list,
            )
            or len(current_matches) != 1
            or not isinstance(
                current_matches[0],
                dict,
            )
        ):
            failures.append(
                f"{case_id}: expected exactly "
                "one concrete Package KB "
                "vulnerability match"
            )
            continue

        current_match = (
            current_matches[0]
        )

        trigger_status = clean_text(
            current_match.get(
                "trigger_status"
            )
        )

        if trigger_status not in {
            "not_assessed",
            "requires_review",
        }:
            failures.append(
                f"{case_id}: unexpected "
                "pending trigger_status="
                + repr(
                    trigger_status
                )
            )
            continue

        vulnerability_id = clean_text(
            current_match.get(
                "vulnerability_id"
            )
        )

        if not vulnerability_id:
            failures.append(
                f"{case_id}: matched "
                "vulnerability_id is empty"
            )
            continue

        try:
            vulnerability = (
                find_vulnerability(
                    kb,
                    vulnerability_id,
                )
            )

            candidate = build_candidate(
                kb=kb,
                protocol=protocol,
                vulnerability=vulnerability,
                case_id=case_id,
            )

            validation_errors = (
                validate_hitl_candidate(
                    schema=schema,
                    protocol=protocol,
                    candidate=candidate,
                    repo_root=repo_root,
                )
            )

        except Exception as exc:
            failures.append(
                f"{case_id}: build failed: "
                f"{type(exc).__name__}: {exc}"
            )
            continue

        if validation_errors:
            failures.append(
                f"{case_id}: validator: "
                + " | ".join(
                    validation_errors
                )
            )
            continue

        proposal = candidate[
            "proposal"
        ]

        review_gate = candidate[
            "review_gate"
        ]

        if (
            proposal[
                "proposed_status"
            ]
            != "requires_review"
        ):
            failures.append(
                f"{case_id}: proposed_status "
                "crossed trust boundary"
            )
            continue

        if (
            proposal.get(
                "candidate_rule"
            )
            is not None
        ):
            failures.append(
                f"{case_id}: candidate_rule "
                "must remain null"
            )
            continue

        if (
            review_gate[
                "status"
            ]
            != "requires_review"
            or review_gate[
                "review_required"
            ]
            is not True
            or review_gate[
                "final_truth_created"
            ]
            is not False
            or review_gate[
                "reviewer"
            ]
            is not None
            or review_gate[
                "reviewed_at"
            ]
            is not None
        ):
            failures.append(
                f"{case_id}: review gate "
                "crossed trust boundary"
            )
            continue

        candidate_rel_path = (
            args.out_dir
            / case_id
            / "candidate.json"
        ).as_posix()

        built_candidates.append(
            (
                case,
                candidate,
                kb_path_text,
                candidate_rel_path,
            )
        )

    if failures:
        print(
            "STEP7 HITL BATCH BUILD FAIL"
        )

        for index, failure in enumerate(
            failures,
            start=1,
        ):
            print(
                f"[{index}] {failure}"
            )

        raise SystemExit(1)

    if (
        len(built_candidates)
        != len(selected_cases)
    ):
        raise ValueError(
            "Internal batch count mismatch"
        )

    #
    # Phase B:
    # All candidates already passed.
    # Only now create output files.
    #
    index_rows: list[
        dict[str, Any]
    ] = []

    trust_counts = Counter()

    for batch_order, (
        case,
        candidate,
        kb_path_text,
        candidate_rel_path,
    ) in enumerate(
        built_candidates,
        start=1,
    ):
        candidate_path = (
            args.out_dir
            / candidate["case_id"]
            / "candidate.json"
        )

        write_json(
            candidate_path,
            candidate,
        )

        proposal = candidate[
            "proposal"
        ]

        review_gate = candidate[
            "review_gate"
        ]

        trust_counts[
            "candidate_rule_null"
        ] += int(
            proposal.get(
                "candidate_rule"
            )
            is None
        )

        trust_counts[
            "requires_review"
        ] += int(
            proposal[
                "proposed_status"
            ]
            == "requires_review"
        )

        trust_counts[
            "review_required_true"
        ] += int(
            review_gate[
                "review_required"
            ]
            is True
        )

        trust_counts[
            "final_truth_created_false"
        ] += int(
            review_gate[
                "final_truth_created"
            ]
            is False
        )

        index_rows.append(
            {
                "batch_order":
                    batch_order,

                "case_id":
                    candidate[
                        "case_id"
                    ],

                "package":
                    clean_text(
                        case.get(
                            "normalized_package"
                        )
                        or case.get(
                            "package"
                        )
                    ),

                "vulnerability_id":
                    candidate[
                        "vulnerability"
                    ][
                        "vulnerability_id"
                    ],

                "affected_version_scope":
                    candidate[
                        "vulnerability"
                    ][
                        "affected_version_scope"
                    ],

                "evidence_source_count":
                    len(
                        candidate[
                            "evidence_sources"
                        ]
                    ),

                "proposed_status":
                    proposal[
                        "proposed_status"
                    ],

                "candidate_rule_present":
                    isinstance(
                        proposal.get(
                            "candidate_rule"
                        ),
                        dict,
                    ),

                "review_required":
                    review_gate[
                        "review_required"
                    ],

                "final_truth_created":
                    review_gate[
                        "final_truth_created"
                    ],

                "validation_status":
                    "pass",

                "formal_kb_path":
                    kb_path_text,

                "candidate_path":
                    candidate_rel_path,
            }
        )

    summary = {
        "schema_version":
            SUMMARY_SCHEMA_VERSION,

        "builder_id":
            BATCH_BUILDER_ID,

        "inputs": {
            "case_plan":
                args.case_plan.as_posix(),

            "case_plan_sha256":
                sha256_file(
                    args.case_plan
                ),

            "schema":
                args.schema.as_posix(),

            "schema_sha256":
                sha256_file(
                    args.schema
                ),

            "protocol":
                args.protocol.as_posix(),

            "protocol_sha256":
                sha256_file(
                    args.protocol
                ),

            "selected_lane":
                args.lane,

            "package_kb_sha256":
                dict(
                    sorted(
                        kb_hashes.items()
                    )
                ),
        },

        "case_count":
            len(
                built_candidates
            ),

        "validation_pass_count":
            len(
                built_candidates
            ),

        "validation_fail_count":
            0,

        "package_counts":
            dict(
                sorted(
                    package_counts.items()
                )
            ),

        "trust_boundary_counts": {
            key:
                trust_counts[key]
            for key in [
                "candidate_rule_null",
                "requires_review",
                "review_required_true",
                "final_truth_created_false",
            ]
        },

        "boundary": {
            "eligibility_created":
                False,

            "package_kb_mutated":
                False,

            "formal_trigger_truth_created":
                False,

            "description":
                (
                    "Batch orchestration only. "
                    "Each packet reuses the "
                    "existing single-case HITL "
                    "builder and validator. "
                    "No eligibility decision or "
                    "formal Trigger truth is "
                    "created."
                ),
        },
    }

    write_json(
        args.out_dir
        / "summary.json",
        summary,
    )

    index_path = (
        args.out_dir
        / "index.csv"
    )

    with index_path.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as f:
        fieldnames = [
            "batch_order",
            "case_id",
            "package",
            "vulnerability_id",
            "affected_version_scope",
            "evidence_source_count",
            "proposed_status",
            "candidate_rule_present",
            "review_required",
            "final_truth_created",
            "validation_status",
            "formal_kb_path",
            "candidate_path",
        ]

        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames,
        )

        writer.writeheader()
        writer.writerows(
            index_rows
        )

    print(
        "STEP7 HITL BATCH BUILT"
    )

    print(
        "case_count:",
        summary[
            "case_count"
        ],
    )

    print(
        "validation_pass_count:",
        summary[
            "validation_pass_count"
        ],
    )

    print(
        "package_counts:",
        summary[
            "package_counts"
        ],
    )

    print(
        "trust_boundary_counts:",
        summary[
            "trust_boundary_counts"
        ],
    )

    print(
        "summary:",
        (
            args.out_dir
            / "summary.json"
        ),
    )

    print(
        "index:",
        index_path,
    )


if __name__ == "__main__":
    main()
