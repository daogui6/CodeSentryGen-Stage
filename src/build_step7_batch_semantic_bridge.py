from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from build_trigger_hitl_candidate import (
    build_candidate,
    find_vulnerability,
)


BRIDGE_ID = "step7_batch_semantic_bridge_v0.1"
BUNDLE_SCHEMA_VERSION = (
    "step7_batch_semantic_excerpt_bundle_v0.1"
)

GLOBAL_TEXT_BUDGET = 24000
MAX_PER_SOURCE_CHARS = 6000

EXCLUDED_UNIT_KINDS = {
    "structured_json_record",
}


def load_json(
    path: Path,
) -> dict[str, Any]:
    data = json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )

    if not isinstance(
        data,
        dict,
    ):
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

    if path.exists():
        raise FileExistsError(
            f"Refusing to overwrite: {path}"
        )

    with path.open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as handle:
        json.dump(
            data,
            handle,
            ensure_ascii=False,
            indent=2,
        )
        handle.write("\n")


def sha256_file(
    path: Path,
) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as handle:
        for chunk in iter(
            lambda: handle.read(
                1024 * 1024
            ),
            b"",
        ):
            digest.update(chunk)

    return digest.hexdigest()


def sha256_text(
    value: str,
) -> str:
    return hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


def normalize_sha(
    value: Any,
) -> str:
    text = str(
        value
        if value is not None
        else ""
    ).strip()

    if text.startswith("sha256:"):
        return text[len("sha256:"):]

    return text


def clean(
    value: Any,
) -> str:
    return str(
        value
        if value is not None
        else ""
    ).strip()


def project_path(
    path: Path,
    repo_root: Path,
) -> str:
    root = repo_root.resolve()
    resolved = path.resolve()

    try:
        return (
            resolved
            .relative_to(root)
            .as_posix()
        )
    except ValueError:
        return path.as_posix()


def verify_sha(
    *,
    path: Path,
    expected: Any,
    label: str,
) -> str:
    actual = sha256_file(path)
    wanted = normalize_sha(expected)

    if not wanted:
        raise ValueError(
            f"{label}: expected SHA is empty"
        )

    if actual != wanted:
        raise ValueError(
            f"{label}: SHA mismatch: "
            f"expected={wanted}, "
            f"actual={actual}, "
            f"path={path}"
        )

    return actual


def unique_strings(
    values: Any,
) -> list[str]:
    if not isinstance(
        values,
        list,
    ):
        return []

    result: list[str] = []

    for value in values:
        text = clean(value)

        if (
            text
            and text not in result
        ):
            result.append(text)

    return result


def find_plan_row(
    plan: dict[str, Any],
    case_id: str,
) -> dict[str, Any]:
    matches = [
        row
        for row in plan.get(
            "cases",
            [],
        )
        if (
            isinstance(row, dict)
            and clean(
                row.get("case_id")
            )
            == case_id
        )
    ]

    if len(matches) != 1:
        raise ValueError(
            f"{case_id}: expected exactly "
            f"one plan row, got "
            f"{len(matches)}"
        )

    return matches[0]


def verify_packet_boundary(
    *,
    case_id: str,
    packet: dict[str, Any],
) -> None:
    if (
        clean(
            packet.get(
                "evidence_status"
            )
        )
        != "structured_complete"
    ):
        raise ValueError(
            f"{case_id}: review packet is "
            "not structured_complete"
        )

    if packet.get(
        "unresolved_acquisitions",
        []
    ):
        raise ValueError(
            f"{case_id}: review packet still "
            "contains unresolved acquisitions"
        )

    boundary = packet.get(
        "semantic_boundary",
        {},
    )

    if not isinstance(
        boundary,
        dict,
    ):
        raise ValueError(
            f"{case_id}: missing semantic boundary"
        )

    required_false = [
        "trigger_truth_created",
        "candidate_rule_created",
        "human_review_created",
        "eligibility_created",
        "package_kb_mutated",
    ]

    for key in required_false:
        if boundary.get(key) is not False:
            raise ValueError(
                f"{case_id}: packet boundary "
                f"{key!r} is not explicitly false"
            )


def verify_unit_text(
    *,
    case_id: str,
    unit: dict[str, Any],
) -> None:
    raw_text = unit.get(
        "text"
    )

    if not isinstance(
        raw_text,
        str,
    ):
        raise ValueError(
            f"{case_id}: selected unit "
            "text is not a string for "
            f"{unit.get('unit_id')!r}"
        )

    # strip() is ONLY an emptiness test.
    # The evidence bytes/text themselves must not
    # be rewritten before size/hash verification.
    if not raw_text.strip():
        raise ValueError(
            f"{case_id}: selected unit "
            "contains empty/whitespace-only text"
        )

    stored_size = unit.get(
        "size_chars"
    )

    if stored_size is not None:
        try:
            stored_size_int = int(
                stored_size
            )
        except (
            TypeError,
            ValueError,
        ) as exc:
            raise ValueError(
                f"{case_id}: invalid size_chars "
                f"for {unit.get('unit_id')!r}: "
                f"{stored_size!r}"
            ) from exc

        if (
            len(raw_text)
            != stored_size_int
        ):
            raise ValueError(
                f"{case_id}: evidence unit "
                "size mismatch for "
                f"{unit.get('unit_id')!r}: "
                f"stored={stored_size_int}, "
                f"actual={len(raw_text)}"
            )

    expected = normalize_sha(
        unit.get(
            "text_sha256"
        )
    )

    if expected:
        actual = sha256_text(
            raw_text
        )

        if actual != expected:
            raise ValueError(
                f"{case_id}: evidence unit "
                "raw-text SHA mismatch for "
                f"{unit.get('unit_id')!r}: "
                f"expected={expected}, "
                f"actual={actual}"
            )


def build_excerpt_bundle(
    *,
    case_id: str,
    row: dict[str, Any],
    packet: dict[str, Any],
    plan_path: Path,
    plan_sha: str,
    closure_path: Path,
    closure_sha: str,
    packet_path: Path,
    packet_sha: str,
    kb_path: Path,
    kb_sha: str,
    batch_label: str,
) -> tuple[
    dict[str, Any],
    str,
]:
    entries = packet.get(
        "evidence_entries",
        [],
    )

    if (
        not isinstance(entries, list)
        or not entries
    ):
        raise ValueError(
            f"{case_id}: no evidence entries"
        )

    if (
        len(entries)
        != int(
            row[
                "evidence_source_count"
            ]
        )
    ):
        raise ValueError(
            f"{case_id}: evidence source "
            "count differs from queue plan"
        )

    eligible_by_source: list[
        tuple[
            dict[str, Any],
            list[dict[str, Any]],
        ]
    ] = []

    total_excerptable = 0
    excluded_structured = 0

    seen_original_source_ids: set[
        str
    ] = set()

    for entry in entries:
        if not isinstance(
            entry,
            dict,
        ):
            raise ValueError(
                f"{case_id}: non-object "
                "evidence entry"
            )

        original_source_id = clean(
            entry.get("source_id")
        )

        if not original_source_id:
            raise ValueError(
                f"{case_id}: evidence entry "
                "has empty source_id"
            )

        if (
            original_source_id
            in seen_original_source_ids
        ):
            raise ValueError(
                f"{case_id}: duplicate "
                "review-packet source_id: "
                f"{original_source_id}"
            )

        seen_original_source_ids.add(
            original_source_id
        )

        units = entry.get(
            "evidence_units",
            [],
        )

        if not isinstance(
            units,
            list,
        ):
            raise ValueError(
                f"{case_id}: evidence_units "
                "must be a list"
            )

        eligible: list[
            dict[str, Any]
        ] = []

        for unit in units:
            if not isinstance(
                unit,
                dict,
            ):
                continue

            kind = clean(
                unit.get("unit_kind")
            )

            if (
                kind
                in EXCLUDED_UNIT_KINDS
            ):
                excluded_structured += 1
                continue

            raw_unit_text = unit.get(
                "text"
            )

            if (
                not isinstance(
                    raw_unit_text,
                    str,
                )
                or not raw_unit_text.strip()
            ):
                continue

            verify_unit_text(
                case_id=case_id,
                unit=unit,
            )

            eligible.append(unit)

        # A review-packet source may legitimately
        # contain only structured_json_record units.
        # Those units are intentionally excluded from
        # LLM excerpts. Such a source is therefore
        # omitted from semantic excerpt selection,
        # not interpreted as evidence failure.
        if not eligible:
            continue

        total_excerptable += len(
            eligible
        )

        eligible_by_source.append(
            (
                entry,
                eligible,
            )
        )

    if (
        total_excerptable
        != int(
            row[
                "excerptable_unit_count"
            ]
        )
    ):
        raise ValueError(
            f"{case_id}: excerptable unit "
            "count differs from queue plan"
        )

    if (
        excluded_structured
        != int(
            row[
                "excluded_structured_json_record_count"
            ]
        )
    ):
        raise ValueError(
            f"{case_id}: structured_json_record "
            "exclusion count differs from queue plan"
        )

    if (
        len(eligible_by_source)
        != int(
            row[
                "sources_with_excerpt"
            ]
        )
    ):
        raise ValueError(
            f"{case_id}: sources_with_excerpt "
            "differs from queue plan"
        )

    source_count = len(
        eligible_by_source
    )

    source_budget = min(
        MAX_PER_SOURCE_CHARS,
        max(
            1,
            GLOBAL_TEXT_BUDGET
            // source_count,
        ),
    )

    selected_sources: list[
        dict[str, Any]
    ] = []

    total_selected_units = 0
    total_selected_chars = 0

    for (
        entry,
        eligible_units,
    ) in eligible_by_source:
        remaining = source_budget

        selected_units: list[
            dict[str, Any]
        ] = []

        for unit in eligible_units:
            if remaining <= 0:
                break

            text = unit.get(
                "text"
            )

            if (
                not isinstance(
                    text,
                    str,
                )
                or not text.strip()
            ):
                continue

            take = min(
                len(text),
                remaining,
            )

            excerpt = text[:take]

            if not excerpt:
                continue

            selected_units.append(
                {
                    "unit_id":
                        clean(
                            unit.get(
                                "unit_id"
                            )
                        ),

                    "unit_kind":
                        clean(
                            unit.get(
                                "unit_kind"
                            )
                        ),

                    "text_sha256":
                        unit.get(
                            "text_sha256"
                        ),

                    "original_size_chars":
                        len(text),

                    "selected_size_chars":
                        len(excerpt),

                    "truncated":
                        len(excerpt)
                        < len(text),

                    "locator":
                        copy.deepcopy(
                            unit.get(
                                "locator"
                            )
                        ),

                    "excerpt_sha256":
                        "sha256:"
                        + sha256_text(
                            excerpt
                        ),

                    "excerpt":
                        excerpt,
                }
            )

            remaining -= len(
                excerpt
            )

            total_selected_chars += len(
                excerpt
            )

        if not selected_units:
            raise ValueError(
                f"{case_id}: source lost all "
                "units during bounded selection"
            )

        total_selected_units += len(
            selected_units
        )

        selected_sources.append(
            {
                "original_source_id":
                    clean(
                        entry.get(
                            "source_id"
                        )
                    ),

                "original_source_type":
                    clean(
                        entry.get(
                            "source_type"
                        )
                    ),

                "source_key":
                    entry.get(
                        "source_key"
                    ),

                "target":
                    copy.deepcopy(
                        entry.get(
                            "target"
                        )
                    ),

                "provenance":
                    copy.deepcopy(
                        entry.get(
                            "provenance"
                        )
                    ),

                "selected_units":
                    selected_units,
            }
        )

    if (
        total_selected_chars
        > GLOBAL_TEXT_BUDGET
    ):
        raise ValueError(
            f"{case_id}: global excerpt "
            "budget exceeded"
        )

    claim_parts = [
        (
            f"{batch_label} bounded Trigger-semantic "
            "evidence excerpts. These excerpts are "
            "evidence for review only; they do not "
            "constitute Trigger truth, exploit proof, "
            "or a human review decision."
        )
    ]

    for source in selected_sources:
        claim_parts.append(
            (
                "\n=== original_source_id="
                + source[
                    "original_source_id"
                ]
                + " | original_source_type="
                + source[
                    "original_source_type"
                ]
                + " ==="
            )
        )

        for unit in source[
            "selected_units"
        ]:
            claim_parts.append(
                (
                    "\n[unit_id="
                    + unit[
                        "unit_id"
                    ]
                    + "; unit_kind="
                    + unit[
                        "unit_kind"
                    ]
                    + "; text_sha256="
                    + clean(
                        unit[
                            "text_sha256"
                        ]
                    )
                    + "; truncated="
                    + str(
                        unit[
                            "truncated"
                        ]
                    ).lower()
                    + "]\n"
                    + unit[
                        "excerpt"
                    ]
                )
            )

    claim = "\n".join(
        claim_parts
    )

    bundle = {
        "schema_version":
            BUNDLE_SCHEMA_VERSION,

        "builder_id":
            BRIDGE_ID,

        "case_id":
            case_id,

        "distribution":
            row[
                "distribution"
            ],

        "vulnerability_id":
            row[
                "canonical_vulnerability_id"
            ],

        "effective_packet_source":
            row[
                "effective_packet_source"
            ],

        "input_refs": {
            "semantic_queue_plan": {
                "path":
                    plan_path.as_posix(),
                "sha256":
                    plan_sha,
            },

            "evidence_closure": {
                "path":
                    closure_path.as_posix(),
                "sha256":
                    closure_sha,
            },

            "review_packet": {
                "path":
                    packet_path.as_posix(),
                "sha256":
                    packet_sha,
            },

            "package_kb": {
                "path":
                    kb_path.as_posix(),
                "sha256":
                    kb_sha,
            },
        },

        "selection_policy": {
            "selection_order":
                (
                    "review_packet.evidence_entries "
                    "order, then evidence_units order"
                ),

            "semantic_ranking_used":
                False,

            "keyword_ranking_used":
                False,

            "excluded_unit_kinds":
                sorted(
                    EXCLUDED_UNIT_KINDS
                ),

            "global_text_budget_chars":
                GLOBAL_TEXT_BUDGET,

            "per_source_budget_chars":
                source_budget,

            "source_balanced":
                True,

            "truncation":
                "prefix_within_source_budget",
        },

        "sources":
            selected_sources,

        "summary": {
            "review_packet_source_count":
                len(entries),

            "selected_source_count":
                len(
                    selected_sources
                ),

            "excerptable_unit_count":
                total_excerptable,

            "selected_unit_count":
                total_selected_units,

            "excluded_structured_json_record_count":
                excluded_structured,

            "selected_text_chars":
                total_selected_chars,

            "claim_chars":
                len(claim),
        },

        "semantic_boundary": {
            "evidence_only":
                True,

            "selection_is_semantic_judgment":
                False,

            "excerpt_is_ground_truth":
                False,

            "trigger_truth_created":
                False,

            "llm_proposal_created":
                False,

            "human_review_created":
                False,

            "eligibility_created":
                False,

            "package_kb_mutated":
                False,
        },
    }

    return bundle, claim


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Bridge batch review packets into "
            "the frozen HITL candidate protocol "
            "without creating Trigger truth."
        )
    )

    parser.add_argument(
        "--repo-root",
        default=".",
        type=Path,
    )

    parser.add_argument(
        "--plan",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--protocol",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--case-id",
        action="append",
        dest="case_ids",
    )

    parser.add_argument(
        "--out-dir",
        required=True,
        type=Path,
    )

    args = parser.parse_args()

    repo_root = (
        args.repo_root.resolve()
    )

    plan_path = (
        repo_root
        / args.plan
    ).resolve()

    protocol_path = (
        repo_root
        / args.protocol
    ).resolve()

    out_dir = (
        repo_root
        / args.out_dir
    ).resolve()

    if out_dir.exists():
        raise FileExistsError(
            "Refusing to overwrite output dir: "
            + str(out_dir)
        )

    plan = load_json(
        plan_path
    )

    batch_id = clean(
        plan.get(
            "batch_id"
        )
    )

    if not batch_id:
        raise ValueError(
            "Semantic queue plan has no batch_id"
        )

    batch_label = (
        batch_id
        .replace("_", "")
        .capitalize()
    )

    protocol = load_json(
        protocol_path
    )

    plan_sha = sha256_file(
        plan_path
    )

    if (
        clean(
            plan.get(
                "schema_version"
            )
        )
        != "step7_batch_semantic_queue_plan_v0.1"
    ):
        raise ValueError(
            "Unexpected semantic queue "
            "plan schema"
        )

    boundary = plan.get(
        "semantic_boundary",
        {},
    )

    required_true = [
        (
            "review_packet_is_evidence_partition_not_human_review"
        ),
        (
            "package_kb_supplies_vulnerability_identity_and_version_scope"
        ),
        (
            "review_packet_supplies_trigger_semantic_evidence"
        ),
        (
            "structured_json_record_excluded_from_llm_excerpt_candidates"
        ),
        "llm_proposal_is_not_ground_truth",
        "human_review_required",
    ]

    for key in required_true:
        if boundary.get(key) is not True:
            raise ValueError(
                "Queue plan semantic boundary "
                f"{key!r} is not true"
            )

    if (
        boundary.get(
            "eligibility_created"
        )
        is not False
        or boundary.get(
            "package_kb_mutated"
        )
        is not False
    ):
        raise ValueError(
            "Queue plan is beyond the "
            "allowed pre-review boundary"
        )

    closure_rel = Path(
        plan[
            "source_closure_path"
        ]
    )

    closure_path = (
        repo_root
        / closure_rel
    ).resolve()

    closure_sha = verify_sha(
        path=closure_path,
        expected=plan[
            "source_closure_sha256"
        ],
        label=f"{batch_label} closure",
    )

    closure = load_json(
        closure_path
    )

    effective = closure.get(
        "effective_result",
        {},
    )

    try:
        expected_case_count = int(
            plan["case_count"]
        )
    except (
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        raise ValueError(
            "Semantic queue plan has invalid "
            "case_count"
        ) from exc

    if expected_case_count <= 0:
        raise ValueError(
            "Semantic queue plan case_count "
            "must be positive"
        )

    if (
        effective.get("case_count")
        != expected_case_count
        or effective.get("ready_count")
        != expected_case_count
        or effective.get("blocked_count") != 0
        or effective.get(
            "repair_required_count"
        ) != 0
    ):
        raise ValueError(
            f"{batch_label} evidence closure is "
            f"not {expected_case_count}/"
            f"{expected_case_count} ready"
        )

    plan_rows = [
        row
        for row in plan.get(
            "cases",
            [],
        )
        if isinstance(
            row,
            dict,
        )
    ]

    if len(plan_rows) != int(
        plan.get(
            "case_count",
            -1,
        )
    ):
        raise ValueError(
            "Queue plan case count mismatch"
        )

    requested_case_ids = (
        args.case_ids
        if args.case_ids
        else [
            clean(
                row.get(
                    "case_id"
                )
            )
            for row in plan_rows
        ]
    )

    if (
        len(requested_case_ids)
        != len(
            set(
                requested_case_ids
            )
        )
    ):
        raise ValueError(
            "Duplicate --case-id values"
        )

    selected_rows = [
        find_plan_row(
            plan,
            case_id,
        )
        for case_id
        in requested_case_ids
    ]

    out_dir.mkdir(
        parents=True,
        exist_ok=False,
    )

    summary_rows: list[
        dict[str, Any]
    ] = []

    for row in selected_rows:
        case_id = clean(
            row["case_id"]
        )

        packet_rel = Path(
            row[
                "review_packet_path"
            ]
        )

        kb_rel = Path(
            row[
                "package_kb_path"
            ]
        )

        packet_path = (
            repo_root
            / packet_rel
        ).resolve()

        kb_path = (
            repo_root
            / kb_rel
        ).resolve()

        packet_sha = verify_sha(
            path=packet_path,
            expected=row[
                "review_packet_sha256"
            ],
            label=(
                case_id
                + " review packet"
            ),
        )

        kb_sha = verify_sha(
            path=kb_path,
            expected=row[
                "package_kb_sha256"
            ],
            label=(
                case_id
                + " Package KB"
            ),
        )

        packet = load_json(
            packet_path
        )

        kb = load_json(
            kb_path
        )

        if (
            clean(
                packet.get(
                    "case_id"
                )
            )
            != case_id
        ):
            raise ValueError(
                f"{case_id}: packet "
                "case_id mismatch"
            )

        if (
            clean(
                packet.get(
                    "distribution"
                )
            )
            != clean(
                row[
                    "distribution"
                ]
            )
        ):
            raise ValueError(
                f"{case_id}: packet "
                "distribution mismatch"
            )

        verify_packet_boundary(
            case_id=case_id,
            packet=packet,
        )

        requested_vulnerability = clean(
            row[
                "canonical_vulnerability_id"
            ]
        )

        vulnerability = (
            find_vulnerability(
                kb,
                requested_vulnerability,
            )
        )

        actual_semantic_state = clean(
            vulnerability.get(
                "trigger_assessment",
                {},
            ).get(
                "status"
            )
        )

        # Formal Package KB is authoritative for
        # Trigger-assessment state. Batch001 contains
        # pending HITL cases only, so an already
        # assessed vulnerability must stop the bridge.
        if actual_semantic_state != "not_assessed":
            raise ValueError(
                f"{case_id}: formal Package KB "
                "trigger_assessment.status must be "
                f"'not_assessed'; got "
                f"{actual_semantic_state!r}"
            )

        base_candidate = build_candidate(
            kb=kb,
            protocol=protocol,
            vulnerability=vulnerability,
            case_id=case_id,
        )

        if (
            base_candidate[
                "vulnerability"
            ][
                "vulnerability_id"
            ]
            != requested_vulnerability
        ):
            raise ValueError(
                f"{case_id}: canonical "
                "vulnerability mismatch"
            )

        if (
            base_candidate[
                "vulnerability"
            ][
                "affected_version_scope"
            ]
            != row[
                "affected_version_scope"
            ]
        ):
            raise ValueError(
                f"{case_id}: affected "
                "version scope drift"
            )

        if set(
            base_candidate[
                "vulnerability"
            ][
                "fixed_versions"
            ]
        ) != set(
            unique_strings(
                row.get(
                    "fixed_versions",
                    [],
                )
            )
        ):
            raise ValueError(
                f"{case_id}: fixed "
                "versions drift"
            )

        if set(
            base_candidate[
                "vulnerability"
            ][
                "aliases"
            ]
        ) != set(
            unique_strings(
                row.get(
                    "aliases",
                    [],
                )
            )
        ):
            raise ValueError(
                f"{case_id}: aliases drift"
            )

        packet_ids = {
            clean(value).lower()
            for value
            in packet.get(
                "vulnerability_ids",
                [],
            )
            if clean(value)
        }

        candidate_ids = {
            requested_vulnerability.lower(),
            *[
                value.lower()
                for value
                in base_candidate[
                    "vulnerability"
                ][
                    "aliases"
                ]
            ],
        }

        display_id = clean(
            row.get(
                "display_id"
            )
        ).lower()

        if (
            display_id
            and (
                display_id
                not in packet_ids
                or display_id
                not in candidate_ids
            )
        ):
            raise ValueError(
                f"{case_id}: display ID "
                "does not bind packet and KB"
            )

        case_dir = (
            out_dir
            / case_id
        )

        case_dir.mkdir(
            parents=True,
            exist_ok=False,
        )

        bundle_path = (
            case_dir
            / "semantic_excerpt_bundle.json"
        )

        candidate_path = (
            case_dir
            / "candidate.json"
        )

        bundle, claim = (
            build_excerpt_bundle(
                case_id=case_id,
                row=row,
                packet=packet,
                plan_path=Path(
                    project_path(
                        plan_path,
                        repo_root,
                    )
                ),
                plan_sha=plan_sha,
                closure_path=Path(
                    project_path(
                        closure_path,
                        repo_root,
                    )
                ),
                closure_sha=closure_sha,
                packet_path=Path(
                    project_path(
                        packet_path,
                        repo_root,
                    )
                ),
                packet_sha=packet_sha,
                kb_path=Path(
                    project_path(
                        kb_path,
                        repo_root,
                    )
                ),
                kb_sha=kb_sha,
                batch_label=batch_label,
            )
        )

        write_json(
            bundle_path,
            bundle,
        )

        bundle_rel = project_path(
            bundle_path,
            repo_root,
        )

        bundle_sha = sha256_file(
            bundle_path
        )

        semantic_source_dir = (
            case_dir
            / "semantic_sources"
        )

        semantic_source_dir.mkdir(
            parents=True,
            exist_ok=False,
        )

        semantic_sources: list[
            dict[str, Any]
        ] = []

        for (
            source_index,
            selected_source,
        ) in enumerate(
            bundle["sources"],
            start=1,
        ):
            original_source_id = clean(
                selected_source[
                    "original_source_id"
                ]
            )

            original_source_type = clean(
                selected_source[
                    "original_source_type"
                ]
            )

            selected_units = (
                selected_source[
                    "selected_units"
                ]
            )

            if not selected_units:
                raise ValueError(
                    f"{case_id}: semantic source "
                    f"{original_source_id!r} "
                    "contains no selected units"
                )

            source_artifact_path = (
                semantic_source_dir
                / (
                    "source_"
                    + f"{source_index:03d}"
                    + ".json"
                )
            )

            claim_parts = [
                (
                    f"{batch_label} bounded Trigger-semantic "
                    "evidence from one review-packet "
                    "source. Evidence only: this does "
                    "not establish Trigger truth, "
                    "exploitability, eligibility, or "
                    "Human Review."
                ),
                (
                    "original_source_id="
                    + original_source_id
                    + "; original_source_type="
                    + original_source_type
                ),
            ]

            for unit in selected_units:
                claim_parts.append(
                    (
                        "[unit_id="
                        + clean(
                            unit[
                                "unit_id"
                            ]
                        )
                        + "; unit_kind="
                        + clean(
                            unit[
                                "unit_kind"
                            ]
                        )
                        + "; text_sha256="
                        + clean(
                            unit[
                                "text_sha256"
                            ]
                        )
                        + "; truncated="
                        + str(
                            unit[
                                "truncated"
                            ]
                        ).lower()
                        + "]\n"
                        + unit[
                            "excerpt"
                        ]
                    )
                )

            source_claim = "\n\n".join(
                claim_parts
            )

            source_artifact = {
                "schema_version":
                    (
                        "step7_batch_semantic_"
                        "source_excerpt_v0.1"
                    ),

                "builder_id":
                    BRIDGE_ID,

                "case_id":
                    case_id,

                "distribution":
                    row[
                        "distribution"
                    ],

                "vulnerability_id":
                    requested_vulnerability,

                "effective_packet_source":
                    row[
                        "effective_packet_source"
                    ],

                "original_source_id":
                    original_source_id,

                "original_source_type":
                    original_source_type,

                "source_key":
                    copy.deepcopy(
                        selected_source.get(
                            "source_key"
                        )
                    ),

                "target":
                    copy.deepcopy(
                        selected_source.get(
                            "target"
                        )
                    ),

                "provenance":
                    copy.deepcopy(
                        selected_source.get(
                            "provenance"
                        )
                    ),

                "selected_units":
                    copy.deepcopy(
                        selected_units
                    ),

                "input_refs": {
                    "semantic_excerpt_bundle": {
                        "path":
                            bundle_rel,

                        "sha256":
                            bundle_sha,
                    },

                    "review_packet": {
                        "path":
                            project_path(
                                packet_path,
                                repo_root,
                            ),

                        "sha256":
                            packet_sha,
                    },
                },

                "semantic_boundary": {
                    "evidence_only":
                        True,

                    "source_partition_preserved":
                        True,

                    "excerpt_is_ground_truth":
                        False,

                    "trigger_truth_created":
                        False,

                    "llm_proposal_created":
                        False,

                    "human_review_created":
                        False,

                    "eligibility_created":
                        False,

                    "package_kb_mutated":
                        False,
                },
            }

            write_json(
                source_artifact_path,
                source_artifact,
            )

            source_rel = project_path(
                source_artifact_path,
                repo_root,
            )

            semantic_sources.append(
                {
                    "source_id":
                        source_rel,

                    "source_type":
                        (
                            "step7_review_packet_"
                            "semantic_source_excerpt"
                        ),

                    "url":
                        None,

                    "path":
                        source_rel,

                    "locator":
                        (
                            "original_source_id="
                            + original_source_id
                            + "; selected_unit_count="
                            + str(
                                len(
                                    selected_units
                                )
                            )
                            + "; manifest="
                            + bundle_rel
                        ),

                    "claim":
                        source_claim,
                }
            )

        expected_semantic_source_count = (
            bundle[
                "summary"
            ][
                "selected_source_count"
            ]
        )

        if (
            len(
                semantic_sources
            )
            != expected_semantic_source_count
        ):
            raise ValueError(
                f"{case_id}: semantic source "
                "partition count mismatch"
            )

        candidate = copy.deepcopy(
            base_candidate
        )

        existing_ids = {
            clean(
                source.get(
                    "source_id"
                )
            )
            for source
            in candidate[
                "evidence_sources"
            ]
            if isinstance(
                source,
                dict,
            )
        }

        semantic_ids = [
            clean(
                source[
                    "source_id"
                ]
            )
            for source
            in semantic_sources
        ]

        if (
            len(
                semantic_ids
            )
            != len(
                set(
                    semantic_ids
                )
            )
        ):
            raise ValueError(
                f"{case_id}: duplicate semantic "
                "candidate source_id"
            )

        collisions = (
            set(
                semantic_ids
            )
            & existing_ids
        )

        if collisions:
            raise ValueError(
                f"{case_id}: semantic evidence "
                "source_id collides with Package KB "
                "source: "
                + repr(
                    sorted(
                        collisions
                    )
                )
            )

        candidate[
            "evidence_sources"
        ].extend(
            semantic_sources
        )

        candidate[
            "proposal"
        ][
            "proposer_id"
        ] = BRIDGE_ID

        candidate[
            "proposal"
        ][
            "notes"
        ] = (
            "Base vulnerability identity and "
            "affected-version evidence were "
            "assembled from the formal Package KB. "
            f"A bounded {batch_label} review-packet "
            "semantic excerpt bundle was appended "
            "as review evidence only. No Trigger "
            "classification, candidate rule, human "
            "review, or ground truth was created."
        )

        if (
            candidate[
                "proposal"
            ][
                "proposed_status"
            ]
            != "requires_review"
            or candidate[
                "proposal"
            ][
                "candidate_rule"
            ]
            is not None
        ):
            raise ValueError(
                f"{case_id}: bridge crossed "
                "the proposal boundary"
            )

        gate = candidate[
            "review_gate"
        ]

        if not (
            gate[
                "status"
            ]
            == "requires_review"
            and gate[
                "review_required"
            ]
            is True
            and gate[
                "final_truth_created"
            ]
            is False
            and gate[
                "reviewer"
            ]
            is None
            and gate[
                "reviewed_at"
            ]
            is None
        ):
            raise ValueError(
                f"{case_id}: review gate changed"
            )

        write_json(
            candidate_path,
            candidate,
        )

        summary_rows.append(
            {
                "case_id":
                    case_id,

                "distribution":
                    row[
                        "distribution"
                    ],

                "vulnerability_id":
                    requested_vulnerability,

                "effective_packet_source":
                    row[
                        "effective_packet_source"
                    ],

                "review_packet_path":
                    project_path(
                        packet_path,
                        repo_root,
                    ),

                "review_packet_sha256":
                    packet_sha,

                "package_kb_path":
                    project_path(
                        kb_path,
                        repo_root,
                    ),

                "package_kb_sha256":
                    kb_sha,

                "semantic_excerpt_bundle_path":
                    bundle_rel,

                "semantic_excerpt_bundle_sha256":
                    sha256_file(
                        bundle_path
                    ),

                "candidate_path":
                    project_path(
                        candidate_path,
                        repo_root,
                    ),

                "candidate_sha256":
                    sha256_file(
                        candidate_path
                    ),

                "package_kb_evidence_source_count":
                    len(
                        base_candidate[
                            "evidence_sources"
                        ]
                    ),

                "semantic_candidate_source_count":
                    len(
                        semantic_sources
                    ),

                "semantic_source_artifact_paths":
                    [
                        source[
                            "path"
                        ]
                        for source
                        in semantic_sources
                    ],

                "candidate_evidence_source_count":
                    len(
                        candidate[
                            "evidence_sources"
                        ]
                    ),

                "selected_semantic_source_count":
                    bundle[
                        "summary"
                    ][
                        "selected_source_count"
                    ],

                "selected_semantic_unit_count":
                    bundle[
                        "summary"
                    ][
                        "selected_unit_count"
                    ],

                "selected_semantic_text_chars":
                    bundle[
                        "summary"
                    ][
                        "selected_text_chars"
                    ],
            }
        )

        print(
            "BRIDGE CASE BUILT:",
            case_id,
        )

        print(
            "  packet_source:",
            row[
                "effective_packet_source"
            ],
        )

        print(
            "  base_kb_sources:",
            len(
                base_candidate[
                    "evidence_sources"
                ]
            ),
        )

        print(
            "  semantic_sources:",
            bundle[
                "summary"
            ][
                "selected_source_count"
            ],
        )

        print(
            "  semantic_units:",
            bundle[
                "summary"
            ][
                "selected_unit_count"
            ],
        )

        print(
            "  semantic_text_chars:",
            bundle[
                "summary"
            ][
                "selected_text_chars"
            ],
        )

    summary = {
        "schema_version":
            "step7_batch_semantic_bridge_summary_v0.1",

        "builder_id":
            BRIDGE_ID,

        "source_plan": {
            "path":
                project_path(
                    plan_path,
                    repo_root,
                ),

            "sha256":
                plan_sha,
        },

        "case_count":
            len(
                summary_rows
            ),

        "cases":
            summary_rows,

        "semantic_boundary": {
            "package_kb_supplies_identity_and_version":
                True,

            "review_packet_supplies_trigger_semantic_evidence":
                True,

            "semantic_excerpt_is_ground_truth":
                False,

            "llm_proposal_created":
                False,

            "human_review_created":
                False,

            "eligibility_created":
                False,

            "package_kb_mutated":
                False,
        },
    }

    summary_path = (
        out_dir
        / "summary.json"
    )

    write_json(
        summary_path,
        summary,
    )

    print()
    print(
        "STEP7 BATCH SEMANTIC BRIDGE PASS"
    )

    print(
        "case_count:",
        len(
            summary_rows
        ),
    )

    print(
        "summary:",
        project_path(
            summary_path,
            repo_root,
        ),
    )

    print(
        "llm_proposal_created:",
        False,
    )

    print(
        "human_review_created:",
        False,
    )

    print(
        "eligibility_created:",
        False,
    )

    print(
        "package_kb_mutated:",
        False,
    )


if __name__ == "__main__":
    main()
