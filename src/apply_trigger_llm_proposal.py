from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from validate_trigger_hitl_candidate import (
    validate_hitl_candidate,
)


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

    path.write_text(
        json.dumps(
            data,
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def validate_proposal_semantics(
    *,
    packet: dict[str, Any],
    proposal: dict[str, Any],
    protocol: dict[str, Any],
) -> list[str]:
    errors: list[str] = []

    if (
        proposal.get(
            "case_id"
        )
        != packet.get(
            "case_id"
        )
    ):
        errors.append(
            "proposal.case_id does not match packet.case_id"
        )

    evidence_sources = packet.get(
        "evidence_sources",
        [],
    )

    source_ids = {
        str(
            source.get(
                "source_id",
                "",
            )
        ).strip()

        for source in evidence_sources

        if isinstance(
            source,
            dict,
        )
    }

    source_ids.discard("")

    vulnerability = packet[
        "vulnerability"
    ]

    canonical_id = str(
        vulnerability[
            "vulnerability_id"
        ]
    ).strip()

    accepted_vulnerability_ids = {
        canonical_id,
        *[
            str(value).strip()
            for value
            in vulnerability.get(
                "aliases",
                [],
            )
            if str(value).strip()
        ],
    }

    allowed_rule_kinds = {
        str(
            row.get(
                "kind",
                "",
            )
        ).strip()

        for row in protocol.get(
            "x-supported-static-rule-kinds",
            [],
        )

        if (
            isinstance(
                row,
                dict,
            )
            and str(
                row.get(
                    "kind",
                    "",
                )
            ).strip()
        )
    }

    candidate_rule = proposal.get(
        "candidate_rule"
    )

    if (
        proposal.get(
            "proposed_status"
        )
        == "eligible"
        and not isinstance(
            candidate_rule,
            dict,
        )
    ):
        errors.append(
            "proposed_status='eligible' requires candidate_rule"
        )

    if isinstance(
        candidate_rule,
        dict,
    ):
        kind = str(
            candidate_rule.get(
                "kind",
                "",
            )
        ).strip()

        if kind not in allowed_rule_kinds:
            errors.append(
                "candidate_rule.kind is not allowed "
                f"by protocol: {kind!r}"
            )

        rule_vulnerability_ids = {
            str(value).strip()
            for value
            in candidate_rule.get(
                "vulnerability_ids",
                [],
            )
            if str(value).strip()
        }

        if canonical_id not in (
            rule_vulnerability_ids
        ):
            errors.append(
                "candidate_rule must contain canonical "
                "vulnerability_id"
            )

        unknown_ids = (
            rule_vulnerability_ids
            - accepted_vulnerability_ids
        )

        if unknown_ids:
            errors.append(
                "candidate_rule contains unknown "
                "vulnerability IDs: "
                + repr(
                    sorted(
                        unknown_ids
                    )
                )
            )

        for evidence_ref in (
            candidate_rule.get(
                "evidence_refs",
                [],
            )
        ):
            if evidence_ref not in source_ids:
                errors.append(
                    "candidate_rule cites unknown "
                    "evidence source: "
                    + repr(
                        evidence_ref
                    )
                )

    claim_ids: list[str] = []

    for claim in proposal.get(
        "claim_evidence_map",
        [],
    ):
        if not isinstance(
            claim,
            dict,
        ):
            continue

        claim_id = str(
            claim.get(
                "claim_id",
                "",
            )
        ).strip()

        claim_ids.append(
            claim_id
        )

        for evidence_ref in (
            claim.get(
                "evidence_refs",
                [],
            )
        ):
            if evidence_ref not in source_ids:
                errors.append(
                    "claim cites unknown evidence source: "
                    f"{claim_id!r} -> "
                    f"{evidence_ref!r}"
                )

    if len(
        claim_ids
    ) != len(
        set(
            claim_ids
        )
    ):
        errors.append(
            "duplicate claim_id found"
        )

    return errors


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Safely merge an LLM Trigger proposal "
            "into an AVCS HITL candidate while "
            "preserving the human-review gate."
        )
    )

    parser.add_argument(
        "--packet",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--proposal",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--proposal-schema",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--candidate-schema",
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
        default=".",
        type=Path,
    )

    parser.add_argument(
        "--out",
        required=True,
        type=Path,
    )

    args = parser.parse_args()

    packet = load_json(
        args.packet
    )

    proposal = load_json(
        args.proposal
    )

    proposal_schema = load_json(
        args.proposal_schema
    )

    candidate_schema = load_json(
        args.candidate_schema
    )

    protocol = load_json(
        args.protocol
    )

    Draft202012Validator.check_schema(
        proposal_schema
    )

    proposal_validator = (
        Draft202012Validator(
            proposal_schema
        )
    )

    schema_errors = sorted(
        proposal_validator.iter_errors(
            proposal
        ),
        key=lambda error: list(
            error.path
        ),
    )

    if schema_errors:
        print(
            "LLM PROPOSAL VALIDATION FAIL"
        )

        for index, error in enumerate(
            schema_errors,
            start=1,
        ):
            location = ".".join(
                str(value)
                for value
                in error.path
            ) or "<root>"

            print(
                f"[{index}] schema:{location}: "
                f"{error.message}"
            )

        raise SystemExit(1)

    semantic_errors = (
        validate_proposal_semantics(
            packet=packet,
            proposal=proposal,
            protocol=protocol,
        )
    )

    if semantic_errors:
        print(
            "LLM PROPOSAL VALIDATION FAIL"
        )

        for index, error in enumerate(
            semantic_errors,
            start=1,
        ):
            print(
                f"[{index}] {error}"
            )

        raise SystemExit(1)

    original_gate = copy.deepcopy(
        packet[
            "review_gate"
        ]
    )

    merged = copy.deepcopy(
        packet
    )

    merged[
        "proposal"
    ] = {
        "proposer_type":
            "llm",

        "proposer_id":
            proposal[
                "proposer_id"
            ],

        "proposed_status":
            proposal[
                "proposed_status"
            ],

        "candidate_rule":
            copy.deepcopy(
                proposal[
                    "candidate_rule"
                ]
            ),

        "claim_evidence_map":
            copy.deepcopy(
                proposal[
                    "claim_evidence_map"
                ]
            ),

        "unresolved_questions":
            copy.deepcopy(
                proposal[
                    "unresolved_questions"
                ]
            ),

        "notes":
            proposal[
                "notes"
            ],
    }

    if (
        merged[
            "review_gate"
        ]
        != original_gate
    ):
        raise RuntimeError(
            "review_gate changed during proposal merge"
        )

    errors = validate_hitl_candidate(
        schema=candidate_schema,
        protocol=protocol,
        candidate=merged,
        repo_root=args.repo_root,
    )

    if errors:
        print(
            "MERGED HITL CANDIDATE VALIDATION FAIL"
        )

        for index, error in enumerate(
            errors,
            start=1,
        ):
            print(
                f"[{index}] {error}"
            )

        raise SystemExit(1)

    write_json(
        args.out,
        merged,
    )

    print(
        "LLM PROPOSAL MERGE PASS"
    )

    print(
        "case_id:",
        merged[
            "case_id"
        ],
    )

    print(
        "proposer_id:",
        merged[
            "proposal"
        ][
            "proposer_id"
        ],
    )

    print(
        "proposed_status:",
        merged[
            "proposal"
        ][
            "proposed_status"
        ],
    )

    print(
        "candidate_rule_present:",
        isinstance(
            merged[
                "proposal"
            ][
                "candidate_rule"
            ],
            dict,
        ),
    )

    print(
        "review_required:",
        merged[
            "review_gate"
        ][
            "review_required"
        ],
    )

    print(
        "final_truth_created:",
        merged[
            "review_gate"
        ][
            "final_truth_created"
        ],
    )

    print(
        "saved:",
        args.out,
    )


if __name__ == "__main__":
    main()
