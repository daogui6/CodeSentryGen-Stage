from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator


def read_json(path: Path) -> dict[str, Any]:
    data = json.loads(
        path.read_text(encoding="utf-8")
    )

    if not isinstance(data, dict):
        raise ValueError(
            f"Expected JSON object: {path}"
        )

    return data


def validate_hitl_candidate(
    *,
    schema: dict[str, Any],
    protocol: dict[str, Any],
    candidate: dict[str, Any],
    repo_root: Path,
) -> list[str]:
    errors: list[str] = []

    validator = Draft202012Validator(schema)

    for error in sorted(
        validator.iter_errors(candidate),
        key=lambda x: list(x.path),
    ):
        location = ".".join(
            str(value)
            for value in error.path
        ) or "<root>"

        errors.append(
            f"schema:{location}: {error.message}"
        )

    if errors:
        return errors

    protocol_id = str(
        protocol.get(
            "x-protocol-id",
            "",
        )
    ).strip()

    if (
        candidate["protocol_version"]
        != protocol_id
    ):
        errors.append(
            "protocol_version does not match "
            f"protocol x-protocol-id: {protocol_id!r}"
        )

    allowed_rule_kinds = {
        str(row.get("kind", "")).strip()
        for row in protocol.get(
            "x-supported-static-rule-kinds",
            [],
        )
        if isinstance(row, dict)
        and str(row.get("kind", "")).strip()
    }

    evidence_sources = candidate[
        "evidence_sources"
    ]

    source_ids = [
        str(source["source_id"]).strip()
        for source in evidence_sources
    ]

    source_id_set = set(source_ids)

    if len(source_ids) != len(source_id_set):
        errors.append(
            "duplicate evidence source_id found"
        )

    for source in evidence_sources:
        path_text = source.get("path")

        if not path_text:
            continue

        normalized = str(
            path_text
        ).replace("\\", "/")

        path = repo_root / normalized

        if not path.exists():
            errors.append(
                "evidence source path does not exist: "
                + normalized
            )

    vulnerability = candidate[
        "vulnerability"
    ]

    vulnerability_id = str(
        vulnerability[
            "vulnerability_id"
        ]
    ).strip()

    accepted_vulnerability_ids = {
        vulnerability_id,
        *[
            str(value).strip()
            for value in vulnerability.get(
                "aliases",
                [],
            )
            if str(value).strip()
        ],
    }

    for source_ref in vulnerability.get(
        "source_refs",
        [],
    ):
        if source_ref not in source_id_set:
            errors.append(
                "vulnerability source_ref does not "
                "resolve to evidence_sources: "
                f"{source_ref!r}"
            )

    proposal = candidate[
        "proposal"
    ]

    proposed_status = str(
        proposal[
            "proposed_status"
        ]
    )

    candidate_rule = proposal.get(
        "candidate_rule"
    )

    if (
        proposed_status == "eligible"
        and not isinstance(
            candidate_rule,
            dict,
        )
    ):
        errors.append(
            "proposed_status='eligible' requires "
            "a candidate_rule"
        )

    if isinstance(
        candidate_rule,
        dict,
    ):
        rule_kind = str(
            candidate_rule[
                "kind"
            ]
        ).strip()

        if (
            rule_kind
            not in allowed_rule_kinds
        ):
            errors.append(
                "candidate_rule.kind is not "
                "allowed by eligibility protocol: "
                f"{rule_kind!r}"
            )

        rule_vulnerability_ids = {
            str(value).strip()
            for value in candidate_rule.get(
                "vulnerability_ids",
                [],
            )
        }

        if (
            vulnerability_id
            not in rule_vulnerability_ids
        ):
            errors.append(
                "candidate_rule.vulnerability_ids "
                "does not contain canonical "
                "vulnerability_id"
            )

        unknown_vulnerability_ids = (
            rule_vulnerability_ids
            - accepted_vulnerability_ids
        )

        if unknown_vulnerability_ids:
            errors.append(
                "candidate_rule contains unexpected "
                "vulnerability IDs: "
                f"{sorted(unknown_vulnerability_ids)}"
            )

        for evidence_ref in candidate_rule.get(
            "evidence_refs",
            [],
        ):
            if evidence_ref not in source_id_set:
                errors.append(
                    "candidate_rule evidence_ref does "
                    "not resolve to evidence_sources: "
                    f"{evidence_ref!r}"
                )

    claim_ids: list[str] = []

    for claim in proposal.get(
        "claim_evidence_map",
        [],
    ):
        claim_id = str(
            claim["claim_id"]
        ).strip()

        claim_ids.append(
            claim_id
        )

        for evidence_ref in claim.get(
            "evidence_refs",
            [],
        ):
            if evidence_ref not in source_id_set:
                errors.append(
                    "claim evidence_ref does not "
                    "resolve to evidence_sources: "
                    f"{claim_id!r} -> "
                    f"{evidence_ref!r}"
                )

    if len(claim_ids) != len(set(claim_ids)):
        errors.append(
            "duplicate claim_id found"
        )

    review_gate = candidate[
        "review_gate"
    ]

    if (
        review_gate["status"]
        != "requires_review"
        or review_gate[
            "review_required"
        ] is not True
        or review_gate[
            "final_truth_created"
        ] is not False
    ):
        errors.append(
            "candidate must remain behind the "
            "human-review gate"
        )

    if (
        review_gate["reviewer"]
        is not None
        or review_gate["reviewed_at"]
        is not None
    ):
        errors.append(
            "unreviewed candidate must not contain "
            "reviewer/reviewed_at values"
        )

    return errors


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Validate an AVCS Human-in-the-loop "
            "Trigger candidate artifact."
        )
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
        "--candidate",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--repo-root",
        default=".",
        type=Path,
    )

    args = parser.parse_args()

    schema = read_json(
        args.schema
    )

    protocol = read_json(
        args.protocol
    )

    candidate = read_json(
        args.candidate
    )

    Draft202012Validator.check_schema(
        schema
    )

    errors = validate_hitl_candidate(
        schema=schema,
        protocol=protocol,
        candidate=candidate,
        repo_root=args.repo_root,
    )

    if errors:
        print(
            "HITL TRIGGER CANDIDATE VALIDATION FAIL"
        )

        for index, error in enumerate(
            errors,
            start=1,
        ):
            print(
                f"[{index}] {error}"
            )

        raise SystemExit(1)

    proposal = candidate[
        "proposal"
    ]

    print(
        "HITL TRIGGER CANDIDATE VALIDATION PASS"
    )

    print(
        "case_id:",
        candidate[
            "case_id"
        ],
    )

    print(
        "distribution:",
        candidate[
            "distribution"
        ],
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
        "proposer_type:",
        proposal[
            "proposer_type"
        ],
    )

    print(
        "proposed_status:",
        proposal[
            "proposed_status"
        ],
    )

    print(
        "candidate_rule_present:",
        isinstance(
            proposal.get(
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


if __name__ == "__main__":
    main()
