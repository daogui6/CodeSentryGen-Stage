import argparse
import json
from pathlib import Path

from jsonschema import Draft202012Validator


FINAL_REVIEWED_STATUSES = {
    "eligible",
    "unsupported_complex",
    "insufficient_evidence",
    "conflicted",
}


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def validate_semantics(protocol: dict, assessment: dict) -> list[str]:
    errors = []

    status = assessment["status"]
    checks = assessment["eligibility_checks"]

    matched_kinds = assessment["matched_supported_rule_kinds"]
    rule_refs = assessment["rule_refs"]
    evidence_refs = assessment["evidence_refs"]
    unsupported_reasons = assessment["unsupported_reasons"]

    review_required = assessment["review_required"]
    review_status = assessment["review"]["status"]

    coverage = assessment["trigger_coverage"]
    coverage_status = coverage["coverage_status"]
    affected_scope = coverage["affected_version_scope"]
    assessed_scope = coverage["assessed_trigger_version_scope"]
    uncovered_note = coverage["uncovered_scope_note"]

    supported_kinds = {
        item["kind"]
        for item in protocol.get(
            "x-supported-static-rule-kinds",
            [],
        )
        if isinstance(item, dict) and item.get("kind")
    }

    #
    # 1. Supported rule kinds
    #
    for kind in matched_kinds:
        if kind not in supported_kinds:
            errors.append(
                f"matched_supported_rule_kind={kind!r} "
                "is not declared by "
                "x-supported-static-rule-kinds"
            )

    #
    # 2. Final classifications require completed review
    #
    if status in FINAL_REVIEWED_STATUSES:
        if review_required:
            errors.append(
                f"status={status!r} is a final reviewed "
                "classification, so review_required "
                "must be false"
            )

        if review_status != "approved":
            errors.append(
                f"status={status!r} requires "
                "review.status='approved', "
                f"got {review_status!r}"
            )

    #
    # 3. Trigger coverage consistency
    #
    if coverage_status == "full":
        if affected_scope is None:
            errors.append(
                "full Trigger coverage requires "
                "affected_version_scope"
            )

        if assessed_scope is None:
            errors.append(
                "full Trigger coverage requires "
                "assessed_trigger_version_scope"
            )

        if (
            affected_scope is not None
            and assessed_scope is not None
            and affected_scope != assessed_scope
        ):
            errors.append(
                "full Trigger coverage requires "
                "affected_version_scope and "
                "assessed_trigger_version_scope "
                "to be identical"
            )

        if uncovered_note is not None:
            errors.append(
                "full Trigger coverage requires "
                "uncovered_scope_note=null"
            )

    elif coverage_status == "partial":
        if affected_scope is None:
            errors.append(
                "partial Trigger coverage requires "
                "affected_version_scope"
            )

        if assessed_scope is None:
            errors.append(
                "partial Trigger coverage requires "
                "assessed_trigger_version_scope"
            )

        if not uncovered_note:
            errors.append(
                "partial Trigger coverage requires "
                "a non-empty uncovered_scope_note"
            )

    elif coverage_status == "not_assessed":
        if assessed_scope is not None:
            errors.append(
                "not_assessed Trigger coverage requires "
                "assessed_trigger_version_scope=null"
            )

    #
    # 4. Eligible is deliberately strict
    #
    if status == "eligible":
        failed_checks = {
            key: value
            for key, value in checks.items()
            if value != "pass"
        }

        if failed_checks:
            errors.append(
                "eligible requires every eligibility "
                "check to be 'pass'; "
                f"non-pass checks={failed_checks}"
            )

        if not matched_kinds:
            errors.append(
                "eligible requires at least one "
                "matched_supported_rule_kind"
            )

        if not rule_refs:
            errors.append(
                "eligible requires at least one rule_ref"
            )

        if not evidence_refs:
            errors.append(
                "eligible requires at least one "
                "evidence_ref"
            )

        if unsupported_reasons:
            errors.append(
                "eligible must not contain "
                "unsupported_reasons"
            )

        if coverage_status not in {
            "full",
            "partial",
        }:
            errors.append(
                "eligible requires Trigger coverage "
                "to be either 'full' or 'partial'"
            )

    #
    # 5. Unsupported-complex
    #
    elif status == "unsupported_complex":
        if (
            checks["supported_static_expressibility"]
            != "fail"
        ):
            errors.append(
                "unsupported_complex requires "
                "supported_static_expressibility='fail'"
            )

        if matched_kinds:
            errors.append(
                "unsupported_complex requires "
                "matched_supported_rule_kinds=[]"
            )

        if not unsupported_reasons:
            errors.append(
                "unsupported_complex requires at least "
                "one unsupported_reason"
            )

    #
    # 6. Insufficient evidence
    #
    elif status == "insufficient_evidence":
        evidence_related_checks = {
            "affected_version_range",
            "upstream_trigger_semantics",
            "counterfactual_validation",
            "provenance_completeness",
        }

        has_evidence_gap = any(
            checks[name] in {
                "fail",
                "unknown",
            }
            for name in evidence_related_checks
        )

        if not has_evidence_gap:
            errors.append(
                "insufficient_evidence requires at least "
                "one evidence-related check to be "
                "'fail' or 'unknown'"
            )

    #
    # 7. Conflicted
    #
    elif status == "conflicted":
        if "conflicted" not in checks.values():
            errors.append(
                "conflicted requires at least one "
                "eligibility check with value "
                "'conflicted'"
            )

    #
    # 8. Requires review
    #
    elif status == "requires_review":
        if not review_required:
            errors.append(
                "requires_review requires "
                "review_required=true"
            )

        if review_status == "approved":
            errors.append(
                "requires_review cannot have "
                "review.status='approved'"
            )

    #
    # 9. Not assessed
    #
    elif status == "not_assessed":
        if matched_kinds:
            errors.append(
                "not_assessed requires "
                "matched_supported_rule_kinds=[]"
            )

        if rule_refs:
            errors.append(
                "not_assessed must not contain "
                "final rule_refs"
            )

        if coverage_status != "not_assessed":
            errors.append(
                "not_assessed requires "
                "trigger_coverage.coverage_status="
                "'not_assessed'"
            )

    return errors


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--protocol",
        required=True,
    )

    parser.add_argument(
        "--assessment",
        required=True,
    )

    args = parser.parse_args()

    protocol_path = Path(args.protocol)
    assessment_path = Path(args.assessment)

    protocol = read_json(protocol_path)
    assessment = read_json(assessment_path)

    #
    # Layer 1: JSON Schema validation
    #
    Draft202012Validator.check_schema(protocol)
    Draft202012Validator(protocol).validate(
        assessment
    )

    #
    # Layer 2: semantic consistency validation
    #
    errors = validate_semantics(
        protocol,
        assessment,
    )

    if errors:
        print(
            "TRIGGER ELIGIBILITY "
            "SEMANTIC VALIDATION FAIL"
        )

        for index, error in enumerate(
            errors,
            start=1,
        ):
            print(f"[{index}] {error}")

        raise SystemExit(1)

    print(
        "TRIGGER ELIGIBILITY "
        "SEMANTIC VALIDATION PASS"
    )

    print(
        f"vulnerability_id: "
        f"{assessment['vulnerability_id']}"
    )

    print(
        f"status: "
        f"{assessment['status']}"
    )

    print(
        "matched_supported_rule_kinds: "
        f"{assessment['matched_supported_rule_kinds']}"
    )

    print(
        "trigger_coverage: "
        f"{assessment['trigger_coverage']['coverage_status']}"
    )

    print(
        f"review_status: "
        f"{assessment['review']['status']}"
    )


if __name__ == "__main__":
    main()