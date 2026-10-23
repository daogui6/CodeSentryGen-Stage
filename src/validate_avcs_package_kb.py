import argparse
import json
from pathlib import Path

from jsonschema import Draft202012Validator


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def validate_package_kb(schema: dict, kb: dict, repo_root: Path) -> list[str]:
    errors = []

    # 1. JSON Schema
    validator = Draft202012Validator(schema)
    for error in sorted(validator.iter_errors(kb), key=lambda x: list(x.path)):
        location = ".".join(str(x) for x in error.path) or "<root>"
        errors.append(f"schema:{location}: {error.message}")

    if errors:
        return errors

    # 2. Uniqueness
    source_ids = [
        x["source_id"]
        for x in kb["provenance"]["sources"]
    ]
    if len(source_ids) != len(set(source_ids)):
        errors.append("duplicate source_id found in provenance.sources")

    trigger_ids = [
        x["trigger_id"]
        for x in kb["trigger_rules"]
    ]
    if len(trigger_ids) != len(set(trigger_ids)):
        errors.append("duplicate trigger_id found in trigger_rules")

    vulnerability_ids = [
        x["vulnerability_id"]
        for x in kb["vulnerability_catalog"]
    ]
    if len(vulnerability_ids) != len(set(vulnerability_ids)):
        errors.append("duplicate vulnerability_id found in vulnerability_catalog")

    source_id_set = set(source_ids)
    trigger_id_set = set(trigger_ids)

    # 3. Check artifact paths actually exist
    artifact_paths = []

    artifact_paths += [
        x["path"]
        for x in kb["release_history"]["artifacts"]
    ]

    artifact_paths += [
        x["path"]
        for x in kb["api_surface_history"]["artifacts"]
    ]

    artifact_paths += [
        x["path"]
        for x in kb["provenance"]["generated_from"]
    ]

    for entry in kb["api_surface_history"]["entries"]:
        artifact_paths += entry.get("evidence_refs", [])

        for rule in entry.get("version_rules", []):
            evidence_ref = rule.get("evidence_ref")
            if evidence_ref:
                artifact_paths.append(evidence_ref)

    for vuln in kb["vulnerability_catalog"]:
        assessment = vuln["trigger_assessment"]

        for key in [
            "positive_regression_refs",
            "negative_regression_refs",
        ]:
            for value in assessment.get(key, []):
                if value:
                    artifact_paths.append(value)

    for rule in kb["trigger_rules"]:
        source_artifact = rule.get("source_artifact")
        if source_artifact:
            artifact_paths.append(source_artifact)

    checked_paths = set()

    for value in artifact_paths:
        if not isinstance(value, str):
            continue

        # Only treat repository-like references as paths.
        if not (
            "/" in value
            or "\\" in value
            or value.endswith(".json")
            or value.endswith(".jsonl")
        ):
            continue

        normalized = value.replace("\\", "/")

        if normalized in checked_paths:
            continue

        checked_paths.add(normalized)

        path = repo_root / normalized

        if not path.exists():
            errors.append(
                f"referenced artifact does not exist: {normalized}"
            )

    # 4. Vulnerability -> Trigger Rule references
    for vuln in kb["vulnerability_catalog"]:
        vuln_id = vuln["vulnerability_id"]
        aliases = set(vuln.get("aliases", []))
        accepted_vuln_ids = {vuln_id, *aliases}

        assessment = vuln["trigger_assessment"]

        for rule_ref in assessment["rule_refs"]:
            if rule_ref not in trigger_id_set:
                errors.append(
                    f"{vuln_id}: trigger_assessment.rule_ref "
                    f"{rule_ref!r} does not exist"
                )

                continue

            rule = next(
                x
                for x in kb["trigger_rules"]
                if x["trigger_id"] == rule_ref
            )

            rule_vuln_ids = set(rule["vulnerability_ids"])

            if vuln_id not in rule_vuln_ids:
                errors.append(
                    f"{vuln_id}: Trigger Rule {rule_ref!r} does not "
                    "contain the canonical vulnerability_id"
                )

            unknown_rule_vuln_ids = (
                rule_vuln_ids - accepted_vuln_ids
            )

            if unknown_rule_vuln_ids:
                errors.append(
                    f"{vuln_id}: Trigger Rule {rule_ref!r} contains "
                    f"unexpected vulnerability IDs "
                    f"{sorted(unknown_rule_vuln_ids)}"
                )

        # Vulnerability source_refs should resolve to provenance sources.
        for source_ref in vuln["source_refs"]:
            if source_ref not in source_id_set:
                errors.append(
                    f"{vuln_id}: source_ref {source_ref!r} "
                    "does not exist in provenance.sources"
                )

    # 5. Trigger Rule provenance
    for rule in kb["trigger_rules"]:
        trigger_id = rule["trigger_id"]

        for evidence_ref in rule["evidence_refs"]:
            if (
                "/" not in evidence_ref
                and "\\" not in evidence_ref
                and not evidence_ref.endswith(".json")
                and evidence_ref not in source_id_set
            ):
                errors.append(
                    f"{trigger_id}: evidence_ref {evidence_ref!r} "
                    "does not exist in provenance.sources"
                )

    # 6. Eligibility consistency
    for vuln in kb["vulnerability_catalog"]:
        assessment = vuln["trigger_assessment"]

        if assessment["status"] == "eligible":
            if assessment["review_required"]:
                errors.append(
                    f"{vuln['vulnerability_id']}: eligible "
                    "must have review_required=false"
                )

            if not assessment["rule_refs"]:
                errors.append(
                    f"{vuln['vulnerability_id']}: eligible "
                    "must reference at least one Trigger Rule"
                )

            if assessment["unsupported_reasons"]:
                errors.append(
                    f"{vuln['vulnerability_id']}: eligible "
                    "must not contain unsupported_reasons"
                )

    return errors


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--schema",
        required=True,
    )

    parser.add_argument(
        "--kb",
        required=True,
    )

    parser.add_argument(
        "--repo-root",
        default=".",
    )

    args = parser.parse_args()

    schema_path = Path(args.schema)
    kb_path = Path(args.kb)
    repo_root = Path(args.repo_root)

    schema = read_json(schema_path)
    kb = read_json(kb_path)

    Draft202012Validator.check_schema(schema)

    errors = validate_package_kb(
        schema=schema,
        kb=kb,
        repo_root=repo_root,
    )

    if errors:
        print("PACKAGE KB VALIDATION FAIL")

        for index, error in enumerate(errors, start=1):
            print(f"[{index}] {error}")

        raise SystemExit(1)

    print("PACKAGE KB VALIDATION PASS")
    print(f"kb_id: {kb['kb_id']}")
    print(f"distribution: {kb['distribution']}")
    print(
        "api_history_entry_count: "
        f"{len(kb['api_surface_history']['entries'])}"
    )
    print(
        "vulnerability_count: "
        f"{len(kb['vulnerability_catalog'])}"
    )
    print(
        "trigger_rule_count: "
        f"{len(kb['trigger_rules'])}"
    )


if __name__ == "__main__":
    main()