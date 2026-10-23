from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from packaging.specifiers import (
    InvalidSpecifier,
    SpecifierSet,
)
from packaging.version import (
    InvalidVersion,
    Version,
)


def load_json(
    path: Path,
) -> dict[str, Any]:
    return json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )

def is_affected_version(
    version_text: str,
    version: Version,
    affected_specifier: SpecifierSet,
    explicit_affected_versions: set[str],
) -> bool:
    """
    按 OSV affected 语义判断一个版本是否受漏洞影响。

    一个版本只要满足以下任一条件，就视为 affected：
    1. 明确出现在 OSV affected_versions 中；
    2. 满足当前解析得到的 affected version range。

    显式版本列表优先用于保留 ECOSYSTEM range
    在通用 PEP 440 specifier 转换中可能丢失的版本，
    例如 PyYAML 5.4b1 / 5.4b2。
    """
    if version_text in explicit_affected_versions:
        return True

    return affected_specifier.contains(
        version,
        prereleases=True,
    )

def build_exposed_release_view(
    api_compatible: dict[str, Any],
    vulnerability_constraints: dict[str, Any],
    manifest_compatible: dict[str, Any] | None = None,
) -> dict[str, Any]:
    distribution = str(
        api_compatible.get(
            "distribution",
            "",
        )
    )

    normalized_distribution = str(
        api_compatible.get(
            "normalized_distribution",
            "",
        )
    )

    vulnerabilities = (
        vulnerability_constraints.get(
            "vulnerabilities",
            [],
        )
    )

    sample_id = str(api_compatible.get("sample_id", ""))
    manifest_context_status = "not_provided"

    api_compatible_releases = api_compatible.get(
        "confirmed_api_compatible_releases",
        [],
    )

    if manifest_compatible is not None:
        release_evidence_mode = "manifest_compatible"

        manifest_sample_id = str(
            manifest_compatible.get("sample_id", "")
        )
        manifest_normalized_distribution = str(
            manifest_compatible.get(
                "normalized_distribution",
                "",
            )
        )

        if manifest_sample_id != sample_id:
            manifest_context_status = "sample_id_mismatch"

        elif manifest_normalized_distribution != normalized_distribution:
            manifest_context_status = "distribution_mismatch"

        else:
            manifest_context_status = "matched"

        api_compatible_count = api_compatible.get(
            "confirmed_api_compatible_release_count"
        )

        manifest_compatible_status = str(
            manifest_compatible.get("status", "unknown")
        )

        s_manifest = str(
            manifest_compatible.get("s_manifest", "")
        )

        if manifest_context_status == "matched":
            compatible_releases = manifest_compatible.get(
                "confirmed_manifest_compatible_releases",
                [],
            )

            time_unknown_compatible = manifest_compatible.get(
                "time_unknown_manifest_compatible_release_labels",
                [],
            )

            candidate_release_count = manifest_compatible.get(
                "confirmed_manifest_compatible_release_count"
            )

        else:
            compatible_releases = []
            time_unknown_compatible = []
            candidate_release_count = None

    else:
        release_evidence_mode = "api_compatible"
        manifest_context_status = "not_provided"

        compatible_releases = api_compatible_releases

        time_unknown_compatible = api_compatible.get(
            "time_unknown_api_compatible_release_labels",
            [],
        )

        if "confirmed_api_compatible_release_count" in api_compatible:
            candidate_release_count = api_compatible.get(
                "confirmed_api_compatible_release_count"
            )
        else:
            candidate_release_count = len(
                api_compatible_releases
            )

        api_compatible_count = candidate_release_count
        manifest_compatible_status = "not_provided"
        s_manifest = ""

    evaluations: list[
        dict[str, Any]
    ] = []

    for vulnerability in vulnerabilities:
        vulnerability_id = str(
            vulnerability.get(
                "vulnerability_id",
                "",
            )
        )

        affected_specifier_text = str(
            vulnerability.get(
                "affected_version_specifier",
                "",
            )
        ).strip()

        explicit_affected_versions_raw = (
            vulnerability.get(
                "affected_versions",
                [],
            )
        )

        if not isinstance(
            explicit_affected_versions_raw,
            list,
        ):
            explicit_affected_versions_raw = []

        explicit_affected_versions = {
            str(version_text).strip()
            for version_text
            in explicit_affected_versions_raw
            if str(version_text).strip()
        }

        fixed_specifier = str(
            vulnerability.get(
                "fixed_version_specifier",
                "",
            )
        ).strip()

        vulnerability_constraint_status = str(
            vulnerability.get(
                "constraint_status",
                "resolved",
            )
        )

        if candidate_release_count is None:
            evaluations.append(
                {
                    "vulnerability_id": vulnerability_id,
                    "severity": vulnerability.get(
                        "severity",
                        "not_calibrated",
                    ),
                    "status": "upstream_release_candidates_unresolved",
                    "vulnerability_constraint_status": (
                        vulnerability_constraint_status
                    ),
                    "s_vuln": affected_specifier_text,
                    "fixed_version_specifier": fixed_specifier,
                    "confirmed_api_compatible_release_count": (
                        api_compatible_count
                    ),
                    "confirmed_manifest_compatible_release_count": None,
                    "release_candidate_count": None,
                    "confirmed_exposed_release_count": None,
                    "confirmed_not_affected_release_count": None,
                    "confirmed_exposed_releases": [],
                    "confirmed_not_affected_releases": [],
                    "time_unknown_exposed_release_labels": [],
                    "trigger_conditions": vulnerability.get(
                        "trigger_conditions",
                        {},
                    ),
                    "safe_api_symbols": vulnerability.get(
                        "safe_api_symbols",
                        [],
                    ),
                    "evidence_type": vulnerability.get(
                        "evidence_type"
                    ),
                    "evidence_ref": vulnerability.get(
                        "evidence_ref"
                    ),
                }
            )
            continue

        if (
            vulnerability_constraint_status
            != "resolved"
        ):
            evaluations.append(
                {
                    "vulnerability_id":
                        vulnerability_id,

                    "severity":
                        vulnerability.get(
                            "severity",
                            "not_calibrated",
                        ),

                    "status": (
                        "vulnerability_constraint_"
                        f"{vulnerability_constraint_status}"
                    ),

                    "vulnerability_constraint_status":
                        vulnerability_constraint_status,

                    "s_vuln":
                        affected_specifier_text,

                    "fixed_version_specifier":
                        fixed_specifier,

                    "confirmed_api_compatible_release_count":
                        api_compatible_count,

                    "confirmed_manifest_compatible_release_count": (
                        candidate_release_count
                        if release_evidence_mode
                        == "manifest_compatible"
                        else None
                    ),

                    "release_candidate_count":
                        candidate_release_count,

                    "confirmed_exposed_release_count":
                        None,

                    "confirmed_not_affected_release_count":
                        None,

                    "confirmed_exposed_releases":
                        [],

                    "confirmed_not_affected_releases":
                        [],

                    "time_unknown_exposed_release_labels":
                        [],

                    "trigger_conditions":
                        vulnerability.get(
                            "trigger_conditions",
                            {},
                        ),

                    "safe_api_symbols":
                        vulnerability.get(
                            "safe_api_symbols",
                            [],
                        ),

                    "evidence_type":
                        vulnerability.get(
                            "evidence_type"
                        ),

                    "evidence_ref":
                        vulnerability.get(
                            "evidence_ref"
                        ),
                }
            )
            continue

        if not affected_specifier_text:
            evaluations.append(
                {
                    "vulnerability_id":
                        vulnerability_id,

                    "severity":
                        vulnerability.get(
                            "severity",
                            "not_calibrated",
                        ),

                    "status":
                        "vulnerability_specifier_missing",

                    "vulnerability_constraint_status":
                        vulnerability_constraint_status,

                    "s_vuln":
                        affected_specifier_text,

                    "fixed_version_specifier":
                        fixed_specifier,

                    "confirmed_api_compatible_release_count":
                        api_compatible_count,

                    "confirmed_manifest_compatible_release_count": (
                        candidate_release_count
                        if release_evidence_mode
                        == "manifest_compatible"
                        else None
                    ),

                    "release_candidate_count":
                        candidate_release_count,

                    "confirmed_exposed_release_count":
                        None,

                    "confirmed_not_affected_release_count":
                        None,

                    "confirmed_exposed_releases":
                        [],

                    "confirmed_not_affected_releases":
                        [],

                    "time_unknown_exposed_release_labels":
                        [],

                    "trigger_conditions":
                        vulnerability.get(
                            "trigger_conditions",
                            {},
                        ),

                    "safe_api_symbols":
                        vulnerability.get(
                            "safe_api_symbols",
                            [],
                        ),

                    "evidence_type":
                        vulnerability.get(
                            "evidence_type"
                        ),

                    "evidence_ref":
                        vulnerability.get(
                            "evidence_ref"
                        ),
                }
            )
            continue

        try:
            affected_specifier = (
                SpecifierSet(
                    affected_specifier_text
                )
            )
        except InvalidSpecifier:
            evaluations.append(
                {
                    "vulnerability_id": (
                        vulnerability_id
                    ),
                    "status": (
                        "invalid_vulnerability_specifier"
                    ),
                    "vulnerability_constraint_status": (
                        vulnerability_constraint_status
                    ),
                    "s_vuln": (
                        affected_specifier_text
                    ),
                    "fixed_version_specifier": (
                        fixed_specifier
                    ),
                    "confirmed_exposed_release_count": (
                        None
                    ),
                    "confirmed_exposed_releases": [],
                    "confirmed_not_affected_releases": [],
                    "time_unknown_exposed_release_labels": [],
                }
            )
            continue

        exposed_releases: list[
            dict[str, Any]
        ] = []

        not_affected_releases: list[
            dict[str, Any]
        ] = []

        for release in compatible_releases:
            version_text = str(
                release.get(
                    "version",
                    "",
                )
            )

            try:
                version = Version(
                    version_text
                )
            except InvalidVersion:
                continue

            is_affected = is_affected_version(
                version_text=version_text,
                version=version,
                affected_specifier=affected_specifier,
                explicit_affected_versions=(
                    explicit_affected_versions
                ),
            )

            if is_affected:
                exposed_releases.append(
                    release
                )
            else:
                not_affected_releases.append(
                    release
                )

        time_unknown_exposed: list[str] = []

        for version_text in time_unknown_compatible:
            try:
                version = Version(
                    version_text
                )
            except InvalidVersion:
                continue

            if is_affected_version(
                    version_text=version_text,
                    version=version,
                    affected_specifier=affected_specifier,
                    explicit_affected_versions=(
                            explicit_affected_versions
                    ),
            ):
                time_unknown_exposed.append(
                    version_text
                )

        evaluations.append(
            {
                "vulnerability_id": (
                    vulnerability_id
                ),
                "severity": vulnerability.get(
                    "severity",
                    "not_calibrated",
                ),
                "status": "resolved",
                "vulnerability_constraint_status": (
                    vulnerability_constraint_status
                ),
                "s_vuln": (
                    affected_specifier_text
                ),
                "fixed_version_specifier": (
                    fixed_specifier
                ),
                "confirmed_api_compatible_release_count": (
                    api_compatible_count
                ),
                "confirmed_manifest_compatible_release_count": (
                    candidate_release_count
                    if release_evidence_mode == "manifest_compatible"
                    else None
                ),
                "release_candidate_count": candidate_release_count,
                "confirmed_exposed_release_count": (
                    len(exposed_releases)
                ),
                "confirmed_not_affected_release_count": (
                    len(not_affected_releases)
                ),
                "confirmed_exposed_releases": (
                    exposed_releases
                ),
                "confirmed_not_affected_releases": (
                    not_affected_releases
                ),
                "time_unknown_exposed_release_labels": (
                    sorted(
                        time_unknown_exposed,
                        key=Version,
                    )
                ),
                "trigger_conditions": (
                    vulnerability.get(
                        "trigger_conditions",
                        {},
                    )
                ),
                "safe_api_symbols": (
                    vulnerability.get(
                        "safe_api_symbols",
                        [],
                    )
                ),
                "evidence_type": vulnerability.get(
                    "evidence_type"
                ),
                "evidence_ref": vulnerability.get(
                    "evidence_ref"
                ),
            }
        )

    return {
        "schema_version": (
            "avcs_exposed_releases_v0.1"
        ),
        "release_evidence_mode": release_evidence_mode,
        "manifest_context_status": manifest_context_status,
        "manifest_compatible_status": manifest_compatible_status,
        "s_manifest": s_manifest,
        "sample_id": api_compatible.get(
            "sample_id"
        ),
        "distribution": distribution,
        "normalized_distribution": (
            normalized_distribution
        ),
        "time_view": api_compatible.get(
            "time_view"
        ),
        "api_compatible_status": (
            api_compatible.get(
                "status"
            )
        ),
        "s_api": api_compatible.get(
            "s_api",
            "",
        ),
        "release_history_status": (
            api_compatible.get(
                "release_history_status"
            )
        ),
        "evaluation_count": len(
            evaluations
        ),
        "evaluations": evaluations,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Intersect confirmed AVCS "
            "API-compatible releases with "
            "vulnerability-affected releases."
        )
    )

    parser.add_argument(
        "--api-compatible-releases",
        type=Path,
        required=True,
    )

    parser.add_argument(
        "--manifest-compatible-releases",
        type=Path,
        default=None,
    )

    parser.add_argument(
        "--vulnerability-constraints",
        type=Path,
        required=True,
    )

    parser.add_argument(
        "--out",
        type=Path,
        required=True,
    )

    args = parser.parse_args()

    api_compatible = load_json(
        args.api_compatible_releases
    )

    manifest_compatible = (
        load_json(args.manifest_compatible_releases)
        if args.manifest_compatible_releases
        else None
    )

    vulnerability_constraints = load_json(
        args.vulnerability_constraints
    )

    result = build_exposed_release_view(
        api_compatible=api_compatible,
        vulnerability_constraints=vulnerability_constraints,
        manifest_compatible=manifest_compatible,
    )

    result[
        "api_compatible_releases_file"
    ] = str(
        args.api_compatible_releases
    ).replace("\\", "/")

    if args.manifest_compatible_releases:
        result["manifest_compatible_releases_file"] = str(
            args.manifest_compatible_releases
        ).replace("\\", "/")

    result[
        "vulnerability_constraints_file"
    ] = str(
        args.vulnerability_constraints
    ).replace("\\", "/")

    args.out.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    args.out.write_text(
        json.dumps(
            result,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    print(
        f"[OK] sample id: "
        f"{result['sample_id']}"
    )

    print(
        f"[OK] distribution: "
        f"{result['distribution']}"
    )

    print(
        f"[OK] S_api: "
        f"{result['s_api']}"
    )

    print(
        f"[OK] vulnerabilities: "
        f"{result['evaluation_count']}"
    )

    for evaluation in result[
        "evaluations"
    ]:
        print(
            f"[OK] "
            f"{evaluation['vulnerability_id']} "
            f"| S_vuln: "
            f"{evaluation['s_vuln']} "
            f"| exposed: "
            f"{evaluation['confirmed_exposed_release_count']} "
            f"| not affected: "
            f"{evaluation.get('confirmed_not_affected_release_count')}"
        )

    print(
        f"[OK] result saved to: "
        f"{args.out}"
    )


if __name__ == "__main__":
    main()