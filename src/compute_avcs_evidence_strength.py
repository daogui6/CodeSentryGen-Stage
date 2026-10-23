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


SCHEMA_VERSION = "avcs_evidence_strength_v0.2"


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(
        path.read_text(encoding="utf-8")
    )


def filter_versions(
    releases: list[dict[str, Any]],
    specifier_text: str,
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    str,
]:
    """
    对真实离散 release 集合应用版本约束。

    返回：
        compatible
        incompatible
        status
    """
    specifier_text = specifier_text.strip()

    if not specifier_text:
        return releases, [], "unconstrained"

    try:
        specifier = SpecifierSet(
            specifier_text
        )
    except InvalidSpecifier:
        return [], [], "invalid_specifier"

    compatible: list[dict[str, Any]] = []
    incompatible: list[dict[str, Any]] = []

    for release in releases:
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

        if specifier.contains(
            version,
            prereleases=True,
        ):
            compatible.append(
                release
            )
        else:
            incompatible.append(
                release
            )

    return (
        compatible,
        incompatible,
        "resolved",
    )

def filter_version_labels(
    labels: list[str],
    specifier_text: str,
) -> tuple[
    list[str],
    list[str],
    str,
]:
    """
    对只有 version label、但缺少明确上传时间证据的版本
    应用版本约束。

    注意：
    这里不会把这些 label 当成 generation-time confirmed release。
    只是判断：
    如果它们当时已经存在，它们是否可能进入当前版本集合。
    """
    specifier_text = specifier_text.strip()

    if not specifier_text:
        return list(labels), [], "unconstrained"

    try:
        specifier = SpecifierSet(
            specifier_text
        )
    except InvalidSpecifier:
        return [], [], "invalid_specifier"

    compatible: list[str] = []
    incompatible: list[str] = []

    for version_text in labels:
        try:
            version = Version(
                str(version_text)
            )
        except InvalidVersion:
            continue

        if specifier.contains(
            version,
            prereleases=True,
        ):
            compatible.append(
                str(version_text)
            )
        else:
            incompatible.append(
                str(version_text)
            )

    return (
        compatible,
        incompatible,
        "resolved",
    )


def build_v_before_api(
    release_history: dict[str, Any],
    manifest_constraints: dict[str, Any],
) -> dict[str, Any]:
    """
    V_before_api：

    generation-time releases
    ∩ manifest constraints

    注意：
    此处故意不加入 API constraint。

    confirmed releases 与缺少 file-time evidence 的
    release labels 分开保存，不能混为一个集合。
    """
    confirmed_releases = (
        release_history.get(
            "confirmed_releases_as_of_time_view",
            [],
        )
    )

    time_unknown_release_labels = [
        str(version_text)
        for version_text in release_history.get(
            "release_labels_without_file_evidence",
            [],
        )
    ]

    manifest_status = str(
        manifest_constraints.get(
            "status",
            "unknown",
        )
    )

    manifest_kind = str(
        manifest_constraints.get(
            "constraint_kind",
            "unknown",
        )
    )

    s_manifest = str(
        manifest_constraints.get(
            "specifier",
            "",
        )
    ).strip()

    if manifest_status == "not_declared":
        return {
            "status": "resolved",
            "s_manifest": "",
            "releases": confirmed_releases,
            "excluded_releases": [],
            "time_unknown_candidate_labels": (
                time_unknown_release_labels
            ),
            "time_unknown_excluded_labels": [],
        }

    if manifest_status != "resolved":
        return {
            "status": (
                f"manifest_constraint_"
                f"{manifest_status}"
            ),
            "s_manifest": s_manifest,
            "releases": [],
            "excluded_releases": [],
            "time_unknown_candidate_labels": [],
            "time_unknown_excluded_labels": [],
        }

    if manifest_kind == "unconstrained":
        return {
            "status": "resolved",
            "s_manifest": "",
            "releases": confirmed_releases,
            "excluded_releases": [],
            "time_unknown_candidate_labels": (
                time_unknown_release_labels
            ),
            "time_unknown_excluded_labels": [],
        }

    compatible, incompatible, status = (
        filter_versions(
            releases=confirmed_releases,
            specifier_text=s_manifest,
        )
    )

    (
        time_unknown_compatible,
        time_unknown_incompatible,
        time_unknown_status,
    ) = filter_version_labels(
        labels=time_unknown_release_labels,
        specifier_text=s_manifest,
    )

    if (
        status == "invalid_specifier"
        or time_unknown_status
        == "invalid_specifier"
    ):
        result_status = "invalid_specifier"
    else:
        result_status = "resolved"

    return {
        "status": result_status,
        "s_manifest": s_manifest,
        "releases": compatible,
        "excluded_releases": incompatible,
        "time_unknown_candidate_labels": (
            time_unknown_compatible
        ),
        "time_unknown_excluded_labels": (
            time_unknown_incompatible
        ),
    }

def find_exposure(
    exposed_releases: dict[str, Any],
    vulnerability_id: str,
) -> dict[str, Any] | None:
    for evaluation in exposed_releases.get(
        "evaluations",
        [],
    ):
        if (
            str(
                evaluation.get(
                    "vulnerability_id",
                    "",
                )
            )
            == vulnerability_id
        ):
            return evaluation

    return None


def compute_fixed_excluded(
    v_before_api: list[dict[str, Any]],
    v_feasible: list[dict[str, Any]],
    fixed_specifier_text: str,
) -> dict[str, Any]:
    """
    FixedExcluded：

    在 API 加入之前，本来可行的 fixed releases，
    是否全部被 API constraint 排除。

    True：
        至少存在一个 fixed candidate，
        且加入 API 后一个都不剩。

    False：
        至少一个 fixed release 仍然 feasible。

    None：
        无法评估。
    """
    fixed_specifier_text = (
        fixed_specifier_text.strip()
    )

    if not fixed_specifier_text:
        return {
            "status": "not_evaluable",
            "fixed_excluded": None,
            "fixed_candidate_count_before_api": None,
            "fixed_feasible_count": None,
            "fixed_candidate_versions_before_api": [],
            "fixed_feasible_versions": [],
        }

    (
        fixed_before_api,
        _,
        before_status,
    ) = filter_versions(
        releases=v_before_api,
        specifier_text=fixed_specifier_text,
    )

    (
        fixed_feasible,
        _,
        feasible_status,
    ) = filter_versions(
        releases=v_feasible,
        specifier_text=fixed_specifier_text,
    )

    if (
        before_status == "invalid_specifier"
        or feasible_status == "invalid_specifier"
    ):
        return {
            "status": "invalid_fixed_specifier",
            "fixed_excluded": None,
            "fixed_candidate_count_before_api": None,
            "fixed_feasible_count": None,
            "fixed_candidate_versions_before_api": [],
            "fixed_feasible_versions": [],
        }

    before_versions = [
        str(row.get("version", ""))
        for row in fixed_before_api
    ]

    feasible_versions = [
        str(row.get("version", ""))
        for row in fixed_feasible
    ]

    if not fixed_before_api:
        fixed_excluded = None
        status = "no_fixed_candidate_before_api"

    elif not fixed_feasible:
        fixed_excluded = True
        status = "resolved"

    else:
        fixed_excluded = False
        status = "resolved"

    return {
        "status": status,
        "fixed_excluded": fixed_excluded,
        "fixed_candidate_count_before_api": (
            len(fixed_before_api)
        ),
        "fixed_feasible_count": (
            len(fixed_feasible)
        ),
        "fixed_candidate_versions_before_api": (
            before_versions
        ),
        "fixed_feasible_versions": (
            feasible_versions
        ),
    }


def compute_strength(
    release_history: dict[str, Any],
    manifest_constraints: dict[str, Any],
    manifest_compatible: dict[str, Any],
    exposed_releases: dict[str, Any],
    vulnerability_constraints: dict[str, Any],
) -> dict[str, Any]:
    sample_id = str(
        manifest_compatible.get(
            "sample_id",
            "",
        )
    )

    distribution = str(
        manifest_compatible.get(
            "distribution",
            "",
        )
    )

    v_before_api_result = (
        build_v_before_api(
            release_history=release_history,
            manifest_constraints=(
                manifest_constraints
            ),
        )
    )

    if (
        v_before_api_result["status"]
        != "resolved"
    ):
        return {
            "schema_version": SCHEMA_VERSION,
            "sample_id": sample_id,
            "distribution": distribution,
            "status":
                "v_before_api_unresolved",
            "v_before_api_status":
                v_before_api_result[
                    "status"
                ],
            "evaluations": [],
        }

    v_before_api = (
        v_before_api_result[
            "releases"
        ]
    )

    time_unknown_before_api = list(
        v_before_api_result.get(
            "time_unknown_candidate_labels",
            [],
        )
    )

    v_before_api_status = (
        "partial"
        if time_unknown_before_api
        else "resolved"
    )

    feasible_status = str(
        manifest_compatible.get(
            "status",
            "unknown",
        )
    )

    if feasible_status not in {
        "resolved",
        "resolved_with_partial_release_history",
    }:
        return {
            "schema_version": SCHEMA_VERSION,
            "sample_id": sample_id,
            "distribution": distribution,
            "status": "v_feasible_unresolved",
            "v_feasible_status":
                feasible_status,
            "evaluations": [],
        }

    v_feasible = (
        manifest_compatible.get(
            "confirmed_manifest_compatible_releases",
            [],
        )
    )

    time_unknown_feasible = list(
        manifest_compatible.get(
            "time_unknown_manifest_compatible_release_labels",
            [],
        )
    )

    v_feasible_status = (
        "partial"
        if time_unknown_feasible
        else "resolved"
    )

    before_count = len(
        v_before_api
    )

    feasible_count = len(
        v_feasible
    )

    if before_count == 0:
        reduction = None
    else:
        reduction = (
            1.0
            - feasible_count
            / before_count
        )

    if reduction is None:
        reduction_status = "unknown"
    elif (
        v_before_api_status == "resolved"
        and v_feasible_status == "resolved"
    ):
        reduction_status = "resolved"
    else:
        reduction_status = "partial"

    reduction_basis = (
        "confirmed_releases_only"
        if reduction_status == "partial"
        else "confirmed_releases"
    )

    evaluations: list[
        dict[str, Any]
    ] = []

    for vulnerability in (
        vulnerability_constraints.get(
            "vulnerabilities",
            [],
        )
    ):
        vulnerability_id = str(
            vulnerability.get(
                "vulnerability_id",
                "",
            )
        )

        exposure = find_exposure(
            exposed_releases=(
                exposed_releases
            ),
            vulnerability_id=(
                vulnerability_id
            ),
        )

        if exposure is None:
            evaluations.append(
                {
                    "vulnerability_id":
                        vulnerability_id,
                    "status":
                        "exposure_evidence_not_found",
                }
            )
            continue

        time_unknown_exposed = list(
            exposure.get(
                "time_unknown_exposed_release_labels",
                [],
            )
        )

        v_exposed_status = (
            "partial"
            if time_unknown_exposed
            else "resolved"
        )

        exposed_count = exposure.get(
            "confirmed_exposed_release_count"
        )

        if (
            exposed_count is None
            or feasible_count == 0
        ):
            exposure_ratio = None
        else:
            exposure_ratio = (
                exposed_count
                / feasible_count
            )

        if exposure_ratio is None:
            exposure_ratio_status = "unknown"
        elif (
            v_feasible_status == "resolved"
            and v_exposed_status == "resolved"
        ):
            exposure_ratio_status = "resolved"
        else:
            exposure_ratio_status = "partial"

        fixed_specifier = str(
            vulnerability.get(
                "fixed_version_specifier",
                "",
            )
        )

        fixed_result = (
            compute_fixed_excluded(
                v_before_api=v_before_api,
                v_feasible=v_feasible,
                fixed_specifier_text=(
                    fixed_specifier
                ),
            )
        )

        time_unknown_fixed_before_api: list[str] = []
        time_unknown_fixed_feasible: list[str] = []

        if fixed_specifier:
            (
                time_unknown_fixed_before_api,
                _,
                _,
            ) = filter_version_labels(
                labels=time_unknown_before_api,
                specifier_text=fixed_specifier,
            )

            (
                time_unknown_fixed_feasible,
                _,
                _,
            ) = filter_version_labels(
                labels=time_unknown_feasible,
                specifier_text=fixed_specifier,
            )

        fixed_result_status = str(
            fixed_result.get(
                "status",
                "not_evaluable",
            )
        )

        fixed_excluded_value = (
            fixed_result.get(
                "fixed_excluded"
            )
        )

        if fixed_result_status == "resolved":
            if (
                fixed_excluded_value is True
                and time_unknown_fixed_feasible
            ):
                fixed_excluded_status = "partial"
            else:
                fixed_excluded_status = "resolved"

        elif time_unknown_fixed_before_api:
            fixed_excluded_status = "partial"

        else:
            fixed_excluded_status = "unknown"

        uncertainty_reasons: list[str] = []

        if time_unknown_before_api:
            uncertainty_reasons.append(
                "time_unknown_release_labels_"
                "may_affect_v_before_api"
            )

        if time_unknown_feasible:
            uncertainty_reasons.append(
                "time_unknown_release_labels_"
                "may_affect_v_feasible"
            )

        if time_unknown_exposed:
            uncertainty_reasons.append(
                "time_unknown_release_labels_"
                "may_affect_v_exposed"
            )

        metric_statuses = [
            reduction_status,
            exposure_ratio_status,
            fixed_excluded_status,
        ]

        if all(
            status == "resolved"
            for status in metric_statuses
        ):
            evaluation_status = "resolved"

        elif any(
            status in {
                "resolved",
                "partial",
            }
            for status in metric_statuses
        ):
            evaluation_status = "partial"

        else:
            evaluation_status = "unknown"

        evaluations.append(
            {
                "vulnerability_id":
                    vulnerability_id,

                "status":
                    evaluation_status,

                "s_api":
                    manifest_compatible.get(
                        "s_api",
                        "",
                    ),

                "s_manifest":
                    manifest_compatible.get(
                        "s_manifest",
                        "",
                    ),

                "s_vuln":
                    exposure.get(
                        "s_vuln",
                        "",
                    ),

                "fixed_version_specifier":
                    fixed_specifier,

                 "v_before_api_count":
                    before_count,

                "v_before_api_status":
                    v_before_api_status,

                "time_unknown_before_api_candidate_count":
                    len(time_unknown_before_api),

                "time_unknown_before_api_candidate_labels":
                    time_unknown_before_api,

                "v_feasible_count":
                    feasible_count,

                "v_feasible_status":
                    v_feasible_status,

                "time_unknown_feasible_candidate_count":
                    len(time_unknown_feasible),

                "time_unknown_feasible_candidate_labels":
                    time_unknown_feasible,

                "v_exposed_count":
                    exposed_count,

                "v_exposed_status":
                    v_exposed_status,

                "time_unknown_exposed_candidate_count":
                    len(time_unknown_exposed),

                "time_unknown_exposed_candidate_labels":
                    time_unknown_exposed,

                "v_before_api_versions": [
                    str(
                        row.get(
                            "version",
                            "",
                        )
                    )
                    for row in v_before_api
                ],

                "v_feasible_versions": [
                    str(
                        row.get(
                            "version",
                            "",
                        )
                    )
                    for row in v_feasible
                ],

                "v_exposed_versions": [
                    str(
                        row.get(
                            "version",
                            "",
                        )
                    )
                    for row in exposure.get(
                        "confirmed_exposed_releases",
                        [],
                    )
                ],

                "reduction":
                    reduction,

                "reduction_status":
                    reduction_status,

                "reduction_basis":
                    reduction_basis,

                "exposure_ratio":
                    exposure_ratio,

                "exposure_ratio_status":
                    exposure_ratio_status,

                "fixed_excluded":
                    fixed_excluded_value,

                "fixed_excluded_status":
                    fixed_excluded_status,

                "fixed_candidate_count_before_api":
                    fixed_result.get(
                        "fixed_candidate_count_before_api"
                    ),

                "fixed_feasible_count":
                    fixed_result.get(
                        "fixed_feasible_count"
                    ),

                "fixed_candidate_versions_before_api":
                    fixed_result.get(
                        "fixed_candidate_versions_before_api",
                        [],
                    ),

                "fixed_feasible_versions":
                    fixed_result.get(
                        "fixed_feasible_versions",
                        [],
                    ),

                "time_unknown_fixed_candidate_versions_before_api":
                    time_unknown_fixed_before_api,

                "time_unknown_fixed_feasible_versions":
                    time_unknown_fixed_feasible,

                "uncertainty_reasons":
                    uncertainty_reasons,
            }
        )

    evaluation_statuses = [
        str(
            evaluation.get(
                "status",
                "unknown",
            )
        )
        for evaluation in evaluations
    ]

    if (
        evaluation_statuses
        and all(
            status == "resolved"
            for status in evaluation_statuses
        )
    ):
        overall_status = "resolved"

    elif any(
        status in {
            "resolved",
            "partial",
        }
        for status in evaluation_statuses
    ):
        overall_status = "partial"

    else:
        overall_status = "unknown"

    return {
        "schema_version":
            SCHEMA_VERSION,

        "sample_id":
            sample_id,

        "distribution":
            distribution,

        "time_view":
            release_history.get(
                "time_view"
            ),

        "release_history_status":
            release_history.get(
                "release_history_status"
            ),

        "status":
            overall_status,

        "evaluation_count":
            len(evaluations),

        "evaluations":
            evaluations,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Compute AVCS evidence-strength "
            "metrics from discrete release sets."
        )
    )

    parser.add_argument(
        "--release-history",
        type=Path,
        required=True,
    )

    parser.add_argument(
        "--manifest-constraints",
        type=Path,
        required=True,
    )

    parser.add_argument(
        "--manifest-compatible-releases",
        type=Path,
        required=True,
    )

    parser.add_argument(
        "--exposed-releases",
        type=Path,
        required=True,
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

    result = compute_strength(
        release_history=load_json(
            args.release_history
        ),
        manifest_constraints=load_json(
            args.manifest_constraints
        ),
        manifest_compatible=load_json(
            args.manifest_compatible_releases
        ),
        exposed_releases=load_json(
            args.exposed_releases
        ),
        vulnerability_constraints=load_json(
            args.vulnerability_constraints
        ),
    )

    result["source_files"] = {
        "release_history":
            str(
                args.release_history
            ).replace("\\", "/"),

        "manifest_constraints":
            str(
                args.manifest_constraints
            ).replace("\\", "/"),

        "manifest_compatible_releases":
            str(
                args.manifest_compatible_releases
            ).replace("\\", "/"),

        "exposed_releases":
            str(
                args.exposed_releases
            ).replace("\\", "/"),

        "vulnerability_constraints":
            str(
                args.vulnerability_constraints
            ).replace("\\", "/"),
    }

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
        f"{result.get('sample_id')}"
    )

    print(
        f"[OK] status: "
        f"{result.get('status')}"
    )

    for evaluation in (
        result.get(
            "evaluations",
            [],
        )
    ):
        print(
            f"[OK] "
            f"{evaluation['vulnerability_id']}"
        )

        print(
            f"     "
            f"V_before_api = "
            f"{evaluation['v_before_api_count']}"
        )

        print(
            f"     "
            f"V_feasible   = "
            f"{evaluation['v_feasible_count']}"
        )

        print(
            f"     "
            f"V_exposed    = "
            f"{evaluation['v_exposed_count']}"
        )

        print(
            f"     "
            f"Reduction    = "
            f"{evaluation['reduction']}"
        )

        print(
            f"     "
            f"ExposureRatio = "
            f"{evaluation['exposure_ratio']}"
        )

        print(
            f"     "
            f"FixedExcluded = "
            f"{evaluation['fixed_excluded']}"
        )

    print(
        f"[OK] result saved to: "
        f"{args.out}"
    )


if __name__ == "__main__":
    main()