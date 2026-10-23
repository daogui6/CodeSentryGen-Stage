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


def find_distribution_constraint(
    api_constraints: dict[str, Any],
    normalized_distribution: str,
) -> dict[str, Any] | None:
    for constraint in api_constraints.get(
        "distribution_constraints",
        [],
    ):
        if (
            constraint.get(
                "normalized_distribution"
            )
            == normalized_distribution
        ):
            return constraint

    return None


def get_s_api(
    distribution_constraint: dict[str, Any],
) -> str:
    s_api = distribution_constraint.get(
        "s_api",
        {},
    )

    return str(
        s_api.get(
            "simplified_specifier"
        )
        or s_api.get(
            "raw_specifier"
        )
        or ""
    ).strip()


def build_api_compatible_release_view(
    release_history: dict[str, Any],
    api_constraints: dict[str, Any],
) -> dict[str, Any]:
    normalized_distribution = str(
        release_history.get(
            "normalized_distribution",
            "",
        )
    )

    distribution = str(
        release_history.get(
            "distribution",
            "",
        )
    )

    distribution_constraint = (
        find_distribution_constraint(
            api_constraints=api_constraints,
            normalized_distribution=(
                normalized_distribution
            ),
        )
    )

    base_result = {
        "schema_version": (
            "avcs_api_compatible_releases_v0.1"
        ),
        "sample_id": api_constraints.get(
            "sample_id"
        ),
        "distribution": distribution,
        "normalized_distribution": (
            normalized_distribution
        ),
        "time_view": release_history.get(
            "time_view"
        ),
        "release_history_status": (
            release_history.get(
                "release_history_status",
                "unknown",
            )
        ),
        "release_history_evidence_scope": (
            release_history.get(
                "release_history_evidence_scope"
            )
        ),
        "time_unknown_release_labels": (
            release_history.get(
                "release_labels_without_file_evidence",
                [],
            )
        ),
        "invalid_release_labels": (
            release_history.get(
                "invalid_version_labels",
                [],
            )
        ),
    }

    if distribution_constraint is None:
        return {
            **base_result,
            "status": (
                "api_constraint_not_found"
            ),
            "api_constraint_status": (
                "not_found"
            ),
            "s_api": "",
            "confirmed_release_count_before_api": (
                len(
                    release_history.get(
                        "confirmed_releases_as_of_time_view",
                        [],
                    )
                )
            ),
            "confirmed_api_compatible_release_count": (
                None
            ),
            "confirmed_api_incompatible_release_count": (
                None
            ),
            "confirmed_api_compatible_releases": [],
            "confirmed_api_incompatible_releases": [],
            "time_unknown_api_compatible_release_labels": (
                []
            ),
            "time_unknown_api_incompatible_release_labels": (
                []
            ),
        }

    api_constraint_status = str(
        distribution_constraint.get(
            "status",
            "unresolved",
        )
    )

    s_api = get_s_api(
        distribution_constraint
    )

    confirmed_releases = (
        release_history.get(
            "confirmed_releases_as_of_time_view",
            [],
        )
    )

    if (
        api_constraint_status != "resolved"
        or not s_api
    ):
        return {
            **base_result,
            "status": (
                f"api_constraint_"
                f"{api_constraint_status}"
            ),
            "api_constraint_status": (
                api_constraint_status
            ),
            "s_api": s_api,
            "confirmed_release_count_before_api": (
                len(confirmed_releases)
            ),
            "confirmed_api_compatible_release_count": (
                None
            ),
            "confirmed_api_incompatible_release_count": (
                None
            ),
            "confirmed_api_compatible_releases": [],
            "confirmed_api_incompatible_releases": [],
            "time_unknown_api_compatible_release_labels": (
                []
            ),
            "time_unknown_api_incompatible_release_labels": (
                []
            ),
        }

    try:
        specifier = SpecifierSet(
            s_api
        )
    except InvalidSpecifier:
        return {
            **base_result,
            "status": (
                "invalid_api_specifier"
            ),
            "api_constraint_status": (
                api_constraint_status
            ),
            "s_api": s_api,
            "confirmed_release_count_before_api": (
                len(confirmed_releases)
            ),
            "confirmed_api_compatible_release_count": (
                None
            ),
            "confirmed_api_incompatible_release_count": (
                None
            ),
            "confirmed_api_compatible_releases": [],
            "confirmed_api_incompatible_releases": [],
            "time_unknown_api_compatible_release_labels": (
                []
            ),
            "time_unknown_api_incompatible_release_labels": (
                []
            ),
        }

    compatible_releases: list[
        dict[str, Any]
    ] = []

    incompatible_releases: list[
        dict[str, Any]
    ] = []

    for release in confirmed_releases:
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

        # 这里不是模拟 pip 默认选版本。
        # 我们是在逐个判断一个已经真实存在的
        # release 是否满足 API version constraint。
        #
        # 因此 prerelease 也应该正常参与版本关系判断。
        is_compatible = specifier.contains(
            version,
            prereleases=True,
        )

        if is_compatible:
            compatible_releases.append(
                release
            )
        else:
            incompatible_releases.append(
                release
            )

    time_unknown_api_compatible: list[str] = []
    time_unknown_api_incompatible: list[str] = []

    for version_text in (
        release_history.get(
            "release_labels_without_file_evidence",
            [],
        )
    ):
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
            time_unknown_api_compatible.append(
                version_text
            )
        else:
            time_unknown_api_incompatible.append(
                version_text
            )

    release_history_status = str(
        release_history.get(
            "release_history_status",
            "unknown",
        )
    )

    if (
        release_history_status
        == "current_registry_file_evidence_complete"
    ):
        status = "resolved"
    else:
        status = (
            "resolved_with_partial_release_history"
        )

    return {
        **base_result,
        "status": status,
        "api_constraint_status": (
            api_constraint_status
        ),
        "s_api": s_api,
        "confirmed_release_count_before_api": (
            len(confirmed_releases)
        ),
        "confirmed_api_compatible_release_count": (
            len(compatible_releases)
        ),
        "confirmed_api_incompatible_release_count": (
            len(incompatible_releases)
        ),
        "confirmed_api_compatible_releases": (
            compatible_releases
        ),
        "confirmed_api_incompatible_releases": (
            incompatible_releases
        ),
        "time_unknown_api_compatible_release_labels": (
            sorted(
                time_unknown_api_compatible,
                key=Version,
            )
        ),
        "time_unknown_api_incompatible_release_labels": (
            sorted(
                time_unknown_api_incompatible,
                key=Version,
            )
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Filter confirmed historical releases "
            "with the resolved AVCS API constraint."
        )
    )

    parser.add_argument(
        "--release-history",
        type=Path,
        required=True,
    )

    parser.add_argument(
        "--api-constraints",
        type=Path,
        required=True,
    )

    parser.add_argument(
        "--out",
        type=Path,
        required=True,
    )

    args = parser.parse_args()

    release_history = load_json(
        args.release_history
    )

    api_constraints = load_json(
        args.api_constraints
    )

    result = (
        build_api_compatible_release_view(
            release_history=release_history,
            api_constraints=api_constraints,
        )
    )

    result["release_history_file"] = str(
        args.release_history
    ).replace("\\", "/")

    result["api_constraints_file"] = str(
        args.api_constraints
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
        f"[OK] time view: "
        f"{result['time_view']}"
    )

    print(
        f"[OK] API constraint status: "
        f"{result['api_constraint_status']}"
    )

    print(
        f"[OK] S_api: "
        f"{result['s_api'] or '(unresolved)'}"
    )

    print(
        f"[OK] confirmed releases before API: "
        f"{result['confirmed_release_count_before_api']}"
    )

    print(
        f"[OK] confirmed API-compatible releases: "
        f"{result['confirmed_api_compatible_release_count']}"
    )

    print(
        f"[OK] confirmed API-incompatible releases: "
        f"{result['confirmed_api_incompatible_release_count']}"
    )

    print(
        f"[OK] time-unknown but API-compatible labels: "
        f"{len(result['time_unknown_api_compatible_release_labels'])}"
    )

    print(
        f"[OK] status: "
        f"{result['status']}"
    )

    print(
        f"[OK] result saved to: "
        f"{args.out}"
    )


if __name__ == "__main__":
    main()