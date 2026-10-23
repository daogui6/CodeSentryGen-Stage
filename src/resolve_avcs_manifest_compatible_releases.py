from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def build_manifest_compatible_release_view(
    api_compatible: dict[str, Any],
    manifest_constraints: dict[str, Any],
) -> dict[str, Any]:
    sample_id = str(api_compatible.get("sample_id", ""))
    distribution = str(api_compatible.get("distribution", ""))
    normalized_distribution = str(
        api_compatible.get("normalized_distribution", "")
    )

    manifest_sample_id = str(
        manifest_constraints.get("sample_id", "")
    )
    manifest_normalized_distribution = str(
        manifest_constraints.get("normalized_distribution", "")
    )

    api_compatible_status = str(
        api_compatible.get("status", "unknown")
    )
    manifest_constraint_status = str(
        manifest_constraints.get("status", "unknown")
    )
    manifest_constraint_kind = str(
        manifest_constraints.get("constraint_kind", "unknown")
    )
    s_manifest = str(
        manifest_constraints.get("specifier", "")
    ).strip()

    manifest_declared = manifest_constraint_kind != "not_declared"

    resolved_status = "resolved" if api_compatible_status == "resolved" else "resolved_with_partial_release_history"

    base_result = {
        "schema_version": "avcs_manifest_compatible_releases_v0.1",
        "sample_id": sample_id,
        "distribution": distribution,
        "normalized_distribution": normalized_distribution,
        "time_view": api_compatible.get("time_view"),
        "release_history_status": api_compatible.get(
            "release_history_status"
        ),
        "api_compatible_status": api_compatible_status,
        "s_api": api_compatible.get("s_api", ""),
        "manifest_constraint_status": manifest_constraint_status,
        "manifest_constraint_kind": manifest_constraint_kind,
        "s_manifest": s_manifest,
        "manifest_declared": manifest_declared,
        "matched_requirements": manifest_constraints.get(
            "matched_requirements",
            [],
        ),
    }

    if manifest_sample_id != sample_id:
        return {
            **base_result,
            "status": "sample_id_mismatch",
            "confirmed_api_compatible_release_count_before_manifest": None,
            "confirmed_manifest_compatible_release_count": None,
            "confirmed_manifest_incompatible_release_count": None,
            "confirmed_manifest_compatible_releases": [],
            "confirmed_manifest_incompatible_releases": [],
            "time_unknown_manifest_compatible_release_labels": [],
            "time_unknown_manifest_incompatible_release_labels": [],
        }

    if manifest_normalized_distribution != normalized_distribution:
        return {
            **base_result,
            "status": "distribution_mismatch",
            "confirmed_api_compatible_release_count_before_manifest": None,
            "confirmed_manifest_compatible_release_count": None,
            "confirmed_manifest_incompatible_release_count": None,
            "confirmed_manifest_compatible_releases": [],
            "confirmed_manifest_incompatible_releases": [],
            "time_unknown_manifest_compatible_release_labels": [],
            "time_unknown_manifest_incompatible_release_labels": [],
        }

    upstream_count = api_compatible.get(
        "confirmed_api_compatible_release_count"
    )

    if upstream_count is None:
        return {
            **base_result,
            "status": "upstream_api_compatible_unresolved",
            "confirmed_api_compatible_release_count_before_manifest": None,
            "confirmed_manifest_compatible_release_count": None,
            "confirmed_manifest_incompatible_release_count": None,
            "confirmed_manifest_compatible_releases": [],
            "confirmed_manifest_incompatible_releases": [],
            "time_unknown_manifest_compatible_release_labels": [],
            "time_unknown_manifest_incompatible_release_labels": [],
        }

    compatible_releases = api_compatible.get(
        "confirmed_api_compatible_releases",
        [],
    )
    time_unknown_api_compatible = api_compatible.get(
        "time_unknown_api_compatible_release_labels",
        [],
    )

    if manifest_constraint_status == "not_declared":
        return {
            **base_result,
            "status": resolved_status,
            "confirmed_api_compatible_release_count_before_manifest": len(
                compatible_releases
            ),
            "confirmed_manifest_compatible_release_count": len(
                compatible_releases
            ),
            "confirmed_manifest_incompatible_release_count": 0,
            "confirmed_manifest_compatible_releases": compatible_releases,
            "confirmed_manifest_incompatible_releases": [],
            "time_unknown_manifest_compatible_release_labels": (
                time_unknown_api_compatible
            ),
            "time_unknown_manifest_incompatible_release_labels": [],
        }

    if manifest_constraint_status != "resolved":
        return {
            **base_result,
            "status": f"manifest_constraint_{manifest_constraint_status}",
            "confirmed_api_compatible_release_count_before_manifest": len(
                compatible_releases
            ),
            "confirmed_manifest_compatible_release_count": None,
            "confirmed_manifest_incompatible_release_count": None,
            "confirmed_manifest_compatible_releases": [],
            "confirmed_manifest_incompatible_releases": [],
            "time_unknown_manifest_compatible_release_labels": [],
            "time_unknown_manifest_incompatible_release_labels": [],
        }

    if manifest_constraint_kind == "unconstrained":
        return {
            **base_result,
            "status": resolved_status,
            "confirmed_api_compatible_release_count_before_manifest": len(
                compatible_releases
            ),
            "confirmed_manifest_compatible_release_count": len(
                compatible_releases
            ),
            "confirmed_manifest_incompatible_release_count": 0,
            "confirmed_manifest_compatible_releases": compatible_releases,
            "confirmed_manifest_incompatible_releases": [],
            "time_unknown_manifest_compatible_release_labels": (
                time_unknown_api_compatible
            ),
            "time_unknown_manifest_incompatible_release_labels": [],
        }

    try:
        specifier = SpecifierSet(s_manifest)
    except InvalidSpecifier:
        return {
            **base_result,
            "status": "invalid_manifest_specifier",
            "confirmed_api_compatible_release_count_before_manifest": len(
                compatible_releases
            ),
            "confirmed_manifest_compatible_release_count": None,
            "confirmed_manifest_incompatible_release_count": None,
            "confirmed_manifest_compatible_releases": [],
            "confirmed_manifest_incompatible_releases": [],
            "time_unknown_manifest_compatible_release_labels": [],
            "time_unknown_manifest_incompatible_release_labels": [],
        }

    manifest_compatible_releases: list[dict[str, Any]] = []
    manifest_incompatible_releases: list[dict[str, Any]] = []

    for release in compatible_releases:
        version_text = str(release.get("version", ""))

        try:
            version = Version(version_text)
        except InvalidVersion:
            continue

        if specifier.contains(version, prereleases=True):
            manifest_compatible_releases.append(release)
        else:
            manifest_incompatible_releases.append(release)

    time_unknown_manifest_compatible: list[str] = []
    time_unknown_manifest_incompatible: list[str] = []

    for version_text in time_unknown_api_compatible:
        try:
            version = Version(version_text)
        except InvalidVersion:
            continue

        if specifier.contains(version, prereleases=True):
            time_unknown_manifest_compatible.append(version_text)
        else:
            time_unknown_manifest_incompatible.append(version_text)

    status = resolved_status

    return {
        **base_result,
        "status": status,
        "confirmed_api_compatible_release_count_before_manifest": len(
            compatible_releases
        ),
        "confirmed_manifest_compatible_release_count": len(
            manifest_compatible_releases
        ),
        "confirmed_manifest_incompatible_release_count": len(
            manifest_incompatible_releases
        ),
        "confirmed_manifest_compatible_releases": (
            manifest_compatible_releases
        ),
        "confirmed_manifest_incompatible_releases": (
            manifest_incompatible_releases
        ),
        "time_unknown_manifest_compatible_release_labels": sorted(
            time_unknown_manifest_compatible,
            key=Version,
        ),
        "time_unknown_manifest_incompatible_release_labels": sorted(
            time_unknown_manifest_incompatible,
            key=Version,
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Filter AVCS API-compatible releases "
            "with manifest version constraints."
        )
    )

    parser.add_argument(
        "--api-compatible-releases",
        type=Path,
        required=True,
    )

    parser.add_argument(
        "--manifest-constraints",
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
    manifest_constraints = load_json(
        args.manifest_constraints
    )

    result = build_manifest_compatible_release_view(
        api_compatible=api_compatible,
        manifest_constraints=manifest_constraints,
    )

    result["api_compatible_releases_file"] = str(
        args.api_compatible_releases
    ).replace("\\", "/")

    result["manifest_constraints_file"] = str(
        args.manifest_constraints
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

    print(f"[OK] sample id: {result['sample_id']}")
    print(f"[OK] distribution: {result['distribution']}")
    print(f"[OK] S_api: {result['s_api'] or '(unresolved)'}")
    print(
        f"[OK] S_manifest: "
        f"{result['s_manifest'] or '(unconstrained)'}"
    )
    print(
        f"[OK] releases before manifest: "
        f"{result['confirmed_api_compatible_release_count_before_manifest']}"
    )
    print(
        f"[OK] manifest-compatible releases: "
        f"{result['confirmed_manifest_compatible_release_count']}"
    )
    print(
        f"[OK] manifest-incompatible releases: "
        f"{result['confirmed_manifest_incompatible_release_count']}"
    )
    print(f"[OK] status: {result['status']}")
    print(f"[OK] result saved to: {args.out}")


if __name__ == "__main__":
    main()