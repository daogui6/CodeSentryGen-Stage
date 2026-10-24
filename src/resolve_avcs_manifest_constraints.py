from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from normalizer import pep503_normalize
from package_identity_v1 import (
    DEFAULT_POLICY as DEFAULT_IDENTITY_POLICY,
)
from project_dependency_facts_v1 import (
    FACTS_SCHEMA_VERSION,
    collect_project_dependency_facts,
    manifest_context_id_for_row,
)


ROOT = Path(__file__).resolve().parents[1]


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    with path.open("r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if line:
                rows.append(json.loads(line))

    return rows


def find_sample(
    rows: list[dict[str, Any]],
    sample_id: str,
) -> dict[str, Any] | None:
    for row in rows:
        if str(row.get("sample_id", "")) == sample_id:
            return row

    return None


def parse_manifest_constraints(
    requirements_text: str,
    distribution: str,
) -> dict[str, Any]:
    normalized_distribution = pep503_normalize(distribution)

    matched_requirements: list[dict[str, Any]] = []
    invalid_lines: list[str] = []

    for raw_line in requirements_text.splitlines():
        line = raw_line.strip().lstrip("\ufeff")

        if not line:
            continue

        if line.startswith("#"):
            continue

        if line.startswith("-"):
            continue

        line = line.split("#", 1)[0].strip()

        if not line:
            continue

        try:
            requirement = Requirement(line)
        except InvalidRequirement:
            invalid_lines.append(raw_line)
            continue

        if pep503_normalize(requirement.name) != normalized_distribution:
            continue

        matched_requirements.append(
            {
                "name": requirement.name,
                "normalized_name": pep503_normalize(
                    requirement.name
                ),
                "specifier": str(requirement.specifier),
                "extras": sorted(requirement.extras),
                "marker": (
                    str(requirement.marker)
                    if requirement.marker is not None
                    else ""
                ),
                "url": requirement.url or "",
                "original_text": raw_line,
            }
        )

    if not matched_requirements:
        return {
            "status": "not_declared",
            "constraint_kind": "not_declared",
            "specifier": "",
            "matched_requirements": [],
            "invalid_lines": invalid_lines,
        }

    has_url = any(
        item["url"]
        for item in matched_requirements
    )

    if has_url:
        return {
            "status": "unsupported_direct_url",
            "constraint_kind": "direct_url",
            "specifier": "",
            "matched_requirements": matched_requirements,
            "invalid_lines": invalid_lines,
        }

    has_marker = any(
        item["marker"]
        for item in matched_requirements
    )

    specifiers = [
        item["specifier"]
        for item in matched_requirements
        if item["specifier"]
    ]

    combined_specifier = ",".join(specifiers)

    if has_marker:
        return {
            "status": "conditional",
            "constraint_kind": "environment_marker",
            "specifier": combined_specifier,
            "matched_requirements": matched_requirements,
            "invalid_lines": invalid_lines,
        }

    if not combined_specifier:
        return {
            "status": "resolved",
            "constraint_kind": "unconstrained",
            "specifier": "",
            "matched_requirements": matched_requirements,
            "invalid_lines": invalid_lines,
        }

    return {
        "status": "resolved",
        "constraint_kind": "version_specifier",
        "specifier": combined_specifier,
        "matched_requirements": matched_requirements,
        "invalid_lines": invalid_lines,
    }


def exact_pin_from_specifier(specifier: str) -> str | None:
    text = str(specifier or "").strip()
    if not text.startswith("==") or "," in text or ".*" in text:
        return None
    version_text = text[2:].strip()
    if not version_text:
        return None
    try:
        Version(version_text)
    except InvalidVersion:
        return None
    return version_text


def read_sample_lockfile(
    sample: dict[str, Any],
    *,
    root: Path = ROOT,
) -> tuple[str | None, str | None, str | None]:
    inline = sample.get("lockfile_text")
    if inline is not None and str(inline).strip():
        return str(inline), str(sample.get("lockfile_format") or "requirements"), None

    raw_path = str(sample.get("lockfile_path", "") or "").strip()
    if not raw_path:
        return None, None, None

    candidate = Path(raw_path)
    if not candidate.is_absolute():
        candidate = root / candidate

    if not candidate.exists() or not candidate.is_file():
        return None, "missing_file", raw_path

    text = candidate.read_text(encoding="utf-8-sig")
    lowered = candidate.name.lower()
    if lowered == "pipfile.lock" or candidate.suffix.lower() == ".json":
        fmt = "pipfile_lock"
    else:
        fmt = "requirements"

    return text, fmt, raw_path


def parse_lockfile_inventory(
    sample: dict[str, Any],
    *,
    root: Path = ROOT,
) -> dict[str, Any]:
    text, fmt, source_path = read_sample_lockfile(sample, root=root)
    if text is None:
        return {
            "status": "not_provided" if fmt is None else "missing_file",
            "format": fmt,
            "source_path": source_path,
            "entries": [],
            "invalid_entries": [],
        }

    entries: list[dict[str, Any]] = []
    invalid_entries: list[str] = []

    if fmt == "pipfile_lock":
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return {
                "status": "invalid_lockfile",
                "format": fmt,
                "source_path": source_path,
                "entries": [],
                "invalid_entries": ["invalid_json"],
            }

        for section_name in ("default", "develop"):
            section = payload.get(section_name, {})
            if not isinstance(section, dict):
                continue
            for name, meta in section.items():
                if not isinstance(meta, dict):
                    continue
                version_specifier = str(meta.get("version", "") or "").strip()
                entries.append(
                    {
                        "name": str(name),
                        "normalized_name": pep503_normalize(str(name)),
                        "specifier": version_specifier,
                        "exact_version": exact_pin_from_specifier(
                            version_specifier
                        ),
                        "section": section_name,
                    }
                )
    elif fmt == "requirements":
        for raw_line in text.splitlines():
            line = raw_line.strip().lstrip("\ufeff")
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            try:
                requirement = Requirement(line)
            except InvalidRequirement:
                invalid_entries.append(raw_line)
                continue
            specifier = str(requirement.specifier)
            entries.append(
                {
                    "name": requirement.name,
                    "normalized_name": pep503_normalize(
                        requirement.name
                    ),
                    "specifier": specifier,
                    "exact_version": exact_pin_from_specifier(specifier),
                    "section": "requirements",
                }
            )
    else:
        return {
            "status": "unsupported_format",
            "format": fmt,
            "source_path": source_path,
            "entries": [],
            "invalid_entries": [],
        }

    return {
        "status": "resolved",
        "format": fmt,
        "source_path": source_path,
        "entries": entries,
        "invalid_entries": invalid_entries,
    }


def lockfile_declared_distributions(
    sample: dict[str, Any] | None,
    *,
    root: Path = ROOT,
) -> list[str]:
    if sample is None:
        return []

    inventory = parse_lockfile_inventory(sample, root=root)
    result = {
        str(row.get("normalized_name", "")).strip()
        for row in inventory.get("entries", [])
        if isinstance(row, dict)
        and str(row.get("normalized_name", "")).strip()
    }
    return sorted(result)


def resolve_lockfile_constraint(
    sample: dict[str, Any],
    distribution: str,
    *,
    root: Path = ROOT,
) -> dict[str, Any]:
    inventory = parse_lockfile_inventory(sample, root=root)
    normalized = pep503_normalize(distribution)

    if inventory["status"] != "resolved":
        return {
            "status": inventory["status"],
            "constraint_kind": inventory["status"],
            "specifier": "",
            "exact_version": None,
            "format": inventory.get("format"),
            "source_path": inventory.get("source_path"),
            "matched_entries": [],
            "invalid_entries": inventory.get("invalid_entries", []),
        }

    matched = [
        row
        for row in inventory.get("entries", [])
        if isinstance(row, dict)
        and row.get("normalized_name") == normalized
    ]

    if not matched:
        return {
            "status": "not_declared",
            "constraint_kind": "not_declared",
            "specifier": "",
            "exact_version": None,
            "format": inventory.get("format"),
            "source_path": inventory.get("source_path"),
            "matched_entries": [],
            "invalid_entries": inventory.get("invalid_entries", []),
        }

    exact_versions = {
        str(row.get("exact_version"))
        for row in matched
        if row.get("exact_version")
    }

    if len(exact_versions) != 1 or any(
        row.get("exact_version") is None
        for row in matched
    ):
        return {
            "status": "non_exact_lock_constraint",
            "constraint_kind": "non_exact_lock_constraint",
            "specifier": "",
            "exact_version": None,
            "format": inventory.get("format"),
            "source_path": inventory.get("source_path"),
            "matched_entries": matched,
            "invalid_entries": inventory.get("invalid_entries", []),
        }

    version = next(iter(exact_versions))
    return {
        "status": "resolved",
        "constraint_kind": "lockfile_exact_pin",
        "specifier": f"=={version}",
        "exact_version": version,
        "format": inventory.get("format"),
        "source_path": inventory.get("source_path"),
        "matched_entries": matched,
        "invalid_entries": inventory.get("invalid_entries", []),
    }


def _manifest_context_metadata(
    rows: list[dict[str, Any]],
    *,
    available_rows: list[dict[str, Any]] | None = None,
    install_targets: set[str] | None = None,
) -> dict[str, Any]:
    available = available_rows if available_rows is not None else rows
    groups = sorted(
        {
            str(row.get("dependency_group") or "default")
            for row in rows
        }
    )
    files = sorted(
        {
            str(row.get("file") or "")
            for row in rows
            if str(row.get("file") or "").strip()
        }
    )
    selected_contexts = sorted(
        {manifest_context_id_for_row(row) for row in rows}
    )
    available_contexts = sorted(
        {manifest_context_id_for_row(row) for row in available}
    )
    targets = sorted(
        value
        for value in (install_targets or set())
        if str(value).strip()
    )
    return {
        "selected_dependency_group": (
            groups[0] if len(groups) == 1 else None
        ),
        "selected_manifest_files": files,
        "available_dependency_groups": groups,
        "selected_manifest_context_id": (
            selected_contexts[0] if len(selected_contexts) == 1 else None
        ),
        "selected_manifest_context_ids": selected_contexts,
        "available_manifest_context_ids": available_contexts,
        "selected_install_target": (
            targets[0] if len(targets) == 1 else None
        ),
        "available_install_targets": targets,
    }


def _relevant_installability_unresolved(
    project_facts: dict[str, Any],
    distribution: str,
) -> list[dict[str, Any]]:
    """Keep unresolved install contexts that can affect this distribution.

    Package-scoped rows can be filtered precisely.  Context-scoped rows are
    deliberately retained because dynamic project metadata, a variable local
    target, or an unresolved cwd can contain the distribution even when the
    extractor cannot enumerate its dependencies.
    """
    normalized = pep503_normalize(distribution)
    relevant: list[dict[str, Any]] = []
    for value in project_facts.get("installability_unresolved", []):
        if not isinstance(value, dict):
            continue
        raw_package = str(value.get("package") or "").strip()
        if raw_package and pep503_normalize(raw_package) != normalized:
            continue
        relevant.append(dict(value))
    return sorted(
        relevant,
        key=lambda row: (
            str(row.get("file") or ""),
            int(row.get("line") or 0),
            str(row.get("install_target") or row.get("target") or ""),
            str(row.get("reason") or ""),
        ),
    )


def manifest_constraint_from_project_facts(
    project_facts: dict[str, Any],
    distribution: str,
) -> dict[str, Any]:
    normalized = pep503_normalize(distribution)
    all_rows = [
        row
        for row in project_facts.get("manifests", {}).get(
            normalized, []
        )
        if isinstance(row, dict)
    ]
    unresolved_installability = _relevant_installability_unresolved(
        project_facts,
        normalized,
    )
    if unresolved_installability:
        install_targets = {
            str(
                row.get("install_target")
                or row.get("target")
                or ""
            ).strip()
            for row in unresolved_installability
            if str(
                row.get("install_target")
                or row.get("target")
                or ""
            ).strip()
        }
        return {
            "status": "manifest_context_unresolved",
            "constraint_kind": "installability_unresolved",
            "specifier": "",
            "matched_requirements": all_rows,
            "invalid_lines": [],
            **_manifest_context_metadata(
                all_rows,
                install_targets=install_targets,
            ),
            "installability_unresolved": unresolved_installability,
            "context_selection": "installability_unresolved",
        }
    if not all_rows:
        return {
            "status": "not_declared",
            "constraint_kind": "not_declared",
            "specifier": "",
            "matched_requirements": [],
            "invalid_lines": [],
            "selected_dependency_group": None,
            "selected_manifest_files": [],
            "available_dependency_groups": [],
            "selected_manifest_context_id": None,
            "selected_manifest_context_ids": [],
            "available_manifest_context_ids": [],
            "selected_install_target": None,
            "available_install_targets": [],
            "context_selection": "not_declared",
        }

    install_rows = [
        row
        for row in project_facts.get("installability", {}).get(
            normalized, []
        )
        if isinstance(row, dict)
    ]
    bound_install_rows = [
        row
        for row in install_rows
        if str(row.get("manifest_file") or "").strip()
    ]
    bound_files = {
        str(row.get("manifest_file") or "").strip()
        for row in bound_install_rows
        if str(row.get("manifest_file") or "").strip()
    }
    bound_targets = {
        str(row.get("install_target") or "").strip()
        for row in bound_install_rows
        if str(row.get("install_target") or "").strip()
    }

    context_selection = "single_or_default_group"
    if bound_files:
        if len(bound_targets) != 1:
            meta = _manifest_context_metadata(
                all_rows,
                install_targets=bound_targets,
            )
            return {
                "status": "manifest_context_unresolved",
                "constraint_kind": "multiple_install_targets",
                "specifier": "",
                "matched_requirements": all_rows,
                "invalid_lines": [],
                **meta,
                "context_selection": "ambiguous_install_targets",
            }
        rows = [
            row
            for row in all_rows
            if str(row.get("file") or "").strip() in bound_files
        ]
        context_selection = "install_target_bound"
        if not rows:
            meta = _manifest_context_metadata(
                all_rows,
                install_targets=bound_targets,
            )
            return {
                "status": "manifest_context_unresolved",
                "constraint_kind": "install_target_manifest_not_found",
                "specifier": "",
                "matched_requirements": all_rows,
                "invalid_lines": [],
                **meta,
                "context_selection": context_selection,
            }
    else:
        context_rows: dict[str, list[dict[str, Any]]] = {}
        for row in all_rows:
            context_rows.setdefault(
                manifest_context_id_for_row(row), []
            ).append(row)
        default_context_ids = sorted(
            {
                manifest_context_id_for_row(row)
                for row in all_rows
                if str(row.get("dependency_group") or "default")
                == "default"
            }
        )
        if len(default_context_ids) == 1:
            rows = context_rows[default_context_ids[0]]
            context_selection = "single_default_context"
        elif len(default_context_ids) > 1:
            meta = _manifest_context_metadata(all_rows)
            return {
                "status": "manifest_context_unresolved",
                "constraint_kind": "multiple_default_manifest_contexts",
                "specifier": "",
                "matched_requirements": all_rows,
                "invalid_lines": [],
                **meta,
                "context_selection": "ambiguous_default_contexts",
            }
        elif len(context_rows) == 1:
            rows = next(iter(context_rows.values()))
            context_selection = "single_manifest_context"
        else:
            meta = _manifest_context_metadata(all_rows)
            return {
                "status": "manifest_context_unresolved",
                "constraint_kind": "multiple_manifest_contexts",
                "specifier": "",
                "matched_requirements": all_rows,
                "invalid_lines": [],
                **meta,
                "context_selection": "ambiguous_groups",
            }

    meta = _manifest_context_metadata(
        rows,
        available_rows=all_rows,
        install_targets=bound_targets,
    )
    if (
        meta["selected_dependency_group"] is None
        and context_selection != "install_target_bound"
    ):
        return {
            "status": "manifest_context_unresolved",
            "constraint_kind": "multiple_active_dependency_groups",
            "specifier": "",
            "matched_requirements": rows,
            "invalid_lines": [],
            **meta,
            "context_selection": context_selection,
        }

    statuses = {
        str(row.get("constraint_status") or "resolved")
        for row in rows
    }
    common = {
        **meta,
        "context_selection": context_selection,
    }
    if statuses & {
        "unsupported_direct_url",
        "unsupported_direct_source",
    }:
        return {
            "status": "unsupported_direct_url",
            "constraint_kind": "direct_url",
            "specifier": "",
            "matched_requirements": rows,
            "invalid_lines": [],
            **common,
        }
    if "conditional" in statuses:
        return {
            "status": "conditional",
            "constraint_kind": "environment_marker",
            "specifier": "",
            "matched_requirements": rows,
            "invalid_lines": [],
            **common,
        }
    if "unsupported_manifest_syntax" in statuses:
        return {
            "status": "manifest_context_unresolved",
            "constraint_kind": "unsupported_manifest_syntax",
            "specifier": "",
            "matched_requirements": rows,
            "invalid_lines": [],
            **common,
        }

    specifiers = [
        str(row.get("specifier") or "").strip()
        for row in rows
        if str(row.get("specifier") or "").strip()
    ]
    combined = ",".join(specifiers)
    if not combined:
        return {
            "status": "resolved",
            "constraint_kind": "unconstrained",
            "specifier": "",
            "matched_requirements": rows,
            "invalid_lines": [],
            **common,
        }
    try:
        SpecifierSet(combined)
    except InvalidSpecifier:
        return {
            "status": "manifest_context_unresolved",
            "constraint_kind": "combined_specifier_invalid",
            "specifier": "",
            "matched_requirements": rows,
            "invalid_lines": [],
            **common,
        }
    return {
        "status": "resolved",
        "constraint_kind": "version_specifier",
        "specifier": combined,
        "matched_requirements": rows,
        "invalid_lines": [],
        **common,
    }


def lock_constraint_from_project_facts(
    project_facts: dict[str, Any],
    distribution: str,
    *,
    dependency_group: str | None = None,
    manifest_context_ids: list[str] | None = None,
) -> dict[str, Any]:
    normalized = pep503_normalize(distribution)
    all_rows = [
        row
        for row in project_facts.get("locks", {}).get(
            normalized, []
        )
        if isinstance(row, dict)
    ]
    rows = all_rows
    selected_context_ids = {
        str(value).strip()
        for value in (manifest_context_ids or [])
        if str(value).strip()
    }
    if selected_context_ids:
        rows = [
            row
            for row in all_rows
            if manifest_context_id_for_row(row) in selected_context_ids
        ]
    elif dependency_group is not None:
        rows = [
            row
            for row in all_rows
            if str(row.get("dependency_group") or "default")
            == dependency_group
        ]

    if not rows:
        return {
            "status": "not_declared",
            "constraint_kind": "not_declared",
            "specifier": "",
            "exact_version": None,
            "format": "project_snapshot",
            "source_path": None,
            "matched_entries": [],
            "invalid_entries": [],
            "selected_dependency_group": dependency_group,
            "selected_manifest_context_ids": sorted(selected_context_ids),
        }

    exact_versions = {
        str(row.get("exact_version"))
        for row in rows
        if row.get("exact_version")
    }
    if len(exact_versions) != 1 or any(
        row.get("exact_version") is None
        for row in rows
    ):
        return {
            "status": "non_exact_lock_constraint",
            "constraint_kind": "non_exact_lock_constraint",
            "specifier": "",
            "exact_version": None,
            "format": "project_snapshot",
            "source_path": None,
            "matched_entries": rows,
            "invalid_entries": [],
            "selected_dependency_group": dependency_group,
            "selected_manifest_context_ids": sorted(selected_context_ids),
        }

    version = next(iter(exact_versions))
    return {
        "status": "resolved",
        "constraint_kind": "lockfile_exact_pin",
        "specifier": f"=={version}",
        "exact_version": version,
        "format": "project_snapshot",
        "source_path": str(rows[0].get("file") or ""),
        "matched_entries": rows,
        "invalid_entries": [],
        "selected_dependency_group": dependency_group,
        "selected_manifest_context_ids": sorted(selected_context_ids),
    }


def manifest_accepts_exact_version(
    manifest_constraint: dict[str, Any],
    version_text: str,
) -> bool | None:
    status = str(manifest_constraint.get("status", ""))
    kind = str(manifest_constraint.get("constraint_kind", ""))

    if status == "not_declared":
        return True
    if status != "resolved":
        return None
    if kind == "unconstrained":
        return True

    specifier_text = str(manifest_constraint.get("specifier", "")).strip()
    if not specifier_text:
        return True

    try:
        specifier = SpecifierSet(specifier_text)
        version = Version(version_text)
    except (InvalidSpecifier, InvalidVersion):
        return None

    return specifier.contains(version, prereleases=True)


def resolve_manifest_constraints(
    sample: dict[str, Any],
    distribution: str,
    *,
    project_root: Path | None = None,
    project_facts_override: dict[str, Any] | None = None,
    identity_policy_path: Path = DEFAULT_IDENTITY_POLICY,
) -> dict[str, Any]:
    sample_id = str(sample.get("sample_id", ""))
    requirements_text = str(
        sample.get("requirements_text", "") or ""
    )

    if (
        project_facts_override is not None
        and project_root is not None
    ):
        raise ValueError(
            "resolve_manifest_constraints received both canonical "
            "project facts and project_root"
        )

    project_facts: dict[str, Any] | None = project_facts_override
    if project_facts is not None:
        if project_facts.get("schema_version") != FACTS_SCHEMA_VERSION:
            raise ValueError(
                "Unexpected canonical project dependency facts schema"
            )
        manifest_constraint = manifest_constraint_from_project_facts(
            project_facts,
            distribution,
        )
        lockfile_constraint = lock_constraint_from_project_facts(
            project_facts,
            distribution,
            dependency_group=manifest_constraint.get(
                "selected_dependency_group"
            ),
            manifest_context_ids=manifest_constraint.get(
                "selected_manifest_context_ids"
            ),
        )
    elif project_root is not None:
        project_facts = collect_project_dependency_facts(
            project_root,
            identity_policy_path=identity_policy_path,
        )
        manifest_constraint = manifest_constraint_from_project_facts(
            project_facts,
            distribution,
        )
        lockfile_constraint = lock_constraint_from_project_facts(
            project_facts,
            distribution,
            dependency_group=manifest_constraint.get(
                "selected_dependency_group"
            ),
            manifest_context_ids=manifest_constraint.get(
                "selected_manifest_context_ids"
            ),
        )
    else:
        manifest_constraint = parse_manifest_constraints(
            requirements_text=requirements_text,
            distribution=distribution,
        )
        lockfile_constraint = resolve_lockfile_constraint(
            sample,
            distribution,
        )

    final_status = manifest_constraint["status"]
    final_kind = manifest_constraint["constraint_kind"]
    final_specifier = manifest_constraint["specifier"]
    constraint_source = "manifest"

    if lockfile_constraint["status"] == "resolved":
        exact_version = str(lockfile_constraint["exact_version"])
        compatible = manifest_accepts_exact_version(
            manifest_constraint,
            exact_version,
        )
        if compatible is False:
            final_status = "conflicted"
            final_kind = "manifest_lockfile_conflict"
            final_specifier = ""
            constraint_source = "conflict"
        elif compatible is None:
            final_status = "manifest_context_unresolved"
            final_kind = "manifest_context_unresolved_with_lockfile"
            final_specifier = ""
            constraint_source = "unknown"
        else:
            final_status = "resolved"
            final_kind = "lockfile_exact_pin"
            final_specifier = lockfile_constraint["specifier"]
            constraint_source = "lockfile"
    elif (
        manifest_constraint["status"] == "not_declared"
        and lockfile_constraint["status"]
        not in {"not_provided", "not_declared"}
    ):
        final_status = lockfile_constraint["status"]
        final_kind = lockfile_constraint["constraint_kind"]
        final_specifier = ""
        constraint_source = "lockfile"

    return {
        "schema_version": "avcs_manifest_constraints_v0.2",
        "sample_id": sample_id,
        "distribution": distribution,
        "normalized_distribution": pep503_normalize(
            distribution
        ),
        "requirements_text": requirements_text,
        "project_dependency_facts_schema": (
            FACTS_SCHEMA_VERSION
            if project_facts is not None
            else None
        ),
        "project_snapshot_bound": project_facts is not None,
        "status": final_status,
        "constraint_kind": final_kind,
        "specifier": final_specifier,
        "constraint_source": constraint_source,
        "matched_requirements": manifest_constraint[
            "matched_requirements"
        ],
        "invalid_lines": manifest_constraint["invalid_lines"],
        "manifest": manifest_constraint,
        "lockfile": lockfile_constraint,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Resolve AVCS manifest and minimal Python lockfile constraints."
        )
    )

    parser.add_argument(
        "--samples",
        type=Path,
        required=True,
    )

    parser.add_argument(
        "--sample-id",
        required=True,
    )

    parser.add_argument(
        "--distribution",
        required=True,
    )

    parser.add_argument(
        "--out",
        type=Path,
        required=True,
    )

    args = parser.parse_args()

    samples = read_jsonl(args.samples)

    sample = find_sample(
        samples,
        args.sample_id,
    )

    if sample is None:
        raise SystemExit(
            f"[FAIL] sample not found: {args.sample_id}"
        )

    result = resolve_manifest_constraints(
        sample=sample,
        distribution=args.distribution,
    )

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
    print(f"[OK] status: {result['status']}")
    print(
        f"[OK] constraint kind: "
        f"{result['constraint_kind']}"
    )
    print(
        f"[OK] effective specifier: "
        f"{result['specifier'] or '(unconstrained/unknown)'}"
    )
    print(f"[OK] result saved to: {args.out}")


if __name__ == "__main__":
    main()
