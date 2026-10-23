from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(
    __file__
).resolve().parents[1]


PIPELINE_VERSION = (
    "rq1_evidence_automation_pipeline_v0.1"
)

CURRENT_ECOSYSTEM = "PyPI"


def now_iso() -> str:
    return datetime.now(
        timezone.utc
    ).isoformat()


def clean_text(
    value: Any,
) -> str:
    if value is None:
        return ""

    return str(
        value
    ).strip()


def safe_component(
    value: str,
) -> str:
    result = re.sub(
        r"[^A-Za-z0-9._-]+",
        "_",
        clean_text(
            value
        ),
    )

    return (
        result
        or "unknown"
    )


def project_path(
    value: Path,
    *,
    must_exist: bool = False,
) -> Path:
    path = value

    if not path.is_absolute():
        path = (
            ROOT
            / path
        )

    path = path.resolve()

    try:
        path.relative_to(
            ROOT.resolve()
        )

    except ValueError as exc:
        raise ValueError(
            "RQ1 pipeline paths must stay "
            "inside the project root: "
            f"{path}"
        ) from exc

    if (
        must_exist
        and not path.exists()
    ):
        raise FileNotFoundError(
            path
        )

    return path


def project_relative(
    value: Path,
) -> str:
    try:
        return str(
            value.resolve().relative_to(
                ROOT.resolve()
            )
        ).replace(
            "\\",
            "/",
        )

    except ValueError:
        return str(
            value
        ).replace(
            "\\",
            "/",
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


def inventory_cases(
    inventory: dict[str, Any],
) -> list[dict[str, Any]]:
    raw_cases = inventory.get(
        "cases",
        [],
    )

    if not isinstance(
        raw_cases,
        list,
    ):
        raise ValueError(
            "Inventory field 'cases' "
            "must be a list."
        )

    return [
        row
        for row in raw_cases
        if isinstance(
            row,
            dict,
        )
    ]


def inventory_distributions(
    inventory: dict[str, Any],
    *,
    ecosystem: str,
) -> list[str]:
    distributions: set[str] = set()

    for index, case in enumerate(
        inventory_cases(
            inventory
        )
    ):
        distribution = clean_text(
            case.get(
                "distribution",
                case.get(
                    "normalized_distribution"
                ),
            )
        )

        if not distribution:
            raise ValueError(
                "Inventory case "
                f"{index} has no distribution."
            )

        case_ecosystem = clean_text(
            case.get(
                "ecosystem"
            )
        )

        if (
            case_ecosystem
            and case_ecosystem.lower()
            != ecosystem.lower()
        ):
            raise ValueError(
                "Mixed or unsupported ecosystem "
                "in current RQ1 runner: "
                f"{case_ecosystem}"
            )

        distributions.add(
            distribution
        )

    if not distributions:
        raise ValueError(
            "Inventory contains no "
            "package distributions."
        )

    return sorted(
        distributions,
        key=str.lower,
    )


def python_command(
    script_name: str,
    *arguments: str,
) -> list[str]:
    return [
        sys.executable,
        str(
            ROOT
            / "src"
            / script_name
        ),
        *arguments,
    ]


def stage(
    name: str,
    command: list[str],
) -> dict[str, Any]:
    return {
        "name":
            name,

        "command":
            command,
    }


def build_paths(
    out_dir: Path,
) -> dict[str, Path]:

    return {
        "manifest":
            out_dir
            / "00_pipeline_manifest.json",

        "summary":
            out_dir
            / "22_pipeline_summary.json",

        "osv_query_cache":
            out_dir
            / "cache"
            / "osv_query",

        "osv_raw":
            out_dir
            / "osv_raw",

        "osv_snapshots":
            out_dir
            / "01_osv_snapshots",

        "seed_plan":
            out_dir
            / "02_seed_source_plan.json",

        "seed_local":
            out_dir
            / "03_seed_local_acquisition.json",

        "discovery":
            out_dir
            / "04_osv_reference_discovery.json",

        "expanded_inventory":
            out_dir
            / "05_expanded_inventory.json",

        "expanded_plan":
            out_dir
            / "06_expanded_source_plan.json",

        "local":
            out_dir
            / "07_local_structured_acquisition.json",

        "github_files":
            out_dir
            / "08_github_file_acquisition.json",

        "github_commits":
            out_dir
            / "09_github_commit_acquisition.json",

        "github_metadata":
            out_dir
            / "10_github_metadata_acquisition.json",

        "generic_http":
            out_dir
            / "11_generic_http_acquisition.json",

        "structured_corpus":
            out_dir
            / "12_structured_corpus.json",

        "augmented_corpus":
            out_dir
            / "13_augmented_corpus.json",

        "atomic_facts":
            out_dir
            / "14_atomic_facts.json",

        "atomic_validation":
            out_dir
            / "15_atomic_validation.json",

        "semantic_relations":
            out_dir
            / "16_semantic_relations.json",

        "semantic_validation":
            out_dir
            / "17_semantic_validation.json",

        "version_drafts":
            out_dir
            / "18_version_drafts.json",

        "semantic_drafts":
            out_dir
            / "19_semantic_drafts.json",

        "version_aware_drafts":
            out_dir
            / "20_version_aware_drafts.json",

        "admission":
            out_dir
            / "21_executable_admission.json",

        "github_file_cache":
            out_dir
            / "cache"
            / "github_files",

        "github_commit_cache":
            out_dir
            / "cache"
            / "github_commits",

        "github_metadata_cache":
            out_dir
            / "cache"
            / "github_metadata",

        "generic_http_cache":
            out_dir
            / "cache"
            / "generic_http",
    }


def build_pipeline_plan(
    *,
    inventory_path: Path,
    out_dir: Path,
    ecosystem: str,
    refresh: bool,
    timeout: int,
) -> dict[str, Any]:

    inventory_path = project_path(
        inventory_path,
        must_exist=True,
    )

    out_dir = project_path(
        out_dir
    )

    inventory = load_json(
        inventory_path
    )

    if (
        ecosystem.lower()
        != CURRENT_ECOSYSTEM.lower()
    ):
        raise ValueError(
            "RQ1 Evidence Pipeline v0 "
            "currently supports PyPI only. "
            "npm automation remains outside "
            "the frozen current capability."
        )

    distributions = (
        inventory_distributions(
            inventory,
            ecosystem=ecosystem,
        )
    )

    paths = build_paths(
        out_dir
    )

    stages: list[
        dict[str, Any]
    ] = []

    # --------------------------------------------------
    # Stage 1:
    # Materialize OSV package vulnerability records.
    #
    # This gives the local structured acquisition
    # backend a complete package-scoped OSV mirror.
    # --------------------------------------------------

    for distribution in distributions:
        snapshot_path = (
            paths[
                "osv_snapshots"
            ]
            / (
                safe_component(
                    distribution
                )
                + ".json"
            )
        )

        command = python_command(
            "fetch_osv_package_vulnerabilities.py",

            "--distribution",
            distribution,

            "--ecosystem",
            ecosystem,

            "--query-cache-dir",
            str(
                paths[
                    "osv_query_cache"
                ]
            ),

            "--record-cache-dir",
            str(
                paths[
                    "osv_raw"
                ]
            ),

            "--timeout",
            str(
                timeout
            ),

            "--out",
            str(
                snapshot_path
            ),
        )

        if refresh:
            command.append(
                "--refresh"
            )

        stages.append(
            stage(
                (
                    "fetch_osv_"
                    + safe_component(
                        distribution
                    )
                ),
                command,
            )
        )

    # --------------------------------------------------
    # Stage 2:
    # Compile seed source acquisition plan.
    # --------------------------------------------------

    stages.append(
        stage(
            "compile_seed_source_plan",
            python_command(
                "compile_trigger_source_acquisition_plan.py",

                "--inventory",
                str(
                    inventory_path
                ),

                "--out",
                str(
                    paths[
                        "seed_plan"
                    ]
                ),
            ),
        )
    )

    # --------------------------------------------------
    # Stage 3:
    # Resolve seed local/OSV structured evidence.
    # --------------------------------------------------

    stages.append(
        stage(
            "acquire_seed_local_structured",
            python_command(
                "acquire_trigger_local_structured_evidence.py",

                "--plan",
                str(
                    paths[
                        "seed_plan"
                    ]
                ),

                "--osv-raw-dir",
                str(
                    paths[
                        "osv_raw"
                    ]
                ),

                "--out",
                str(
                    paths[
                        "seed_local"
                    ]
                ),
            ),
        )
    )

    # --------------------------------------------------
    # Stage 4:
    # Discover follow-up evidence sources from
    # the acquired OSV records.
    # --------------------------------------------------

    stages.append(
        stage(
            "discover_osv_references",
            python_command(
                "discover_osv_reference_sources.py",

                "--seed-inventory",
                str(
                    inventory_path
                ),

                "--local-acquisition",
                str(
                    paths[
                        "seed_local"
                    ]
                ),

                "--out",
                str(
                    paths[
                        "discovery"
                    ]
                ),

                "--out-inventory",
                str(
                    paths[
                        "expanded_inventory"
                    ]
                ),
            ),
        )
    )

    # --------------------------------------------------
    # Stage 5:
    # Compile the expanded source plan.
    # --------------------------------------------------

    stages.append(
        stage(
            "compile_expanded_source_plan",
            python_command(
                "compile_trigger_source_acquisition_plan.py",

                "--inventory",
                str(
                    paths[
                        "expanded_inventory"
                    ]
                ),

                "--out",
                str(
                    paths[
                        "expanded_plan"
                    ]
                ),
            ),
        )
    )

    # --------------------------------------------------
    # Stage 6:
    # Acquire all currently supported evidence backends.
    #
    # Each backend remains independent so unsupported
    # evidence stays explicit instead of being hidden.
    # --------------------------------------------------

    stages.append(
        stage(
            "acquire_local_structured",
            python_command(
                "acquire_trigger_local_structured_evidence.py",

                "--plan",
                str(
                    paths[
                        "expanded_plan"
                    ]
                ),

                "--osv-raw-dir",
                str(
                    paths[
                        "osv_raw"
                    ]
                ),

                "--out",
                str(
                    paths[
                        "local"
                    ]
                ),
            ),
        )
    )

    github_file_command = (
        python_command(
            "acquire_trigger_github_file_evidence.py",

            "--plan",
            str(
                paths[
                    "expanded_plan"
                ]
            ),

            "--cache-dir",
            str(
                paths[
                    "github_file_cache"
                ]
            ),

            "--timeout",
            str(
                timeout
            ),

            "--out",
            str(
                paths[
                    "github_files"
                ]
            ),
        )
    )

    if refresh:
        github_file_command.append(
            "--refresh"
        )

    stages.append(
        stage(
            "acquire_github_files",
            github_file_command,
        )
    )

    github_commit_command = (
        python_command(
            "acquire_trigger_github_commit_evidence.py",

            "--plan",
            str(
                paths[
                    "expanded_plan"
                ]
            ),

            "--cache-dir",
            str(
                paths[
                    "github_commit_cache"
                ]
            ),

            "--timeout",
            str(
                timeout
            ),

            "--out",
            str(
                paths[
                    "github_commits"
                ]
            ),
        )
    )

    if refresh:
        github_commit_command.append(
            "--refresh"
        )

    stages.append(
        stage(
            "acquire_github_commits",
            github_commit_command,
        )
    )

    github_metadata_command = (
        python_command(
            "acquire_trigger_github_metadata_evidence.py",

            "--plan",
            str(
                paths[
                    "expanded_plan"
                ]
            ),

            "--cache-dir",
            str(
                paths[
                    "github_metadata_cache"
                ]
            ),

            "--timeout",
            str(
                timeout
            ),

            "--out",
            str(
                paths[
                    "github_metadata"
                ]
            ),
        )
    )

    if refresh:
        github_metadata_command.append(
            "--refresh"
        )

    stages.append(
        stage(
            "acquire_github_metadata",
            github_metadata_command,
        )
    )

    stages.append(
        stage(
            "acquire_generic_http",
            python_command(
                "acquire_trigger_generic_http_evidence.py",

                "--plan",
                str(
                    paths[
                        "expanded_plan"
                    ]
                ),

                "--cache-dir",
                str(
                    paths[
                        "generic_http_cache"
                    ]
                ),

                "--timeout",
                str(
                    timeout
                ),

                "--out",
                str(
                    paths[
                        "generic_http"
                    ]
                ),
            ),
        )
    )

    # --------------------------------------------------
    # Stage 7:
    # Build provenance-preserving corpus.
    # --------------------------------------------------

    stages.append(
        stage(
            "build_structured_corpus",
            python_command(
                "build_trigger_candidate_evidence_corpus.py",

                "--plan",
                str(
                    paths[
                        "expanded_plan"
                    ]
                ),

                "--local",
                str(
                    paths[
                        "local"
                    ]
                ),

                "--github-files",
                str(
                    paths[
                        "github_files"
                    ]
                ),

                "--github-commits",
                str(
                    paths[
                        "github_commits"
                    ]
                ),

                "--github-metadata",
                str(
                    paths[
                        "github_metadata"
                    ]
                ),

                "--out",
                str(
                    paths[
                        "structured_corpus"
                    ]
                ),
            ),
        )
    )

    # --------------------------------------------------
    # Stage 8:
    # Admit target-specific generic semantic text.
    #
    # Generic web evidence still cannot contribute
    # version facts.
    # --------------------------------------------------

    stages.append(
        stage(
            "augment_generic_semantics",
            python_command(
                (
                    "augment_trigger_candidate_"
                    "evidence_corpus_with_"
                    "generic_semantics.py"
                ),

                "--corpus",
                str(
                    paths[
                        "structured_corpus"
                    ]
                ),

                "--generic-http",
                str(
                    paths[
                        "generic_http"
                    ]
                ),

                "--out",
                str(
                    paths[
                        "augmented_corpus"
                    ]
                ),
            ),
        )
    )

    # --------------------------------------------------
    # Stage 9:
    # Atomic fact extraction + conservative validation.
    # --------------------------------------------------

    stages.append(
        stage(
            "extract_atomic_facts",
            python_command(
                "extract_trigger_candidate_facts.py",

                "--corpus",
                str(
                    paths[
                        "augmented_corpus"
                    ]
                ),

                "--out",
                str(
                    paths[
                        "atomic_facts"
                    ]
                ),
            ),
        )
    )

    stages.append(
        stage(
            "validate_atomic_facts",
            python_command(
                "validate_trigger_candidate_facts.py",

                "--corpus",
                str(
                    paths[
                        "augmented_corpus"
                    ]
                ),

                "--facts",
                str(
                    paths[
                        "atomic_facts"
                    ]
                ),

                "--out",
                str(
                    paths[
                        "atomic_validation"
                    ]
                ),
            ),
        )
    )

    # --------------------------------------------------
    # Stage 10:
    # Semantic relation extraction + validation.
    # --------------------------------------------------

    stages.append(
        stage(
            "extract_semantic_relations",
            python_command(
                (
                    "extract_trigger_semantic_"
                    "relation_candidates.py"
                ),

                "--corpus",
                str(
                    paths[
                        "augmented_corpus"
                    ]
                ),

                "--out",
                str(
                    paths[
                        "semantic_relations"
                    ]
                ),
            ),
        )
    )

    stages.append(
        stage(
            "validate_semantic_relations",
            python_command(
                "validate_trigger_candidate_facts.py",

                "--corpus",
                str(
                    paths[
                        "augmented_corpus"
                    ]
                ),

                "--facts",
                str(
                    paths[
                        "semantic_relations"
                    ]
                ),

                "--out",
                str(
                    paths[
                        "semantic_validation"
                    ]
                ),
            ),
        )
    )

    # --------------------------------------------------
    # Stage 11:
    # Compile version and semantic drafts independently.
    # --------------------------------------------------

    stages.append(
        stage(
            "compile_version_drafts",
            python_command(
                "compile_trigger_evidence_drafts.py",

                "--corpus",
                str(
                    paths[
                        "augmented_corpus"
                    ]
                ),

                "--facts",
                str(
                    paths[
                        "atomic_facts"
                    ]
                ),

                "--validation",
                str(
                    paths[
                        "atomic_validation"
                    ]
                ),

                "--out",
                str(
                    paths[
                        "version_drafts"
                    ]
                ),
            ),
        )
    )

    stages.append(
        stage(
            "compile_semantic_drafts",
            python_command(
                "compile_trigger_semantic_drafts.py",

                "--corpus",
                str(
                    paths[
                        "augmented_corpus"
                    ]
                ),

                "--relations",
                str(
                    paths[
                        "semantic_relations"
                    ]
                ),

                "--validation",
                str(
                    paths[
                        "semantic_validation"
                    ]
                ),

                "--out",
                str(
                    paths[
                        "semantic_drafts"
                    ]
                ),
            ),
        )
    )

    # --------------------------------------------------
    # Stage 12:
    # Identity-level version/semantic join.
    #
    # This still does NOT prove per-version
    # Trigger semantics.
    # --------------------------------------------------

    stages.append(
        stage(
            "join_version_aware_drafts",
            python_command(
                (
                    "join_version_aware_"
                    "trigger_evidence_drafts.py"
                ),

                "--version-drafts",
                str(
                    paths[
                        "version_drafts"
                    ]
                ),

                "--semantic-drafts",
                str(
                    paths[
                        "semantic_drafts"
                    ]
                ),

                "--out",
                str(
                    paths[
                        "version_aware_drafts"
                    ]
                ),
            ),
        )
    )

    # --------------------------------------------------
    # Stage 13:
    # Conservative executable admission.
    # --------------------------------------------------

    stages.append(
        stage(
            "build_executable_admission",
            python_command(
                "build_executable_trigger_admission.py",

                "--version-aware-drafts",
                str(
                    paths[
                        "version_aware_drafts"
                    ]
                ),

                "--out",
                str(
                    paths[
                        "admission"
                    ]
                ),
            ),
        )
    )

    return {
        "pipeline_version":
            PIPELINE_VERSION,

        "ecosystem":
            ecosystem,

        "inventory":
            project_relative(
                inventory_path
            ),

        "case_count":
            len(
                inventory_cases(
                    inventory
                )
            ),

        "distributions":
            distributions,

        "output_dir":
            project_relative(
                out_dir
            ),

        "refresh":
            refresh,

        "timeout_seconds":
            timeout,

        "artifacts": {
            key:
                project_relative(
                    value
                )
            for key, value
            in paths.items()
        },

        "stages":
            stages,
    }


def render_command(
    command: list[str],
) -> str:
    return subprocess.list2cmdline(
        command
    )


def stage_for_manifest(
    item: dict[str, Any],
    *,
    status: str,
    return_code: int | None,
) -> dict[str, Any]:
    return {
        "name":
            item.get(
                "name"
            ),

        "status":
            status,

        "return_code":
            return_code,

        "command":
            render_command(
                item.get(
                    "command",
                    [],
                )
            ),
    }


def optional_summary(
    path: Path,
) -> dict[str, Any] | None:
    if not path.is_file():
        return None

    try:
        data = load_json(
            path
        )

    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
    ):
        return None

    summary = data.get(
        "summary"
    )

    if not isinstance(
        summary,
        dict,
    ):
        return None

    return summary


def optional_metrics(
    path: Path,
) -> dict[str, Any] | None:
    """
    Read compact metrics from either historical artifact shape:

    1. {"summary": {...}}
    2. top-level metric fields + large results/sources arrays

    The adapter is summary-only and never changes evidence semantics.
    """

    if not path.is_file():
        return None

    try:
        data = load_json(
            path
        )

    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
    ):
        return None

    nested_summary = data.get(
        "summary"
    )

    if isinstance(
        nested_summary,
        dict,
    ):
        return nested_summary

    excluded_keys = {
        "results",
        "sources",
        "cases",
        "entries",
        "records",
        "items",
        "admission_records",
        "unresolved_sources",
        "discovered_sources",
        "limitations",
    }

    compact: dict[
        str,
        Any
    ] = {}

    for key, value in data.items():

        if key in excluded_keys:
            continue

        # Avoid copying large record collections
        # into the final pipeline summary.
        if isinstance(
            value,
            list,
        ):
            continue

        compact[
            key
        ] = value

    return compact


def summary_count(
    summary: dict[str, Any] | None,
    key: str,
) -> int:
    if not isinstance(
        summary,
        dict,
    ):
        return 0

    value = summary.get(
        key,
        0,
    )

    try:
        return int(
            value
            or 0
        )

    except (
        TypeError,
        ValueError,
    ):
        return 0


def safe_rate(
    numerator: int,
    denominator: int,
) -> float | None:
    if denominator <= 0:
        return None

    return (
        numerator
        / denominator
    )


def build_acquisition_overview(
    paths: dict[str, Path],
) -> dict[str, Any]:

    seed_local = optional_metrics(
        paths[
            "seed_local"
        ]
    )

    github_files = optional_metrics(
        paths[
            "github_files"
        ]
    )

    github_commits = optional_metrics(
        paths[
            "github_commits"
        ]
    )

    github_metadata = optional_metrics(
        paths[
            "github_metadata"
        ]
    )

    generic_http = optional_metrics(
        paths[
            "generic_http"
        ]
    )

    seed_selected = summary_count(
        seed_local,
        "selected_source_count",
    )

    seed_resolved = summary_count(
        seed_local,
        "resolved_source_count",
    )

    structured_selected = sum(
        [
            summary_count(
                github_files,
                "selected_source_count",
            ),

            summary_count(
                github_commits,
                "selected_source_count",
            ),

            summary_count(
                github_metadata,
                "selected_source_count",
            ),
        ]
    )

    structured_resolved = sum(
        [
            summary_count(
                github_files,
                "resolved_source_count",
            ),

            summary_count(
                github_commits,
                "resolved_source_count",
            ),

            summary_count(
                github_metadata,
                "resolved_source_count",
            ),
        ]
    )

    generic_selected = summary_count(
        generic_http,
        "selected_source_count",
    )

    generic_resolved = summary_count(
        generic_http,
        "resolved_source_count",
    )

    network_selected = (
        structured_selected
        + generic_selected
    )

    network_resolved = (
        structured_resolved
        + generic_resolved
    )

    return {
        "seed_source_selected_count":
            seed_selected,

        "seed_source_resolved_count":
            seed_resolved,

        "seed_source_resolution_rate":
            safe_rate(
                seed_resolved,
                seed_selected,
            ),

        "structured_followup_selected_count":
            structured_selected,

        "structured_followup_resolved_count":
            structured_resolved,

        "structured_followup_acquisition_rate":
            safe_rate(
                structured_resolved,
                structured_selected,
            ),

        "generic_http_selected_count":
            generic_selected,

        "generic_http_resolved_count":
            generic_resolved,

        "generic_http_unresolved_count":
            (
                generic_selected
                - generic_resolved
            ),

        "generic_http_acquisition_rate":
            safe_rate(
                generic_resolved,
                generic_selected,
            ),

        "network_acquirable_followup_count":
            network_selected,

        "network_acquirable_followup_resolved_count":
            network_resolved,

        "network_acquirable_followup_acquisition_rate":
            safe_rate(
                network_resolved,
                network_selected,
            ),

        "measurement_boundary": {
            "github_web_url_deferred_is_network_failure":
                False,

            "unsupported_content_type_is_network_failure":
                False,

            "seed_sources_are_followup_sources":
                False,
        },
    }


def build_final_summary(
    *,
    plan: dict[str, Any],
    paths: dict[str, Path],
) -> dict[str, Any]:
    return {
        "pipeline_version":
            PIPELINE_VERSION,

        "completed_at":
            now_iso(),

        "case_count":
            plan.get(
                "case_count"
            ),

        "distributions":
            plan.get(
                "distributions",
                [],
            ),

        "seed_source_plan":
            optional_metrics(
                paths[
                    "seed_plan"
                ]
            ),

        "seed_local_acquisition":
            optional_metrics(
                paths[
                    "seed_local"
                ]
            ),

        "osv_reference_discovery":
            optional_metrics(
                paths[
                    "discovery"
                ]
            ),

        "expanded_source_plan":
            optional_metrics(
                paths[
                    "expanded_plan"
                ]
            ),

        "local_structured_acquisition":
            optional_metrics(
                paths[
                    "local"
                ]
            ),

        "github_file_acquisition":
            optional_metrics(
                paths[
                    "github_files"
                ]
            ),

        "github_commit_acquisition":
            optional_metrics(
                paths[
                    "github_commits"
                ]
            ),

        "github_metadata_acquisition":
            optional_metrics(
                paths[
                    "github_metadata"
                ]
            ),

        "generic_http_acquisition":
            optional_metrics(
                paths[
                    "generic_http"
                ]
            ),

        "acquisition_overview":
            build_acquisition_overview(
                paths
            ),

        "structured_corpus":
            optional_summary(
                paths[
                    "structured_corpus"
                ]
            ),

        "augmented_corpus":
            optional_summary(
                paths[
                    "augmented_corpus"
                ]
            ),

        "atomic_facts":
            optional_summary(
                paths[
                    "atomic_facts"
                ]
            ),

        "atomic_validation":
            optional_summary(
                paths[
                    "atomic_validation"
                ]
            ),

        "semantic_relations":
            optional_summary(
                paths[
                    "semantic_relations"
                ]
            ),

        "semantic_validation":
            optional_summary(
                paths[
                    "semantic_validation"
                ]
            ),

        "version_drafts":
            optional_summary(
                paths[
                    "version_drafts"
                ]
            ),

        "semantic_drafts":
            optional_summary(
                paths[
                    "semantic_drafts"
                ]
            ),

        "version_aware_drafts":
            optional_summary(
                paths[
                    "version_aware_drafts"
                ]
            ),

        "executable_admission":
            optional_summary(
                paths[
                    "admission"
                ]
            ),

        "semantic_boundary": {
            "candidate_fact_is_ground_truth":
                False,

            "semantic_hypothesis_is_executable_rule":
                False,

            "version_aware_draft_is_executable_rule":
                False,

            "unresolved_is_pipeline_failure":
                False,

            "human_ground_truth_is_generated":
                False,
        },
    }


def run_pipeline(
    plan: dict[str, Any],
    *,
    dry_run: bool,
) -> int:
    out_dir = project_path(
        Path(
            plan[
                "output_dir"
            ]
        )
    )

    paths = build_paths(
        out_dir
    )

    stages = plan.get(
        "stages",
        [],
    )

    if not isinstance(
        stages,
        list,
    ):
        raise ValueError(
            "Pipeline plan stages "
            "must be a list."
        )

    print()
    print(
        "=" * 80
    )
    print(
        "CodeSentry-Gen RQ1 Evidence Automation"
    )
    print(
        "=" * 80
    )

    print(
        "[INFO] pipeline:",
        PIPELINE_VERSION,
    )

    print(
        "[INFO] cases:",
        plan.get(
            "case_count"
        ),
    )

    print(
        "[INFO] distributions:",
        ", ".join(
            plan.get(
                "distributions",
                [],
            )
        ),
    )

    print(
        "[INFO] stages:",
        len(
            stages
        ),
    )

    print(
        "[INFO] dry run:",
        dry_run,
    )

    print()

    if dry_run:
        for index, item in enumerate(
            stages,
            start=1,
        ):
            print(
                (
                    f"[PLAN {index:02d}/"
                    f"{len(stages):02d}] "
                    f"{item['name']}"
                )
            )

            print(
                "  "
                + render_command(
                    item[
                        "command"
                    ]
                )
            )

        print()
        print(
            "[PASS] dry-run pipeline plan built."
        )

        return 0

    out_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    manifest: dict[
        str,
        Any
    ] = {
        "pipeline_version":
            PIPELINE_VERSION,

        "started_at":
            now_iso(),

        "completed_at":
            None,

        "status":
            "running",

        "inventory":
            plan.get(
                "inventory"
            ),

        "case_count":
            plan.get(
                "case_count"
            ),

        "distributions":
            plan.get(
                "distributions",
                [],
            ),

        "ecosystem":
            plan.get(
                "ecosystem"
            ),

        "stage_count":
            len(
                stages
            ),

        "stage_results":
            [],
    }

    write_json(
        paths[
            "manifest"
        ],
        manifest,
    )

    for index, item in enumerate(
        stages,
        start=1,
    ):
        print()
        print(
            "=" * 80
        )

        print(
            (
                f"[{index:02d}/"
                f"{len(stages):02d}] "
                f"{item['name']}"
            )
        )

        print(
            "=" * 80
        )

        print(
            render_command(
                item[
                    "command"
                ]
            )
        )

        result = subprocess.run(
            item[
                "command"
            ],
            cwd=ROOT,
            check=False,
        )

        if (
            result.returncode
            == 0
        ):
            status = "completed"

        else:
            status = "failed"

        manifest[
            "stage_results"
        ].append(
            stage_for_manifest(
                item,
                status=status,
                return_code=(
                    result.returncode
                ),
            )
        )

        if (
            result.returncode
            != 0
        ):
            manifest[
                "status"
            ] = "failed"

            manifest[
                "completed_at"
            ] = now_iso()

            manifest[
                "failed_stage"
            ] = item[
                "name"
            ]

            write_json(
                paths[
                    "manifest"
                ],
                manifest,
            )

            print()
            print(
                "[FAIL] pipeline stopped at:",
                item[
                    "name"
                ],
            )

            return (
                result.returncode
                or 1
            )

        write_json(
            paths[
                "manifest"
            ],
            manifest,
        )

    manifest[
        "status"
    ] = "completed"

    manifest[
        "completed_at"
    ] = now_iso()

    write_json(
        paths[
            "manifest"
        ],
        manifest,
    )

    summary = build_final_summary(
        plan=plan,
        paths=paths,
    )

    write_json(
        paths[
            "summary"
        ],
        summary,
    )

    print()
    print(
        "=" * 80
    )
    print(
        "RQ1 EVIDENCE PIPELINE COMPLETE"
    )
    print(
        "=" * 80
    )

    print(
        "[OK] manifest:",
        project_relative(
            paths[
                "manifest"
            ]
        ),
    )

    print(
        "[OK] summary:",
        project_relative(
            paths[
                "summary"
            ]
        ),
    )

    print(
        "[OK] final admission:",
        project_relative(
            paths[
                "admission"
            ]
        ),
    )

    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Run the current frozen RQ1 Trigger "
            "Evidence automation pipeline from "
            "a source inventory through the "
            "Executable Trigger Admission Gate."
        )
    )

    parser.add_argument(
        "--inventory",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--out-dir",
        required=True,
        type=Path,
    )

    parser.add_argument(
        "--ecosystem",
        default=CURRENT_ECOSYSTEM,
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
    )

    parser.add_argument(
        "--refresh",
        action="store_true",
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
    )

    args = parser.parse_args()

    if args.timeout <= 0:
        raise ValueError(
            "--timeout must be positive."
        )

    plan = build_pipeline_plan(
        inventory_path=args.inventory,
        out_dir=args.out_dir,
        ecosystem=args.ecosystem,
        refresh=args.refresh,
        timeout=args.timeout,
    )

    raise SystemExit(
        run_pipeline(
            plan,
            dry_run=args.dry_run,
        )
    )


if __name__ == "__main__":
    main()
