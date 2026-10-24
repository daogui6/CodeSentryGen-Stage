from __future__ import annotations

import argparse
import ast
import json
import platform
import subprocess
import sys
from importlib import metadata
from pathlib import Path
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement

from freeze_hash_v1 import (
    canonical_manifest_sha256,
    hash_record,
)
from time_contract_v1 import (
    TIMELINE_CONTRACT_VERSION,
    validate_release_snapshot_timeline,
)


ROOT = Path(__file__).resolve().parents[1]

CORE_ENTRY_SCRIPTS = [
    "src/run_codesentry_gen_e2e.py",
    "src/generate_code_from_prompts.py",
    "src/run_pilot.py",
    "src/build_sceg_ir_v21.py",
    "src/enrich_temporal_status.py",
    "src/enrich_reachability_v2.py",
    "src/build_temporal_risk_cards.py",
    "src/run_step8_unified_avcs.py",
    "src/finalize_sceg_ir_v21.py",
    "src/build_core_freeze_closure_v1.py",
    "src/build_step9_method_freeze_v1.py",
    "src/run_step9_generation_stage.py",
    "src/build_step9_generation_recovery_assessment.py",
    "src/build_step9_generation_raw_capture_v1.py",
    "src/build_step9_generation_checkpoint_evidence.py",
    "src/build_step9_post_generation_evidence.py",
    "src/verify_core_freeze_closure_v1.py",
    "src/step9_protocol_registry.py",
    "src/audit_step9_dataset_leakage.py",
    "src/prepare_step9_fresh_benchmark.py",
    "src/check_step9_fresh_selection.py",
    "src/close_step9_fresh_pilot.py",
    "src/check_step9_package_identity_regression.py",
    "src/materialize_project_snapshots_v1.py",
    "src/package_identity_v1.py",
    "src/project_dependency_facts_v1.py",
    "src/enrich_reachability_v2.py",
]

STATIC_RUNTIME_INPUTS = [
    "config/import_mapping.json",
    "config/false_positive_packages.csv",
    "config/step8_avcs_threshold_policy_v2_f10_exposure_prerequisite.json",
    "config/core_risk_semantics_v2_1_repair_v1.json",
    "config/step9_protocol_registry_v1.json",
    "config/step9_active_protocol.json",
    "config/step9_fresh_benchmark_protocol_v4_repair_draft.json",
    "config/step9_fresh_benchmark_protocol_v4_final.json",
    "config/step9_fresh_benchmark_protocol_v4_final_r2.json",
    "config/step9_fresh_benchmark_protocol_v4_final_r3_repair.json",
    "config/step9_fresh_benchmark_protocol_v4_final_r3.json",
    "config/step9_fresh_benchmark_protocol_v4_final_r4_repair.json",
    "config/step9_fresh_benchmark_protocol_v4_final_r4.json",
    "config/step9_fresh_benchmark_protocol_v4_r5_repair_draft.json",
    "config/step9_fresh_benchmark_protocol_v4_final_r5_repair.json",
    "config/step9_fresh_benchmark_protocol_v4_final_r5.json",
    "config/step9_fresh_benchmark_protocol_v4_final_r5_r2_repair.json",
    "config/step9_fresh_benchmark_protocol_v4_final_r5_r3_repair.json",
    "config/step9_fresh_benchmark_protocol_v4_final_r5_r3.json",
    "config/step9_fresh_benchmark_protocol_v4_final_r5_r4_repair.json",
    "config/step9_fresh_benchmark_protocol_v4_final_r5_r5_repair.json",
    "config/step9_fresh_benchmark_protocol_v4_final_r5_r5.json",
    "config/step9_v4_final_r5_r5_freeze_request.json",
    "config/step9_fresh_benchmark_protocol_v4_final_r5_r6_repair.json",
    "config/step9_fresh_benchmark_protocol_v4_final_r5_r6.json",
    "config/step9_v4_final_r5_r6_freeze_request.json",
    "config/step9_fresh_benchmark_protocol_v4_final_r5_r7_repair.json",
    "config/step9_fresh_benchmark_protocol_v4_final_r5_r7_r2_repair.json",
    "config/step9_fresh_benchmark_protocol_v4_final_r5_r8_repair.json",
    "config/step9_fresh_benchmark_protocol_v4_final_r5_r8_r2_repair.json",
    "config/step9_fresh_benchmark_protocol_v4_final_r5_r8_r2.json",
    "config/step9_v4_final_r5_r8_r2_freeze_request.json",
    "config/step9_fresh_benchmark_protocol_v4_final_r5_r9_repair.json",
    "config/step9_fresh_benchmark_protocol_v4_final_r5_r9.json",
    "config/step9_v4_final_r5_r9_freeze_request.json",
    "config/step9_fresh_benchmark_protocol_v4_final_r5_r10.json",
    "config/step9_v4_final_r5_r10_freeze_request.json",
    "config/step9_v4_r5_r11_evidence_persistence_contract_v1.json",
    "provenance/step9_v4_r5_r11_selection_salt/selection_salt_provenance.json",
    "config/generation_reliability_system_audit_candidate_v1.json",
    "config/generation_reliability_endpoint_decision_v1.json",
    "provenance/generation_reliability_system_audit/audit_result_20260926.json",
    "provenance/generation_crash_recovery_sealing/closure_result_20260926.json",
    "provenance/generation_endpoint_decision/closure_result_20260926.json",
    "provenance/step9_v4_r5_r10_selection_salt/selection_salt_provenance.json",
    "provenance/step9_v4_r5_r10_method_freeze_correction/incident_20260926.json",
    "config/step9_fresh_benchmark_protocol_v4_final_r5_r7_r2.json",
    "config/step9_v4_final_r5_r7_r2_freeze_request.json",
    "config/step9_fresh_benchmark_protocol_v4_final_r5_r7.json",
    "config/step9_v4_final_r5_r7_freeze_request.json",
    "docs/STEP9_V4_R5_R6_SELECTION_SALT_PROVENANCE_2026-09-24.md",
    "docs/STEP9_V4_R5_R7_SELECTION_SALT_PROVENANCE_2026-09-24.md",
    "docs/STEP9_V4_R5_R7_R2_SELECTION_SALT_PROVENANCE_2026-09-24.md",
    "config/step9_v4_r5_r7_syntax_validity_contract_proposal.json",
    "docs/STEP9_R5_R7_SYNTAX_CORRECTIVE_REAUDIT_HARDENING_2026-09-24.md",
    "docs/STEP9_R5_R7_GENERATION_MODEL_CONTRACT_CLOSURE_2026-09-24.md",
    "provenance/step9_v4_r5_r7_predecessor_exclusion/predecessor_prompt_fingerprints.json",
    "provenance/step9_v4_r5_r8_predecessor_exclusion/predecessor_prompt_fingerprints.json",
    "provenance/step9_v4_r5_r8_selection_salt/selection_salt_provenance.json",
    "provenance/step9_v4_r5_r8_r2_selection_salt/selection_salt_provenance.json",
    "provenance/step9_v4_r5_r9_predecessor_exclusion/predecessor_prompt_fingerprints.json",
    "provenance/step9_v4_r5_r9_selection_salt/selection_salt_provenance.json",
    "config/step9_v4_r5_r9_empty_sse_reliability_contract_proposal.json",
    "config/step9_v4_r5_r8_generation_reliability_contract_proposal.json",
    "docs/STEP9_R5_R8_GENERATION_RELIABILITY_REPAIR_CLOSURE_2026-09-25.md",
    "provenance/step9_v4_r5_r5_partial_generation_20260924/incident_manifest.json",
    "provenance/step9_v4_r5_r5_partial_generation_20260924/selection/selection_manifest.json",
    "provenance/step9_v4_r5_r5_partial_generation_20260924/selection/step9_fresh_pilot20_v4_r5_r5.jsonl",
    "provenance/step9_v4_r5_r5_partial_generation_20260924/selection/step9_fresh_test100_v4_r5_r5.jsonl",
    "provenance/step9_v4_r5_r4_wrong_model_pilot_20260924/incident_manifest.json",
    "provenance/step9_v4_r5_r4_wrong_model_pilot_20260924/selection/selection_manifest.json",
    "provenance/step9_v4_r5_r4_wrong_model_pilot_20260924/selection/step9_fresh_pilot20_v4_r5.jsonl",
    "provenance/step9_v4_r5_r4_wrong_model_pilot_20260924/selection/step9_fresh_test100_v4_r5.jsonl",
    "config/step9_v4_final_r5_r3_freeze_request.json",
    "provenance/step9_v4_r5_r3_failed_promotion_20260923/failure_manifest.json",
    "config/step9_v4_final_freeze_request.json",
    "config/step9_v4_final_r2_freeze_request.json",
    "config/step9_v4_final_r3_freeze_request.json",
    "config/step9_v4_final_r4_freeze_request.json",
    "config/step9_v4_final_r5_freeze_request.json",
    "config/package_identity_policy_v1.json",
    "config/package_identity_mapping_v1.json",
    "config/avcs_curated_scope_v1.json",
    "docs/CORE_AUDIT_F09_CLOSURE.md",
    "config/false_positive_packages.csv",
    "schemas/sceg_schema_v2_1.json",
    "schemas/risk_card_schema_v2_1.json",
    "output/step7_batch_review_v0/step7_freeze_v1/step7_freeze_report.json",
    "requirements.txt",
    "requirements-core-lock.txt",
    "requirements-workflow-parser.txt",
] 

OPTIONAL_RUNTIME_INPUTS = [
    "config/step9_fresh_benchmark_protocol_v4_final_r5_r4.json",
    "config/step9_v4_final_r5_r4_freeze_request.json",
    # R5-r11 is staged before live promotion. These become mandatory in the
    # exact Method Freeze once they exist at the promoted source commit.
    "config/step9_fresh_benchmark_protocol_v4_final_r5_r11.json",
    "config/step9_v4_final_r5_r11_freeze_request.json",
    # R5-r12 post-promotion Exact Method Freeze must bind both the promoted
    # final protocol and its post-promotion-acceptance freeze request. Salt,
    # predecessor960, leakage, selection, and generation evidence remain absent.
    "config/step9_fresh_benchmark_protocol_v4_final_r5_r12.json",
    "config/step9_v4_final_r5_r12_freeze_request.json",
    # R5-r13 preserves the same pre-selection freeze ordering but fixes salt
    # delivery: the external salt provenance is intentionally absent here and
    # may be created only after Method Freeze, predecessor960, and Leakage PASS.
    "config/step9_fresh_benchmark_protocol_v4_final_r5_r13.json",
    "config/step9_v4_final_r5_r13_freeze_request.json",
]


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def git_text(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    return result.stdout.strip()


def resolve_local_module(module: str) -> Path | None:
    if not module:
        return None
    candidate = ROOT / "src" / (module.replace(".", "/") + ".py")
    if candidate.exists() and candidate.is_file():
        return candidate
    package_init = ROOT / "src" / module.replace(".", "/") / "__init__.py"
    if package_init.exists() and package_init.is_file():
        return package_init
    return None


def python_dependencies(path: Path) -> set[Path]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8-sig"))
    except (SyntaxError, UnicodeDecodeError) as exc:
        raise ValueError(f"Cannot parse runtime source: {path}") from exc

    result: set[Path] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = resolve_local_module(alias.name)
                if local is not None:
                    result.add(local)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                local = resolve_local_module(node.module)
                if local is not None:
                    result.add(local)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            text = node.value.strip().replace("\\", "/")
            if text.startswith("src/") and text.endswith(".py"):
                candidate = ROOT / text
                if candidate.exists() and candidate.is_file():
                    result.add(candidate)
    return result


def collect_python_closure(entry_paths: list[Path]) -> set[Path]:
    pending = list(entry_paths)
    seen: set[Path] = set()

    while pending:
        path = pending.pop()
        resolved = path.resolve()
        if resolved in seen:
            continue
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(path)
        seen.add(resolved)
        for child in python_dependencies(path):
            if child.resolve() not in seen:
                pending.append(child)

    return {Path(value) for value in seen}


def _repo_relative_runtime_path(
    text: str,
    *,
    label: str,
) -> Path:
    raw = str(text or "").strip().replace("\\", "/")
    if not raw:
        raise ValueError(f"{label} is empty")
    candidate = Path(raw)
    if candidate.is_absolute():
        raise ValueError(
            f"{label} must be repository-relative: {raw}"
        )
    resolved = (ROOT / candidate).resolve()
    try:
        resolved.relative_to(ROOT.resolve())
    except ValueError as exc:
        raise ValueError(
            f"{label} escapes repository root: {raw}"
        ) from exc
    return resolved


def package_kb_declared_hashed_artifact_refs(
    kb_path: Path,
    kb: dict[str, Any],
) -> set[Path]:
    """All Package-KB local artifacts declared with path+sha256.

    This deliberately mirrors the recursive runtime verification performed by
    run_step8_unified_avcs.verify_declared_kb_artifact_hashes().
    """

    refs: set[Path] = set()

    def visit(value: Any, trail: str) -> None:
        if isinstance(value, dict):
            path_text = str(value.get("path", "") or "").strip()
            digest = str(value.get("sha256", "") or "").strip()
            if path_text and digest:
                refs.add(
                    _repo_relative_runtime_path(
                        path_text,
                        label=f"{kb_path.name}:{trail}.path",
                    )
                )
            for key, child in value.items():
                visit(child, f"{trail}.{key}")
            return
        if isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, f"{trail}[{index}]")

    visit(kb, "root")
    return refs


def package_kb_runtime_refs(
    kb_path: Path,
    kb: dict[str, Any],
) -> set[Path]:
    """Collect every local artifact that the AVCS Package-KB runtime touches."""

    refs = package_kb_declared_hashed_artifact_refs(kb_path, kb)

    for artifact in kb.get("release_history", {}).get("artifacts", []):
        if not isinstance(artifact, dict):
            continue
        text = str(artifact.get("path", "") or "").strip()
        if text:
            refs.add(
                _repo_relative_runtime_path(
                    text,
                    label=f"{kb_path.name}:release_history.artifact",
                )
            )

    api_surface = kb.get("api_surface_history", {})
    if not isinstance(api_surface, dict):
        api_surface = {}

    for artifact in api_surface.get("artifacts", []):
        if not isinstance(artifact, dict):
            continue
        text = str(artifact.get("path", "") or "").strip()
        if text:
            refs.add(
                _repo_relative_runtime_path(
                    text,
                    label=f"{kb_path.name}:api_surface_history.artifact",
                )
            )

    for entry in api_surface.get("entries", []):
        if not isinstance(entry, dict):
            continue
        for rule in entry.get("version_rules", []):
            if not isinstance(rule, dict):
                continue
            text = str(rule.get("evidence_ref", "") or "").strip()
            if text:
                refs.add(
                    _repo_relative_runtime_path(
                        text,
                        label=f"{kb_path.name}:version_rule.evidence_ref",
                    )
                )

    return refs


def release_snapshot_refs(manifest_path: Path) -> set[Path]:
    manifest = read_json(manifest_path)
    if manifest.get("status") != "FROZEN":
        raise ValueError("Release snapshot manifest must be FROZEN")

    packages = manifest.get("packages")
    if not isinstance(packages, dict) or not packages:
        raise ValueError("Release snapshot manifest has no packages")

    refs: set[Path] = {manifest_path}
    timeline_artifacts: dict[str, dict[str, Any]] = {}
    for package, raw in packages.items():
        if not isinstance(raw, dict):
            raise ValueError(
                f"Invalid release snapshot entry for {package}"
            )
        artifact_text = str(raw.get("path", "") or "").strip()
        if not artifact_text:
            raise ValueError(
                f"Release snapshot entry has no artifact path: {package}"
            )
        artifact_path = ROOT / artifact_text
        if not artifact_path.exists():
            raise FileNotFoundError(artifact_path)
        timeline_artifacts[str(package)] = read_json(
            artifact_path
        )

        for key in ("path", "raw_pypi_path", "package_kb_path"):
            text = str(raw.get(key, "") or "").strip()
            if text:
                refs.add(ROOT / text)

    validate_release_snapshot_timeline(
        manifest,
        artifacts=timeline_artifacts,
        label=f"core_freeze_release_snapshot:{manifest_path}",
    )
    return refs


def installed_requirement_versions(
    requirements_path: Path,
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for raw_line in requirements_path.read_text(
        encoding="utf-8-sig"
    ).splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            requirement = Requirement(line)
        except InvalidRequirement:
            continue
        name = requirement.name
        try:
            version = metadata.version(name)
            installed = True
        except metadata.PackageNotFoundError:
            version = None
            installed = False
        result[name] = {
            "declared": str(requirement),
            "installed": installed,
            "installed_version": version,
        }
    return result


def runtime_extension_versions(root: Path) -> dict[str, dict[str, Any]]:
    """Validate prospective parser pins without rewriting the historical lock."""
    path = root / "requirements-workflow-parser.txt"
    if not path.is_file():
        return {}  # Historical source checkouts predate this extension.
    result: dict[str, dict[str, Any]] = {}
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            requirement = Requirement(line)
        except InvalidRequirement as exc:
            raise ValueError("Invalid runtime extension pin") from exc
        specifiers = list(requirement.specifier)
        if (len(specifiers) != 1 or specifiers[0].operator != "=="
                or requirement.url or requirement.extras or requirement.marker
                or "*" in specifiers[0].version):
            raise ValueError("Runtime extension must have a plain exact pin")
        if requirement.name.lower() in {name.lower() for name in result}:
            raise ValueError("Duplicate runtime extension pin")
        try:
            observed = metadata.version(requirement.name)
        except metadata.PackageNotFoundError as exc:
            raise ValueError(f"Runtime extension missing: {requirement.name}") from exc
        if str(observed) != specifiers[0].version:
            raise ValueError(f"Runtime extension version drift: {requirement.name}")
        result[requirement.name] = {"declared": str(requirement), "installed": True,
                                    "installed_version": observed, "source_file": path.name}
    if not result:
        raise ValueError("Runtime extension pins missing")
    return result


def installed_runtime_requirement_versions(path: Path) -> dict[str, dict[str, Any]]:
    result = installed_requirement_versions(path)
    extension = runtime_extension_versions(path.parent)
    if {name.lower() for name in result}.intersection(name.lower() for name in extension):
        raise ValueError("Runtime extension overlaps historical core lock")
    return {**result, **extension}


def verify_runtime_extension_binding(requirements: dict[str, Any],
                                     files: dict[str, Any], root: Path) -> None:
    if "requirements-workflow-parser.txt" not in files:
        return
    expected = runtime_extension_versions(root)
    for name, row in expected.items():
        frozen = requirements.get(name)
        if not isinstance(frozen, dict) or any(
            frozen.get(key) != row[key] for key in ("declared", "installed", "installed_version")
        ):
            raise ValueError(f"Runtime extension not bound in frozen environment: {name}")


def tracked_dirty_files() -> list[str]:
    values: set[str] = set()
    for args in [
        ("diff", "--name-only"),
        ("diff", "--cached", "--name-only"),
    ]:
        text = git_text(*args)
        for line in text.splitlines():
            line = line.strip().replace("\\", "/")
            if line:
                values.add(line)
    return sorted(values)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Build an append-only canonical freeze closure for the repaired "
            "CodeSentry-Gen core runtime."
        )
    )
    parser.add_argument(
        "--release-snapshot-manifest",
        required=True,
        type=Path,
    )
    parser.add_argument(
        "--method-freeze",
        type=Path,
        default=None,
        help=(
            "Optional pre-generation Step9 method-freeze artifact. Formal "
            "post-generation evidence closure should supply it."
        ),
    )
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    release_manifest = args.release_snapshot_manifest
    if not release_manifest.is_absolute():
        release_manifest = ROOT / release_manifest

    method_freeze = args.method_freeze
    if method_freeze is not None and not method_freeze.is_absolute():
        method_freeze = ROOT / method_freeze

    out = args.out
    if not out.is_absolute():
        out = ROOT / out
    if out.exists():
        raise FileExistsError(f"Refusing overwrite: {out}")

    blockers: list[str] = []
    files: set[Path] = set()

    entry_paths = [ROOT / value for value in CORE_ENTRY_SCRIPTS]
    files.update(collect_python_closure(entry_paths))

    for relative in STATIC_RUNTIME_INPUTS:
        files.add(ROOT / relative)
    for relative in OPTIONAL_RUNTIME_INPUTS:
        path = ROOT / relative
        if path.exists():
            files.add(path)

    kb_paths = sorted(
        (ROOT / "data/avcs_package_kb").glob("*_package_kb_v0.json")
    )
    if len(kb_paths) != 11:
        blockers.append(
            f"expected_11_package_kbs_got_{len(kb_paths)}"
        )

    package_kb_runtime_artifacts: set[Path] = set()
    package_kb_declared_hashed_artifacts: set[Path] = set()
    for kb_path in kb_paths:
        files.add(kb_path)
        kb = read_json(kb_path)
        runtime_refs = package_kb_runtime_refs(kb_path, kb)
        declared_hashed_refs = package_kb_declared_hashed_artifact_refs(
            kb_path,
            kb,
        )
        package_kb_runtime_artifacts.update(runtime_refs)
        package_kb_declared_hashed_artifacts.update(
            declared_hashed_refs
        )
        files.update(runtime_refs)

    method_freeze_report: dict[str, Any] | None = None
    if method_freeze is not None:
        try:
            method_freeze_report = read_json(method_freeze)
            if method_freeze_report.get("schema_version") != (
                "codesentry_gen_step9_method_freeze_v1"
            ):
                raise ValueError("unexpected method-freeze schema")
            if method_freeze_report.get("status") != "PASS":
                raise ValueError("method freeze is not PASS")
            method_revision = str(
                method_freeze_report.get("contract_revision") or ""
            ).strip()
            if method_revision not in {
                "pre_step9_selection_validator_contract_r4",
                "pre_step9_avcs_curated_scope_contract_r5",
                "pre_step9_syntax_support_model_contract_r5_r7",
                "pre_step9_generation_reliability_contract_r5_r8",
                "pre_step9_generation_reliability_contract_r5_r9",
            }:
                raise ValueError(
                    "unsupported method freeze contract revision: "
                    + repr(method_revision)
                )
            method_runtime = method_freeze_report.get("runtime_environment")
            if not isinstance(method_runtime, dict):
                raise ValueError("method freeze runtime environment missing")
            frozen_python_exact = str(
                method_runtime.get("python_version_exact") or ""
            ).strip()
            if not frozen_python_exact:
                raise ValueError("method freeze exact Python version missing")
            if frozen_python_exact != platform.python_version():
                raise ValueError(
                    "method freeze exact Python version differs from current runtime"
                )
            method_git = method_freeze_report.get("git")
            if not isinstance(method_git, dict):
                raise ValueError("method freeze git identity missing")
            if str(method_git.get("commit") or "") != git_text(
                "rev-parse", "HEAD"
            ):
                raise ValueError(
                    "method freeze commit differs from current HEAD"
                )
            if str(method_git.get("tree") or "") != git_text(
                "rev-parse", "HEAD^{tree}"
            ):
                raise ValueError(
                    "method freeze tree differs from current HEAD"
                )
            method_files = method_freeze_report.get("files")
            if not isinstance(method_files, dict) or not method_files:
                raise ValueError("method freeze has no runtime files")
            for relative, expected in method_files.items():
                target = ROOT / str(relative)
                if not target.exists() or not target.is_file():
                    raise FileNotFoundError(target)
                actual = hash_record(target)
                if actual.get("sha256") != expected.get("sha256"):
                    raise ValueError(
                        f"method runtime drift after generation: {relative}"
                    )
            files.add(method_freeze)
        except Exception as exc:
            blockers.append(
                "method_freeze_invalid:"
                f"{type(exc).__name__}:{exc}"
            )

    try:
        files.update(release_snapshot_refs(release_manifest))
    except Exception as exc:
        blockers.append(
            f"release_snapshot_manifest_invalid:{type(exc).__name__}:{exc}"
        )

    missing = sorted(
        rel(path)
        for path in files
        if not path.exists() or not path.is_file()
    )
    for value in missing:
        blockers.append(f"closure_file_missing:{value}")

    existing = sorted(
        (path for path in files if path.exists() and path.is_file()),
        key=lambda value: rel(value),
    )
    entries = {
        rel(path): {
            **hash_record(path),
            "source_kind": (
                "python_runtime"
                if path.suffix.lower() == ".py"
                else "runtime_input"
            ),
        }
        for path in existing
    }

    if method_freeze_report is not None:
        method_files = method_freeze_report.get("files", {})
        missing_method_paths = sorted(
            relative
            for relative in method_files
            if relative not in entries
        )
        if missing_method_paths:
            blockers.append(
                "core_closure_missing_method_freeze_files:"
                + ",".join(missing_method_paths[:20])
            )

    dirty = tracked_dirty_files()
    closure_paths = set(entries)
    dirty_in_closure = sorted(
        value for value in dirty if value in closure_paths
    )
    if dirty_in_closure:
        blockers.append(
            "tracked_runtime_files_dirty:"
            + ",".join(dirty_in_closure)
        )

    exact_lock_path = ROOT / "requirements-core-lock.txt"
    requirements_path = (
        exact_lock_path
        if exact_lock_path.exists()
        else ROOT / "requirements.txt"
    )
    environment = {
        "python_version": sys.version,
        "python_implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "requirements_file": rel(requirements_path),
        "requirements": (
            installed_runtime_requirement_versions(requirements_path)
            if requirements_path.exists()
            else {}
        ),
    }

    git_commit = git_text("rev-parse", "HEAD")
    git_tree = git_text("rev-parse", "HEAD^{tree}")

    report = {
        "schema_version": "codesentry_gen_core_freeze_closure_v1",
        "status": "PASS" if not blockers else "BLOCKED",
        "hash_contract": {
            "schema_version": "codesentry_gen_canonical_hash_v1",
            "text_newline_policy": "LF",
            "json_policy": (
                "UTF-8 parsed JSON; sort_keys=true; compact separators"
            ),
            "jsonl_policy": (
                "preserve row order; canonicalize each JSON object; LF"
            ),
            "binary_policy": "exact bytes",
        },
        "git": {
            "commit": git_commit,
            "tree": git_tree,
            "tracked_dirty_files": dirty,
            "tracked_dirty_files_in_closure": dirty_in_closure,
        },
        "runtime_environment": environment,
        "release_snapshot_manifest": rel(release_manifest),
        "release_snapshot_manifest_hash": (
            hash_record(release_manifest)
            if release_manifest.exists()
            else None
        ),
        "method_freeze_file": (
            rel(method_freeze)
            if method_freeze is not None
            else None
        ),
        "method_freeze_hash": (
            hash_record(method_freeze)
            if method_freeze is not None and method_freeze.exists()
            else None
        ),
        "method_closure_sha256": (
            method_freeze_report.get("method_closure_sha256")
            if method_freeze_report is not None
            else None
        ),
        "entry_scripts": CORE_ENTRY_SCRIPTS,
        "static_runtime_inputs": STATIC_RUNTIME_INPUTS,
        "optional_runtime_inputs_present": [
            relative
            for relative in OPTIONAL_RUNTIME_INPUTS
            if (ROOT / relative).exists()
        ],
        "package_kb_count": len(kb_paths),
        "package_kb_declared_hashed_artifact_count": len(
            package_kb_declared_hashed_artifacts
        ),
        "package_kb_runtime_artifact_count": len(
            package_kb_runtime_artifacts
        ),
        "file_count": len(entries),
        "files": entries,
        "closure_sha256": canonical_manifest_sha256(entries),
        "blockers": sorted(set(blockers)),
        "scientific_boundary": {
            "cross_platform_line_endings_are_canonicalized": True,
            "json_formatting_is_canonicalized": True,
            "runtime_python_dependencies_auto_enumerated": True,
            "package_kbs_in_closure": True,
            "package_kb_runtime_artifacts_in_closure": True,
            "package_kb_recursive_path_sha256_inventory_in_closure": True,
            "package_kb_runtime_inventory_rederived_from_kb": True,
            "release_snapshot_in_closure": True,
            "pre_generation_method_freeze_bound": (
                method_freeze_report is not None
            ),
            "post_generation_method_runtime_drift_forbidden": (
                method_freeze_report is not None
            ),
            "timeline_contract_version": TIMELINE_CONTRACT_VERSION,
            "release_snapshot_timeline_verified": True,
            "future_dated_snapshot_forbidden": True,
            "git_commit_and_tree_recorded": True,
            "runtime_versions_recorded": True,
            "tracked_runtime_drift_blocks_freeze": True,
            "untracked_historical_outputs_are_not_deleted": True,
        },
    }

    write_json(out, report)

    print("F-06 CORE FREEZE CLOSURE", report["status"])
    print("files =", report["file_count"])
    print("package_kbs =", report["package_kb_count"])
    print("git_commit =", git_commit)
    print("git_tree =", git_tree)
    print("closure_sha256 =", report["closure_sha256"])
    if blockers:
        print("blockers =")
        for blocker in sorted(set(blockers)):
            print(" -", blocker)
    print("saved =", rel(out))

    if blockers:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
