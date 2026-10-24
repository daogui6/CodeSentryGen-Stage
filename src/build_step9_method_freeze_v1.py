from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
from importlib import metadata
from pathlib import Path
from typing import Any

from build_core_freeze_closure_v1 import (
    CORE_ENTRY_SCRIPTS,
    OPTIONAL_RUNTIME_INPUTS,
    STATIC_RUNTIME_INPUTS,
    ROOT,
    collect_python_closure,
    git_text,
    installed_runtime_requirement_versions,
    package_kb_declared_hashed_artifact_refs,
    package_kb_runtime_refs,
    read_json,
    rel,
    tracked_dirty_files,
    verify_runtime_extension_binding,
)
from freeze_hash_v1 import canonical_manifest_sha256, hash_record
from step9_protocol_registry import require_active_frozen_protocol


LEGACY_R4_METHOD_FREEZE_CONTRACT_REVISION = (
    "pre_step9_selection_validator_contract_r4"
)
R5_METHOD_FREEZE_CONTRACT_REVISION = (
    "pre_step9_avcs_curated_scope_contract_r5"
)
R5_R7_METHOD_FREEZE_CONTRACT_REVISION = (
    "pre_step9_syntax_support_model_contract_r5_r7"
)
R5_R8_METHOD_FREEZE_CONTRACT_REVISION = (
    "pre_step9_generation_reliability_contract_r5_r8"
)
R5_R9_METHOD_FREEZE_CONTRACT_REVISION = (
    "pre_step9_generation_reliability_contract_r5_r9"
)
R5_R10_METHOD_FREEZE_CONTRACT_REVISION = (
    "pre_step9_generation_reliability_contract_r5_r10"
)
R5_R11_METHOD_FREEZE_CONTRACT_REVISION = (
    "pre_step9_evidence_first_orchestration_contract_r5_r11"
)
R5_R12_METHOD_FREEZE_CONTRACT_REVISION = (
    "pre_step9_generation_outcome_accounting_and_statistical_eligibility_contract_r5_r12"
)
R5_R13_METHOD_FREEZE_CONTRACT_REVISION = (
    "pre_step9_post_leakage_external_salt_authority_contract_r5_r13"
)
LEGACY_R4_EVIDENCE_SCHEMA_VERSION = (
    "step9_v4_final_r4_evidence_manifest_v1"
)
R5_EVIDENCE_SCHEMA_VERSION = (
    "step9_v4_final_r5_evidence_manifest_v1"
)
R5_R2_EVIDENCE_SCHEMA_VERSION = (
    "step9_v4_final_r5_r2_evidence_manifest_v1"
)
R5_R3_EVIDENCE_SCHEMA_VERSION = (
    "step9_v4_final_r5_r3_evidence_manifest_v1"
)
R5_R4_EVIDENCE_SCHEMA_VERSION = (
    "step9_v4_final_r5_r4_evidence_manifest_v1"
)
R5_R5_EVIDENCE_SCHEMA_VERSION = (
    "step9_v4_final_r5_r5_evidence_manifest_v1"
)
R5_R6_EVIDENCE_SCHEMA_VERSION = (
    "step9_v4_final_r5_r6_evidence_manifest_v1"
)
R5_R7_EVIDENCE_SCHEMA_VERSION = (
    "step9_v4_final_r5_r7_evidence_manifest_v1"
)
R5_R7_R2_EVIDENCE_SCHEMA_VERSION = (
    "step9_v4_final_r5_r7_r2_evidence_manifest_v1"
)
R5_R8_EVIDENCE_SCHEMA_VERSION = (
    "step9_v4_final_r5_r8_evidence_manifest_v1"
)
R5_R8_R2_EVIDENCE_SCHEMA_VERSION = (
    "step9_v4_final_r5_r8_r2_evidence_manifest_v1"
)
R5_R9_EVIDENCE_SCHEMA_VERSION = (
    "step9_v4_final_r5_r9_evidence_manifest_v1"
)
R5_R10_EVIDENCE_SCHEMA_VERSION = (
    "step9_v4_final_r5_r10_evidence_manifest_v1"
)
R5_R11_EVIDENCE_SCHEMA_VERSION = (
    "step9_v4_final_r5_r11_evidence_manifest_v1"
)
R5_R12_EVIDENCE_SCHEMA_VERSION = (
    "step9_v4_final_r5_r12_evidence_manifest_v1"
)
R5_R13_EVIDENCE_SCHEMA_VERSION = (
    "step9_v4_final_r5_r13_evidence_manifest_v1"
)


def method_freeze_contract_revision(
    protocol: dict[str, Any],
) -> str:
    decisions = protocol.get("final_freeze_decisions")
    if isinstance(decisions, dict):
        declared = str(
            decisions.get("method_freeze_contract_revision") or ""
        ).strip()
        if declared:
            return declared
    return LEGACY_R4_METHOD_FREEZE_CONTRACT_REVISION


def final_freeze_evidence_schema(
    protocol: dict[str, Any],
) -> str:
    archive = protocol.get("evidence_archive")
    if isinstance(archive, dict):
        declared = str(
            archive.get("evidence_schema_version") or ""
        ).strip()
        if declared:
            return declared
    return LEGACY_R4_EVIDENCE_SCHEMA_VERSION


def validate_supported_freeze_revision(
    revision: str,
) -> None:
    if revision not in {
        LEGACY_R4_METHOD_FREEZE_CONTRACT_REVISION,
        R5_METHOD_FREEZE_CONTRACT_REVISION,
        R5_R7_METHOD_FREEZE_CONTRACT_REVISION,
        R5_R8_METHOD_FREEZE_CONTRACT_REVISION,
        R5_R9_METHOD_FREEZE_CONTRACT_REVISION,
        R5_R10_METHOD_FREEZE_CONTRACT_REVISION,
        R5_R11_METHOD_FREEZE_CONTRACT_REVISION,
        R5_R12_METHOD_FREEZE_CONTRACT_REVISION,
        R5_R13_METHOD_FREEZE_CONTRACT_REVISION,
    }:
        raise ValueError(
            "Unsupported Step9 method-freeze contract revision: "
            + repr(revision)
        )


def validate_supported_evidence_schema(
    schema_version: str,
) -> None:
    if schema_version not in {
        LEGACY_R4_EVIDENCE_SCHEMA_VERSION,
        R5_EVIDENCE_SCHEMA_VERSION,
        R5_R2_EVIDENCE_SCHEMA_VERSION,
        R5_R3_EVIDENCE_SCHEMA_VERSION,
        R5_R4_EVIDENCE_SCHEMA_VERSION,
        R5_R5_EVIDENCE_SCHEMA_VERSION,
        R5_R6_EVIDENCE_SCHEMA_VERSION,
        R5_R7_EVIDENCE_SCHEMA_VERSION,
        R5_R7_R2_EVIDENCE_SCHEMA_VERSION,
        R5_R8_EVIDENCE_SCHEMA_VERSION,
        R5_R8_R2_EVIDENCE_SCHEMA_VERSION,
        R5_R9_EVIDENCE_SCHEMA_VERSION,
        R5_R10_EVIDENCE_SCHEMA_VERSION,
        R5_R11_EVIDENCE_SCHEMA_VERSION,
        R5_R12_EVIDENCE_SCHEMA_VERSION,
        R5_R13_EVIDENCE_SCHEMA_VERSION,
    }:
        raise ValueError(
            "Unsupported Final Freeze evidence schema: "
            + repr(schema_version)
        )


def verify_frozen_python_runtime(
    runtime: dict[str, Any],
    *,
    expected_exact: str | None = None,
) -> None:
    if runtime.get("python_implementation") != platform.python_implementation():
        raise ValueError(
            "Python implementation differs from Step9 method freeze"
        )
    frozen_exact = str(runtime.get("python_version_exact") or "").strip()
    if not frozen_exact:
        raise ValueError("Step9 method-freeze exact Python version missing")
    if expected_exact is not None and frozen_exact != expected_exact:
        raise ValueError(
            "Step9 method-freeze Python version differs from frozen protocol"
        )
    if platform.python_version() != frozen_exact:
        raise ValueError(
            "Exact Python patch differs from Step9 method freeze: "
            f"expected={frozen_exact} actual={platform.python_version()}"
        )


def write_json(path: Path, value: dict[str, Any]) -> None:
    if path.exists():
        raise FileExistsError(f"Refusing overwrite: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def raw_sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def installed_requirement_versions(path: Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "==" not in line:
            continue
        name = line.split("==", 1)[0].strip()
        if not name:
            continue
        try:
            version = metadata.version(name)
            installed = True
        except metadata.PackageNotFoundError:
            version = None
            installed = False
        result[name] = {
            "declared": line,
            "installed": installed,
            "installed_version": version,
        }
    return result


def verify_step9_method_freeze(
    path: Path,
    *,
    protocol_path: Path | None = None,
    require_git_identity: bool = True,
    require_environment_versions: bool = True,
) -> dict[str, Any]:
    report = read_json(path)
    if report.get("schema_version") != "codesentry_gen_step9_method_freeze_v1":
        raise ValueError("Unexpected Step9 method-freeze schema")
    if report.get("status") != "PASS":
        raise ValueError("Step9 method freeze is not PASS")
    report_revision = str(
        report.get("contract_revision") or ""
    ).strip()
    validate_supported_freeze_revision(report_revision)

    files = report.get("files")
    if not isinstance(files, dict) or not files:
        raise ValueError("Step9 method freeze has no runtime files")
    for relative, expected in files.items():
        target = ROOT / str(relative)
        if not target.exists() or not target.is_file():
            raise FileNotFoundError(target)
        actual = hash_record(target)
        if actual.get("sha256") != expected.get("sha256"):
            raise ValueError(
                f"Step9 method runtime drift: {relative}"
            )

    if canonical_manifest_sha256(files) != report.get(
        "method_closure_sha256"
    ):
        raise ValueError("Step9 method-freeze closure digest mismatch")

    expected_python_exact: str | None = None
    if protocol_path is not None:
        protocol = read_json(protocol_path)
        expected_revision = method_freeze_contract_revision(protocol)
        validate_supported_freeze_revision(expected_revision)
        if report_revision != expected_revision:
            raise ValueError(
                "Step9 method-freeze contract revision differs from "
                "the bound protocol"
            )
        expected_python_exact = str(
            protocol.get("final_freeze_decisions", {}).get(
                "method_freeze_python_exact"
            )
            or ""
        ).strip()
        if not expected_python_exact:
            raise ValueError(
                "Frozen protocol does not declare method_freeze_python_exact"
            )
        expected_protocol = str(report.get("protocol_file") or "")
        if rel(protocol_path) != expected_protocol:
            raise ValueError("Step9 method freeze protocol path mismatch")
        actual_protocol_hash = hash_record(protocol_path)
        expected_protocol_hash = report.get("protocol_hash")
        if not isinstance(expected_protocol_hash, dict):
            raise ValueError("Step9 method freeze protocol hash missing")
        if actual_protocol_hash.get("sha256") != expected_protocol_hash.get(
            "sha256"
        ):
            raise ValueError("Step9 protocol drift after method freeze")

    git_info = report.get("git")
    if not isinstance(git_info, dict):
        raise ValueError("Step9 method freeze git identity missing")
    if require_git_identity:
        if git_text("rev-parse", "HEAD") != str(
            git_info.get("commit") or ""
        ):
            raise ValueError("Git commit differs from Step9 method freeze")
        if git_text("rev-parse", "HEAD^{tree}") != str(
            git_info.get("tree") or ""
        ):
            raise ValueError("Git tree differs from Step9 method freeze")

    if require_environment_versions:
        runtime = report.get("runtime_environment")
        if not isinstance(runtime, dict):
            raise ValueError("Step9 method-freeze environment missing")
        verify_frozen_python_runtime(
            runtime,
            expected_exact=expected_python_exact,
        )
        requirements = runtime.get("requirements")
        if not isinstance(requirements, dict):
            raise ValueError(
                "Step9 method-freeze requirement versions missing"
            )
        verify_runtime_extension_binding(requirements, files, ROOT)
        for name, row in requirements.items():
            if not isinstance(row, dict):
                raise ValueError(
                    f"Invalid method-freeze requirement row: {name}"
                )
            try:
                actual_version = metadata.version(name)
                actual_installed = True
            except metadata.PackageNotFoundError:
                actual_version = None
                actual_installed = False
            if actual_installed != row.get("installed"):
                raise ValueError(
                    f"Method-freeze dependency presence drift: {name}"
                )
            if actual_installed and str(actual_version) != str(
                row.get("installed_version")
            ):
                raise ValueError(
                    f"Method-freeze dependency version drift: {name}"
                )

    return report


def verify_step9_formal_freeze_binding(
    method_path: Path,
    *,
    protocol_path: Path,
    evidence_path: Path | None = None,
    require_git_identity: bool = True,
    require_environment_versions: bool = True,
) -> dict[str, Any]:
    """Verify the exact archived Method Freeze bytes used by Formal Step9.

    Method semantic equivalence is not enough at the formal benchmark boundary:
    the runtime file must be byte-identical to the independently archived
    pre-generation freeze artifact recorded by the final freeze evidence.
    """
    method = verify_step9_method_freeze(
        method_path,
        protocol_path=protocol_path,
        require_git_identity=require_git_identity,
        require_environment_versions=require_environment_versions,
    )
    protocol = read_json(protocol_path)
    archive = protocol.get("evidence_archive")
    if not isinstance(archive, dict):
        raise ValueError("Frozen protocol evidence_archive missing")
    runtime_evidence_rel = str(
        archive.get("runtime_evidence_file") or ""
    ).strip()
    if not runtime_evidence_rel:
        raise ValueError(
            "Frozen protocol does not declare evidence_archive.runtime_evidence_file"
        )
    expected_evidence_path = (ROOT / runtime_evidence_rel).resolve()
    resolved_evidence_path = (
        expected_evidence_path
        if evidence_path is None
        else evidence_path.resolve()
    )
    if resolved_evidence_path != expected_evidence_path:
        raise ValueError("Formal Step9 evidence manifest path mismatch")
    if not resolved_evidence_path.exists():
        raise FileNotFoundError(
            "Exact Final Freeze evidence manifest must be restored before "
            f"Formal Step9: {rel(resolved_evidence_path)}"
        )
    evidence = read_json(resolved_evidence_path)
    expected_evidence_schema = final_freeze_evidence_schema(protocol)
    validate_supported_evidence_schema(expected_evidence_schema)
    if evidence.get("schema_version") != expected_evidence_schema:
        raise ValueError("Unexpected Final Freeze evidence schema")
    if evidence.get("status") != "PASS":
        raise ValueError("Final Freeze evidence is not PASS")
    if evidence.get("protocol_file") != rel(protocol_path):
        raise ValueError("Final Freeze evidence protocol path mismatch")
    if evidence.get("method_freeze_runtime_file") != rel(method_path):
        raise ValueError("Final Freeze evidence Method Freeze runtime path mismatch")
    archived_rel = str(archive.get("method_freeze_path") or "").strip()
    if evidence.get("archived_method_freeze_path") != archived_rel:
        raise ValueError("Final Freeze evidence archive path mismatch")
    actual_method_raw = raw_sha256_file(method_path)
    if actual_method_raw != str(
        evidence.get("method_freeze_raw_sha256") or ""
    ):
        raise ValueError(
            "Formal Step9 Method Freeze bytes differ from archived Final Freeze "
            "evidence"
        )
    actual_protocol_raw = raw_sha256_file(protocol_path)
    if actual_protocol_raw != str(
        evidence.get("protocol_raw_sha256") or ""
    ):
        raise ValueError("Final Freeze evidence protocol raw SHA-256 mismatch")
    if evidence.get("method_closure_sha256") != method.get(
        "method_closure_sha256"
    ):
        raise ValueError("Final Freeze evidence method-closure mismatch")
    git_info = method.get("git") or {}
    if evidence.get("source_commit") != git_info.get("commit"):
        raise ValueError("Final Freeze evidence source commit mismatch")
    if evidence.get("source_tree") != git_info.get("tree"):
        raise ValueError("Final Freeze evidence source tree mismatch")
    authority = evidence.get("freeze_authority")
    if not isinstance(authority, dict):
        raise ValueError("Final Freeze authority record missing")
    if authority.get("commit_sha") != git_info.get("commit"):
        raise ValueError("Final Freeze authority is not the bound full commit SHA")
    if authority.get("branch_ref_role") != "convenience_only_not_authority":
        raise ValueError("Movable branch ref is incorrectly treated as freeze authority")
    if evidence.get("formal_step9_started_at_freeze") is not False:
        raise ValueError("Final Freeze evidence was not captured pre-Step9")
    method["formal_freeze_evidence_verification"] = {
        "status": "PASS",
        "evidence_file": rel(resolved_evidence_path),
        "method_freeze_raw_sha256": actual_method_raw,
        "protocol_raw_sha256": actual_protocol_raw,
        "freeze_authority_commit": authority.get("commit_sha"),
        "branch_ref_role": authority.get("branch_ref_role"),
    }
    return method


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Freeze the repaired CodeSentry-Gen method/runtime before any "
            "fresh Step9 generation. Registry/release evidence is intentionally "
            "not part of this pre-generation method freeze."
        )
    )
    parser.add_argument("--protocol", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    protocol_path, protocol, lineage = require_active_frozen_protocol(
        args.protocol,
        operation="Step9 pre-generation method freeze",
    )
    protocol_id = str(protocol.get("protocol_id") or "").strip()
    freeze_requests = {
        "step9_v4_final_r5_r9": (
            ROOT / "config/step9_v4_final_r5_r9_freeze_request.json"
        ),
        "step9_v4_final_r5_r10": (
            ROOT / "config/step9_v4_final_r5_r10_freeze_request.json"
        ),
        "step9_v4_final_r5_r11": (
            ROOT / "config/step9_v4_final_r5_r11_freeze_request.json"
        ),
        "step9_v4_final_r5_r12": (
            ROOT / "config/step9_v4_final_r5_r12_freeze_request.json"
        ),
        "step9_v4_final_r5_r13": (
            ROOT / "config/step9_v4_final_r5_r13_freeze_request.json"
        ),
    }
    if protocol_id in freeze_requests:
        pointer_acceptance = lineage["pointer"].get(
            "post_promotion_acceptance"
        )
        active_entry = lineage["registry"].get("active_protocol")
        registry_acceptance = (
            active_entry.get("post_promotion_acceptance")
            if isinstance(active_entry, dict)
            else None
        )
        freeze_request = read_json(freeze_requests[protocol_id])
        if not (
            isinstance(pointer_acceptance, dict)
            and pointer_acceptance.get("status") == "PASS"
            and isinstance(registry_acceptance, dict)
            and registry_acceptance.get("status") == "PASS"
            and freeze_request.get("status")
            == "POST_PROMOTION_ACCEPTANCE_PASS"
            and freeze_request.get("post_promotion_acceptance_status")
            == "PASS"
        ):
            raise ValueError(
                f"{protocol_id} Method Freeze requires mandatory "
                "post-promotion acceptance PASS"
            )
        if (
            freeze_request.get("exact_method_freeze_created") is not False
            or freeze_request.get("leakage_audit_started") is not False
            or freeze_request.get("fresh_selection_started") is not False
            or freeze_request.get("fresh_generation_started") is not False
        ):
            raise ValueError(
                f"{protocol_id} Method Freeze must precede exact-freeze "
                "closure, leakage, selection, and generation"
            )
    if protocol.get("fresh_generation_started") is not False:
        raise ValueError("Method freeze must precede fresh generation")
    expected_python_exact = str(
        protocol.get("final_freeze_decisions", {}).get(
            "method_freeze_python_exact"
        )
        or ""
    ).strip()
    if not expected_python_exact:
        raise ValueError(
            "Frozen protocol must declare final_freeze_decisions."
            "method_freeze_python_exact"
        )
    if platform.python_version() != expected_python_exact:
        raise ValueError(
            "Method freeze must run under the protocol-bound exact Python "
            f"version: expected={expected_python_exact} "
            f"actual={platform.python_version()}"
        )

    out = args.out if args.out.is_absolute() else ROOT / args.out
    expected_out = ROOT / str(
        protocol.get("planned_outputs", {}).get("method_freeze") or ""
    )
    if not str(protocol.get("planned_outputs", {}).get("method_freeze") or ""):
        raise ValueError("Protocol does not declare planned_outputs.method_freeze")
    if out.resolve() != expected_out.resolve():
        raise ValueError(
            "Method freeze must use the protocol-declared output path"
        )

    files: set[Path] = set()
    entry_paths = [ROOT / value for value in CORE_ENTRY_SCRIPTS]
    files.update(collect_python_closure(entry_paths))
    for relative in STATIC_RUNTIME_INPUTS:
        files.add(ROOT / relative)
    optional_runtime_inputs_present: list[str] = []
    for relative in OPTIONAL_RUNTIME_INPUTS:
        path = ROOT / relative
        if path.is_file():
            files.add(path)
            optional_runtime_inputs_present.append(relative)

    kb_paths = sorted(
        (ROOT / "data/avcs_package_kb").glob("*_package_kb_v0.json")
    )
    if len(kb_paths) != 11:
        raise ValueError(
            f"Expected 11 Package KBs, got {len(kb_paths)}"
        )

    declared_refs: set[Path] = set()
    runtime_refs: set[Path] = set()
    for kb_path in kb_paths:
        files.add(kb_path)
        kb = read_json(kb_path)
        declared = package_kb_declared_hashed_artifact_refs(kb_path, kb)
        runtime = package_kb_runtime_refs(kb_path, kb)
        declared_refs.update(declared)
        runtime_refs.update(runtime)
        files.update(runtime)

    missing = sorted(
        rel(path) for path in files
        if not path.exists() or not path.is_file()
    )
    if missing:
        raise FileNotFoundError(
            "Method freeze runtime inputs missing: " + ",".join(missing[:20])
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
        for path in sorted(files, key=rel)
    }

    dirty = tracked_dirty_files()
    dirty_in_closure = sorted(
        value for value in dirty if value in entries
    )
    if dirty_in_closure:
        raise ValueError(
            "Tracked method runtime files are dirty: "
            + ",".join(dirty_in_closure)
        )

    exact_lock = ROOT / "requirements-core-lock.txt"
    if not exact_lock.exists():
        raise FileNotFoundError(exact_lock)

    contract_revision = method_freeze_contract_revision(protocol)
    validate_supported_freeze_revision(contract_revision)

    report = {
        "schema_version": "codesentry_gen_step9_method_freeze_v1",
        "contract_revision": contract_revision,
        "status": "PASS",
        "protocol_file": rel(protocol_path),
        "protocol_hash": hash_record(protocol_path),
        "git": {
            "commit": git_text("rev-parse", "HEAD"),
            "tree": git_text("rev-parse", "HEAD^{tree}"),
            "tracked_dirty_files": dirty,
            "tracked_dirty_files_in_method_closure": dirty_in_closure,
        },
        "runtime_environment": {
            "python_version": sys.version,
            "python_version_exact": platform.python_version(),
            "protocol_expected_python_version_exact": expected_python_exact,
            "python_implementation": platform.python_implementation(),
            "platform": platform.platform(),
            "requirements_file": rel(exact_lock),
            "requirements": installed_runtime_requirement_versions(exact_lock),
        },
        "entry_scripts": CORE_ENTRY_SCRIPTS,
        "static_runtime_inputs": STATIC_RUNTIME_INPUTS,
        "optional_runtime_inputs_present": optional_runtime_inputs_present,
        "package_kb_count": len(kb_paths),
        "package_kb_declared_hashed_artifact_count": len(declared_refs),
        "package_kb_runtime_artifact_count": len(runtime_refs),
        "file_count": len(entries),
        "files": entries,
        "method_closure_sha256": canonical_manifest_sha256(entries),
        "scientific_boundary": {
            "created_before_fresh_generation": True,
            "generation_outputs_not_inputs": True,
            "release_snapshot_not_yet_acquired": True,
            "method_and_thresholds_frozen_before_generation": True,
            "exact_python_patch_protocol_bound_and_verified": True,
            "exact_archived_method_freeze_bytes_required_for_formal_step9": True,
            "full_commit_sha_is_freeze_authority": True,
            "movable_branch_ref_is_not_freeze_authority": True,
            "historical_step8_freeze_is_provenance_only": True,
            "post_generation_registry_evidence_may_not_change_method_hashes": True,
        },
    }
    write_json(out, report)

    print("STEP9 PRE-GENERATION METHOD FREEZE PASS")
    print("files =", report["file_count"])
    print("git_commit =", report["git"]["commit"])
    print("method_closure_sha256 =", report["method_closure_sha256"])
    print("saved =", rel(out))


if __name__ == "__main__":
    main()
