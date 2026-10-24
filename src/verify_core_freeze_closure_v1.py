from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
from importlib import metadata
from pathlib import Path
from typing import Any

from build_core_freeze_closure_v1 import (
    CORE_ENTRY_SCRIPTS,
    STATIC_RUNTIME_INPUTS,
    collect_python_closure,
    package_kb_declared_hashed_artifact_refs,
    package_kb_runtime_refs,
    release_snapshot_refs,
    verify_runtime_extension_binding,
)
from build_step9_method_freeze_v1 import validate_supported_freeze_revision
from freeze_hash_v1 import (
    canonical_manifest_sha256,
    verify_hash,
)


ROOT = Path(__file__).resolve().parents[1]


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return value


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


def rederive_required_runtime_paths(
    report: dict[str, Any],
) -> tuple[set[Path], set[Path], set[Path]]:
    required: set[Path] = set()
    entry_paths = [ROOT / value for value in CORE_ENTRY_SCRIPTS]
    required.update(collect_python_closure(entry_paths))
    required.update(ROOT / value for value in STATIC_RUNTIME_INPUTS)

    kb_runtime: set[Path] = set()
    kb_declared_hashed: set[Path] = set()
    kb_paths = sorted(
        (ROOT / "data/avcs_package_kb").glob("*_package_kb_v0.json")
    )
    if len(kb_paths) != 11:
        raise ValueError(
            f"Expected 11 Package KBs while verifying closure, got {len(kb_paths)}"
        )
    for kb_path in kb_paths:
        required.add(kb_path)
        kb = read_json(kb_path)
        runtime_refs = package_kb_runtime_refs(kb_path, kb)
        declared_refs = package_kb_declared_hashed_artifact_refs(
            kb_path,
            kb,
        )
        kb_runtime.update(runtime_refs)
        kb_declared_hashed.update(declared_refs)
        required.update(runtime_refs)

    release_text = str(
        report.get("release_snapshot_manifest") or ""
    ).strip()
    if not release_text:
        raise ValueError(
            "Core freeze closure release_snapshot_manifest missing"
        )
    release_manifest = ROOT / release_text
    required.update(release_snapshot_refs(release_manifest))
    return required, kb_runtime, kb_declared_hashed


def verify_core_freeze_closure(
    path: Path,
    *,
    require_git_identity: bool = True,
    require_environment_versions: bool = True,
) -> dict[str, Any]:
    report = read_json(path)

    if report.get("schema_version") != (
        "codesentry_gen_core_freeze_closure_v1"
    ):
        raise ValueError("Unexpected core freeze closure schema")
    if report.get("status") != "PASS":
        raise ValueError("Core freeze closure is not PASS")

    files = report.get("files")
    if not isinstance(files, dict) or not files:
        raise ValueError("Core freeze closure has no files")

    expected_closure = str(
        report.get("closure_sha256", "") or ""
    ).strip()
    actual_closure = canonical_manifest_sha256(files)
    if not expected_closure or actual_closure != expected_closure:
        raise ValueError(
            "Core freeze closure manifest hash drift: "
            f"expected={expected_closure} actual={actual_closure}"
        )

    for relative, expected in files.items():
        if not isinstance(expected, dict):
            raise ValueError(
                f"Invalid closure hash record: {relative}"
            )
        verify_hash(
            ROOT / relative,
            expected,
            label=f"core freeze closure:{relative}",
        )

    required_paths, kb_runtime_refs, kb_declared_hashed_refs = (
        rederive_required_runtime_paths(report)
    )
    reported_paths = {
        (ROOT / str(relative)).resolve()
        for relative in files
    }
    missing_required = sorted(
        path.relative_to(ROOT.resolve()).as_posix()
        for path in required_paths
        if path.resolve() not in reported_paths
    )
    if missing_required:
        raise ValueError(
            "Core freeze closure omits runtime-reachable inputs: "
            + json.dumps(missing_required[:20])
        )

    declared_count = int(
        report.get("package_kb_declared_hashed_artifact_count", -1)
    )
    if declared_count != len(kb_declared_hashed_refs):
        raise ValueError(
            "Core freeze Package-KB declared artifact count drift: "
            f"expected={len(kb_declared_hashed_refs)} "
            f"reported={declared_count}"
        )
    runtime_count = int(
        report.get("package_kb_runtime_artifact_count", -1)
    )
    if runtime_count != len(kb_runtime_refs):
        raise ValueError(
            "Core freeze Package-KB runtime artifact count drift: "
            f"expected={len(kb_runtime_refs)} reported={runtime_count}"
        )

    method_freeze_text = str(
        report.get("method_freeze_file") or ""
    ).strip()
    if method_freeze_text:
        method_freeze_path = ROOT / method_freeze_text
        if not method_freeze_path.exists():
            raise FileNotFoundError(method_freeze_path)
        method_freeze_hash = report.get("method_freeze_hash")
        if not isinstance(method_freeze_hash, dict):
            raise ValueError("Core closure method-freeze hash missing")
        verify_hash(
            method_freeze_path,
            method_freeze_hash,
            label="core closure method freeze",
        )
        method_freeze = read_json(method_freeze_path)
        if method_freeze.get("schema_version") != (
            "codesentry_gen_step9_method_freeze_v1"
        ):
            raise ValueError("Unexpected bound method-freeze schema")
        if method_freeze.get("status") != "PASS":
            raise ValueError("Bound Step9 method freeze is not PASS")
        method_revision = str(
            method_freeze.get("contract_revision") or ""
        ).strip()
        validate_supported_freeze_revision(method_revision)
        method_runtime = method_freeze.get("runtime_environment")
        if not isinstance(method_runtime, dict):
            raise ValueError("Bound method-freeze runtime environment missing")
        method_python_exact = str(
            method_runtime.get("python_version_exact") or ""
        ).strip()
        if not method_python_exact:
            raise ValueError("Bound method freeze exact Python version missing")
        if platform.python_version() != method_python_exact:
            raise ValueError(
                "Exact Python patch differs from bound method freeze: "
                f"expected={method_python_exact} "
                f"actual={platform.python_version()}"
            )
        if method_freeze.get("method_closure_sha256") != report.get(
            "method_closure_sha256"
        ):
            raise ValueError(
                "Core closure method-freeze digest mismatch"
            )
        method_git = method_freeze.get("git")
        closure_git = report.get("git")
        if not isinstance(method_git, dict) or not isinstance(
            closure_git, dict
        ):
            raise ValueError(
                "Core/method closure git identity missing"
            )
        if (
            method_git.get("commit") != closure_git.get("commit")
            or method_git.get("tree") != closure_git.get("tree")
        ):
            raise ValueError(
                "Core closure was built from a different method revision"
            )
        method_files = method_freeze.get("files")
        if not isinstance(method_files, dict) or not method_files:
            raise ValueError("Bound method freeze has no files")
        for relative, expected in method_files.items():
            current = files.get(relative)
            if not isinstance(current, dict):
                raise ValueError(
                    f"Core closure omits method-frozen file: {relative}"
                )
            if current.get("sha256") != expected.get("sha256"):
                raise ValueError(
                    f"Core closure differs from method freeze: {relative}"
                )

    boundary = report.get("scientific_boundary")
    if not isinstance(boundary, dict):
        raise ValueError("Core freeze scientific_boundary missing")
    required_boundary_keys = [
        "package_kb_runtime_artifacts_in_closure",
        "package_kb_recursive_path_sha256_inventory_in_closure",
        "package_kb_runtime_inventory_rederived_from_kb",
        "release_snapshot_timeline_verified",
        "future_dated_snapshot_forbidden",
    ]
    if method_freeze_text:
        required_boundary_keys.extend(
            [
                "pre_generation_method_freeze_bound",
                "post_generation_method_runtime_drift_forbidden",
            ]
        )
    for key in required_boundary_keys:
        if boundary.get(key) is not True:
            raise ValueError(
                f"Core freeze closure missing required boundary flag: {key}"
            )

    git_info = report.get("git")
    if not isinstance(git_info, dict):
        raise ValueError("Core freeze closure git identity missing")

    if require_git_identity:
        expected_commit = str(git_info.get("commit") or "").strip()
        expected_tree = str(git_info.get("tree") or "").strip()
        actual_commit = git_text("rev-parse", "HEAD")
        actual_tree = git_text("rev-parse", "HEAD^{tree}")
        if expected_commit != actual_commit:
            raise ValueError(
                "Core freeze commit mismatch: "
                f"expected={expected_commit} actual={actual_commit}"
            )
        if expected_tree != actual_tree:
            raise ValueError(
                "Core freeze tree mismatch: "
                f"expected={expected_tree} actual={actual_tree}"
            )

    runtime = report.get("runtime_environment")
    if not isinstance(runtime, dict):
        raise ValueError(
            "Core freeze runtime_environment is missing"
        )

    if runtime.get("python_implementation") != (
        platform.python_implementation()
    ):
        raise ValueError("Python implementation differs from freeze")

    frozen_python = str(runtime.get("python_version") or "")
    frozen_major_minor = ".".join(
        frozen_python.split(".", 2)[:2]
    )
    actual_major_minor = f"{sys.version_info.major}.{sys.version_info.minor}"
    if frozen_major_minor != actual_major_minor:
        raise ValueError(
            "Python major/minor differs from freeze: "
            f"expected={frozen_major_minor} actual={actual_major_minor}"
        )

    if require_environment_versions:
        requirements = runtime.get("requirements")
        if not isinstance(requirements, dict):
            raise ValueError(
                "Core freeze exact runtime requirement versions missing"
            )
        verify_runtime_extension_binding(requirements, files, ROOT)
        for name, row in requirements.items():
            if not isinstance(row, dict):
                raise ValueError(
                    f"Invalid frozen requirement entry: {name}"
                )
            expected_installed = row.get("installed")
            expected_version = row.get("installed_version")
            try:
                actual_version = metadata.version(name)
                actual_installed = True
            except metadata.PackageNotFoundError:
                actual_version = None
                actual_installed = False

            if actual_installed != expected_installed:
                raise ValueError(
                    f"Runtime dependency presence drift: {name}"
                )
            if (
                actual_installed
                and str(actual_version) != str(expected_version)
            ):
                raise ValueError(
                    f"Runtime dependency version drift: {name} "
                    f"expected={expected_version} actual={actual_version}"
                )

    return report


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify a CodeSentry-Gen canonical core freeze closure."
    )
    parser.add_argument("--closure", required=True, type=Path)
    parser.add_argument(
        "--allow-different-git-commit",
        action="store_true",
        help=(
            "Debug-only: verify file/content closure without requiring the "
            "same HEAD commit/tree. Formal runs must not use this."
        ),
    )
    args = parser.parse_args()

    closure = args.closure
    if not closure.is_absolute():
        closure = ROOT / closure

    report = verify_core_freeze_closure(
        closure,
        require_git_identity=not args.allow_different_git_commit,
        require_environment_versions=True,
    )

    print("F-06 CORE FREEZE VERIFY PASS")
    print("closure_sha256 =", report["closure_sha256"])
    print("files =", report["file_count"])
    print("git_commit =", report["git"]["commit"])
    print("git_tree =", report["git"]["tree"])


if __name__ == "__main__":
    main()
