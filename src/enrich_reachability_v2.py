from __future__ import annotations

import argparse
import ast
import configparser
import json
import re

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 compatibility
    import tomli as tomllib
from collections import Counter
from pathlib import Path
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement

from package_identity_v1 import (
    DEFAULT_POLICY as DEFAULT_IDENTITY_POLICY,
    PackageIdentityService,
)
from project_dependency_facts_v1 import (
    FACTS_SCHEMA_VERSION,
    collect_project_dependency_facts,
)
from sceg_ir_v21 import (
    project_dependency_facts_for_sample,
    read_json as read_sceg_json,
    verify_ir as verify_sceg_ir,
)


ROOT = Path(__file__).resolve().parents[1]
REACHABILITY_ORDER = {
    "mention_only": 0,
    "import_only": 1,
    "manifest_declared": 2,
    "lockfile_resolved": 3,
    "ci_installable": 4,
}
LEGACY_LEVEL_ALIASES = {
    "docker_installable": "ci_installable",
}


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8-sig") as handle:
        for line_no, raw in enumerate(handle, start=1):
            text = raw.strip()
            if not text:
                continue
            value = json.loads(text)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_no}: expected object")
            rows.append(value)
    return rows


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def rel_to(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name


def normalize_level(value: Any) -> str:
    text = str(value or "").strip() or "import_only"
    return LEGACY_LEVEL_ALIASES.get(text, text)


def max_level(*levels: str) -> str:
    normalized = [normalize_level(value) for value in levels]
    return max(
        normalized,
        key=lambda value: REACHABILITY_ORDER.get(value, -1),
    )


def parse_requirement_name(
    text: str,
    *,
    identity_service: PackageIdentityService,
) -> str | None:
    stripped = str(text or "").strip()
    if not stripped or stripped.startswith(("#", "-", "--")):
        return None
    stripped = stripped.split("#", 1)[0].strip()
    try:
        req = Requirement(stripped)
    except InvalidRequirement:
        return None
    identity = identity_service.resolve(
        raw_name=req.name,
        source_type="manifest",
    )
    return identity.normalized_distribution


def add_manifest_entry(
    result: dict[str, list[dict[str, Any]]],
    *,
    package: str | None,
    path: Path,
    line: int | None,
    source_kind: str,
    sample_root: Path,
    version: str | None = None,
) -> None:
    if not package:
        return
    result.setdefault(package, []).append(
        {
            "file": rel_to(path, sample_root),
            "line": line,
            "source_kind": source_kind,
            "version": version,
        }
    )


def collect_requirements_manifests(
    sample_root: Path,
    identity_service: PackageIdentityService,
) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}
    for path in sorted(sample_root.rglob("requirements*.txt")):
        if not path.is_file():
            continue
        for line_no, raw in enumerate(
            path.read_text(
                encoding="utf-8-sig",
                errors="ignore",
            ).splitlines(),
            start=1,
        ):
            package = parse_requirement_name(
                raw,
                identity_service=identity_service,
            )
            add_manifest_entry(
                result,
                package=package,
                path=path,
                line=line_no,
                source_kind="requirements",
                sample_root=sample_root,
            )
    return result


def collect_pyproject(
    sample_root: Path,
    identity_service: PackageIdentityService,
) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}
    path = sample_root / "pyproject.toml"
    if not path.exists():
        return result
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return result

    project = data.get("project")
    if isinstance(project, dict):
        deps = project.get("dependencies")
        if isinstance(deps, list):
            for raw in deps:
                package = parse_requirement_name(
                    str(raw),
                    identity_service=identity_service,
                )
                add_manifest_entry(
                    result,
                    package=package,
                    path=path,
                    line=None,
                    source_kind="pyproject.project.dependencies",
                    sample_root=sample_root,
                )

    tool = data.get("tool")
    poetry = tool.get("poetry") if isinstance(tool, dict) else None
    deps = poetry.get("dependencies") if isinstance(poetry, dict) else None
    if isinstance(deps, dict):
        for name, spec in deps.items():
            if str(name).lower() == "python":
                continue
            # Optional Poetry dependencies are not promoted conservatively.
            if isinstance(spec, dict) and spec.get("optional") is True:
                continue
            identity = identity_service.resolve(
                raw_name=str(name),
                source_type="manifest",
            )
            add_manifest_entry(
                result,
                package=identity.normalized_distribution,
                path=path,
                line=None,
                source_kind="pyproject.poetry.dependencies",
                sample_root=sample_root,
            )
    return result


def collect_setup_cfg(
    sample_root: Path,
    identity_service: PackageIdentityService,
) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}
    path = sample_root / "setup.cfg"
    if not path.exists():
        return result
    parser = configparser.ConfigParser()
    try:
        parser.read(path, encoding="utf-8")
    except Exception:
        return result
    if not parser.has_option("options", "install_requires"):
        return result
    raw = parser.get("options", "install_requires")
    for line in raw.splitlines():
        package = parse_requirement_name(
            line,
            identity_service=identity_service,
        )
        add_manifest_entry(
            result,
            package=package,
            path=path,
            line=None,
            source_kind="setup_cfg.install_requires",
            sample_root=sample_root,
        )
    return result


def _literal_string_list(node: ast.AST) -> list[str] | None:
    if not isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return None
    values: list[str] = []
    for item in node.elts:
        if not isinstance(item, ast.Constant) or not isinstance(
            item.value, str
        ):
            return None
        values.append(item.value)
    return values


def collect_setup_py(
    sample_root: Path,
    identity_service: PackageIdentityService,
) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}
    path = sample_root / "setup.py"
    if not path.exists():
        return result
    try:
        tree = ast.parse(path.read_text(encoding="utf-8-sig"))
    except (SyntaxError, UnicodeDecodeError):
        return result

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for keyword in node.keywords:
            if keyword.arg != "install_requires":
                continue
            values = _literal_string_list(keyword.value)
            if values is None:
                continue
            for raw in values:
                package = parse_requirement_name(
                    raw,
                    identity_service=identity_service,
                )
                add_manifest_entry(
                    result,
                    package=package,
                    path=path,
                    line=getattr(keyword.value, "lineno", None),
                    source_kind="setup_py.install_requires",
                    sample_root=sample_root,
                )
    return result


def collect_pipfile(
    sample_root: Path,
    identity_service: PackageIdentityService,
) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}
    path = sample_root / "Pipfile"
    if not path.exists():
        return result
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return result
    packages = data.get("packages")
    if not isinstance(packages, dict):
        return result
    for name in packages:
        identity = identity_service.resolve(
            raw_name=str(name),
            source_type="manifest",
        )
        add_manifest_entry(
            result,
            package=identity.normalized_distribution,
            path=path,
            line=None,
            source_kind="pipfile.packages",
            sample_root=sample_root,
        )
    return result


def merge_evidence_maps(
    *values: dict[str, list[dict[str, Any]]],
) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}
    for value in values:
        for package, rows in value.items():
            result.setdefault(package, []).extend(rows)
    return result


def collect_manifest_evidence(
    sample_root: Path,
    identity_service: PackageIdentityService,
) -> dict[str, list[dict[str, Any]]]:
    return merge_evidence_maps(
        collect_requirements_manifests(sample_root, identity_service),
        collect_pyproject(sample_root, identity_service),
        collect_setup_cfg(sample_root, identity_service),
        collect_setup_py(sample_root, identity_service),
        collect_pipfile(sample_root, identity_service),
    )


def collect_lock_evidence(
    sample_root: Path,
    identity_service: PackageIdentityService,
    manifest_packages: set[str],
) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}

    pipfile_lock = sample_root / "Pipfile.lock"
    if pipfile_lock.exists():
        try:
            value = json.loads(
                pipfile_lock.read_text(encoding="utf-8-sig")
            )
        except Exception:
            value = {}
        default = value.get("default") if isinstance(value, dict) else None
        if isinstance(default, dict):
            for name, row in default.items():
                identity = identity_service.resolve(
                    raw_name=str(name),
                    source_type="manifest",
                )
                package = identity.normalized_distribution
                if package not in manifest_packages:
                    continue
                version = (
                    str(row.get("version") or "").strip()
                    if isinstance(row, dict)
                    else ""
                )
                if version.startswith("==") and len(version) > 2:
                    add_manifest_entry(
                        result,
                        package=package,
                        path=pipfile_lock,
                        line=None,
                        source_kind="pipfile_lock.default",
                        sample_root=sample_root,
                        version=version[2:],
                    )

    lock_candidates = [
        path
        for path in sample_root.rglob("*")
        if path.is_file()
        and (
            path.name.lower() in {
                "requirements.lock",
                "requirements.txt.lock",
            }
            or (
                "lock" in path.name.lower()
                and path.suffix.lower() in {".txt", ".lock"}
            )
        )
    ]
    exact_pattern = re.compile(
        r"^\s*([A-Za-z0-9_.-]+)\s*==\s*([^\s;#]+)"
    )
    for path in sorted(set(lock_candidates)):
        for line_no, raw in enumerate(
            path.read_text(
                encoding="utf-8-sig",
                errors="ignore",
            ).splitlines(),
            start=1,
        ):
            match = exact_pattern.match(raw)
            if not match:
                continue
            identity = identity_service.resolve(
                raw_name=match.group(1),
                source_type="manifest",
            )
            package = identity.normalized_distribution
            if package not in manifest_packages:
                continue
            add_manifest_entry(
                result,
                package=package,
                path=path,
                line=line_no,
                source_kind="requirements_lock_exact_pin",
                sample_root=sample_root,
                version=match.group(2),
            )
    return result


_DIRECT_INSTALL_RE = re.compile(
    r"(?i)(?:python\s+-m\s+)?pip(?:3)?\s+install\b(?P<args>[^\n]*)"
)


def collect_installability_evidence(
    sample_root: Path,
    identity_service: PackageIdentityService,
    manifest_packages: set[str],
) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}
    candidates: list[Path] = []
    for path in sample_root.rglob("*"):
        if not path.is_file():
            continue
        rel = rel_to(path, sample_root).lower()
        if (
            path.name.lower().startswith("dockerfile")
            or rel.startswith(".github/workflows/")
            or path.suffix.lower() in {".sh", ".bash", ".yml", ".yaml"}
        ):
            candidates.append(path)

    for path in sorted(set(candidates)):
        lines = path.read_text(
            encoding="utf-8-sig",
            errors="ignore",
        ).splitlines()
        for line_no, line in enumerate(lines, start=1):
            match = _DIRECT_INSTALL_RE.search(line)
            if not match:
                continue
            args = match.group("args")
            is_manifest_install = bool(
                re.search(r"(?:^|\s)(?:-r|--requirement)\s+\S+", args)
                or re.search(r"(?:^|\s)\.\s*(?:$|\s)", args)
            )
            if is_manifest_install:
                for package in sorted(manifest_packages):
                    add_manifest_entry(
                        result,
                        package=package,
                        path=path,
                        line=line_no,
                        source_kind="ci_manifest_install",
                        sample_root=sample_root,
                    )
                continue

            tokens = [
                token.strip()
                for token in re.split(r"\s+", args.strip())
                if token.strip() and not token.startswith("-")
            ]
            for token in tokens:
                package = parse_requirement_name(
                    token,
                    identity_service=identity_service,
                )
                add_manifest_entry(
                    result,
                    package=package,
                    path=path,
                    line=line_no,
                    source_kind="ci_direct_install",
                    sample_root=sample_root,
                )
    return result


def identity_package(record: dict[str, Any]) -> str:
    identity = record.get("package_identity")
    if isinstance(identity, dict):
        package = str(
            identity.get("normalized_distribution") or ""
        ).strip()
        if package:
            return package
    return str(record.get("package") or "").strip()


def enrich(
    *,
    input_path: Path,
    output_path: Path,
    summary_path: Path,
    project_snapshots_dir: Path | None,
    identity_policy_path: Path,
    sceg_ir_path: Path | None = None,
    requirements_dir: Path | None = None,
    evidence_dir: Path | None = None,
) -> None:
    records = read_jsonl(input_path)
    enriched: list[dict[str, Any]] = []
    cache: dict[str, dict[str, Any]] = {}

    sceg_ir: dict[str, Any] | None = None
    if sceg_ir_path is not None:
        sceg_ir = read_sceg_json(sceg_ir_path)
        verify_sceg_ir(sceg_ir)
        if sceg_ir.get("schema_version") != "2.1":
            raise ValueError(
                "Reachability requires SCEG schema_version 2.1"
            )
    elif project_snapshots_dir is None:
        raise ValueError(
            "Reachability requires canonical --sceg-ir or legacy "
            "--project-snapshots-dir"
        )

    for rec in records:
        sample_id = str(rec.get("sample_id") or "").strip()
        if not sample_id:
            raise ValueError("Reachability record missing sample_id")

        if sample_id not in cache:
            if sceg_ir is not None:
                project_facts = project_dependency_facts_for_sample(
                    sceg_ir,
                    sample_id,
                )
                if project_facts.get("schema_version") != FACTS_SCHEMA_VERSION:
                    raise ValueError(
                        f"{sample_id}: unexpected canonical project facts schema"
                    )
                identity_policy_version = str(
                    (
                        sceg_ir.get("package_identity_contract") or {}
                    ).get("policy_version")
                    or ""
                )
                if not identity_policy_version:
                    raise ValueError(
                        f"{sample_id}: SCEG identity policy version missing"
                    )
                snapshots_root = str(
                    (
                        sceg_ir.get("source_inputs") or {}
                    ).get("project_snapshots_dir")
                    or ""
                ).strip()
                project_snapshot = (
                    f"{snapshots_root.rstrip('/')}/{sample_id}"
                    if snapshots_root
                    else None
                )
                cache[sample_id] = {
                    "identity_policy_version": identity_policy_version,
                    "project_facts": project_facts,
                    "manifests": project_facts["manifests"],
                    "locks": project_facts["locks"],
                    "installable": project_facts["installability"],
                    "project_snapshot": project_snapshot,
                    "sceg_source_snapshot_id": sceg_ir.get(
                        "source_snapshot_id"
                    ),
                    "canonical_sceg_input": True,
                }
            else:
                assert project_snapshots_dir is not None
                sample_root = project_snapshots_dir / sample_id
                if not sample_root.exists():
                    raise FileNotFoundError(
                        f"Project snapshot missing for {sample_id}: "
                        f"{sample_root}"
                    )
                identity_service = PackageIdentityService(
                    policy_path=identity_policy_path,
                    project_root=sample_root,
                )
                project_facts = collect_project_dependency_facts(
                    sample_root,
                    identity_policy_path=identity_policy_path,
                )
                if project_facts.get("identity_policy_version") != (
                    identity_service.policy_version
                ):
                    raise ValueError(
                        f"{sample_id}: project dependency fact identity drift"
                    )
                cache[sample_id] = {
                    "identity_policy_version": (
                        identity_service.policy_version
                    ),
                    "project_facts": project_facts,
                    "manifests": project_facts["manifests"],
                    "locks": project_facts["locks"],
                    "installable": project_facts["installability"],
                    "project_snapshot": rel_to(sample_root, ROOT),
                    "sceg_source_snapshot_id": None,
                    "canonical_sceg_input": False,
                }

        info = cache[sample_id]
        package = identity_package(rec)
        identity = rec.get("package_identity")
        if not isinstance(identity, dict):
            raise ValueError(
                f"{sample_id}/{package}: package_identity missing"
            )
        if identity.get("policy_version") != (
            info["identity_policy_version"]
        ):
            raise ValueError(
                f"{sample_id}/{package}: identity policy drift"
            )

        identity_status = str(identity.get("identity_status") or "")
        original = normalize_level(
            rec.get("install_reachability")
        )

        manifest_rows = info["manifests"].get(package, [])
        lock_rows = info["locks"].get(package, [])
        install_rows = info["installable"].get(package, [])

        if identity_status != "distribution_candidate":
            level = original
        elif install_rows:
            level = "ci_installable"
        elif lock_rows:
            level = "lockfile_resolved"
        elif manifest_rows:
            level = "manifest_declared"
        else:
            level = max_level(original, "import_only")

        new_rec = dict(rec)
        new_rec["install_reachability_v2"] = level
        new_rec["reachability_policy_version"] = (
            "codesentry_gen_reachability_r0_r4_v1"
        )
        new_rec["reachability_v2_evidence"] = {
            "sample_id": sample_id,
            "package": package,
            "identity_policy_version": identity.get("policy_version"),
            "project_dependency_facts_schema": FACTS_SCHEMA_VERSION,
            "identity_status": identity_status,
            "original_install_reachability": original,
            "install_reachability_v2": level,
            "manifest_declared": bool(manifest_rows),
            "manifest_evidence": manifest_rows,
            "lockfile_resolved": bool(lock_rows),
            "lockfile_evidence": lock_rows,
            "ci_installable": bool(install_rows),
            "ci_install_evidence": install_rows,
            # Historical fields retained for downstream compatibility only.
            "docker_installable": False,
            "docker_install_commands": [],
            "ci_install_commands": install_rows,
            "project_snapshot": info["project_snapshot"],
            "path_policy": "project_snapshot_relative_only",
            "canonical_sceg_input": info["canonical_sceg_input"],
            "sceg_source_snapshot_id": info[
                "sceg_source_snapshot_id"
            ],
            "project_source_reread_after_sceg": (
                False if info["canonical_sceg_input"] else None
            ),
            "r5_install_script_executable_implemented": False,
        }
        new_rec["install_time_evidence"] = {
            "status": "unknown",
            "t_install": None,
            "source": None,
            "reason": (
                "R2-R4 evidence proves install reachability only; it does not "
                "prove observed or scheduled installation time."
            ),
        }
        enriched.append(new_rec)

    write_jsonl(output_path, enriched)
    write_summary(
        summary_path=summary_path,
        input_path=input_path,
        output_path=output_path,
        old_records=records,
        new_records=enriched,
    )


def write_summary(
    *,
    summary_path: Path,
    input_path: Path,
    output_path: Path,
    old_records: list[dict[str, Any]],
    new_records: list[dict[str, Any]],
) -> None:
    counter = Counter(
        str(row.get("install_reachability_v2") or "unknown")
        for row in new_records
    )
    lines = [
        "# Install Reachability R0-R4 Summary",
        "",
        f"- input: `{input_path.name}`",
        f"- output: `{output_path.name}`",
        f"- total_records: {len(new_records)}",
        "- policy: `codesentry_gen_reachability_r0_r4_v1`",
        "- R5 install-script execution: not implemented",
        "",
        "## Levels",
        "",
    ]
    for key in (
        "mention_only",
        "import_only",
        "manifest_declared",
        "lockfile_resolved",
        "ci_installable",
    ):
        lines.append(f"- {key}: {counter.get(key, 0)}")
    lines.extend(
        [
            "",
            "## Scientific boundary",
            "",
            "- Package matching consumes the shared PackageIdentityService identity.",
            "- Manifest names remain literal distribution identities.",
            "- Lockfile resolution upgrades only direct manifest packages with an exact resolved version.",
            "- Docker/CI/shell installation evidence maps to R4 ci_installable.",
            "- Optional/dynamic/transitive cases are not promoted when evidence is insufficient.",
            "- Installability does not establish t_install.",
            "- Evidence paths are project-snapshot relative.",
        ]
    )
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--summary", required=True, type=Path)
    parser.add_argument(
        "--project-snapshots-dir",
        required=False,
        type=Path,
        default=None,
        help=(
            "Legacy standalone fallback only. Formal repaired E2E uses "
            "--sceg-ir as the canonical post-extraction input."
        ),
    )
    parser.add_argument(
        "--sceg-ir",
        required=False,
        type=Path,
        default=None,
        help="Canonical SCEG 2.1 input for formal repaired E2E.",
    )
    parser.add_argument(
        "--identity-policy",
        type=Path,
        default=DEFAULT_IDENTITY_POLICY,
    )
    # Legacy args stay accepted for historical commands but are not the
    # repair-line evidence source.
    parser.add_argument("--requirements-dir", default=None)
    parser.add_argument("--evidence-dir", default=None)
    args = parser.parse_args()

    def resolve(path: Path) -> Path:
        return path if path.is_absolute() else ROOT / path

    enrich(
        input_path=resolve(args.input),
        output_path=resolve(args.output),
        summary_path=resolve(args.summary),
        project_snapshots_dir=(
            resolve(args.project_snapshots_dir)
            if args.project_snapshots_dir is not None
            else None
        ),
        identity_policy_path=resolve(args.identity_policy),
        sceg_ir_path=(
            resolve(args.sceg_ir)
            if args.sceg_ir is not None
            else None
        ),
        requirements_dir=(
            resolve(Path(args.requirements_dir))
            if args.requirements_dir
            else None
        ),
        evidence_dir=(
            resolve(Path(args.evidence_dir))
            if args.evidence_dir
            else None
        ),
    )
    print("REACHABILITY R0-R4 ENRICHMENT PASS")
    print("output =", resolve(args.output))
    print("summary =", resolve(args.summary))


if __name__ == "__main__":
    main()
