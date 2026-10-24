from __future__ import annotations

import ast
import configparser
import json
import re
import shlex
from pathlib import Path, PurePosixPath
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 compatibility
    import tomli as tomllib

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet

from install_command_context_v1 import (
    RunPayload,
    install_invocations,
    install_operands,
    workflow_payloads,
)
from package_identity_v1 import (
    DEFAULT_POLICY as DEFAULT_IDENTITY_POLICY,
    PackageIdentityService,
)


FACTS_SCHEMA_VERSION = "codesentry_gen_project_dependency_facts_v1"
FACTS_EXTRACTOR_VERSION = (
    "project_dependency_facts_v1_4_structured_workflow_installs"
)

PROJECT_METADATA_FILENAMES = (
    "pyproject.toml",
    "setup.cfg",
    "setup.py",
    "Pipfile",
)

PIP_LOCAL_PROJECT_METADATA_FILENAMES = {
    "pyproject.toml",
    "setup.cfg",
    "setup.py",
}


def _recursive_files(root: Path, filename: str) -> list[Path]:
    """Return project files without generated environments or VCS data."""
    ignored_parts = {
        ".git",
        ".venv",
        "venv",
        "__pycache__",
        "node_modules",
        "site-packages",
    }
    return sorted(
        path
        for path in root.rglob(filename)
        if path.is_file()
        and not ignored_parts.intersection(path.relative_to(root).parts)
    )


def _rel(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name


def _dependency_group_for_source(
    path: Path,
    root: Path,
    source_kind: str,
) -> str:
    rel = _rel(path, root).lower()
    name = Path(rel).name.lower()

    if source_kind.startswith("requirements"):
        if name in {
            "requirements.txt",
            "requirements.lock",
            "requirements.txt.lock",
        }:
            return "default"
        match = re.match(
            r"requirements[-_.](?P<group>.+?)(?:\.txt)?(?:\.lock)?$",
            name,
        )
        if match:
            group = str(match.group("group") or "").strip("._-")
            if group:
                return group

    if source_kind.startswith("pipfile"):
        return "default"
    if source_kind.startswith("pyproject"):
        return "default"
    if source_kind.startswith("setup_"):
        return "default"
    return "default"


def manifest_family_for_source(source_kind: str) -> str:
    """Return the manifest family used to separate install contexts."""
    kind = str(source_kind or "").strip().lower()
    if kind.startswith("requirements"):
        return "requirements"
    if kind.startswith("pipfile"):
        return "pipfile"
    if kind.startswith("pyproject"):
        return "pyproject"
    if kind.startswith("setup_cfg"):
        return "setup_cfg"
    if kind.startswith("setup_py"):
        return "setup_py"
    if kind.startswith("ci_direct"):
        return "direct"
    return kind.split(".", 1)[0] or "unknown"


def manifest_context_id_for_row(row: dict[str, Any]) -> str:
    """Build a stable context identity, including for legacy fact rows."""
    declared = str(row.get("manifest_context_id") or "").strip()
    if declared:
        return declared

    rel = str(row.get("file") or "").strip().replace("\\", "/")
    parent = PurePosixPath(rel).parent.as_posix() if rel else "."
    if parent in {"", "/"}:
        parent = "."
    family = manifest_family_for_source(str(row.get("source_kind") or ""))
    group = str(row.get("dependency_group") or "default").strip()
    return f"{family}::{parent}::{group or 'default'}"


def _append(
    result: dict[str, list[dict[str, Any]]],
    *,
    package: str,
    raw_name: str,
    path: Path,
    root: Path,
    source_kind: str,
    line: int | None,
    specifier: str = "",
    raw_specifier: str = "",
    marker: str = "",
    url: str = "",
    constraint_status: str = "resolved",
    exact_version: str | None = None,
    dependency_group: str | None = None,
    environment: str | None = None,
    manifest_file: str | None = None,
    install_target: str | None = None,
    manifest_family: str | None = None,
    manifest_parent: str | None = None,
    manifest_context_id: str | None = None,
) -> None:
    normalized = str(package or "").strip()
    if not normalized:
        return
    group = (
        str(dependency_group).strip()
        if dependency_group is not None
        else _dependency_group_for_source(path, root, source_kind)
    ) or "default"
    env = (
        str(environment).strip()
        if environment is not None
        else group
    ) or "default"
    rel = _rel(path, root)
    family = (
        str(manifest_family).strip()
        if manifest_family is not None
        else manifest_family_for_source(source_kind)
    ) or "unknown"
    parent = (
        str(manifest_parent).strip()
        if manifest_parent is not None
        else PurePosixPath(rel).parent.as_posix()
    ) or "."
    context_id = (
        str(manifest_context_id).strip()
        if manifest_context_id is not None
        else f"{family}::{parent}::{group}"
    ) or f"{family}::{parent}::{group}"
    result.setdefault(normalized, []).append(
        {
            "raw_name": str(raw_name or ""),
            "normalized_distribution": normalized,
            "file": rel,
            "line": line,
            "source_kind": source_kind,
            "specifier": str(specifier or ""),
            "raw_specifier": str(raw_specifier or ""),
            "marker": str(marker or ""),
            "url": str(url or ""),
            "constraint_status": constraint_status,
            "exact_version": exact_version,
            "dependency_group": group,
            "environment": env,
            "manifest_file": manifest_file,
            "install_target": install_target,
            "manifest_family": family,
            "manifest_parent": parent,
            "manifest_context_id": context_id,
        }
    )


def _requirement_fact(
    raw: str,
    *,
    identity_service: PackageIdentityService,
) -> dict[str, Any] | None:
    text = str(raw or "").strip().lstrip("\ufeff")
    if not text or text.startswith(("#", "-", "--")):
        return None
    text = text.split("#", 1)[0].strip()
    if not text:
        return None
    try:
        req = Requirement(text)
    except InvalidRequirement:
        return None
    identity = identity_service.resolve(
        raw_name=req.name,
        source_type="manifest",
    )
    marker = str(req.marker or "")
    url = str(req.url or "")
    if url:
        status = "unsupported_direct_url"
    elif marker:
        status = "conditional"
    else:
        status = "resolved"
    return {
        "raw_name": req.name,
        "package": identity.normalized_distribution,
        "specifier": str(req.specifier),
        "raw_specifier": str(req.specifier),
        "marker": marker,
        "url": url,
        "constraint_status": status,
    }


def _poetry_or_pipfile_spec(value: Any) -> tuple[str, str, str]:
    if isinstance(value, str):
        raw = value.strip()
    elif isinstance(value, dict):
        if value.get("optional") is True:
            return "", "", "optional_skipped"
        if any(key in value for key in ("git", "path", "url")):
            return (
                "",
                json.dumps(value, ensure_ascii=False, sort_keys=True),
                "unsupported_direct_source",
            )
        raw = str(value.get("version") or "").strip()
    else:
        return "", str(value or ""), "unsupported_manifest_syntax"

    if raw in {"", "*"}:
        return "", raw, "resolved"
    try:
        SpecifierSet(raw)
    except InvalidSpecifier:
        return "", raw, "unsupported_manifest_syntax"
    return raw, raw, "resolved"


def _collect_requirements(
    root: Path,
    service: PackageIdentityService,
) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}
    for path in sorted(root.rglob("requirements*.txt")):
        if not path.is_file():
            continue
        for line_no, raw in enumerate(
            path.read_text(
                encoding="utf-8-sig",
                errors="ignore",
            ).splitlines(),
            start=1,
        ):
            fact = _requirement_fact(raw, identity_service=service)
            if fact is None:
                continue
            _append(
                result,
                package=fact["package"],
                raw_name=fact["raw_name"],
                path=path,
                root=root,
                source_kind="requirements",
                line=line_no,
                specifier=fact["specifier"],
                raw_specifier=fact["raw_specifier"],
                marker=fact["marker"],
                url=fact["url"],
                constraint_status=fact["constraint_status"],
            )
    return result


def _collect_pyproject(
    root: Path,
    service: PackageIdentityService,
) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}
    for path in _recursive_files(root, "pyproject.toml"):
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8-sig"))
        except Exception:
            continue

        project = data.get("project")
        deps = (
            project.get("dependencies")
            if isinstance(project, dict)
            else None
        )
        if isinstance(deps, list):
            for raw in deps:
                fact = _requirement_fact(
                    str(raw),
                    identity_service=service,
                )
                if fact is None:
                    continue
                _append(
                    result,
                    package=fact["package"],
                    raw_name=fact["raw_name"],
                    path=path,
                    root=root,
                    source_kind="pyproject.project.dependencies",
                    line=None,
                    specifier=fact["specifier"],
                    raw_specifier=fact["raw_specifier"],
                    marker=fact["marker"],
                    url=fact["url"],
                    constraint_status=fact["constraint_status"],
                )

        tool = data.get("tool")
        poetry = (
            tool.get("poetry")
            if isinstance(tool, dict)
            else None
        )
        poetry_deps = (
            poetry.get("dependencies")
            if isinstance(poetry, dict)
            else None
        )
        if isinstance(poetry_deps, dict):
            for name, value in poetry_deps.items():
                if str(name).lower() == "python":
                    continue
                specifier, raw_specifier, status = (
                    _poetry_or_pipfile_spec(value)
                )
                if status == "optional_skipped":
                    continue
                identity = service.resolve(
                    raw_name=str(name),
                    source_type="manifest",
                )
                _append(
                    result,
                    package=identity.normalized_distribution,
                    raw_name=str(name),
                    path=path,
                    root=root,
                    source_kind="pyproject.poetry.dependencies",
                    line=None,
                    specifier=specifier,
                    raw_specifier=raw_specifier,
                    constraint_status=status,
                )
    return result


def _collect_setup_cfg(
    root: Path,
    service: PackageIdentityService,
) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}
    for path in _recursive_files(root, "setup.cfg"):
        parser = configparser.ConfigParser()
        try:
            parser.read(path, encoding="utf-8")
        except Exception:
            continue
        if not parser.has_option("options", "install_requires"):
            continue
        for raw in parser.get("options", "install_requires").splitlines():
            fact = _requirement_fact(
                raw,
                identity_service=service,
            )
            if fact is None:
                continue
            _append(
                result,
                package=fact["package"],
                raw_name=fact["raw_name"],
                path=path,
                root=root,
                source_kind="setup_cfg.install_requires",
                line=None,
                specifier=fact["specifier"],
                raw_specifier=fact["raw_specifier"],
                marker=fact["marker"],
                url=fact["url"],
                constraint_status=fact["constraint_status"],
            )
    return result


def _literal_strings(node: ast.AST) -> list[str] | None:
    if not isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return None
    values: list[str] = []
    for item in node.elts:
        if (
            not isinstance(item, ast.Constant)
            or not isinstance(item.value, str)
        ):
            return None
        values.append(item.value)
    return values


def _collect_setup_py(
    root: Path,
    service: PackageIdentityService,
) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}
    for path in _recursive_files(root, "setup.py"):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8-sig"))
        except (SyntaxError, UnicodeDecodeError):
            continue

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for keyword in node.keywords:
                if keyword.arg != "install_requires":
                    continue
                values = _literal_strings(keyword.value)
                if values is None:
                    continue
                for raw in values:
                    fact = _requirement_fact(
                        raw,
                        identity_service=service,
                    )
                    if fact is None:
                        continue
                    _append(
                        result,
                        package=fact["package"],
                        raw_name=fact["raw_name"],
                        path=path,
                        root=root,
                        source_kind="setup_py.install_requires",
                        line=getattr(keyword.value, "lineno", None),
                        specifier=fact["specifier"],
                        raw_specifier=fact["raw_specifier"],
                        marker=fact["marker"],
                        url=fact["url"],
                        constraint_status=fact["constraint_status"],
                    )
    return result


def _collect_pipfile(
    root: Path,
    service: PackageIdentityService,
) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}
    for path in _recursive_files(root, "Pipfile"):
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8-sig"))
        except Exception:
            continue
        packages = data.get("packages")
        if not isinstance(packages, dict):
            continue
        for name, value in packages.items():
            specifier, raw_specifier, status = (
                _poetry_or_pipfile_spec(value)
            )
            if status == "optional_skipped":
                continue
            identity = service.resolve(
                raw_name=str(name),
                source_type="manifest",
            )
            _append(
                result,
                package=identity.normalized_distribution,
                raw_name=str(name),
                path=path,
                root=root,
                source_kind="pipfile.packages",
                line=None,
                specifier=specifier,
                raw_specifier=raw_specifier,
                constraint_status=status,
            )
    return result


def _merge(
    *values: dict[str, list[dict[str, Any]]],
) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}
    for value in values:
        for package, rows in value.items():
            result.setdefault(package, []).extend(rows)
    return result


def _collect_locks(
    root: Path,
    service: PackageIdentityService,
    manifest_packages: set[str],
) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}

    pipfile_lock = root / "Pipfile.lock"
    if pipfile_lock.is_file():
        try:
            value = json.loads(
                pipfile_lock.read_text(encoding="utf-8-sig")
            )
        except Exception:
            value = {}
        default = (
            value.get("default")
            if isinstance(value, dict)
            else None
        )
        if isinstance(default, dict):
            for name, row in default.items():
                identity = service.resolve(
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
                    _append(
                        result,
                        package=package,
                        raw_name=str(name),
                        path=pipfile_lock,
                        root=root,
                        source_kind="pipfile_lock.default",
                        line=None,
                        specifier=version,
                        raw_specifier=version,
                        exact_version=version[2:],
                    )

    exact_pattern = re.compile(
        r"^\s*([A-Za-z0-9_.-]+)\s*==\s*([^\s;#]+)"
    )
    candidates = [
        path
        for path in root.rglob("*")
        if path.is_file()
        and (
            path.name.lower()
            in {"requirements.lock", "requirements.txt.lock"}
            or (
                "lock" in path.name.lower()
                and path.suffix.lower() in {".txt", ".lock"}
            )
        )
    ]
    for path in sorted(set(candidates)):
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
            identity = service.resolve(
                raw_name=match.group(1),
                source_type="manifest",
            )
            package = identity.normalized_distribution
            if package not in manifest_packages:
                continue
            version = match.group(2)
            _append(
                result,
                package=package,
                raw_name=match.group(1),
                path=path,
                root=root,
                source_kind="requirements_lock_exact_pin",
                line=line_no,
                specifier=f"=={version}",
                raw_specifier=f"=={version}",
                exact_version=version,
            )
    return result


def _requirement_targets(args: str) -> list[str]:
    tokens = shlex.split(args, posix=True)
    return [tokens[1]] if tokens[:1] == ["-r"] and len(tokens) == 2 else []


def _project_metadata_inventory(root: Path) -> list[dict[str, Any]]:
    """Record every supported project root and fail-closed parser status."""
    rows: list[dict[str, Any]] = []
    for filename in PROJECT_METADATA_FILENAMES:
        for path in _recursive_files(root, filename):
            status = "resolved"
            try:
                if filename in {"pyproject.toml", "Pipfile"}:
                    value = tomllib.loads(
                        path.read_text(encoding="utf-8-sig")
                    )
                    if filename == "pyproject.toml":
                        project = value.get("project")
                        dynamic = (
                            project.get("dynamic", [])
                            if isinstance(project, dict)
                            else []
                        )
                        if (
                            isinstance(dynamic, list)
                            and "dependencies" in dynamic
                        ):
                            status = "unsupported_dynamic_dependencies"
                elif filename == "setup.cfg":
                    parser = configparser.ConfigParser()
                    parser.read(path, encoding="utf-8")
                    if parser.has_option("options", "install_requires"):
                        install_requires = parser.get(
                            "options", "install_requires"
                        )
                        if re.search(
                            r"(?im)^\s*file\s*:",
                            install_requires,
                        ):
                            status = (
                                "unsupported_indirect_install_requires"
                            )
                else:
                    tree = ast.parse(path.read_text(encoding="utf-8-sig"))
                    setup_calls = [
                        node
                        for node in ast.walk(tree)
                        if isinstance(node, ast.Call)
                        and (
                            (
                                isinstance(node.func, ast.Name)
                                and node.func.id == "setup"
                            )
                            or (
                                isinstance(node.func, ast.Attribute)
                                and node.func.attr == "setup"
                            )
                        )
                    ]
                    install_requires = [
                        keyword.value
                        for node in setup_calls
                        for keyword in node.keywords
                        if keyword.arg == "install_requires"
                    ]
                    if any(
                        _literal_strings(value) is None
                        for value in install_requires
                    ):
                        status = "unsupported_dynamic_install_requires"
                    elif any(
                        keyword.arg is None
                        for node in setup_calls
                        for keyword in node.keywords
                    ):
                        status = "unsupported_dynamic_project_metadata"
            except Exception:
                status = "metadata_parse_error"
            rel = _rel(path, root)
            parent = PurePosixPath(rel).parent.as_posix() or "."
            rows.append(
                {
                    "file": rel,
                    "project_root": parent,
                    "manifest_family": manifest_family_for_source(filename),
                    "status": status,
                }
            )
    return sorted(rows, key=lambda row: str(row["file"]))


def _installation_candidates(
    root: Path,
    path: Path,
    lines: list[str],
) -> list[tuple[str, int, Path | None, str | None, str | None]]:
    """Decode real workflow runs, then separate proven pip argv operands."""
    result: list[tuple[str, int, Path | None, str | None, str | None]] = []
    rel = _rel(path, root).lower()
    is_workflow = rel.startswith(".github/workflows/")
    if path.suffix.lower() in {".yml", ".yaml"}:
        payloads, error = workflow_payloads("\n".join(lines))
        if error:
            return [("", 1, None, None, error)]
    elif path.name.lower().startswith("dockerfile"):
        payloads = []
        joined = "\n".join(lines).replace("\\\n", " ")
        for index, line in enumerate(joined.splitlines(), start=1):
            match = re.match(r"^\s*RUN\s+(.+)$", line, re.IGNORECASE)
            if match:
                payloads.append(RunPayload(match.group(1), index))
    else:
        payloads = [RunPayload("\n".join(lines), 1)]

    for payload in payloads:
        base_dir: Path | None = root if is_workflow else None
        base_reason: str | None = None
        if not is_workflow:
            base_reason = ("docker_workdir_not_resolved"
                           if path.name.lower().startswith("dockerfile")
                           else "command_working_directory_not_proven")
        wd = payload.working_directory
        if wd is not None:
            if any(marker in wd for marker in ("$", "`", "%", "{", "}", "*", "?")):
                base_dir, base_reason = None, "dynamic_step_working_directory"
            else:
                try:
                    candidate = (root / wd).resolve()
                    candidate.relative_to(root.resolve())
                    if not candidate.is_dir():
                        base_dir, base_reason = None, "working_directory_missing"
                    else:
                        base_dir, base_reason = candidate, None
                except (OSError, ValueError):
                    base_dir, base_reason = None, "working_directory_outside_project"
        for invocation in install_invocations(payload):
            reason = invocation.reason or (base_reason if is_workflow and base_dir is None else None)
            if reason:
                result.append((invocation.args, invocation.line, None, None, reason))
                continue
            operands, error = install_operands(invocation.args)
            if error:
                result.append((invocation.args, invocation.line, None, None, error))
            else:
                result.extend((args, invocation.line, base_dir, base_reason, None)
                              for args in operands)
    return result


def _local_project_tokens(args: str, base_dir: Path) -> list[str]:
    try:
        tokens = shlex.split(str(args or ""), posix=True)
    except ValueError:
        return []
    result: list[str] = []
    skip_next = False
    for token in tokens:
        if skip_next:
            skip_next = False
            continue
        if token in {
            "-r",
            "--requirement",
            "-c",
            "--constraint",
            "--index-url",
            "--extra-index-url",
        }:
            skip_next = True
            continue
        if token in {"-e", "--editable"}:
            continue
        if token.startswith(("-r=", "--requirement=", "-c=", "--constraint=")):
            continue
        if token.startswith(("-e=", "--editable=")):
            token = token.split("=", 1)[1]
        elif token.startswith("-"):
            continue
        local_token = re.sub(r"\[[^\]]+\]$", "", token)
        if (
            local_token == "."
            or local_token.startswith(("./", "../", "/"))
            or (base_dir / local_token).is_dir()
        ):
            result.append(local_token)
    return result


def _dynamic_install_tokens(args: str) -> list[str]:
    """Return install operands whose target cannot be bound statically."""
    try:
        tokens = shlex.split(str(args or ""), posix=True)
    except ValueError:
        return [str(args or "").strip()] if str(args or "").strip() else []
    result: list[str] = []
    skip_next = False
    for token in tokens:
        if skip_next:
            skip_next = False
            continue
        if token in {
            "-r",
            "--requirement",
            "-c",
            "--constraint",
            "--index-url",
            "--extra-index-url",
        }:
            skip_next = True
            continue
        if token in {"-e", "--editable"}:
            continue
        if token.startswith(("-r=", "--requirement=", "-c=", "--constraint=")):
            continue
        if token.startswith(("-e=", "--editable=")):
            token = token.split("=", 1)[1]
        elif token.startswith("-"):
            continue
        if "://" in token:
            continue
        if any(marker in token for marker in ("$", "{", "}", "*", "?")):
            result.append(token)
    return sorted(set(result))


def _literal_project_target(
    root: Path,
    base_dir: Path,
    raw_target: str,
) -> tuple[str | None, str | None]:
    target = str(raw_target or "").strip().strip("\"'")
    if not target:
        return None, "empty_local_project_target"
    if (
        "://" in target
        or any(token in target for token in ("$", "{", "}", "*", "?"))
    ):
        return None, "dynamic_or_remote_local_project_target"
    try:
        candidate = (base_dir / target).resolve()
        rel = candidate.relative_to(root.resolve()).as_posix()
    except (OSError, ValueError):
        return None, "local_project_outside_project"
    if not candidate.is_dir():
        return None, "local_project_target_missing"
    return rel or ".", None


def _manifest_rows_by_file(
    manifests: dict[str, list[dict[str, Any]]],
) -> dict[str, list[tuple[str, dict[str, Any]]]]:
    result: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    for package, rows in manifests.items():
        for row in rows:
            rel = str(row.get("file") or "").strip()
            if rel:
                result.setdefault(rel, []).append((package, row))
    return result


def _literal_manifest_target(
    root: Path,
    base_dir: Path,
    raw_target: str,
) -> tuple[str | None, str | None]:
    target = str(raw_target or "").strip().strip("\"'")
    if not target:
        return None, "empty_target"
    if (
        "://" in target
        or any(token in target for token in ("$", "{", "}", "*", "?"))
    ):
        return None, "dynamic_or_remote_target"
    try:
        candidate = (base_dir / target).resolve()
        rel = candidate.relative_to(root.resolve()).as_posix()
    except (OSError, ValueError):
        return None, "outside_project_or_invalid_target"
    if not candidate.is_file():
        return None, "missing_target"
    return rel, None


def _requirement_manifest_closure(
    *,
    root: Path,
    target_rel: str,
    rows_by_file: dict[str, list[tuple[str, dict[str, Any]]]],
) -> tuple[list[tuple[str, dict[str, Any]]], list[dict[str, Any]]]:
    selected: list[tuple[str, dict[str, Any]]] = []
    unresolved: list[dict[str, Any]] = []
    queue = [target_rel]
    seen: set[str] = set()

    while queue:
        rel = queue.pop(0)
        if rel in seen:
            continue
        seen.add(rel)

        rows = rows_by_file.get(rel)
        if rows is None:
            unresolved.append(
                {
                    "manifest_file": rel,
                    "reason": "manifest_not_indexed",
                }
            )
        else:
            selected.extend(rows)

        path = root / rel
        if not path.is_file():
            continue
        for line_no, raw in enumerate(
            path.read_text(
                encoding="utf-8-sig",
                errors="ignore",
            ).splitlines(),
            start=1,
        ):
            match = re.match(
                r"^\s*(?:-r|--requirement)(?:=|\s+)(?P<target>[^\s#]+)",
                raw,
            )
            if not match:
                continue
            include_raw = str(match.group("target") or "")
            if any(
                token in include_raw
                for token in ("$", "{", "}", "*", "?")
            ):
                unresolved.append(
                    {
                        "manifest_file": rel,
                        "line": line_no,
                        "target": include_raw,
                        "reason": "dynamic_include",
                    }
                )
                continue
            include_path = (path.parent / include_raw.strip("\"'")).resolve()
            try:
                include_rel = include_path.relative_to(
                    root.resolve()
                ).as_posix()
            except ValueError:
                unresolved.append(
                    {
                        "manifest_file": rel,
                        "line": line_no,
                        "target": include_raw,
                        "reason": "include_outside_project",
                    }
                )
                continue
            if not include_path.is_file():
                unresolved.append(
                    {
                        "manifest_file": rel,
                        "line": line_no,
                        "target": include_raw,
                        "reason": "include_missing",
                    }
                )
                continue
            queue.append(include_rel)

    dedup: dict[tuple[str, str, int | None], tuple[str, dict[str, Any]]] = {}
    for package, row in selected:
        key = (
            package,
            str(row.get("file") or ""),
            row.get("line"),
        )
        dedup[key] = (package, row)
    return list(dedup.values()), unresolved


def _collect_installability(
    root: Path,
    service: PackageIdentityService,
    manifests: dict[str, list[dict[str, Any]]],
    project_metadata: list[dict[str, Any]],
) -> tuple[
    dict[str, list[dict[str, Any]]],
    list[dict[str, Any]],
]:
    result: dict[str, list[dict[str, Any]]] = {}
    unresolved: list[dict[str, Any]] = []
    rows_by_file = _manifest_rows_by_file(manifests)
    candidates: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel = _rel(path, root).lower()
        if (
            path.name.lower().startswith("dockerfile")
            or rel.startswith(".github/workflows/")
            or path.suffix.lower()
            in {".sh", ".bash", ".yml", ".yaml"}
        ):
            candidates.append(path)

    project_metadata_kinds = {
        "pyproject.project.dependencies",
        "pyproject.poetry.dependencies",
        "setup_cfg.install_requires",
        "setup_py.install_requires",
    }

    for path in sorted(set(candidates)):
        lines = path.read_text(
            encoding="utf-8-sig",
            errors="ignore",
        ).splitlines()
        for args, line_no, base_dir, base_reason, parse_reason in (
            _installation_candidates(root, path, lines)
        ):
            if parse_reason:
                unresolved.append(
                    {
                        "file": _rel(path, root),
                        "line": line_no,
                        "target": args.strip(),
                        "reason": parse_reason,
                    }
                )
                continue

            target_matches = _requirement_targets(args)
            if target_matches:
                for raw_target in target_matches:
                    if base_dir is None:
                        unresolved.append(
                            {
                                "file": _rel(path, root),
                                "line": line_no,
                                "target": raw_target,
                                "reason": base_reason,
                            }
                        )
                        continue
                    target_rel, reason = _literal_manifest_target(
                        root,
                        base_dir,
                        raw_target,
                    )
                    if target_rel is None:
                        unresolved.append(
                            {
                                "file": _rel(path, root),
                                "line": line_no,
                                "target": raw_target,
                                "reason": reason,
                            }
                        )
                        continue

                    selected, include_unresolved = (
                        _requirement_manifest_closure(
                            root=root,
                            target_rel=target_rel,
                            rows_by_file=rows_by_file,
                        )
                    )
                    for item in include_unresolved:
                        unresolved.append(
                            {
                                "file": _rel(path, root),
                                "line": line_no,
                                "install_target": target_rel,
                                **item,
                            }
                        )
                    for package, manifest_row in selected:
                        if (
                            str(
                                manifest_row.get("constraint_status")
                                or "resolved"
                            )
                            == "conditional"
                        ):
                            unresolved.append(
                                {
                                    "file": _rel(path, root),
                                    "line": line_no,
                                    "install_target": target_rel,
                                    "manifest_file": str(
                                        manifest_row.get("file") or ""
                                    ),
                                    "package": package,
                                    "marker": str(
                                        manifest_row.get("marker") or ""
                                    ),
                                    "reason": (
                                        "conditional_manifest_entry_"
                                        "without_target_environment"
                                    ),
                                }
                            )
                            continue
                        _append(
                            result,
                            package=package,
                            raw_name=str(
                                manifest_row.get("raw_name")
                                or package
                            ),
                            path=path,
                            root=root,
                            source_kind="ci_manifest_install",
                            line=line_no,
                            specifier=str(
                                manifest_row.get("specifier") or ""
                            ),
                            raw_specifier=str(
                                manifest_row.get("raw_specifier") or ""
                            ),
                            marker=str(
                                manifest_row.get("marker") or ""
                            ),
                            url=str(manifest_row.get("url") or ""),
                            constraint_status=str(
                                manifest_row.get("constraint_status")
                                or "resolved"
                            ),
                            dependency_group=str(
                                manifest_row.get("dependency_group")
                                or "default"
                            ),
                            environment=str(
                                manifest_row.get("environment")
                                or manifest_row.get("dependency_group")
                                or "default"
                            ),
                            manifest_file=str(
                                manifest_row.get("file") or ""
                            ),
                            install_target=target_rel,
                            manifest_family=str(
                                manifest_row.get("manifest_family") or ""
                            ),
                            manifest_parent=str(
                                manifest_row.get("manifest_parent") or ""
                            ),
                            manifest_context_id=str(
                                manifest_row.get("manifest_context_id") or ""
                            ),
                        )
                continue

            dynamic_targets = _dynamic_install_tokens(args)
            if dynamic_targets:
                for raw_target in dynamic_targets:
                    unresolved.append(
                        {
                            "file": _rel(path, root),
                            "line": line_no,
                            "target": raw_target,
                            "reason": (
                                base_reason
                                if base_dir is None and base_reason
                                else "dynamic_install_target_not_resolved"
                            ),
                        }
                    )
                continue

            local_targets = (
                _local_project_tokens(args, base_dir)
                if base_dir is not None
                else []
            )
            local_path_hint = bool(
                re.search(r"(?:^|\s)(?:-e\s+|--editable\s+)?\.{1,2}(?:/|\s|$)", args)
            )
            if base_dir is None and local_path_hint:
                unresolved.append(
                    {
                        "file": _rel(path, root),
                        "line": line_no,
                        "target": args.strip(),
                        "reason": base_reason,
                    }
                )
                continue
            if local_targets:
                for raw_target in local_targets:
                    target_rel, reason = _literal_project_target(
                        root,
                        base_dir,
                        raw_target,
                    )
                    if target_rel is None:
                        unresolved.append(
                            {
                                "file": _rel(path, root),
                                "line": line_no,
                                "target": raw_target,
                                "reason": reason,
                            }
                        )
                        continue

                    metadata_rows = [
                        row
                        for row in project_metadata
                        if str(row.get("project_root") or ".")
                        == target_rel
                    ]
                    if not metadata_rows:
                        unresolved.append(
                            {
                                "file": _rel(path, root),
                                "line": line_no,
                                "install_target": target_rel,
                                "reason": "local_project_metadata_missing",
                            }
                        )
                        continue
                    packaging_metadata_rows = [
                        row
                        for row in metadata_rows
                        if PurePosixPath(
                            str(row.get("file") or "")
                        ).name
                        in PIP_LOCAL_PROJECT_METADATA_FILENAMES
                    ]
                    if not packaging_metadata_rows:
                        unresolved.append(
                            {
                                "file": _rel(path, root),
                                "line": line_no,
                                "install_target": target_rel,
                                "reason": (
                                    "local_project_packaging_metadata_missing"
                                ),
                            }
                        )
                        continue
                    for metadata_row in packaging_metadata_rows:
                        if metadata_row.get("status") != "resolved":
                            unresolved.append(
                                {
                                    "file": _rel(path, root),
                                    "line": line_no,
                                    "install_target": target_rel,
                                    "manifest_file": metadata_row.get("file"),
                                    "reason": metadata_row.get("status"),
                                }
                            )

                    metadata_files = {
                        str(row.get("file") or "")
                        for row in packaging_metadata_rows
                        if row.get("status") == "resolved"
                    }
                    selected = [
                        (package, manifest_row)
                        for package, rows in manifests.items()
                        for manifest_row in rows
                        if str(manifest_row.get("file") or "")
                        in metadata_files
                        and str(manifest_row.get("source_kind") or "")
                        in project_metadata_kinds
                    ]
                    for package, manifest_row in selected:
                        if (
                            str(
                                manifest_row.get("constraint_status")
                                or "resolved"
                            )
                            == "conditional"
                        ):
                            unresolved.append(
                                {
                                    "file": _rel(path, root),
                                    "line": line_no,
                                    "install_target": target_rel,
                                    "manifest_file": str(
                                        manifest_row.get("file") or ""
                                    ),
                                    "package": package,
                                    "marker": str(
                                        manifest_row.get("marker") or ""
                                    ),
                                    "reason": (
                                        "conditional_project_dependency_"
                                        "without_target_environment"
                                    ),
                                }
                            )
                            continue
                        _append(
                            result,
                            package=package,
                            raw_name=str(
                                manifest_row.get("raw_name") or package
                            ),
                            path=path,
                            root=root,
                            source_kind="ci_project_install",
                            line=line_no,
                            specifier=str(
                                manifest_row.get("specifier") or ""
                            ),
                            raw_specifier=str(
                                manifest_row.get("raw_specifier") or ""
                            ),
                            marker=str(manifest_row.get("marker") or ""),
                            url=str(manifest_row.get("url") or ""),
                            constraint_status=str(
                                manifest_row.get("constraint_status")
                                or "resolved"
                            ),
                            dependency_group=str(
                                manifest_row.get("dependency_group")
                                or "default"
                            ),
                            environment=str(
                                manifest_row.get("environment")
                                or manifest_row.get("dependency_group")
                                or "default"
                            ),
                            manifest_file=str(
                                manifest_row.get("file") or ""
                            ),
                            install_target=target_rel,
                            manifest_family=str(
                                manifest_row.get("manifest_family") or ""
                            ),
                            manifest_parent=str(
                                manifest_row.get("manifest_parent") or ""
                            ),
                            manifest_context_id=str(
                                manifest_row.get("manifest_context_id") or ""
                            ),
                        )
                continue

            tokens = shlex.split(args, posix=True)
            for token in tokens:
                fact = _requirement_fact(
                    token,
                    identity_service=service,
                )
                if fact is None:
                    unresolved.append({
                        "file": _rel(path, root), "line": line_no,
                        "target": token, "reason": "unsupported_install_operand",
                    })
                    continue
                _append(
                    result,
                    package=fact["package"],
                    raw_name=fact["raw_name"],
                    path=path,
                    root=root,
                    source_kind="ci_direct_install",
                    line=line_no,
                    specifier=fact["specifier"],
                    raw_specifier=fact["raw_specifier"],
                    marker=fact["marker"],
                    url=fact["url"],
                    constraint_status=fact["constraint_status"],
                    dependency_group="direct",
                    environment="direct",
                    install_target=token,
                )
    return result, unresolved


def collect_project_dependency_facts(
    sample_root: Path,
    *,
    identity_policy_path: Path = DEFAULT_IDENTITY_POLICY,
) -> dict[str, Any]:
    if not sample_root.exists() or not sample_root.is_dir():
        raise FileNotFoundError(sample_root)

    service = PackageIdentityService(
        policy_path=identity_policy_path,
        project_root=sample_root,
    )
    manifests = _merge(
        _collect_requirements(sample_root, service),
        _collect_pyproject(sample_root, service),
        _collect_setup_cfg(sample_root, service),
        _collect_setup_py(sample_root, service),
        _collect_pipfile(sample_root, service),
    )
    project_metadata = _project_metadata_inventory(sample_root)
    locks = _collect_locks(
        sample_root,
        service,
        set(manifests),
    )
    installability, installability_unresolved = _collect_installability(
        sample_root,
        service,
        manifests,
        project_metadata,
    )
    return {
        "schema_version": FACTS_SCHEMA_VERSION,
        "extractor_version": FACTS_EXTRACTOR_VERSION,
        "identity_policy_version": service.policy_version,
        "manifest_packages": sorted(manifests),
        "manifest_context_ids": sorted(
            {
                manifest_context_id_for_row(row)
                for rows in manifests.values()
                for row in rows
            }
        ),
        "project_metadata": project_metadata,
        "manifests": manifests,
        "locks": locks,
        "installability": installability,
        "installability_unresolved": installability_unresolved,
    }
