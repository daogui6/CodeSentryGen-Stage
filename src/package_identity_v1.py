from __future__ import annotations

import csv
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from freeze_hash_v1 import canonical_sha256_file
from normalizer import (
    load_import_mapping,
    pep503_normalize,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY = ROOT / "config/package_identity_policy_v1.json"


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return value


def rel(path: Path | None) -> str | None:
    if path is None:
        return None
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def _lookup_mapping(
    *,
    raw_name: str,
    import_path: str,
    mapping: dict[str, str],
) -> tuple[str, str, str]:
    candidates: list[str] = []
    if import_path:
        parts = import_path.split(".")
        candidates.extend(
            ".".join(parts[:end])
            for end in range(len(parts), 0, -1)
        )
    if raw_name:
        candidates.append(raw_name)

    seen: set[str] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        if candidate in mapping:
            return (
                str(mapping[candidate]),
                candidate,
                "curated_exact",
            )

    lower_index: dict[str, tuple[str, str]] = {}
    ambiguous: set[str] = set()
    for key, value in mapping.items():
        lowered = key.lower()
        if lowered in lower_index and lower_index[lowered][1] != value:
            ambiguous.add(lowered)
        else:
            lower_index[lowered] = (key, value)

    for candidate in candidates:
        lowered = candidate.lower()
        if lowered in ambiguous:
            continue
        pair = lower_index.get(lowered)
        if pair is not None:
            return (
                str(pair[1]),
                str(pair[0]),
                "curated_casefold",
            )

    return raw_name, "", "literal_fallback"


def discover_local_modules(project_root: Path | None) -> set[str]:
    if project_root is None or not project_root.exists():
        return set()

    modules: set[str] = set()

    def scan_root(root: Path) -> None:
        if not root.exists() or not root.is_dir():
            return
        for item in root.iterdir():
            if item.name.startswith("."):
                continue
            if item.is_file() and item.suffix == ".py":
                modules.add(item.stem)
            elif item.is_dir() and (item / "__init__.py").exists():
                modules.add(item.name)

    scan_root(project_root)
    scan_root(project_root / "src")
    return modules


def load_legacy_false_positive_hints(path: Path) -> set[str]:
    """
    Historical artifact only.

    The CSV is an exported review table whose first column is often a numeric
    index and whose second column is the observed package token. These rows
    are useful as THO false-positive hints, but they must never globally
    suppress a real distribution from registry or AVCS analysis.
    """
    result: set[str] = set()
    if not path.exists():
        return result

    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        for row in csv.reader(handle):
            if not row:
                continue
            first = str(row[0] or "").strip()
            if first.startswith("#"):
                continue
            candidate = (
                str(row[1] or "").strip()
                if len(row) > 1 and first.isdigit()
                else first
            )
            candidate = candidate.strip().strip('"').strip("'")
            normalized = pep503_normalize(candidate)
            if normalized:
                result.add(normalized)
    return result


def detect_private_registry_context(
    project_root: Path | None,
) -> bool:
    if project_root is None or not project_root.exists():
        return False

    url_pattern = re.compile(r"(?i)https?://[^\s\"']+")

    def has_non_public_index(text: str) -> bool:
        urls = url_pattern.findall(text)
        for url in urls:
            lowered = url.lower().rstrip("),]}")
            if (
                "pypi.org" not in lowered
                and "pythonhosted.org" not in lowered
            ):
                return True
        return False

    direct_config_candidates = [
        project_root / "pip.conf",
        project_root / "pip.ini",
        project_root / ".pypirc",
        project_root / ".config" / "pip" / "pip.conf",
    ]
    for path in direct_config_candidates:
        if not path.exists() or not path.is_file():
            continue
        text = path.read_text(
            encoding="utf-8-sig",
            errors="ignore",
        )
        if has_non_public_index(text):
            return True

    # Explicit package-index declarations also commonly live in manifests,
    # Pipfile/Poetry config, Docker/CI, and shell files. Only inspect URLs on
    # lines carrying a registry marker; arbitrary application URLs must not
    # turn a project into private-registry context.
    markers = (
        "index-url",
        "extra-index-url",
        "pip_index_url",
        "pip_extra_index_url",
        "[[source]]",
        "tool.poetry.source",
        "source =",
    )
    candidate_paths: list[Path] = []
    for path in project_root.rglob("*"):
        if not path.is_file():
            continue
        rel_path = path.relative_to(project_root).as_posix().lower()
        name = path.name.lower()
        if (
            name.startswith("requirements")
            or name in {"pipfile", "pyproject.toml"}
            or name.startswith("dockerfile")
            or rel_path.startswith(".github/workflows/")
            or path.suffix.lower() in {".sh", ".bash", ".yml", ".yaml"}
        ):
            candidate_paths.append(path)

    for path in sorted(set(candidate_paths)):
        text = path.read_text(
            encoding="utf-8-sig",
            errors="ignore",
        )
        lowered_text = text.lower()
        if (
            any(marker in lowered_text for marker in markers)
            and has_non_public_index(text)
        ):
            return True

    return False


def load_project_context_metadata(
    project_root: Path | None,
) -> tuple[str, set[str], bool]:
    """
    Read only explicit context metadata from a repair-line project snapshot.

    Absence of a complete repository context is preserved as unknown. The
    service never infers "not local" merely because a module is absent from a
    partial/generated-only snapshot.
    """
    if project_root is None or not project_root.exists():
        return "not_available", set(), False

    manifest_path = project_root / "snapshot_manifest.json"
    if not manifest_path.is_file():
        return "untracked_project_root", set(), False

    try:
        manifest = read_json(manifest_path)
    except Exception:
        return "snapshot_manifest_unreadable", set(), False

    status = str(
        manifest.get("source_project_context_status")
        or "not_provided_by_source"
    ).strip()
    declared = {
        str(value).strip()
        for value in (
            manifest.get("repo_context_local_modules") or []
        )
        if str(value).strip()
    }
    complete = status in {
        "complete",
        "complete_project_context",
        "complete_repo_context",
    }
    return status, declared, complete


@dataclass(frozen=True)
class PackageIdentity:
    schema_version: str
    policy_version: str
    ecosystem: str
    source_type: str
    raw_name: str
    import_path: str
    distribution: str
    normalized_distribution: str
    identity_status: str
    legacy_false_positive_hint: bool
    mapping_key: str | None
    mapping_source: str
    mapping_confidence: str
    query_registry: bool
    avcs_candidate: bool
    registry_scope: str
    private_registry_status: str
    project_context_status: str
    local_module_exclusion_status: str
    project_root: str | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class PackageIdentityService:
    def __init__(
        self,
        *,
        policy_path: Path = DEFAULT_POLICY,
        project_root: Path | None = None,
    ) -> None:
        self.policy_path = policy_path
        self.policy = read_json(policy_path)
        if self.policy.get("schema_version") != (
            "codesentry_gen_package_identity_policy_v1"
        ):
            raise ValueError("Unexpected package identity policy schema")

        mapping_path = ROOT / str(self.policy["mapping_file"])
        legacy_fp = self.policy.get("legacy_false_positive_policy", {})
        fp_path = ROOT / str(
            legacy_fp.get(
                "file",
                "config/false_positive_packages.csv",
            )
        )
        self.mapping_path = mapping_path
        self.false_positive_path = fp_path
        self.mapping = load_import_mapping(mapping_path)
        self.legacy_false_positive_hints = (
            load_legacy_false_positive_hints(fp_path)
        )
        self.project_root = (
            project_root.resolve()
            if project_root is not None
            else None
        )
        (
            self.project_context_status,
            declared_local_modules,
            self.project_context_complete,
        ) = load_project_context_metadata(self.project_root)
        self.local_modules = (
            discover_local_modules(self.project_root)
            | declared_local_modules
        )
        self.private_registry_context = detect_private_registry_context(
            self.project_root
        )
        self.known_public_distributions = {
            pep503_normalize(value)
            for value in self.mapping.values()
            if str(value).strip()
        }

    @property
    def policy_version(self) -> str:
        return str(self.policy["policy_version"])

    @property
    def policy_sha256(self) -> str:
        return canonical_sha256_file(self.policy_path)

    @property
    def mapping_sha256(self) -> str:
        return canonical_sha256_file(self.mapping_path)

    def contract(self) -> dict[str, Any]:
        return {
            "schema_version": "codesentry_gen_package_identity_contract_v1",
            "policy_file": rel(self.policy_path),
            "policy_version": self.policy_version,
            "policy_sha256": self.policy_sha256,
            "mapping_file": rel(self.mapping_path),
            "mapping_sha256": self.mapping_sha256,
            "ecosystem": str(self.policy.get("ecosystem") or "pypi"),
        }

    def resolve(
        self,
        *,
        raw_name: str,
        source_type: str,
        import_path: str = "",
    ) -> PackageIdentity:
        raw_name = str(raw_name or "").strip()
        import_path = str(import_path or "").strip()
        source_type = str(source_type or "").strip() or "unknown"
        top_level = (import_path or raw_name).split(".")[0]
        raw_normalized = pep503_normalize(raw_name)

        if source_type == "import":
            distribution, mapping_key, mapping_source = _lookup_mapping(
                raw_name=raw_name,
                import_path=import_path,
                mapping=self.mapping,
            )
        else:
            # Manifest/install identities are literal distribution names.
            distribution = raw_name
            mapping_key = ""
            mapping_source = "literal_distribution_name"

        normalized = pep503_normalize(distribution)
        local_match = (
            raw_name in self.local_modules
            or top_level in self.local_modules
            or raw_normalized
            in {pep503_normalize(value) for value in self.local_modules}
        )

        if source_type != "import":
            local_module_exclusion_status = (
                "not_applicable_manifest_distribution"
            )
        elif top_level in sys.stdlib_module_names:
            local_module_exclusion_status = "not_applicable_stdlib"
        elif local_match:
            local_module_exclusion_status = "matched_local_module"
        elif self.project_context_complete:
            local_module_exclusion_status = (
                "not_local_confirmed_complete_context"
            )
        else:
            local_module_exclusion_status = (
                "unknown_incomplete_project_context"
            )

        if source_type == "import" and top_level in sys.stdlib_module_names:
            identity_status = "stdlib"
        elif local_match:
            identity_status = "local_module"
        elif (
            self.private_registry_context
            and normalized not in self.known_public_distributions
        ):
            identity_status = "private_unknown"
        else:
            identity_status = "distribution_candidate"

        candidate = identity_status == "distribution_candidate"
        legacy_false_positive_hint = (
            normalized in self.legacy_false_positive_hints
            or raw_normalized in self.legacy_false_positive_hints
        )
        mapping_confidence = (
            "curated"
            if mapping_source.startswith("curated_")
            else (
                "literal"
                if mapping_source == "literal_distribution_name"
                else "fallback"
            )
        )

        return PackageIdentity(
            schema_version="codesentry_gen_package_identity_record_v1",
            policy_version=self.policy_version,
            ecosystem=str(self.policy.get("ecosystem") or "pypi"),
            source_type=source_type,
            raw_name=raw_name,
            import_path=import_path,
            distribution=distribution,
            normalized_distribution=normalized,
            identity_status=identity_status,
            legacy_false_positive_hint=legacy_false_positive_hint,
            mapping_key=(mapping_key or None),
            mapping_source=mapping_source,
            mapping_confidence=mapping_confidence,
            query_registry=candidate,
            avcs_candidate=candidate,
            registry_scope=(
                "unknown_before_registry_evidence"
                if candidate
                else (
                    "private_registry_context_unknown"
                    if identity_status == "private_unknown"
                    else "not_applicable"
                )
            ),
            private_registry_status=(
                "unknown_not_inferred"
                if candidate
                else (
                    "private_context_detected_unresolved"
                    if identity_status == "private_unknown"
                    else "not_applicable"
                )
            ),
            project_context_status=self.project_context_status,
            local_module_exclusion_status=(
                local_module_exclusion_status
            ),
            project_root=rel(self.project_root),
        )


def identity_for_record(
    record: dict[str, Any],
) -> dict[str, Any] | None:
    value = record.get("package_identity")
    return value if isinstance(value, dict) else None


def validate_identity_record(
    value: Any,
    *,
    expected_policy_version: str,
    expected_normalized_distribution: str | None = None,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("Package identity record is missing")
    if value.get("schema_version") != (
        "codesentry_gen_package_identity_record_v1"
    ):
        raise ValueError("Unexpected package identity record schema")
    if str(value.get("policy_version") or "") != str(
        expected_policy_version
    ):
        raise ValueError(
            "Package identity policy version mismatch: "
            f"expected={expected_policy_version} "
            f"actual={value.get('policy_version')}"
        )
    normalized = pep503_normalize(
        str(value.get("normalized_distribution") or "")
    )
    if not normalized:
        raise ValueError(
            "Package identity normalized_distribution is missing"
        )
    if expected_normalized_distribution is not None:
        expected = pep503_normalize(
            expected_normalized_distribution
        )
        if normalized != expected:
            raise ValueError(
                "Package identity distribution mismatch: "
                f"expected={expected} actual={normalized}"
            )
    status = str(value.get("identity_status") or "")
    if status not in {
        "stdlib",
        "local_module",
        "private_unknown",
        "distribution_candidate",
    }:
        raise ValueError(
            f"Unexpected package identity status: {status!r}"
        )
    candidate = status == "distribution_candidate"
    if bool(value.get("query_registry")) != candidate:
        raise ValueError(
            "Package identity query_registry is inconsistent with status"
        )
    if bool(value.get("avcs_candidate")) != candidate:
        raise ValueError(
            "Package identity avcs_candidate is inconsistent with status"
        )
    return value



def identity_has_unresolved_local_context(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and value.get("identity_status") == "distribution_candidate"
        and value.get("source_type") == "import"
        and value.get("local_module_exclusion_status")
        == "unknown_incomplete_project_context"
    )


def is_avcs_candidate_identity(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and value.get("schema_version")
        == "codesentry_gen_package_identity_record_v1"
        and value.get("avcs_candidate") is True
        and value.get("identity_status") == "distribution_candidate"
    )
