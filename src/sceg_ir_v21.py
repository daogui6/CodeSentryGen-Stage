from __future__ import annotations

import copy
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from packaging.requirements import InvalidRequirement, Requirement

from extract_api_calls import extract_api_calls
from package_identity_v1 import (
    DEFAULT_POLICY as DEFAULT_IDENTITY_POLICY,
    PackageIdentityService,
    is_avcs_candidate_identity,
    validate_identity_record,
)
from project_dependency_facts_v1 import (
    FACTS_SCHEMA_VERSION,
    collect_project_dependency_facts,
)
from risk_semantics_v21 import (
    deduplicate_cards,
    normalize_risk_card,
    validate_risk_card,
)
from time_view_contract_v1 import validate_time_view_contract


ROOT = Path(__file__).resolve().parents[1]

SCEG_SCHEMA_VERSION = "2.1"
SCEG_BUILDER_VERSION = "codesentry_gen_sceg_v2_1_builder_v5_r5_r7_syntax_accounting"

NODE_TYPES = {
    "Sample",
    "Package",
    "Import",
    "ManifestDep",
    "DependencyEntity",
    "InstallCommand",
    "APICall",
    "Version",
    "Vulnerability",
    "Evidence",
    "PromptMention",
    "ContextMention",
    "Risk",
}

EDGE_TYPES = {
    "contains",
    "maps_to_package",
    "installs",
    "uses_api",
    "api_of",
    "mentions",
    "supports",
    "contradicts",
    "requires_version",
    "has_version",
    "affected_by",
    "introduced_by",
    "derives_risk",
}

EVIDENCE_KINDS = {
    "registry",
    "vulnerability",
    "api_surface",
    "manifest",
    "code",
    "prompt",
    "context",
    "temporal",
    "reachability",
}

REGISTRY_TRANSPORT_ONLY_FIELDS = {
    "evidence_source",
    "cache_status",
    "cache_as_of",
    "cache_age_seconds",
    "cache_ttl_seconds",
}


def registry_scientific_evidence(
    value: dict[str, Any],
) -> dict[str, Any]:
    """Remove cache/network transport metadata from scientific registry facts.

    Audit time, registry status, release time, raw-response hash, snapshot
    record hash, run identity and errors remain scientific provenance. Only the
    mechanics of how an already-bound observation was obtained are excluded.
    """
    result = copy.deepcopy(value)
    for key in REGISTRY_TRANSPORT_ONLY_FIELDS:
        result.pop(key, None)
    return result


def dependency_record_for_sceg(
    value: dict[str, Any],
) -> dict[str, Any]:
    """Canonical dependency fact stored in SCEG.

    The raw run_pilot JSONL remains provenance on disk. SCEG stores the
    scientific fact view, so a cache hit cannot change the authoritative
    pre-analysis IR when the underlying registry observation is identical.
    """
    result = copy.deepcopy(value)
    pypi = result.get("pypi")
    if isinstance(pypi, dict):
        result["pypi"] = registry_scientific_evidence(pypi)
    return result


def dependency_records_scientific_sha256(
    rows: list[dict[str, Any]],
) -> str:
    return sha256_object(
        [dependency_record_for_sceg(row) for row in rows]
    )



def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return value


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        raise FileNotFoundError(path)
    with path.open("r", encoding="utf-8-sig") as handle:
        for line_no, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"Expected object at {path}:{line_no}")
            rows.append(value)
    return rows


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_object(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def stable_id(prefix: str, *parts: Any) -> str:
    digest = sha256_object(list(parts))[:20]
    return f"{prefix}_{digest}"


def pep503_normalize(value: Any) -> str:
    return re.sub(r"[-_.]+", "-", str(value or "").strip().lower())


def rel(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def basename(value: Any) -> str:
    text = str(value or "").replace("\\", "/")
    return text.rsplit("/", 1)[-1]


def normalize_location(value: Any) -> dict[str, Any]:
    raw = value if isinstance(value, dict) else {}
    return {
        "file": raw.get("file"),
        "file_name": basename(raw.get("file")),
        "line": raw.get("line"),
        "column": raw.get("column"),
    }


def location_identity(value: Any) -> tuple[str, Any, Any]:
    loc = normalize_location(value)
    return (
        str(loc.get("file_name") or ""),
        loc.get("line"),
        loc.get("column"),
    )


def record_identity(record: dict[str, Any]) -> str:
    return stable_id(
        "depident",
        record.get("sample_id"),
        pep503_normalize(record.get("package")),
        record.get("raw_name"),
        record.get("source_type"),
        *location_identity(record.get("location")),
    )


def package_key(
    *,
    sample_id: str,
    ecosystem: str,
    package: str,
) -> tuple[str, str, str]:
    return (
        pep503_normalize(ecosystem or "pypi"),
        pep503_normalize(package),
        sample_id,
    )


def make_evidence(
    *,
    kind: str,
    source: str,
    payload: Any,
    source_url: str | None = None,
    db_revision: str | None = None,
    queried_at: str | None = None,
    as_of: str | None = None,
    confidence: str = "observed",
) -> dict[str, Any]:
    if kind not in EVIDENCE_KINDS:
        raise ValueError(f"Unsupported evidence kind: {kind}")

    hash_payload = {
        "kind": kind,
        "source": source,
        "source_url": source_url,
        "db_revision": db_revision,
        "queried_at": queried_at,
        "as_of": as_of,
        "confidence": confidence,
        "payload": payload,
    }
    evidence_hash = sha256_object(hash_payload)
    return {
        "evidence_id": stable_id(
            "evidence",
            kind,
            source,
            evidence_hash,
        ),
        **hash_payload,
        "evidence_hash": evidence_hash,
    }


def make_edge(
    *,
    edge_type: str,
    source: str,
    target: str,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if edge_type not in EDGE_TYPES:
        raise ValueError(f"Unsupported edge type: {edge_type}")
    body = payload or {}
    return {
        "edge_id": stable_id(
            "edge",
            edge_type,
            source,
            target,
            body,
        ),
        "type": edge_type,
        "source": source,
        "target": target,
        "payload": body,
    }


def _node(
    *,
    node_type: str,
    node_id: str,
    sample_id: str | None,
    source_scope: str,
    location: dict[str, Any] | None,
    payload: dict[str, Any],
) -> dict[str, Any]:
    if node_type not in NODE_TYPES:
        raise ValueError(f"Unsupported node type: {node_type}")
    return {
        "node_id": node_id,
        "type": node_type,
        "sample_id": sample_id,
        "source_scope": source_scope,
        "location": normalize_location(location),
        "payload": payload,
    }


def _put_unique(
    mapping: dict[str, dict[str, Any]],
    value: dict[str, Any],
    *,
    id_field: str,
) -> None:
    item_id = str(value[id_field])
    previous = mapping.get(item_id)
    if previous is not None and previous != value:
        raise ValueError(f"Identity collision: {item_id}")
    mapping[item_id] = value


def _package_node(
    *,
    nodes: dict[str, dict[str, Any]],
    sample_id: str,
    ecosystem: str,
    package: str,
) -> str:
    normalized = pep503_normalize(package)
    normalized_ecosystem = pep503_normalize(ecosystem or "pypi")
    node_id = stable_id(
        "pkg",
        normalized_ecosystem,
        normalized,
        sample_id,
    )
    _put_unique(
        nodes,
        _node(
            node_type="Package",
            node_id=node_id,
            sample_id=sample_id,
            source_scope=sample_id,
            location=None,
            payload={
                # Package identity is canonical. Source spellings/casing are
                # preserved on Import/ManifestDep/APICall evidence and in the
                # package_aliases relation, not in the Package identity node.
                "name": normalized,
                "normalized_name": normalized,
                "ecosystem": normalized_ecosystem,
            },
        ),
        id_field="node_id",
    )
    return node_id


def _add_evidence_support(
    *,
    evidence_map: dict[str, dict[str, Any]],
    edge_map: dict[str, dict[str, Any]],
    evidence: dict[str, Any],
    target_ids: Iterable[str],
) -> None:
    _put_unique(
        evidence_map,
        evidence,
        id_field="evidence_id",
    )
    for target_id in target_ids:
        edge = make_edge(
            edge_type="supports",
            source=evidence["evidence_id"],
            target=target_id,
        )
        _put_unique(
            edge_map,
            edge,
            id_field="edge_id",
        )


def _contains_entity(text: str, candidates: Iterable[str]) -> bool:
    lowered = text.lower()
    for candidate in candidates:
        token = str(candidate or "").strip().lower()
        if token and token in lowered:
            return True
    return False


def build_base_ir(
    *,
    samples_path: Path,
    dependency_records_path: Path,
    code_dir: Path,
    mapping_path: Path,
    dataset_label: str,
    identity_policy_path: Path = DEFAULT_IDENTITY_POLICY,
    project_snapshots_dir: Path | None = None,
) -> dict[str, Any]:
    samples = read_jsonl(samples_path)
    raw_dependency_records = read_jsonl(dependency_records_path)
    dependency_records = [
        dependency_record_for_sceg(row)
        for row in raw_dependency_records
    ]
    dependency_records_scientific_hash = (
        dependency_records_scientific_sha256(
            raw_dependency_records
        )
    )
    sample_index = {
        str(row.get("sample_id", "")).strip(): row
        for row in samples
        if str(row.get("sample_id", "")).strip()
    }
    identity_contract_service = PackageIdentityService(
        policy_path=identity_policy_path,
    )
    identity_contract = identity_contract_service.contract()
    expected_identity_policy_version = (
        identity_contract_service.policy_version
    )

    input_hashes: dict[str, Any] = {
        "samples": {
            "path": rel(samples_path),
            "sha256": sha256_file(samples_path),
        },
        "dependency_records": {
            "path": rel(dependency_records_path),
            "sha256": sha256_file(dependency_records_path),
            "scientific_sha256": (
                dependency_records_scientific_hash
            ),
            "transport_only_fields_excluded": sorted(
                REGISTRY_TRANSPORT_ONLY_FIELDS
            ),
        },
        "mapping": {
            "path": rel(mapping_path),
            "sha256": sha256_file(mapping_path),
            "compatibility_only": True,
        },
        "package_identity_policy": {
            "path": rel(identity_policy_path),
            "sha256": sha256_file(identity_policy_path),
        },
        "project_snapshots_dir": (
            rel(project_snapshots_dir)
            if project_snapshots_dir is not None
            else None
        ),
        "project_snapshot_manifests": {},
        "code_files": {},
    }

    nodes: dict[str, dict[str, Any]] = {}
    evidence_map: dict[str, dict[str, Any]] = {}
    edges: dict[str, dict[str, Any]] = {}
    extractor_runs: dict[str, dict[str, Any]] = {}
    project_dependency_contexts: dict[str, dict[str, Any]] = {}

    package_aliases: dict[tuple[str, str], set[str]] = {}

    for sample_id, sample in sample_index.items():
        sample_node_id = stable_id("sample", sample_id)
        _put_unique(
            nodes,
            _node(
                node_type="Sample",
                node_id=sample_node_id,
                sample_id=sample_id,
                source_scope=sample_id,
                location=None,
                payload={
                    "sample_id": sample_id,
                    "prompt_id": sample.get("prompt_id"),
                    "model": sample.get("model"),
                    "generation_time": sample.get("generation_time"),
                    "language": sample.get("language"),
                    "ecosystem": sample.get("ecosystem"),
                    "generation_error": sample.get("generation_error"),
                },
            ),
            id_field="node_id",
        )

        code_path = code_dir / f"{sample_id}.py"
        if code_path.exists():
            input_hashes["code_files"][sample_id] = {
                "path": rel(code_path),
                "sha256": sha256_file(code_path),
            }

        if project_snapshots_dir is not None:
            snapshot_manifest = (
                project_snapshots_dir
                / sample_id
                / "snapshot_manifest.json"
            )
            if snapshot_manifest.exists():
                input_hashes["project_snapshot_manifests"][sample_id] = {
                    "path": rel(snapshot_manifest),
                    "sha256": sha256_file(snapshot_manifest),
                }

    for sequence, record in enumerate(dependency_records):
        sample_id = str(record.get("sample_id", "") or "").strip()
        if not sample_id:
            raise ValueError("Dependency record missing sample_id")
        sample = sample_index.get(sample_id, {})
        sample_generation_time = str(
            sample.get("generation_time") or ""
        ).strip()
        record_generation_time = str(
            record.get("generation_time") or ""
        ).strip()
        if (
            sample_generation_time
            and record_generation_time
            and sample_generation_time != record_generation_time
        ):
            raise ValueError(
                "Dependency record generation_time diverges from the "
                "canonical sample time before SCEG construction: "
                f"sample={sample_id} "
                f"sample_time={sample_generation_time!r} "
                f"record_time={record_generation_time!r}"
            )
        ecosystem = str(
            record.get("ecosystem")
            or sample.get("ecosystem")
            or "pypi"
        )
        package = str(record.get("package", "") or "").strip()
        raw_name = str(record.get("raw_name", "") or "").strip()
        source_type = str(record.get("source_type", "") or "").strip()
        location = record.get("location") or {}

        project_root = (
            project_snapshots_dir / sample_id
            if project_snapshots_dir is not None
            and (project_snapshots_dir / sample_id).exists()
            else None
        )
        record_identity_service = PackageIdentityService(
            policy_path=identity_policy_path,
            project_root=project_root,
        )
        identity_value = record.get("package_identity")
        if isinstance(identity_value, dict):
            identity_value = validate_identity_record(
                identity_value,
                expected_policy_version=(
                    expected_identity_policy_version
                ),
                expected_normalized_distribution=package,
            )
        else:
            derived_identity = record_identity_service.resolve(
                raw_name=raw_name,
                source_type=source_type,
                import_path=str(
                    record.get("import_path")
                    or (raw_name if source_type == "import" else "")
                ),
            )
            if package and (
                derived_identity.normalized_distribution
                != pep503_normalize(package)
            ):
                raise ValueError(
                    "Dependency record package identity diverges from the "
                    "active PackageIdentityService: "
                    f"sample={sample_id} raw={raw_name} "
                    f"record={pep503_normalize(package)} "
                    f"service={derived_identity.normalized_distribution}"
                )
            identity_value = derived_identity.to_dict()
            if not package:
                package = derived_identity.normalized_distribution

        record = copy.deepcopy(record)
        record["package"] = package
        record["package_identity"] = copy.deepcopy(identity_value)
        record["identity_policy_version"] = (
            expected_identity_policy_version
        )

        if source_type == "import":
            node_type = "Import"
        elif source_type in {"manifest", "requirements", "lockfile"}:
            node_type = "ManifestDep"
        else:
            node_type = "DependencyEntity"

        identity = record_identity(record)
        dep_node_id = stable_id("dep", identity)
        _put_unique(
            nodes,
            _node(
                node_type=node_type,
                node_id=dep_node_id,
                sample_id=sample_id,
                source_scope=sample_id,
                location=location,
                payload={
                    "record_identity": identity,
                    "sequence": sequence,
                    "raw_name": raw_name,
                    "normalized_package": pep503_normalize(package),
                    "package_identity": copy.deepcopy(
                        identity_value
                    ),
                    "identity_policy_version": (
                        expected_identity_policy_version
                    ),
                    "source_type": source_type,
                    "project_dependency_fact": copy.deepcopy(
                        record.get("project_dependency_fact")
                    ),
                    "dependency_record": copy.deepcopy(record),
                },
            ),
            id_field="node_id",
        )

        sample_node_id = stable_id("sample", sample_id)
        edge = make_edge(
            edge_type="contains",
            source=sample_node_id,
            target=dep_node_id,
        )
        _put_unique(edges, edge, id_field="edge_id")

        package_node_id: str | None = None
        if package:
            package_node_id = _package_node(
                nodes=nodes,
                sample_id=sample_id,
                ecosystem=ecosystem,
                package=package,
            )
            edge = make_edge(
                edge_type="maps_to_package",
                source=dep_node_id,
                target=package_node_id,
            )
            _put_unique(edges, edge, id_field="edge_id")
            package_aliases.setdefault(
                (sample_id, pep503_normalize(package)),
                set(),
            ).update({package, raw_name})

        evidence_kind = (
            "manifest"
            if node_type == "ManifestDep"
            else "code"
        )
        structural = make_evidence(
            kind=evidence_kind,
            source=(
                str(location.get("file") or "")
                or f"{sample_id}.py"
            ),
            payload={
                "raw_name": raw_name,
                "package": package,
                "source_type": source_type,
                "location": normalize_location(location),
                "code_parse_status": record.get("code_parse_status"),
                "code_parse_error": record.get("code_parse_error"),
                "false_positive_filtered": record.get(
                    "false_positive_filtered"
                ),
                "local_module_filtered": record.get(
                    "local_module_filtered"
                ),
                "package_identity": copy.deepcopy(
                    record.get("package_identity")
                ),
            },
            as_of=sample.get("generation_time"),
        )
        _add_evidence_support(
            evidence_map=evidence_map,
            edge_map=edges,
            evidence=structural,
            target_ids=[dep_node_id],
        )

        pypi = record.get("pypi")
        if isinstance(pypi, dict) and package_node_id is not None:
            registry = make_evidence(
                kind="registry",
                source=str(
                    pypi.get("registry_source")
                    or "PyPI JSON API"
                ),
                source_url=pypi.get("query_url"),
                db_revision=pypi.get("raw_response_sha256"),
                queried_at=pypi.get("audit_time"),
                as_of=pypi.get("audit_time"),
                payload=copy.deepcopy(pypi),
                confidence=(
                    "unknown"
                    if pypi.get("error")
                    else "observed"
                ),
            )
            _add_evidence_support(
                evidence_map=evidence_map,
                edge_map=edges,
                evidence=registry,
                target_ids=[package_node_id, dep_node_id],
            )

    # Canonical project dependency facts are extracted exactly once before
    # analysis and materialized into SCEG.  Downstream THO/AVCS consumers
    # project these facts from the IR instead of re-reading project files.
    #
    # The v2.1 node vocabulary already defines ManifestDep and
    # InstallCommand.  Lockfile facts are therefore represented as
    # ManifestDep nodes with dependency_fact_role="lock", while CI/direct
    # installability facts are represented as InstallCommand nodes.
    for sample_id, sample in sample_index.items():
        ecosystem = str(sample.get("ecosystem") or "pypi")
        project_root = (
            project_snapshots_dir / sample_id
            if project_snapshots_dir is not None
            and (project_snapshots_dir / sample_id).exists()
            else None
        )
        identity_service = PackageIdentityService(
            policy_path=identity_policy_path,
            project_root=project_root,
        )

        manifest_facts: list[dict[str, Any]] = []
        lock_facts: list[dict[str, Any]] = []
        installability_facts: list[dict[str, Any]] = []
        project_dependency_contexts[sample_id] = {
            "installability_unresolved": [],
            "project_snapshot_available": project_root is not None,
        }
        if project_root is not None:
            project_facts = collect_project_dependency_facts(
                project_root,
                identity_policy_path=identity_policy_path,
            )
            if project_facts.get("schema_version") != FACTS_SCHEMA_VERSION:
                raise ValueError(
                    f"{sample_id}: unexpected project dependency facts schema"
                )
            if project_facts.get("identity_policy_version") != (
                identity_service.policy_version
            ):
                raise ValueError(
                    f"{sample_id}: project dependency fact identity drift"
                )
            project_dependency_contexts[sample_id] = {
                "installability_unresolved": copy.deepcopy(
                    project_facts.get("installability_unresolved", [])
                ),
                "project_snapshot_available": True,
            }
            for rows in project_facts.get("manifests", {}).values():
                manifest_facts.extend(
                    copy.deepcopy(row)
                    for row in rows
                    if isinstance(row, dict)
                )
            for rows in project_facts.get("locks", {}).values():
                lock_facts.extend(
                    copy.deepcopy(row)
                    for row in rows
                    if isinstance(row, dict)
                )
            for rows in project_facts.get("installability", {}).values():
                installability_facts.extend(
                    copy.deepcopy(row)
                    for row in rows
                    if isinstance(row, dict)
                )
        else:
            # Historical/standalone compatibility only.  Formal repaired E2E
            # always supplies project snapshots before SCEG construction.
            requirements_text = str(
                sample.get("requirements_text") or ""
            )
            for line_no, raw_line in enumerate(
                requirements_text.splitlines(),
                start=1,
            ):
                text = raw_line.strip()
                if not text or text.startswith("#"):
                    continue
                try:
                    requirement = Requirement(text)
                except InvalidRequirement:
                    continue
                identity = identity_service.resolve(
                    raw_name=requirement.name,
                    source_type="manifest",
                )
                manifest_facts.append(
                    {
                        "raw_name": requirement.name,
                        "normalized_distribution": (
                            identity.normalized_distribution
                        ),
                        "file": f"{sample_id}_requirements.txt",
                        "line": line_no,
                        "source_kind": "requirements_text_legacy",
                        "specifier": str(requirement.specifier),
                        "raw_specifier": str(requirement.specifier),
                        "marker": str(requirement.marker or ""),
                        "url": str(requirement.url or ""),
                        "constraint_status": (
                            "unsupported_direct_url"
                            if requirement.url
                            else (
                                "conditional"
                                if requirement.marker
                                else "resolved"
                            )
                        ),
                        "exact_version": None,
                    }
                )

        for dependency_fact_role, source_type, prefix, facts in (
            ("manifest", "manifest", "manifest", manifest_facts),
            ("lock", "lockfile", "lock", lock_facts),
        ):
            for fact in facts:
                raw_name = str(fact.get("raw_name") or "").strip()
                normalized = pep503_normalize(
                    fact.get("normalized_distribution")
                    or raw_name
                )
                if not raw_name or not normalized:
                    continue

                manifest_identity = identity_service.resolve(
                    raw_name=raw_name,
                    source_type="manifest",
                )
                if (
                    manifest_identity.normalized_distribution
                    != normalized
                ):
                    raise ValueError(
                        f"{sample_id}/{raw_name}: shared dependency identity drift"
                    )

                location = {
                    "file": str(fact.get("file") or "manifest"),
                    "line": fact.get("line"),
                }
                existing = [
                    node
                    for node in nodes.values()
                    if node.get("type") == "ManifestDep"
                    and node.get("sample_id") == sample_id
                    and pep503_normalize(
                        (node.get("payload") or {}).get(
                            "normalized_package"
                        )
                    )
                    == normalized
                    and str((node.get("location") or {}).get("file") or "")
                    == str(location["file"])
                    and (
                        (node.get("payload") or {}).get("project_dependency_fact") is None
                        or (node.get("payload") or {}).get("project_dependency_fact") == fact
                    )
                    and location_identity(node.get("location"))[0]
                    == location_identity(location)[0]
                    and (
                        location_identity(node.get("location"))[1] or None
                    )
                    == (location_identity(location)[1] or None)
                    and (
                        dependency_fact_role == "manifest"
                        or (node.get("payload") or {}).get(
                            "dependency_fact_role"
                        )
                        == dependency_fact_role
                    )
                ]
                if existing:
                    for node in existing:
                        payload = node.get("payload") or {}
                        if payload.get("project_dependency_fact") is None:
                            payload["project_dependency_fact"] = copy.deepcopy(
                                fact
                            )
                            payload["specifier"] = str(
                                fact.get("specifier") or ""
                            )
                            payload["exact_version"] = fact.get(
                                "exact_version"
                            )
                            payload["constraint_status"] = fact.get(
                                "constraint_status"
                            )
                        payload["dependency_fact_role"] = (
                            dependency_fact_role
                        )
                        payload["source_kind"] = fact.get("source_kind")
                    continue

                manifest_node_id = stable_id(
                    prefix,
                    sample_id,
                    normalized,
                    fact.get("source_kind"),
                    location_identity(location),
                    fact.get("file"),
                    fact.get("manifest_context_id"),
                    fact.get("specifier"),
                    fact.get("raw_specifier"),
                    fact.get("exact_version"),
                )
                _put_unique(
                    nodes,
                    _node(
                        node_type="ManifestDep",
                        node_id=manifest_node_id,
                        sample_id=sample_id,
                        source_scope=sample_id,
                        location=location,
                        payload={
                            "raw_name": raw_name,
                            "normalized_package": normalized,
                            "package_identity": (
                                manifest_identity.to_dict()
                            ),
                            "identity_policy_version": (
                                manifest_identity.policy_version
                            ),
                            "source_type": source_type,
                            "source_kind": fact.get("source_kind"),
                            "specifier": str(
                                fact.get("specifier") or ""
                            ),
                            "exact_version": fact.get("exact_version"),
                            "constraint_status": fact.get(
                                "constraint_status"
                            ),
                            "dependency_fact_role": (
                                dependency_fact_role
                            ),
                            "project_dependency_fact": copy.deepcopy(fact),
                        },
                    ),
                    id_field="node_id",
                )
                package_node_id = _package_node(
                    nodes=nodes,
                    sample_id=sample_id,
                    ecosystem=ecosystem,
                    package=normalized,
                )
                for edge in [
                    make_edge(
                        edge_type="contains",
                        source=stable_id("sample", sample_id),
                        target=manifest_node_id,
                    ),
                    make_edge(
                        edge_type="maps_to_package",
                        source=manifest_node_id,
                        target=package_node_id,
                    ),
                ]:
                    _put_unique(edges, edge, id_field="edge_id")

                manifest_evidence = make_evidence(
                    kind="manifest",
                    source=location["file"],
                    as_of=sample.get("generation_time"),
                    payload={
                        "package": raw_name,
                        "normalized_package": normalized,
                        "source_kind": fact.get("source_kind"),
                        "specifier": str(fact.get("specifier") or ""),
                        "exact_version": fact.get("exact_version"),
                        "constraint_status": fact.get(
                            "constraint_status"
                        ),
                        "dependency_fact_role": dependency_fact_role,
                        "location": normalize_location(location),
                        "project_dependency_fact": copy.deepcopy(fact),
                    },
                )
                _add_evidence_support(
                    evidence_map=evidence_map,
                    edge_map=edges,
                    evidence=manifest_evidence,
                    target_ids=[manifest_node_id, package_node_id],
                )
                package_aliases.setdefault(
                    (sample_id, normalized),
                    set(),
                ).add(raw_name)

        for fact in installability_facts:
            raw_name = str(fact.get("raw_name") or "").strip()
            normalized = pep503_normalize(
                fact.get("normalized_distribution")
                or raw_name
            )
            if not raw_name or not normalized:
                continue
            install_identity = identity_service.resolve(
                raw_name=raw_name,
                source_type="manifest",
            )
            if install_identity.normalized_distribution != normalized:
                raise ValueError(
                    f"{sample_id}/{raw_name}: installability identity drift"
                )
            location = {
                "file": str(fact.get("file") or "install"),
                "line": fact.get("line"),
            }
            command_node_id = stable_id(
                "project_install",
                sample_id,
                normalized,
                fact.get("source_kind"),
                location_identity(location),
                fact.get("file"),
                fact.get("install_target"),
                fact.get("manifest_context_id"),
                fact.get("specifier"),
            )
            _put_unique(
                nodes,
                _node(
                    node_type="InstallCommand",
                    node_id=command_node_id,
                    sample_id=sample_id,
                    source_scope=sample_id,
                    location=location,
                    payload={
                        "manager": "pip",
                        "package": normalized,
                        "raw_name": raw_name,
                        "normalized_package": normalized,
                        "package_identity": install_identity.to_dict(),
                        "identity_policy_version": (
                            install_identity.policy_version
                        ),
                        "source_type": "install_command",
                        "source_kind": fact.get("source_kind"),
                        "specifier": str(fact.get("specifier") or ""),
                        "constraint_status": fact.get(
                            "constraint_status"
                        ),
                        "dependency_fact_role": "installability",
                        "project_dependency_fact": copy.deepcopy(fact),
                    },
                ),
                id_field="node_id",
            )
            package_node_id = _package_node(
                nodes=nodes,
                sample_id=sample_id,
                ecosystem=ecosystem,
                package=normalized,
            )
            for edge in [
                make_edge(
                    edge_type="contains",
                    source=stable_id("sample", sample_id),
                    target=command_node_id,
                ),
                make_edge(
                    edge_type="installs",
                    source=command_node_id,
                    target=package_node_id,
                ),
            ]:
                _put_unique(edges, edge, id_field="edge_id")
            install_evidence = make_evidence(
                kind="reachability",
                source=location["file"],
                as_of=sample.get("generation_time"),
                payload={
                    "package": raw_name,
                    "normalized_package": normalized,
                    "source_kind": fact.get("source_kind"),
                    "specifier": str(fact.get("specifier") or ""),
                    "constraint_status": fact.get("constraint_status"),
                    "dependency_fact_role": "installability",
                    "location": normalize_location(location),
                    "project_dependency_fact": copy.deepcopy(fact),
                },
            )
            _add_evidence_support(
                evidence_map=evidence_map,
                edge_map=edges,
                evidence=install_evidence,
                target_ids=[command_node_id, package_node_id],
            )
            package_aliases.setdefault(
                (sample_id, normalized),
                set(),
            ).add(raw_name)

    for sample_id, sample in sample_index.items():
        code_path = code_dir / f"{sample_id}.py"
        if not code_path.exists():
            continue

        project_root = (
            project_snapshots_dir / sample_id
            if project_snapshots_dir is not None
            and (project_snapshots_dir / sample_id).exists()
            else None
        )
        api_result = extract_api_calls(
            code_path=code_path,
            mapping_path=mapping_path,
            sample_id=sample_id,
            identity_policy_path=identity_policy_path,
            project_root=project_root,
        )
        if api_result.get("identity_policy_version") != (
            expected_identity_policy_version
        ):
            raise ValueError(
                "API extractor identity policy version diverges from SCEG "
                f"contract for sample {sample_id}"
            )
        raw_parse_status = str(
            api_result.get("parse_status") or "unknown"
        ).strip()
        syntax_parse_status = {
            "ok": "parseable",
            "syntax_error": "syntax_invalid",
            "decode_error": "decode_error",
        }.get(raw_parse_status)
        if syntax_parse_status is None:
            raise ValueError(
                "Unexpected API extractor parse_status for canonical SCEG: "
                f"sample={sample_id} status={raw_parse_status!r}"
            )
        structural_evidence_count = sum(
            1
            for node in nodes.values()
            if node.get("sample_id") == sample_id
            and node.get("type")
            in {"ManifestDep", "InstallCommand", "DependencyEntity"}
        )
        code_ast_available = syntax_parse_status == "parseable"
        dynamic_imports = copy.deepcopy(api_result.get("dynamic_imports") or [])
        dynamic_import_unknown = any(row.get("status") != "resolved" for row in dynamic_imports)
        for dynamic in dynamic_imports:
            if dynamic.get("status") != "resolved":
                continue
            dynamic_identity = validate_identity_record(
                dynamic.get("package_identity"),
                expected_policy_version=expected_identity_policy_version,
            )
            # The initial dependency producer must carry this fact into the
            # same IR consumed by THO. A manifest/APICall is not a substitute
            # for a missing source import or its registry observation.
            if not any(
                node.get("type") == "Import" and node.get("sample_id") == sample_id
                and (node.get("location") or {}).get("line") == dynamic["line"]
                and (node.get("payload") or {}).get("package_identity") == dynamic_identity
                for node in nodes.values()
            ):
                raise ValueError(
                    f"Literal dynamic import missing canonical dependency evidence: "
                    f"sample={sample_id} module={dynamic['import_path']} line={dynamic['line']}"
                )
        extractor_runs[sample_id] = {
            "schema_version": api_result.get("schema_version"),
            "binding_resolution_policy": api_result.get("binding_resolution_policy"),
            "binding_unresolved": copy.deepcopy(api_result.get("binding_unresolved") or []),
            "dynamic_imports": dynamic_imports,
            "code_file": api_result.get("code_file"),
            "content_hash": sha256_file(code_path),
            "parse_status": api_result.get("parse_status"),
            "parse_error": api_result.get("parse_error"),
            "syntax_parse_status": syntax_parse_status,
            "parse_diagnostic": (
                str(api_result.get("parse_error") or "")
                if syntax_parse_status != "parseable"
                else ""
            ),
            "extractor_mode": (
                "python_ast"
                if code_ast_available
                else "python_ast_unavailable_structural_evidence_only"
            ),
            "analysis_support": {
                "THO": {
                    "code_ast_available": code_ast_available,
                    "dependency_extraction_complete": code_ast_available and not dynamic_import_unknown,
                    "unresolved_dynamic_imports": [
                        copy.deepcopy(row) for row in dynamic_imports if row.get("status") != "resolved"
                    ],
                    "independent_dependency_evidence_available": (
                        structural_evidence_count > 0
                    ),
                    "state": (
                        "unknown_or_review"
                        if dynamic_import_unknown else "supported"
                        if code_ast_available
                        else (
                            "independent_structural_evidence"
                            if structural_evidence_count > 0
                            else "unknown_or_review"
                        )
                    ),
                },
                "AVCS": {
                    "api_ast_available": code_ast_available,
                    "state": (
                        "api_evidence_available"
                        if code_ast_available
                        else "syntax_unavailable"
                    ),
                    "manifest_lock_evidence_may_still_support_analysis": True,
                },
            },
            "identity_policy_version": api_result.get(
                "identity_policy_version"
            ),
        }

        sample_node_id = stable_id("sample", sample_id)
        ecosystem = str(sample.get("ecosystem") or "pypi")

        for call in api_result.get("api_calls", []):
            if not isinstance(call, dict):
                continue
            distribution = str(call.get("distribution", "") or "").strip()
            api_symbol = str(call.get("api_symbol", "") or "").strip()
            location = call.get("location") or {}
            validate_identity_record(
                call.get("package_identity"),
                expected_policy_version=(
                    expected_identity_policy_version
                ),
                expected_normalized_distribution=distribution,
            )
            api_node_id = stable_id(
                "api",
                sample_id,
                distribution,
                api_symbol,
                *location_identity(location),
            )
            _put_unique(
                nodes,
                _node(
                    node_type="APICall",
                    node_id=api_node_id,
                    sample_id=sample_id,
                    source_scope=sample_id,
                    location=location,
                    payload={
                        "distribution": distribution,
                        "package_identity": copy.deepcopy(
                            call.get("package_identity")
                        ),
                        "api_symbol": api_symbol,
                        "api_call": copy.deepcopy(call),
                    },
                ),
                id_field="node_id",
            )
            for edge in [
                make_edge(
                    edge_type="uses_api",
                    source=sample_node_id,
                    target=api_node_id,
                ),
            ]:
                _put_unique(edges, edge, id_field="edge_id")

            target_ids = [api_node_id]
            if distribution:
                pkg_node_id = _package_node(
                    nodes=nodes,
                    sample_id=sample_id,
                    ecosystem=ecosystem,
                    package=distribution,
                )
                edge = make_edge(
                    edge_type="api_of",
                    source=api_node_id,
                    target=pkg_node_id,
                )
                _put_unique(edges, edge, id_field="edge_id")
                target_ids.append(pkg_node_id)
                package_aliases.setdefault(
                    (sample_id, pep503_normalize(distribution)),
                    set(),
                ).update(
                    {
                        distribution,
                        str(call.get("import_name") or ""),
                    }
                )

            api_evidence = make_evidence(
                kind="code",
                source=rel(code_path),
                payload=copy.deepcopy(call),
                as_of=sample.get("generation_time"),
            )
            _add_evidence_support(
                evidence_map=evidence_map,
                edge_map=edges,
                evidence=api_evidence,
                target_ids=target_ids,
            )

    for (sample_id, normalized), aliases in package_aliases.items():
        sample = sample_index.get(sample_id, {})
        prompt = str(sample.get("prompt") or "")
        contexts = [
            str(sample.get(key) or "")
            for key in (
                "context",
                "context_text",
                "retrieved_context",
            )
            if sample.get(key)
        ]
        package_node_id = stable_id(
            "pkg",
            pep503_normalize(
                sample.get("ecosystem") or "pypi"
            ),
            normalized,
            sample_id,
        )

        candidates = set(aliases)
        candidates.add(normalized)

        if prompt and _contains_entity(prompt, candidates):
            mention_node_id = stable_id(
                "promptmention",
                sample_id,
                normalized,
            )
            _put_unique(
                nodes,
                _node(
                    node_type="PromptMention",
                    node_id=mention_node_id,
                    sample_id=sample_id,
                    source_scope=sample_id,
                    location={"file": "prompt", "line": 1},
                    payload={
                        "entity": normalized,
                        "prompt_sha256": hashlib.sha256(
                            prompt.encode("utf-8")
                        ).hexdigest(),
                    },
                ),
                id_field="node_id",
            )
            for edge in [
                make_edge(
                    edge_type="mentions",
                    source=mention_node_id,
                    target=package_node_id,
                )
            ]:
                _put_unique(edges, edge, id_field="edge_id")
            prompt_evidence = make_evidence(
                kind="prompt",
                source="generated_sample.prompt",
                payload={
                    "entity": normalized,
                    "text_sha256": hashlib.sha256(
                        prompt.encode("utf-8")
                    ).hexdigest(),
                },
                as_of=sample.get("generation_time"),
            )
            _add_evidence_support(
                evidence_map=evidence_map,
                edge_map=edges,
                evidence=prompt_evidence,
                target_ids=[mention_node_id, package_node_id],
            )

        for index, context_text in enumerate(contexts):
            if not _contains_entity(context_text, candidates):
                continue
            mention_node_id = stable_id(
                "contextmention",
                sample_id,
                normalized,
                index,
            )
            _put_unique(
                nodes,
                _node(
                    node_type="ContextMention",
                    node_id=mention_node_id,
                    sample_id=sample_id,
                    source_scope=sample_id,
                    location={
                        "file": f"context[{index}]",
                        "line": 1,
                    },
                    payload={
                        "entity": normalized,
                        "context_sha256": hashlib.sha256(
                            context_text.encode("utf-8")
                        ).hexdigest(),
                    },
                ),
                id_field="node_id",
            )
            edge = make_edge(
                edge_type="mentions",
                source=mention_node_id,
                target=package_node_id,
            )
            _put_unique(edges, edge, id_field="edge_id")
            context_evidence = make_evidence(
                kind="context",
                source=f"generated_sample.context[{index}]",
                payload={
                    "entity": normalized,
                    "text_sha256": hashlib.sha256(
                        context_text.encode("utf-8")
                    ).hexdigest(),
                },
                as_of=sample.get("generation_time"),
            )
            _add_evidence_support(
                evidence_map=evidence_map,
                edge_map=edges,
                evidence=context_evidence,
                target_ids=[mention_node_id, package_node_id],
            )

    source_identity_inputs = copy.deepcopy(input_hashes)
    dependency_input = source_identity_inputs.get(
        "dependency_records", {}
    )
    if isinstance(dependency_input, dict):
        dependency_input.pop("sha256", None)
    source_snapshot_id = sha256_object(source_identity_inputs)
    time_views = []
    for sample_id, sample in sorted(sample_index.items()):
        audits = sorted(
            {
                str(
                    (
                        row.get("pypi")
                        if isinstance(row.get("pypi"), dict)
                        else {}
                    ).get("audit_time")
                )
                for row in dependency_records
                if row.get("sample_id") == sample_id
                and isinstance(row.get("pypi"), dict)
                and (
                    row.get("pypi")
                    or {}
                ).get("audit_time")
            }
        )
        time_views.append(
            {
                "sample_id": sample_id,
                "generation_time": sample.get("generation_time"),
                "audit_times": audits,
                "knowledge_time": None,
            }
        )

    ir = {
        "schema_version": SCEG_SCHEMA_VERSION,
        "ir_kind": "SupplyChainEvidenceGraph",
        "ir_stage": "base",
        "dataset_label": dataset_label,
        "extractor_version": SCEG_BUILDER_VERSION,
        "source_snapshot_id": source_snapshot_id,
        "created_at": utc_now_iso(),
        "source_inputs": input_hashes,
        "node_type_contract": sorted(NODE_TYPES),
        "edge_type_contract": sorted(EDGE_TYPES),
        "evidence_kind_contract": sorted(EVIDENCE_KINDS),
        "time_view_contexts": time_views,
        "extractor_runs": extractor_runs,
        "project_dependency_contexts": project_dependency_contexts,
        "package_identity_contract": {
            **identity_contract,
            "dependency_records_carry_identity": True,
            "dependency_identity_is_validated": True,
            "api_calls_carry_identity": True,
            "api_identity_is_validated": True,
            "manifest_identity_is_literal_distribution": True,
            "project_dependency_facts_schema": FACTS_SCHEMA_VERSION,
            "project_dependency_facts_shared_with_pilot_reachability_avcs": True,
            "avcs_candidate_status": "distribution_candidate",
        },
        "consumer_contract": {
            "THO": (
                "Formal repaired E2E consumes dependency, manifest, lock, "
                "installability, registry and identity evidence from this "
                "canonical pre-analysis IR; project source files are not "
                "re-read after SCEG construction."
            ),
            "AVCS": (
                "Formal repaired E2E consumes Sample generation time, APICall, "
                "Package, manifest and lock facts from this canonical "
                "pre-analysis IR; external sample/code inputs are validation "
                "only and generated code/project source files are not "
                "re-extracted after SCEG construction."
            ),
        },
        "nodes": sorted(nodes.values(), key=lambda row: row["node_id"]),
        "evidence": sorted(
            evidence_map.values(),
            key=lambda row: row["evidence_id"],
        ),
        "edges": sorted(edges.values(), key=lambda row: row["edge_id"]),
    }
    verify_ir(ir)
    return ir


def project_dependency_records(
    ir: dict[str, Any],
) -> list[dict[str, Any]]:
    verify_ir(ir)
    rows: list[tuple[int, dict[str, Any]]] = []
    for node in ir.get("nodes", []):
        if node.get("type") not in {
            "Import",
            "ManifestDep",
            "DependencyEntity",
        }:
            continue
        payload = node.get("payload") or {}
        record = payload.get("dependency_record")
        if not isinstance(record, dict):
            continue
        copied = copy.deepcopy(record)
        copied["sceg_ir"] = {
            "schema_version": ir["schema_version"],
            "source_snapshot_id": ir["source_snapshot_id"],
            "node_id": node["node_id"],
        }
        rows.append((int(payload.get("sequence", 0)), copied))
    rows.sort(key=lambda item: item[0])
    return [row for _, row in rows]


def sample_context_for_sample(
    ir: dict[str, Any],
    sample_id: str,
) -> dict[str, Any]:
    """Project the authoritative per-sample context from canonical SCEG."""
    verify_ir(ir)

    sample_nodes = [
        node
        for node in ir.get("nodes", [])
        if node.get("type") == "Sample"
        and str(node.get("sample_id") or "") == sample_id
    ]
    if len(sample_nodes) != 1:
        raise ValueError(
            f"Expected exactly one SCEG Sample node for {sample_id!r}, "
            f"got {len(sample_nodes)}"
        )

    payload = sample_nodes[0].get("payload") or {}
    if not isinstance(payload, dict):
        raise ValueError(
            f"SCEG Sample payload is not an object for {sample_id!r}"
        )

    time_rows = [
        row
        for row in ir.get("time_view_contexts", [])
        if isinstance(row, dict)
        and str(row.get("sample_id") or "") == sample_id
    ]
    if len(time_rows) != 1:
        raise ValueError(
            f"Expected exactly one SCEG time_view_context for {sample_id!r}, "
            f"got {len(time_rows)}"
        )

    sample_time = str(payload.get("generation_time") or "").strip()
    time_view_time = str(
        time_rows[0].get("generation_time") or ""
    ).strip()
    if not sample_time:
        raise ValueError(
            f"SCEG Sample generation_time missing for {sample_id!r}"
        )
    if sample_time != time_view_time:
        raise ValueError(
            "SCEG Sample/time_view generation_time mismatch: "
            f"sample={sample_id} "
            f"sample_node={sample_time!r} "
            f"time_view={time_view_time!r}"
        )

    source_inputs = ir.get("source_inputs") or {}
    code_files = (
        source_inputs.get("code_files")
        if isinstance(source_inputs, dict)
        else {}
    )
    if not isinstance(code_files, dict):
        code_files = {}
    code_record = code_files.get(sample_id)
    if code_record is not None and not isinstance(code_record, dict):
        raise ValueError(
            f"SCEG code source record is invalid for {sample_id!r}"
        )

    return {
        "schema_version": "sceg_sample_context_v2.1",
        "sample_id": sample_id,
        "sample": copy.deepcopy(payload),
        "generation_time": sample_time,
        "time_view_context": copy.deepcopy(time_rows[0]),
        "source_code": copy.deepcopy(code_record),
        "sceg_source_snapshot_id": ir.get("source_snapshot_id"),
    }


def api_call_evidence_for_sample(
    ir: dict[str, Any],
    sample_id: str,
) -> dict[str, Any]:
    verify_ir(ir)
    calls = [
        copy.deepcopy((node.get("payload") or {}).get("api_call"))
        for node in ir.get("nodes", [])
        if node.get("type") == "APICall"
        and node.get("sample_id") == sample_id
        and isinstance(
            (node.get("payload") or {}).get("api_call"),
            dict,
        )
    ]
    calls.sort(
        key=lambda row: (
            (row.get("location") or {}).get("line") or 0,
            (row.get("location") or {}).get("column") or 0,
            str(row.get("api_symbol") or ""),
        )
    )
    run = (ir.get("extractor_runs") or {}).get(sample_id, {})
    return {
        "schema_version": "api_call_evidence_from_sceg_v2.1",
        "sample_id": sample_id,
        "code_file": run.get("code_file"),
        "content_hash": run.get("content_hash"),
        "parse_status": run.get("parse_status", "unknown"),
        "parse_error": run.get("parse_error", ""),
        "syntax_parse_status": run.get(
            "syntax_parse_status", "unknown"
        ),
        "parse_diagnostic": run.get("parse_diagnostic", ""),
        "extractor_mode": run.get("extractor_mode"),
        "analysis_support": copy.deepcopy(
            run.get("analysis_support") or {}
        ),
        "identity_policy_version": run.get(
            "identity_policy_version"
        ),
        "api_call_count": len(calls),
        "api_calls": calls,
        "binding_resolution_policy": run.get("binding_resolution_policy"),
        "binding_unresolved": copy.deepcopy(run.get("binding_unresolved") or []),
        "dynamic_imports": copy.deepcopy(run.get("dynamic_imports") or []),
        "sceg_source_snapshot_id": ir.get("source_snapshot_id"),
    }


def project_dependency_facts_for_sample(
    ir: dict[str, Any],
    sample_id: str,
) -> dict[str, Any]:
    """Project canonical manifest/lock/install facts from SCEG for consumers."""
    verify_ir(ir)
    manifests: dict[str, list[dict[str, Any]]] = {}
    locks: dict[str, list[dict[str, Any]]] = {}
    installability: dict[str, list[dict[str, Any]]] = {}

    for node in ir.get("nodes", []):
        if node.get("sample_id") != sample_id:
            continue
        node_type = str(node.get("type") or "")
        payload = node.get("payload") or {}
        fact = payload.get("project_dependency_fact")
        if not isinstance(fact, dict):
            continue
        role = str(payload.get("dependency_fact_role") or "")
        normalized = pep503_normalize(
            fact.get("normalized_distribution")
            or payload.get("normalized_package")
            or payload.get("package")
            or ""
        )
        if not normalized:
            continue
        copied = copy.deepcopy(fact)
        copied["normalized_distribution"] = normalized

        if node_type == "ManifestDep" and role == "manifest":
            manifests.setdefault(normalized, []).append(copied)
        elif node_type == "ManifestDep" and role == "lock":
            locks.setdefault(normalized, []).append(copied)
        elif node_type == "InstallCommand" and role == "installability":
            installability.setdefault(normalized, []).append(copied)

    def ordered(
        values: dict[str, list[dict[str, Any]]],
    ) -> dict[str, list[dict[str, Any]]]:
        result: dict[str, list[dict[str, Any]]] = {}
        for package in sorted(values):
            result[package] = sorted(
                values[package],
                key=lambda row: (
                    str(row.get("file") or ""),
                    int(row.get("line") or 0),
                    str(row.get("source_kind") or ""),
                    str(row.get("specifier") or ""),
                    str(row.get("exact_version") or ""),
                ),
            )
        return result

    manifests = ordered(manifests)
    locks = ordered(locks)
    installability = ordered(installability)
    identity_contract = ir.get("package_identity_contract") or {}
    dependency_context = (
        (ir.get("project_dependency_contexts") or {}).get(
            sample_id, {}
        )
    )
    if not isinstance(dependency_context, dict):
        dependency_context = {}
    installability_unresolved = copy.deepcopy(
        dependency_context.get("installability_unresolved", [])
    )
    if not isinstance(installability_unresolved, list):
        installability_unresolved = []
    return {
        "schema_version": FACTS_SCHEMA_VERSION,
        "extractor_version": "sceg_v2_1_project_facts_projection_v1",
        "identity_policy_version": identity_contract.get("policy_version"),
        "manifest_packages": sorted(manifests),
        "manifests": manifests,
        "locks": locks,
        "installability": installability,
        "installability_unresolved": installability_unresolved,
        "sceg_schema_version": ir.get("schema_version"),
        "sceg_source_snapshot_id": ir.get("source_snapshot_id"),
    }


def distributions_for_sample(
    ir: dict[str, Any],
    sample_id: str,
    *,
    node_types: set[str],
    avcs_candidates_only: bool = False,
) -> list[str]:
    verify_ir(ir)
    values: set[str] = set()
    for node in ir.get("nodes", []):
        if (
            node.get("sample_id") != sample_id
            or node.get("type") not in node_types
        ):
            continue
        payload = node.get("payload") or {}
        if avcs_candidates_only:
            identity = payload.get("package_identity")
            if not is_avcs_candidate_identity(identity):
                continue
        value = (
            payload.get("distribution")
            or payload.get("normalized_package")
        )
        normalized = pep503_normalize(value)
        if normalized:
            values.add(normalized)
    return sorted(values)


def _index_nodes(
    ir: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    return {
        str(row["node_id"]): row
        for row in ir.get("nodes", [])
    }


def _index_edges(
    ir: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    return {
        str(row["edge_id"]): row
        for row in ir.get("edges", [])
    }


def _index_evidence(
    ir: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    return {
        str(row["evidence_id"]): row
        for row in ir.get("evidence", [])
    }


def _find_package_node_id(
    *,
    nodes: dict[str, dict[str, Any]],
    sample_id: str,
    package: str,
) -> str | None:
    normalized = pep503_normalize(package)
    matches = [
        node_id
        for node_id, node in nodes.items()
        if node.get("type") == "Package"
        and node.get("sample_id") == sample_id
        and pep503_normalize(
            (node.get("payload") or {}).get("normalized_name")
        )
        == normalized
    ]
    if len(matches) > 1:
        raise ValueError(
            f"Multiple package nodes for {sample_id}/{normalized}"
        )
    return matches[0] if matches else None


def _ensure_package_in_final(
    *,
    nodes: dict[str, dict[str, Any]],
    sample_id: str,
    package: str,
    ecosystem: str = "pypi",
) -> str:
    existing = _find_package_node_id(
        nodes=nodes,
        sample_id=sample_id,
        package=package,
    )
    if existing:
        return existing
    return _package_node(
        nodes=nodes,
        sample_id=sample_id,
        ecosystem=ecosystem,
        package=package,
    )


def _add_analysis_evidence(
    *,
    evidence_map: dict[str, dict[str, Any]],
    edge_map: dict[str, dict[str, Any]],
    evidence: dict[str, Any],
    targets: Iterable[str],
) -> str:
    _add_evidence_support(
        evidence_map=evidence_map,
        edge_map=edge_map,
        evidence=evidence,
        target_ids=targets,
    )
    return evidence["evidence_id"]


def _risk_package(card: dict[str, Any]) -> str:
    introduced = (
        card.get("introduced_by")
        if isinstance(card.get("introduced_by"), dict)
        else {}
    )
    package_value = card.get("package")
    if isinstance(package_value, dict):
        package_value = (
            package_value.get("name")
            or package_value.get("normalized_name")
        )
    return str(
        card.get("distribution")
        or package_value
        or introduced.get("package")
        or introduced.get("entity")
        or ""
    ).strip()


def _risk_time_view(card: dict[str, Any]) -> dict[str, Any]:
    unified = (
        card.get("time_view")
        if isinstance(card.get("time_view"), dict)
        else None
    )
    if unified is not None:
        return copy.deepcopy(unified)

    temporal = {}
    evidence = card.get("evidence")
    if isinstance(evidence, dict):
        values = evidence.get("temporal")
        if isinstance(values, list) and values:
            if isinstance(values[0], dict):
                temporal = values[0]
    return {
        "generation_time": (
            card.get("generation_time")
            or temporal.get("generation_time")
        ),
        "generation_time_uncertainty_seconds": (
            card.get("generation_time_uncertainty_seconds")
            or temporal.get("generation_time_uncertainty_seconds")
        ),
        "audit_time": temporal.get("audit_time"),
        "knowledge_time": card.get("knowledge_time"),
        "vulnerability_published_at": card.get(
            "vulnerability_published_at"
        ),
        "temporal_classification": (
            card.get("temporal_classification")
            or temporal.get("temporal_status")
        ),
    }


def risk_identity(card: dict[str, Any]) -> str:
    canonical = str(
        card.get("risk_identity") or ""
    ).strip()
    if re.fullmatch(r"[0-9a-f]{64}", canonical):
        return canonical

    # Legacy/standalone compatibility only. Repaired unified Risk Cards carry
    # the canonical identity from risk_semantics_v21; SCEG must not invent a
    # second identity contract for the same risk instance.
    introduced = (
        card.get("introduced_by")
        if isinstance(card.get("introduced_by"), dict)
        else {}
    )
    return stable_id(
        "riskident",
        card.get("sample_id"),
        card.get("type"),
        pep503_normalize(_risk_package(card)),
        location_identity(introduced),
        _risk_time_view(card),
    )


def _risk_vulnerability_ids(
    card: dict[str, Any],
) -> set[str]:
    values: set[str] = set()

    instances = card.get("vulnerability_instances")
    if isinstance(instances, list):
        for row in instances:
            if not isinstance(row, dict):
                continue
            value = str(
                row.get("vulnerability_id") or ""
            ).strip()
            if value:
                values.add(value)

    source_cards = card.get("source_cards")
    if isinstance(source_cards, list):
        for source in source_cards:
            if not isinstance(source, dict):
                continue
            value = str(
                source.get("vulnerability_id") or ""
            ).strip()
            if value:
                values.add(value)

    source_card = card.get("source_card")
    if isinstance(source_card, dict):
        value = str(
            source_card.get("vulnerability_id") or ""
        ).strip()
        if value:
            values.add(value)

    direct = str(
        card.get("vulnerability_id") or ""
    ).strip()
    if direct:
        values.add(direct)

    return values


def _match_risk_source(
    *,
    card: dict[str, Any],
    nodes: dict[str, dict[str, Any]],
) -> str:
    sample_id = str(card.get("sample_id", "") or "")
    package = pep503_normalize(_risk_package(card))
    introduced = (
        card.get("introduced_by")
        if isinstance(card.get("introduced_by"), dict)
        else {}
    )
    loc = location_identity(introduced)
    source_type = str(introduced.get("source_type") or "")
    entity = str(introduced.get("entity") or "")

    if loc[1] is not None:
        preferred_types = (
            {"APICall"}
            if (
                source_type == "api_call"
                or card.get("pipeline_origin") == "AVCS"
            )
            else {"Import", "ManifestDep", "DependencyEntity"}
        )
        matches: list[str] = []
        for node_id, node in nodes.items():
            if (
                node.get("sample_id") != sample_id
                or node.get("type") not in preferred_types
            ):
                continue
            payload = node.get("payload") or {}
            node_package = pep503_normalize(
                payload.get("distribution")
                or payload.get("normalized_package")
            )
            if package and node_package and node_package != package:
                continue
            if location_identity(node.get("location"))[:2] != loc[:2]:
                continue
            if (
                node.get("type") == "APICall"
                and entity
                and payload.get("api_symbol")
                and str(payload.get("api_symbol")) != entity
            ):
                continue
            matches.append(node_id)

        if len(matches) != 1:
            raise ValueError(
                "Risk Card location did not resolve to exactly one SCEG "
                f"entity: sample={sample_id} package={package} "
                f"location={loc} matches={matches}"
            )
        return matches[0]

    package_node_id = _find_package_node_id(
        nodes=nodes,
        sample_id=sample_id,
        package=package,
    )
    if package_node_id is None:
        raise ValueError(
            f"Risk Card package node missing: {sample_id}/{package}"
        )
    return package_node_id


def finalize_ir(
    *,
    base_ir: dict[str, Any],
    tho_records: list[dict[str, Any]],
    avcs_sample_dirs: list[Path],
    risk_cards: list[dict[str, Any]],
) -> dict[str, Any]:
    verify_ir(base_ir)
    if base_ir.get("ir_stage") != "base":
        raise ValueError("Expected base SCEG IR")

    ir = copy.deepcopy(base_ir)
    ir["ir_stage"] = "analyzed"
    ir["finalized_at"] = utc_now_iso()

    nodes = _index_nodes(ir)
    evidence_map = _index_evidence(ir)
    edges = _index_edges(ir)
    analysis_time_view_contexts: dict[str, dict[str, Any]] = {}

    dep_index: dict[str, str] = {}
    for node_id, node in nodes.items():
        payload = node.get("payload") or {}
        identity = payload.get("record_identity")
        if identity:
            dep_index[str(identity)] = node_id

    for row in tho_records:
        identity = record_identity(row)
        dep_node_id = dep_index.get(identity)
        if dep_node_id is None:
            raise ValueError(
                f"THO record not found in base SCEG: {identity}"
            )
        sample_id = str(row.get("sample_id") or "")
        package = str(row.get("package") or "")
        pkg_node_id = _find_package_node_id(
            nodes=nodes,
            sample_id=sample_id,
            package=package,
        )
        targets = [
            value
            for value in [dep_node_id, pkg_node_id]
            if value
        ]
        pypi = (
            row.get("pypi")
            if isinstance(row.get("pypi"), dict)
            else {}
        )
        temporal_evidence = make_evidence(
            kind="temporal",
            source="THO temporal classifier",
            queried_at=pypi.get("audit_time"),
            as_of=row.get("generation_time"),
            payload={
                "generation_time": row.get("generation_time"),
                "audit_time": pypi.get("audit_time"),
                "first_release_time": pypi.get("first_release_time"),
                "status": row.get("status"),
                "temporal_status_v2": row.get(
                    "temporal_status_v2"
                ),
                "temporal_status_v2_note": row.get(
                    "temporal_status_v2_note"
                ),
            },
            confidence=(
                "unknown"
                if row.get("temporal_status_v2")
                in {"temporal_unknown", "registry_unknown"}
                else "derived"
            ),
        )
        _add_analysis_evidence(
            evidence_map=evidence_map,
            edge_map=edges,
            evidence=temporal_evidence,
            targets=targets,
        )

        reachability_evidence = make_evidence(
            kind="reachability",
            source="THO reachability_v2",
            as_of=row.get("generation_time"),
            payload={
                "install_reachability": row.get(
                    "install_reachability"
                ),
                "install_reachability_v2": row.get(
                    "install_reachability_v2"
                ),
                "reachability_v2_evidence": copy.deepcopy(
                    row.get("reachability_v2_evidence")
                ),
            },
            confidence="derived",
        )
        _add_analysis_evidence(
            evidence_map=evidence_map,
            edge_map=edges,
            evidence=reachability_evidence,
            targets=targets,
        )

    for sample_dir in avcs_sample_dirs:
        manifest_path = sample_dir / "manifest.json"
        if not manifest_path.exists():
            raise FileNotFoundError(manifest_path)
        manifest = read_json(manifest_path)
        sample_id = str(manifest.get("sample_id", "") or "")
        evaluation_time_view = validate_time_view_contract(
            manifest.get("evaluation_time_view"),
            allow_legacy=True,
        )
        previous_time_view = analysis_time_view_contexts.get(sample_id)
        if (
            previous_time_view is not None
            and previous_time_view != evaluation_time_view
        ):
            raise ValueError(
                "AVCS sample has conflicting evaluation time views: "
                + sample_id
            )
        analysis_time_view_contexts[sample_id] = copy.deepcopy(
            evaluation_time_view
        )
        packages = manifest.get("packages", [])
        if not isinstance(packages, list):
            raise ValueError(f"Invalid AVCS package summary: {manifest_path}")

        for summary in packages:
            if not isinstance(summary, dict):
                continue
            distribution = str(
                summary.get("normalized_distribution")
                or summary.get("distribution")
                or ""
            ).strip()
            if not distribution:
                continue
            analysis_path = (
                sample_dir
                / "packages"
                / pep503_normalize(distribution)
                / "analysis.json"
            )
            if not analysis_path.exists():
                raise FileNotFoundError(analysis_path)
            analysis = read_json(analysis_path)
            analysis_time_view = validate_time_view_contract(
                analysis.get("evaluation_time_view"),
                allow_legacy=True,
            )
            if analysis_time_view != evaluation_time_view:
                raise ValueError(
                    "AVCS manifest/package time-view contract mismatch: "
                    f"{sample_id}/{distribution}"
                )
            pkg_node_id = _ensure_package_in_final(
                nodes=nodes,
                sample_id=sample_id,
                package=distribution,
            )

            api_constraint_evidence = make_evidence(
                kind="api_surface",
                source="TimeVulnTrace-AVCS",
                db_revision=analysis.get("package_kb_id"),
                as_of=analysis.get("time_view"),
                payload={
                    "distribution": distribution,
                    "api_constraint_status": analysis.get(
                        "api_constraint_status"
                    ),
                    "api_constraint_specifier": analysis.get(
                        "api_constraint_specifier"
                    ),
                    "api_exclusion_rules": copy.deepcopy(
                        analysis.get("api_exclusion_rules", [])
                    ),
                    "V_before_api": copy.deepcopy(
                        analysis.get("V_before_api", [])
                    ),
                    "V_feasible": copy.deepcopy(
                        analysis.get("V_feasible", [])
                    ),
                    "release_history_sha256": analysis.get(
                        "source_release_history_sha256"
                    ),
                    "knowledge_complete_to_requested_time": (
                        analysis.get(
                            "knowledge_complete_to_requested_time"
                        )
                    ),
                    "evaluation_time_view": copy.deepcopy(
                        evaluation_time_view
                    ),
                },
                confidence=(
                    "derived"
                    if analysis.get(
                        "knowledge_complete_to_requested_time"
                    )
                    is True
                    else "unknown"
                ),
            )

            api_nodes = [
                node_id
                for node_id, node in nodes.items()
                if node.get("type") == "APICall"
                and node.get("sample_id") == sample_id
                and pep503_normalize(
                    (node.get("payload") or {}).get("distribution")
                )
                == pep503_normalize(distribution)
            ]
            _add_analysis_evidence(
                evidence_map=evidence_map,
                edge_map=edges,
                evidence=api_constraint_evidence,
                targets=[pkg_node_id, *api_nodes],
            )

            feasible = {
                str(value)
                for value in analysis.get("V_feasible", [])
                if str(value)
            }
            before = {
                str(value)
                for value in analysis.get("V_before_api", [])
                if str(value)
            }
            exposed: set[str] = set()
            findings = analysis.get("findings", [])
            if not isinstance(findings, list):
                findings = []
            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                exposed.update(
                    str(value)
                    for value in finding.get("V_exposed", [])
                    if str(value)
                )

            version_node_ids: dict[str, str] = {}
            for version in sorted(before | feasible | exposed):
                version_node_id = stable_id(
                    "version",
                    sample_id,
                    pep503_normalize(distribution),
                    version,
                )
                version_node_ids[version] = version_node_id
                _put_unique(
                    nodes,
                    _node(
                        node_type="Version",
                        node_id=version_node_id,
                        sample_id=sample_id,
                        source_scope=sample_id,
                        location=None,
                        payload={
                            "package": distribution,
                            "version": version,
                            "released_at": None,
                            "in_V_before_api": version in before,
                            "in_V_feasible": version in feasible,
                            "in_V_exposed": version in exposed,
                        },
                    ),
                    id_field="node_id",
                )
                edge = make_edge(
                    edge_type="has_version",
                    source=pkg_node_id,
                    target=version_node_id,
                )
                _put_unique(edges, edge, id_field="edge_id")

            predicate = analysis.get("api_constraint_specifier")
            for api_node_id in api_nodes:
                edge = make_edge(
                    edge_type="requires_version",
                    source=api_node_id,
                    target=pkg_node_id,
                    payload={
                        "predicate": predicate,
                        "constraint_status": analysis.get(
                            "api_constraint_status"
                        ),
                    },
                )
                _put_unique(edges, edge, id_field="edge_id")

            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                vulnerability_id = str(
                    finding.get("vulnerability_id", "") or ""
                ).strip()
                if not vulnerability_id:
                    continue
                vuln_node_id = stable_id(
                    "vuln",
                    sample_id,
                    pep503_normalize(distribution),
                    vulnerability_id,
                )
                _put_unique(
                    nodes,
                    _node(
                        node_type="Vulnerability",
                        node_id=vuln_node_id,
                        sample_id=sample_id,
                        source_scope=sample_id,
                        location=None,
                        payload={
                            "id": vulnerability_id,
                            "package": distribution,
                            "affected_range": copy.deepcopy(
                                finding.get(
                                    "affected_version_specifiers",
                                    [],
                                )
                            ),
                            "disclosed_at": finding.get(
                                "vulnerability_published_at"
                            ),
                            "fixed_range": None,
                            "knowledge_time": finding.get(
                                "knowledge_time"
                            ),
                            "actionability": finding.get(
                                "actionability"
                            ),
                        },
                    ),
                    id_field="node_id",
                )
                vulnerability_evidence = make_evidence(
                    kind="vulnerability",
                    source="frozen Package KB / AVCS",
                    db_revision=analysis.get("package_kb_id"),
                    as_of=finding.get("knowledge_time"),
                    payload=copy.deepcopy(finding),
                    confidence=(
                        "derived"
                        if finding.get(
                            "affected_range_status"
                        )
                        == "resolved"
                        else "unknown"
                    ),
                )
                _add_analysis_evidence(
                    evidence_map=evidence_map,
                    edge_map=edges,
                    evidence=vulnerability_evidence,
                    targets=[pkg_node_id, vuln_node_id],
                )
                for version in finding.get("V_exposed", []):
                    version_node_id = version_node_ids.get(str(version))
                    if version_node_id is None:
                        continue
                    edge = make_edge(
                        edge_type="affected_by",
                        source=version_node_id,
                        target=vuln_node_id,
                    )
                    _put_unique(edges, edge, id_field="edge_id")

    normalized_risk_cards: list[dict[str, Any]] = []
    for card in risk_cards:
        if card.get("schema_version") == "risk_card_v2.1":
            normalized = copy.deepcopy(card)
            validate_risk_card(normalized)
        else:
            origin = str(
                card.get("pipeline_origin") or ""
            ).strip()
            if origin not in {"THO", "AVCS"}:
                raise ValueError(
                    "Raw Risk Card passed to SCEG finalizer without "
                    f"pipeline_origin: {card.get('risk_id')}"
                )
            normalized = normalize_risk_card(
                card,
                pipeline_origin=origin,
                generation_time_uncertainty_seconds=(
                    float(
                        card.get(
                            "generation_time_uncertainty_seconds"
                        )
                    )
                    if card.get(
                        "generation_time_uncertainty_seconds"
                    )
                    is not None
                    else None
                ),
            )
        normalized_risk_cards.append(normalized)

    risk_cards = deduplicate_cards(
        normalized_risk_cards
    )

    risk_identity_to_node: dict[str, str] = {}
    for card in risk_cards:
        identity = risk_identity(card)
        existing = risk_identity_to_node.get(identity)
        if existing is not None:
            raise ValueError(
                "Aggregated Risk Card identity unexpectedly duplicated: "
                f"{identity}"
            )
        source_node_id = _match_risk_source(
            card=card,
            nodes=nodes,
        )
        risk_node_id = stable_id("risk", identity)
        risk_identity_to_node[identity] = risk_node_id
        _put_unique(
            nodes,
            _node(
                node_type="Risk",
                node_id=risk_node_id,
                sample_id=str(card.get("sample_id") or ""),
                source_scope=str(card.get("sample_id") or ""),
                location=(
                    card.get("introduced_by")
                    if isinstance(card.get("introduced_by"), dict)
                    else None
                ),
                payload={
                    "risk_identity": identity,
                    "risk_id": card.get("risk_id"),
                    "risk_type": card.get("type"),
                    "package": _risk_package(card),
                    "time_view": _risk_time_view(card),
                    "pipeline_origin": card.get("pipeline_origin"),
                    "risk_card": copy.deepcopy(card),
                },
            ),
            id_field="node_id",
        )
        edge = make_edge(
            edge_type="derives_risk",
            source=source_node_id,
            target=risk_node_id,
        )
        _put_unique(edges, edge, id_field="edge_id")

        supporting_evidence_ids: set[str] = set()
        risk_vulnerability_ids = _risk_vulnerability_ids(
            card
        )

        # Risk support is inherited only from the exact source entity chosen
        # above. For aggregated AVCS risks, every vulnerability instance that
        # belongs to this semantic risk identity remains eligible evidence.
        for edge_row in edges.values():
            if (
                edge_row.get("type") == "supports"
                and edge_row.get("target") == source_node_id
                and edge_row.get("source") in evidence_map
            ):
                evidence_id = str(edge_row["source"])
                evidence_row = evidence_map[evidence_id]
                if (
                    card.get("pipeline_origin") == "AVCS"
                    and evidence_row.get("kind") == "vulnerability"
                ):
                    payload = (
                        evidence_row.get("payload")
                        if isinstance(evidence_row.get("payload"), dict)
                        else {}
                    )
                    evidence_vulnerability_id = str(
                        payload.get("vulnerability_id") or ""
                    ).strip()
                    if (
                        risk_vulnerability_ids
                        and evidence_vulnerability_id
                        not in risk_vulnerability_ids
                    ):
                        continue
                supporting_evidence_ids.add(evidence_id)

        # AVCS API-call risks also need all matching vulnerability evidence.
        # This is intentionally set-valued after F-12; a single Risk node may
        # represent multiple vulnerability instances under one stable risk
        # identity.
        if (
            card.get("pipeline_origin") == "AVCS"
            and risk_vulnerability_ids
        ):
            for evidence_id, evidence_row in evidence_map.items():
                if evidence_row.get("kind") != "vulnerability":
                    continue
                payload = (
                    evidence_row.get("payload")
                    if isinstance(evidence_row.get("payload"), dict)
                    else {}
                )
                if (
                    str(payload.get("vulnerability_id") or "").strip()
                    in risk_vulnerability_ids
                ):
                    supporting_evidence_ids.add(evidence_id)

        for evidence_id in sorted(supporting_evidence_ids):
            edge = make_edge(
                edge_type="supports",
                source=evidence_id,
                target=risk_node_id,
            )
            _put_unique(edges, edge, id_field="edge_id")

    ir["nodes"] = sorted(nodes.values(), key=lambda row: row["node_id"])
    ir["evidence"] = sorted(
        evidence_map.values(),
        key=lambda row: row["evidence_id"],
    )
    ir["edges"] = sorted(edges.values(), key=lambda row: row["edge_id"])
    time_view_rows = ir.get("time_view_contexts")
    if not isinstance(time_view_rows, list):
        raise ValueError("SCEG time_view_contexts must be a list")
    time_view_index = {
        str(row.get("sample_id") or ""): row
        for row in time_view_rows
        if isinstance(row, dict)
    }
    for sample_id, contract in sorted(
        analysis_time_view_contexts.items()
    ):
        context = time_view_index.get(sample_id)
        if context is None:
            raise ValueError(
                "AVCS evaluation view has no SCEG sample time context: "
                + sample_id
            )
        context["evaluation_time_view"] = copy.deepcopy(contract)
    ir["analysis_summary"] = {
        "tho_record_count": len(tho_records),
        "avcs_sample_count": len(avcs_sample_dirs),
        "risk_card_count": len(risk_cards),
        "risk_source_card_count": sum(
            int(
                (row.get("aggregation") or {}).get(
                    "source_card_count", 1
                )
            )
            for row in risk_cards
        ),
        "risk_vulnerability_instance_count": sum(
            len(row.get("vulnerability_instances", []))
            for row in risk_cards
        ),
        "risk_node_count": sum(
            row.get("type") == "Risk"
            for row in ir["nodes"]
        ),
    }
    verify_ir(ir)
    return ir


def verify_ir(ir: dict[str, Any]) -> None:
    required = {
        "schema_version",
        "ir_kind",
        "ir_stage",
        "dataset_label",
        "extractor_version",
        "source_snapshot_id",
        "created_at",
        "source_inputs",
        "node_type_contract",
        "edge_type_contract",
        "evidence_kind_contract",
        "time_view_contexts",
        "extractor_runs",
        "package_identity_contract",
        "consumer_contract",
        "nodes",
        "evidence",
        "edges",
    }
    missing = sorted(required - set(ir))
    if missing:
        raise ValueError(f"SCEG 2.1 required fields missing: {missing}")
    if ir.get("schema_version") != SCEG_SCHEMA_VERSION:
        raise ValueError(
            f"Unexpected SCEG schema_version: {ir.get('schema_version')}"
        )
    if ir.get("ir_kind") != "SupplyChainEvidenceGraph":
        raise ValueError("Unexpected SCEG ir_kind")
    source_snapshot_id = str(ir.get("source_snapshot_id") or "")
    if not re.fullmatch(r"[0-9a-f]{64}", source_snapshot_id):
        raise ValueError("source_snapshot_id must be SHA-256")

    project_dependency_contexts = ir.get(
        "project_dependency_contexts"
    )
    if (
        project_dependency_contexts is not None
        and not isinstance(project_dependency_contexts, dict)
    ):
        raise ValueError(
            "project_dependency_contexts must be an object when present"
        )

    if ir.get("extractor_version") == SCEG_BUILDER_VERSION:
        extractor_runs = ir.get("extractor_runs")
        if not isinstance(extractor_runs, dict):
            raise ValueError("extractor_runs must be an object")
        allowed_syntax_status = {
            "parseable",
            "syntax_invalid",
            "decode_error",
        }
        for sample_id, run in extractor_runs.items():
            if not isinstance(run, dict):
                raise ValueError(
                    f"{sample_id}: extractor run must be an object"
                )
            content_hash = str(run.get("content_hash") or "")
            if not re.fullmatch(r"[0-9a-f]{64}", content_hash):
                raise ValueError(
                    f"{sample_id}: extractor content_hash must be SHA-256"
                )
            syntax_status = str(
                run.get("syntax_parse_status") or ""
            )
            if syntax_status not in allowed_syntax_status:
                raise ValueError(
                    f"{sample_id}: invalid syntax_parse_status "
                    f"{syntax_status}"
                )
            if "parse_diagnostic" not in run:
                raise ValueError(
                    f"{sample_id}: parse_diagnostic missing"
                )
            if not str(run.get("extractor_mode") or ""):
                raise ValueError(
                    f"{sample_id}: extractor_mode missing"
                )
            support = run.get("analysis_support")
            if not isinstance(support, dict):
                raise ValueError(
                    f"{sample_id}: analysis_support missing"
                )
            if not isinstance(support.get("THO"), dict):
                raise ValueError(
                    f"{sample_id}: THO analysis_support missing"
                )
            if not isinstance(support.get("AVCS"), dict):
                raise ValueError(
                    f"{sample_id}: AVCS analysis_support missing"
                )

    nodes = ir.get("nodes")
    evidence_rows = ir.get("evidence")
    edges = ir.get("edges")
    if not isinstance(nodes, list):
        raise ValueError("nodes must be a list")
    if not isinstance(evidence_rows, list):
        raise ValueError("evidence must be a list")
    if not isinstance(edges, list):
        raise ValueError("edges must be a list")

    node_ids: set[str] = set()
    package_keys: set[tuple[str, str, str]] = set()
    for node in nodes:
        if not isinstance(node, dict):
            raise ValueError("node must be an object")
        node_id = str(node.get("node_id") or "")
        node_type = str(node.get("type") or "")
        if not node_id or node_id in node_ids:
            raise ValueError(f"Duplicate/missing node_id: {node_id}")
        node_ids.add(node_id)
        if node_type not in NODE_TYPES:
            raise ValueError(f"Unsupported SCEG node type: {node_type}")
        payload = node.get("payload") or {}
        if node_type == "Package":
            key = package_key(
                sample_id=str(node.get("source_scope") or ""),
                ecosystem=str(payload.get("ecosystem") or "pypi"),
                package=str(payload.get("normalized_name") or ""),
            )
            if key in package_keys:
                raise ValueError(f"Duplicate Package identity: {key}")
            package_keys.add(key)

        dependency_fact_role = str(
            payload.get("dependency_fact_role") or ""
        )
        if dependency_fact_role:
            allowed_roles = {
                "ManifestDep": {"manifest", "lock"},
                "InstallCommand": {"installability"},
            }
            if dependency_fact_role not in allowed_roles.get(
                node_type, set()
            ):
                raise ValueError(
                    "Invalid SCEG project dependency fact role: "
                    f"{node_type}/{dependency_fact_role}/{node_id}"
                )
            if not isinstance(
                payload.get("project_dependency_fact"), dict
            ):
                raise ValueError(
                    "SCEG project dependency fact role lacks raw fact: "
                    f"{node_id}"
                )

        if node_type in {"Import", "ManifestDep", "APICall"}:
            identity = payload.get("package_identity")
            if not isinstance(identity, dict):
                raise ValueError(
                    f"{node_type} missing PackageIdentityService record: "
                    f"{node_id}"
                )
            if identity.get("schema_version") != (
                "codesentry_gen_package_identity_record_v1"
            ):
                raise ValueError(
                    f"{node_type} has unexpected identity schema: {node_id}"
                )
            expected = str(
                payload.get("distribution")
                or payload.get("normalized_package")
                or ""
            ).strip()
            actual = str(
                identity.get("normalized_distribution") or ""
            ).strip()
            if expected and pep503_normalize(expected) != pep503_normalize(actual):
                raise ValueError(
                    f"{node_type} package identity mismatch: "
                    f"{expected} != {actual}"
                )

    evidence_ids: set[str] = set()
    for row in evidence_rows:
        if not isinstance(row, dict):
            raise ValueError("evidence row must be an object")
        required_evidence = {
            "evidence_id",
            "kind",
            "source",
            "source_url",
            "db_revision",
            "queried_at",
            "as_of",
            "confidence",
            "payload",
            "evidence_hash",
        }
        if not required_evidence.issubset(row):
            raise ValueError(
                "Evidence metadata incomplete: "
                + str(
                    sorted(required_evidence - set(row))
                )
            )
        evidence_id = str(row["evidence_id"])
        if evidence_id in evidence_ids:
            raise ValueError(f"Duplicate evidence_id: {evidence_id}")
        evidence_ids.add(evidence_id)
        if row.get("kind") not in EVIDENCE_KINDS:
            raise ValueError(
                f"Unsupported evidence kind: {row.get('kind')}"
            )
        hash_payload = {
            "kind": row.get("kind"),
            "source": row.get("source"),
            "source_url": row.get("source_url"),
            "db_revision": row.get("db_revision"),
            "queried_at": row.get("queried_at"),
            "as_of": row.get("as_of"),
            "confidence": row.get("confidence"),
            "payload": row.get("payload"),
        }
        if sha256_object(hash_payload) != row.get("evidence_hash"):
            raise ValueError(
                f"Evidence hash mismatch: {evidence_id}"
            )

    all_ids = node_ids | evidence_ids
    edge_ids: set[str] = set()
    for edge in edges:
        if not isinstance(edge, dict):
            raise ValueError("edge must be an object")
        edge_id = str(edge.get("edge_id") or "")
        if not edge_id or edge_id in edge_ids:
            raise ValueError(f"Duplicate/missing edge_id: {edge_id}")
        edge_ids.add(edge_id)
        if edge.get("type") not in EDGE_TYPES:
            raise ValueError(f"Unsupported edge type: {edge.get('type')}")
        if edge.get("source") not in all_ids:
            raise ValueError(
                f"Edge source does not exist: {edge.get('source')}"
            )
        if edge.get("target") not in all_ids:
            raise ValueError(
                f"Edge target does not exist: {edge.get('target')}"
            )


def export_bundle(
    *,
    ir: dict[str, Any],
    out_dir: Path,
) -> dict[str, int]:
    verify_ir(ir)
    write_jsonl(out_dir / "nodes.jsonl", ir["nodes"])
    write_jsonl(out_dir / "evidence.jsonl", ir["evidence"])
    write_jsonl(out_dir / "edges.jsonl", ir["edges"])
    return {
        "sceg_record_count": 1,
        "node_record_count": len(ir["nodes"]),
        "evidence_record_count": len(ir["evidence"]),
        "edge_count": len(ir["edges"]),
    }

