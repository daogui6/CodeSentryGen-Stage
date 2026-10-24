"""
PyPI registry evidence acquisition for CodeSentry-Gen.

The core-audit repair line treats registry evidence as time-sensitive
scientific evidence rather than an unbounded convenience cache.

Design invariants:
- positive registry metadata cache TTL: 24h by default;
- negative (404) cache TTL: 6h by default;
- query errors are never cached as evidence;
- cache entries are keyed by ecosystem/package/as_of;
- legacy cache records without freshness metadata are never trusted;
- raw PyPI response payloads are preserved in run-scoped snapshots;
- derived evidence is bound to the raw response by SHA-256;
- cache reuse verifies the snapshot record, raw bytes, and derived evidence;
- malformed, missing, or hash-drifted cache provenance is never trusted;
- cached evidence older than a sample generation time is rejected.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import requests


DEFAULT_POSITIVE_TTL_SECONDS = 24 * 60 * 60
DEFAULT_NEGATIVE_TTL_SECONDS = 6 * 60 * 60
CACHE_SCHEMA_VERSION = "pypi_registry_cache_v1"
SNAPSHOT_SCHEMA_VERSION = "pypi_registry_snapshot_v1"
EVIDENCE_SCHEMA_VERSION = "pypi_evidence_v1"


@dataclass
class PyPIEvidence:
    package: str
    exists_now: Optional[bool]
    query_url: str
    audit_time: str
    latest_version: Optional[str] = None
    first_release_time: Optional[str] = None
    status_code: Optional[int] = None
    error: Optional[str] = None
    evidence_schema_version: str = EVIDENCE_SCHEMA_VERSION
    registry_source: str = "PyPI JSON API"
    evidence_source: str = "network"
    cache_status: str = "miss"
    cache_as_of: Optional[str] = None
    cache_age_seconds: Optional[float] = None
    cache_ttl_seconds: Optional[int] = None
    raw_snapshot_file: Optional[str] = None
    raw_response_sha256: Optional[str] = None
    snapshot_record_sha256: Optional[str] = None
    registry_run_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _now().isoformat()


def _parse_time(value: Any) -> Optional[datetime]:
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        result = datetime.fromisoformat(text)
    except ValueError:
        return None
    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)
    return result.astimezone(timezone.utc)


def _earliest_release_time(data: Dict[str, Any]) -> Optional[str]:
    earliest: Optional[datetime] = None
    releases = data.get("releases", {})
    if not isinstance(releases, dict):
        return None

    for files in releases.values():
        if not isinstance(files, list):
            continue
        for file_info in files:
            if not isinstance(file_info, dict):
                continue
            upload_time = (
                file_info.get("upload_time_iso_8601")
                or file_info.get("upload_time")
            )
            dt = _parse_time(upload_time)
            if dt is not None and (earliest is None or dt < earliest):
                earliest = dt

    return earliest.isoformat() if earliest else None


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _is_sha256(value: Any) -> bool:
    text = str(value or "").strip().lower()
    return bool(re.fullmatch(r"[0-9a-f]{64}", text))


def _resolve_snapshot_member(
    snapshot_dir: Optional[Path],
    value: Any,
) -> Optional[Path]:
    if snapshot_dir is None:
        return None
    text = str(value or "").strip()
    if not text:
        return None
    base = snapshot_dir.resolve()
    candidate = Path(text)
    if not candidate.is_absolute():
        candidate = base / candidate
    try:
        resolved = candidate.resolve()
        resolved.relative_to(base)
    except (OSError, ValueError):
        return None
    return resolved


def _safe_time_token(value: str) -> str:
    return (
        value.replace(":", "")
        .replace("-", "")
        .replace("+", "_")
        .replace(".", "_")
    )


def _relative_or_absolute(path: Path, base: Optional[Path]) -> str:
    if base is not None:
        try:
            return path.resolve().relative_to(base.resolve()).as_posix()
        except ValueError:
            pass
    return path.resolve().as_posix()


def _cache_ttl_seconds(
    status_code: Optional[int],
    *,
    positive_ttl_seconds: int,
    negative_ttl_seconds: int,
) -> Optional[int]:
    if status_code == 404:
        return negative_ttl_seconds
    if status_code is not None and 200 <= status_code < 300:
        return positive_ttl_seconds
    return None


def cache_record_is_fresh(
    record: Dict[str, Any],
    *,
    now: datetime,
    positive_ttl_seconds: int = DEFAULT_POSITIVE_TTL_SECONDS,
    negative_ttl_seconds: int = DEFAULT_NEGATIVE_TTL_SECONDS,
    not_before: Optional[datetime] = None,
) -> tuple[bool, Optional[float], Optional[int], str]:
    if record.get("schema_version") != CACHE_SCHEMA_VERSION:
        return False, None, None, "legacy_or_unknown_schema"

    cached_at = _parse_time(record.get("as_of"))
    if cached_at is None:
        return False, None, None, "missing_as_of"

    status_code = record.get("status_code")

    ttl = _cache_ttl_seconds(
        status_code,
        positive_ttl_seconds=positive_ttl_seconds,
        negative_ttl_seconds=negative_ttl_seconds,
    )
    if ttl is None:
        return False, None, None, "non_cacheable_status"

    if not_before is not None and cached_at < not_before:
        return False, None, ttl, "predates_required_time"

    age = (now - cached_at).total_seconds()
    if age < 0:
        return False, age, ttl, "cache_from_future"
    if age > ttl:
        return False, age, ttl, "expired"

    evidence = record.get("evidence")
    if not isinstance(evidence, dict):
        return False, age, ttl, "missing_evidence"
    if evidence.get("evidence_schema_version") != EVIDENCE_SCHEMA_VERSION:
        return False, age, ttl, "invalid_evidence_schema"
    if str(record.get("ecosystem") or "") != "pypi":
        return False, age, ttl, "invalid_ecosystem"
    if str(evidence.get("package") or "") != str(record.get("package") or ""):
        return False, age, ttl, "package_mismatch"
    if evidence.get("status_code") != status_code:
        return False, age, ttl, "status_code_mismatch"
    evidence_time = _parse_time(evidence.get("audit_time"))
    if evidence_time is None or evidence_time != cached_at:
        return False, age, ttl, "audit_time_mismatch"
    if evidence.get("error") not in (None, ""):
        return False, age, ttl, "cached_error_not_authoritative"

    raw_sha = str(record.get("raw_response_sha256", "")).strip().lower()
    if not raw_sha:
        return False, age, ttl, "missing_raw_hash"
    if not _is_sha256(raw_sha):
        return False, age, ttl, "invalid_raw_hash_format"

    evidence_raw_sha = str(
        evidence.get("raw_response_sha256", "")
    ).strip().lower()
    if not _is_sha256(evidence_raw_sha):
        return False, age, ttl, "invalid_evidence_raw_hash"
    if evidence_raw_sha != raw_sha:
        return False, age, ttl, "raw_hash_envelope_mismatch"

    if not str(evidence.get("raw_snapshot_file") or "").strip():
        return False, age, ttl, "missing_snapshot_record"
    if not _is_sha256(evidence.get("snapshot_record_sha256")):
        return False, age, ttl, "invalid_snapshot_record_hash"

    return True, age, ttl, "fresh"


def _iter_cache_records(
    cache_dir: Path,
    package: str,
) -> list[tuple[Path, Dict[str, Any]]]:
    package_dir = cache_dir / "pypi" / package
    if not package_dir.exists():
        return []

    rows: list[tuple[Path, Dict[str, Any]]] = []
    for path in sorted(package_dir.glob("*.json"), reverse=True):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(value, dict):
            rows.append((path, value))
    return rows


def _validate_cache_provenance(
    *,
    record: Dict[str, Any],
    package: str,
    snapshot_dir: Optional[Path],
) -> tuple[bool, str]:
    evidence = record.get("evidence")
    if not isinstance(evidence, dict):
        return False, "missing_evidence"
    if snapshot_dir is None:
        return False, "snapshot_dir_required_for_cache_reuse"

    snapshot_path = _resolve_snapshot_member(
        snapshot_dir,
        evidence.get("raw_snapshot_file"),
    )
    if snapshot_path is None:
        return False, "invalid_snapshot_record_path"
    if not snapshot_path.is_file():
        return False, "snapshot_record_missing"

    expected_snapshot_sha = str(
        evidence.get("snapshot_record_sha256") or ""
    ).strip().lower()
    if not _is_sha256(expected_snapshot_sha):
        return False, "invalid_snapshot_record_hash"
    if _sha256_file(snapshot_path) != expected_snapshot_sha:
        return False, "snapshot_record_hash_mismatch"

    try:
        snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    except Exception:
        return False, "snapshot_record_unreadable"
    if not isinstance(snapshot, dict):
        return False, "snapshot_record_not_object"
    if snapshot.get("schema_version") != SNAPSHOT_SCHEMA_VERSION:
        return False, "snapshot_schema_mismatch"
    if str(snapshot.get("ecosystem") or "") != "pypi":
        return False, "snapshot_ecosystem_mismatch"
    if str(snapshot.get("package") or "") != package:
        return False, "snapshot_package_mismatch"
    if str(record.get("package") or "") != package:
        return False, "cache_package_mismatch"

    for key in ("query_url", "audit_time", "status_code"):
        if snapshot.get(key) != evidence.get(key):
            return False, f"snapshot_evidence_{key}_mismatch"
    if snapshot.get("error") not in (None, ""):
        return False, "snapshot_contains_error"
    if snapshot.get("run_id") != evidence.get("registry_run_id"):
        return False, "snapshot_run_id_mismatch"

    envelope_raw_sha = str(
        record.get("raw_response_sha256") or ""
    ).strip().lower()
    evidence_raw_sha = str(
        evidence.get("raw_response_sha256") or ""
    ).strip().lower()
    snapshot_raw_sha = str(
        snapshot.get("raw_response_sha256") or ""
    ).strip().lower()
    if not (
        _is_sha256(envelope_raw_sha)
        and _is_sha256(evidence_raw_sha)
        and _is_sha256(snapshot_raw_sha)
    ):
        return False, "invalid_raw_hash_format"
    if len({envelope_raw_sha, evidence_raw_sha, snapshot_raw_sha}) != 1:
        return False, "raw_hash_binding_mismatch"

    raw_path = _resolve_snapshot_member(
        snapshot_dir,
        snapshot.get("raw_body_file"),
    )
    if raw_path is None:
        return False, "invalid_raw_body_path"
    if not raw_path.is_file():
        return False, "raw_body_missing"
    if _sha256_file(raw_path) != envelope_raw_sha:
        return False, "raw_body_hash_mismatch"

    status_code = record.get("status_code")
    if status_code == 404:
        if evidence.get("exists_now") is not False:
            return False, "negative_evidence_semantics_mismatch"
        if snapshot.get("raw_json") not in (None, {}):
            return False, "negative_snapshot_json_mismatch"
    elif isinstance(status_code, int) and 200 <= status_code < 300:
        raw_json = snapshot.get("raw_json")
        if not isinstance(raw_json, dict):
            return False, "positive_snapshot_json_missing"
        try:
            raw_body_json = json.loads(raw_path.read_bytes())
        except Exception:
            return False, "positive_raw_body_json_unreadable"
        if raw_body_json != raw_json:
            return False, "raw_body_snapshot_json_mismatch"
        if evidence.get("exists_now") is not True:
            return False, "positive_evidence_semantics_mismatch"
        expected_latest = (
            raw_json.get("info", {}).get("version")
            if isinstance(raw_json.get("info"), dict)
            else None
        )
        if evidence.get("latest_version") != expected_latest:
            return False, "latest_version_derivation_mismatch"
        if evidence.get("first_release_time") != _earliest_release_time(
            raw_json
        ):
            return False, "first_release_derivation_mismatch"
    else:
        return False, "non_cacheable_status"

    return True, "verified"


def _load_fresh_cache(
    *,
    cache_dir: Path,
    package: str,
    now: datetime,
    positive_ttl_seconds: int,
    negative_ttl_seconds: int,
    not_before: Optional[datetime],
    snapshot_dir: Optional[Path],
) -> Optional[PyPIEvidence]:
    for _path, record in _iter_cache_records(cache_dir, package):
        fresh, age, ttl, reason = cache_record_is_fresh(
            record,
            now=now,
            positive_ttl_seconds=positive_ttl_seconds,
            negative_ttl_seconds=negative_ttl_seconds,
            not_before=not_before,
        )
        if not fresh:
            continue

        provenance_ok, _provenance_reason = _validate_cache_provenance(
            record=record,
            package=package,
            snapshot_dir=snapshot_dir,
        )
        if not provenance_ok:
            continue

        evidence = dict(record["evidence"])
        evidence["evidence_source"] = "cache"
        evidence["cache_status"] = reason
        evidence["cache_as_of"] = record.get("as_of")
        evidence["cache_age_seconds"] = age
        evidence["cache_ttl_seconds"] = ttl
        return PyPIEvidence(**evidence)

    return None


def _write_cache_record(
    *,
    cache_dir: Path,
    package: str,
    evidence: PyPIEvidence,
    raw_response_sha256: str,
) -> Path:
    as_of = evidence.audit_time
    package_dir = cache_dir / "pypi" / package
    package_dir.mkdir(parents=True, exist_ok=True)
    path = package_dir / f"{_safe_time_token(as_of)}.json"

    record = {
        "schema_version": CACHE_SCHEMA_VERSION,
        "ecosystem": "pypi",
        "package": package,
        "as_of": as_of,
        "status_code": evidence.status_code,
        "raw_response_sha256": raw_response_sha256,
        "evidence": evidence.to_dict(),
    }
    path.write_text(
        json.dumps(record, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return path


def _write_snapshot(
    *,
    snapshot_dir: Path,
    package: str,
    query_url: str,
    audit_time: str,
    status_code: Optional[int],
    raw_body: bytes,
    raw_json: Any,
    error: Optional[str],
    run_id: Optional[str],
) -> tuple[str, str, str]:
    package_dir = snapshot_dir / "pypi" / package
    package_dir.mkdir(parents=True, exist_ok=True)

    body_sha = _sha256_bytes(raw_body)
    token = _safe_time_token(audit_time)
    body_path = package_dir / f"{token}.raw"
    record_path = package_dir / f"{token}.snapshot.json"

    if body_path.exists() or record_path.exists():
        raise FileExistsError(
            f"Refusing overwrite of registry snapshot for {package}: {token}"
        )

    body_path.write_bytes(raw_body)
    record = {
        "schema_version": SNAPSHOT_SCHEMA_VERSION,
        "ecosystem": "pypi",
        "package": package,
        "query_url": query_url,
        "audit_time": audit_time,
        "status_code": status_code,
        "error": error,
        "run_id": run_id,
        "raw_body_file": _relative_or_absolute(body_path, snapshot_dir),
        "raw_response_sha256": body_sha,
        "raw_json": raw_json,
    }
    record_path.write_text(
        json.dumps(record, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    record_sha = _sha256_file(record_path)
    return (
        _relative_or_absolute(record_path, snapshot_dir),
        body_sha,
        record_sha,
    )


def query_pypi(
    package: str,
    cache_dir: Optional[Path] = None,
    snapshot_dir: Optional[Path] = None,
    timeout: int = 12,
    positive_ttl_seconds: int = DEFAULT_POSITIVE_TTL_SECONDS,
    negative_ttl_seconds: int = DEFAULT_NEGATIVE_TTL_SECONDS,
    not_before: Optional[str] = None,
    run_id: Optional[str] = None,
) -> PyPIEvidence:
    if positive_ttl_seconds <= 0:
        raise ValueError("positive_ttl_seconds must be > 0")
    if not (60 * 60 <= negative_ttl_seconds <= 6 * 60 * 60):
        raise ValueError(
            "negative_ttl_seconds must follow advisor design: 1h..6h"
        )

    query_url = f"https://pypi.org/pypi/{package}/json"
    now = _now()
    required_time = _parse_time(not_before)

    if cache_dir is not None:
        cache_dir.mkdir(parents=True, exist_ok=True)
        cached = _load_fresh_cache(
            cache_dir=cache_dir,
            package=package,
            now=now,
            positive_ttl_seconds=positive_ttl_seconds,
            negative_ttl_seconds=negative_ttl_seconds,
            not_before=required_time,
            snapshot_dir=snapshot_dir,
        )
        if cached is not None:
            return cached

    audit_time = now.isoformat()
    raw_body = b""
    raw_json: Any = None
    status_code: Optional[int] = None
    error: Optional[str] = None

    try:
        response = requests.get(query_url, timeout=timeout)
        status_code = response.status_code
        raw_body = response.content

        if status_code == 404:
            evidence = PyPIEvidence(
                package=package,
                exists_now=False,
                query_url=query_url,
                audit_time=audit_time,
                status_code=404,
            )
        elif response.ok:
            raw_json = response.json()
            evidence = PyPIEvidence(
                package=package,
                exists_now=True,
                query_url=query_url,
                audit_time=audit_time,
                latest_version=raw_json.get("info", {}).get("version"),
                first_release_time=_earliest_release_time(raw_json),
                status_code=status_code,
            )
        else:
            error = f"HTTP {status_code}"
            evidence = PyPIEvidence(
                package=package,
                exists_now=None,
                query_url=query_url,
                audit_time=audit_time,
                status_code=status_code,
                error=error,
            )
    except Exception as exc:
        error = str(exc)
        evidence = PyPIEvidence(
            package=package,
            exists_now=None,
            query_url=query_url,
            audit_time=audit_time,
            status_code=status_code,
            error=error,
        )

    raw_sha = _sha256_bytes(raw_body)

    if snapshot_dir is not None:
        snapshot_dir.mkdir(parents=True, exist_ok=True)
        snapshot_file, snapshot_body_sha, snapshot_record_sha = _write_snapshot(
            snapshot_dir=snapshot_dir,
            package=package,
            query_url=query_url,
            audit_time=audit_time,
            status_code=status_code,
            raw_body=raw_body,
            raw_json=raw_json,
            error=error,
            run_id=run_id,
        )
        evidence.raw_snapshot_file = snapshot_file
        evidence.raw_response_sha256 = snapshot_body_sha
        evidence.snapshot_record_sha256 = snapshot_record_sha
    else:
        evidence.raw_response_sha256 = raw_sha

    evidence.registry_run_id = run_id
    ttl = _cache_ttl_seconds(
        status_code,
        positive_ttl_seconds=positive_ttl_seconds,
        negative_ttl_seconds=negative_ttl_seconds,
    )
    evidence.cache_ttl_seconds = ttl

    if required_time is not None:
        audit_dt = _parse_time(evidence.audit_time)
        if audit_dt is None or audit_dt < required_time:
            evidence.exists_now = None
            evidence.error = "audit_time_precedes_generation_time"

    # Only authoritative 2xx and explicit 404 results are cacheable.
    # Transport failures, server errors, and time-invariant failures remain
    # unknown and are never reused as registry evidence.
    if cache_dir is not None and ttl is not None and evidence.error is None:
        _write_cache_record(
            cache_dir=cache_dir,
            package=package,
            evidence=evidence,
            raw_response_sha256=raw_sha,
        )

    return evidence
