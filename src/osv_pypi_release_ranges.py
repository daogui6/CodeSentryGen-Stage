"""Source-local OSV release sets; never join different advisory claims.

ECOSYSTEM events use public PEP 440 ordering for PyPI. GIT evidence stays
unmapped. SEMVER/unknown domains and incomplete evidence fail closed.
The OSV union of ranges and enumerated versions is compared independently
for each source before emitting a single-interval compatibility specifier.
"""
from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from typing import Any

from packaging.specifiers import SpecifierSet
from packaging.version import InvalidVersion, Version

ANALYSIS_VERSION = "osv_pypi_release_consensus_v1"
EVENT_TYPES = {"introduced", "fixed", "last_affected", "limit"}


class RangeEvidenceError(ValueError):
    """The evidence cannot define a supported public PyPI release set."""


def canonical_version(value: Any) -> Version:
    if not isinstance(value, str) or not value.strip():
        raise RangeEvidenceError("invalid_release_version")
    try:
        version = Version(value.strip())
    except InvalidVersion as error:
        raise RangeEvidenceError("invalid_release_version") from error
    if version.local is not None:
        raise RangeEvidenceError("unsupported_local_release_version")
    release = list(version.release)
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    text = (f"{version.epoch}!" if version.epoch else "")
    text += ".".join(map(str, release))
    if version.pre is not None:
        text += f"{version.pre[0]}{version.pre[1]}"
    if version.post is not None:
        text += f".post{version.post}"
    if version.dev is not None:
        text += f".dev{version.dev}"
    return Version(text)


@dataclass(frozen=True)
class ReleaseInterval:
    lower: Version | None
    upper: Version | None
    upper_inclusive: bool = False

    def contains(self, version: Version) -> bool:
        return ((self.lower is None or version >= self.lower)
                and (self.upper is None or version < self.upper
                     or (self.upper_inclusive and version == self.upper)))

    def as_dict(self) -> dict[str, Any]:
        return {"lower": str(self.lower) if self.lower is not None else None,
                "lower_inclusive": True,
                "upper": str(self.upper) if self.upper is not None else None,
                "upper_inclusive": self.upper_inclusive}


def union_intervals(intervals: list[ReleaseInterval]) -> list[ReleaseInterval]:
    ordered = sorted(intervals, key=lambda item: (
        item.lower is not None, item.lower or Version("0.dev0")))
    result: list[ReleaseInterval] = []
    for item in ordered:
        domain_lower = item.lower or Version("0.dev0")
        if item.upper is not None:
            if item.upper < domain_lower or (
                    item.upper == domain_lower and not item.upper_inclusive):
                continue
        if item.lower == Version("0.dev0"):
            item = ReleaseInterval(None, item.upper, item.upper_inclusive)
        if not result:
            result.append(item)
            continue
        previous = result[-1]
        # All lower endpoints are inclusive, so touching intervals have no gap.
        if (previous.upper is None or item.lower is None
                or item.lower <= previous.upper):
            if previous.upper is None or item.upper is None:
                upper, inclusive = None, False
            elif item.upper > previous.upper:
                upper, inclusive = item.upper, item.upper_inclusive
            elif item.upper < previous.upper:
                upper, inclusive = previous.upper, previous.upper_inclusive
            else:
                upper = previous.upper
                inclusive = previous.upper_inclusive or item.upper_inclusive
            result[-1] = ReleaseInterval(previous.lower, upper, inclusive)
        else:
            result.append(item)
    return result


def parse_ecosystem_range(range_entry: dict[str, Any]) -> tuple[
        list[ReleaseInterval], set[Version]]:
    events = range_entry.get("events")
    if not isinstance(events, list) or not events:
        raise RangeEvidenceError("invalid_events")
    parsed: set[tuple[str, Version | None]] = set()
    for event in events:
        if not isinstance(event, dict) or len(event) != 1:
            raise RangeEvidenceError("invalid_event")
        kind = next(iter(event))
        if kind not in EVENT_TYPES:
            raise RangeEvidenceError("unsupported_event")
        value = event[kind]
        if not isinstance(value, str) or not value.strip():
            raise RangeEvidenceError("invalid_release_version")
        sentinel = ((kind == "introduced" and value == "0")
                    or (kind == "limit" and value == "*"))
        parsed.add((kind, None if sentinel else canonical_version(value)))
    kinds = {kind for kind, _ in parsed}
    if "introduced" not in kinds:
        raise RangeEvidenceError("introduced_event_missing")
    if {"fixed", "last_affected"} <= kinds:
        raise RangeEvidenceError("mixed_terminal_events")
    limits = [version for kind, version in parsed if kind == "limit"]
    ceiling = (None if not limits or None in limits else max(limits))
    timeline = [(kind, version) for kind, version in parsed if kind != "limit"]
    at_version: dict[Version | None, set[str]] = {}
    for kind, version in timeline:
        at_version.setdefault(version, set()).add(kind)
    if any(len(values) > 1 for values in at_version.values()):
        raise RangeEvidenceError("conflicting_events_at_version")
    timeline.sort(key=lambda item: (item[1] is not None,
                                   item[1] or Version("0.dev0")))
    active = False
    lower: Version | None = None
    intervals: list[ReleaseInterval] = []
    fixed: set[Version] = set()
    for kind, version in timeline:
        if kind == "introduced":
            if not active:
                active, lower = True, version
        else:
            if kind == "fixed" and version is not None:
                fixed.add(version)
            if active:
                intervals.append(ReleaseInterval(lower, version,
                                                  kind == "last_affected"))
                active = False
            elif not intervals:
                raise RangeEvidenceError("terminal_before_introduction")
    if active:
        intervals.append(ReleaseInterval(lower, None))
    if ceiling is not None:
        intervals = [ReleaseInterval(item.lower, ceiling, False)
                     if item.upper is None or item.upper >= ceiling else item
                     for item in intervals]
    return union_intervals(intervals), fixed


def _key(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def analyze_source(record: dict[str, Any], ecosystem: str = "PyPI") -> dict[str, Any]:
    result: dict[str, Any] = {
        "source_record_id": record.get("source_record_id", ""),
        "source_url": record.get("source_url"),
        "evidence_hash": record.get("evidence_hash"),
        "raw_osv_file": record.get("raw_osv_file"),
        "normalized_evidence_file": record.get("normalized_evidence_file"),
        "evidence_status": record.get("evidence_status"),
        "normalization_issues": copy.deepcopy(record.get("normalization_issues", [])),
        "withdrawn_at": record.get("withdrawn", record.get("withdrawn_at")),
        "source_fixed_version_claims": copy.deepcopy(record.get("fixed_versions", [])),
        "affected_ranges": copy.deepcopy(record.get("affected_ranges", [])),
        "affected_versions": copy.deepcopy(record.get("affected_versions", [])),
        "fixed_commits": copy.deepcopy(record.get("fixed_commits", [])),
        "status": "resolved", "release_intervals": [],
        "affected_release_intervals": [], "fixed_versions": [], "fixed_version_spellings": [],
        "mapped_versions_outside_release_ranges": [],
        "supplemental_range_types": [],
    }
    try:
        if ecosystem != "PyPI":
            raise RangeEvidenceError("unsupported_release_ecosystem")
        if not isinstance(record.get("source_record_id"), str) or not record["source_record_id"].strip():
            raise RangeEvidenceError("source_record_id_missing")
        if record.get("evidence_status") != "resolved":
            raise RangeEvidenceError("upstream_evidence_unresolved")
        if record.get("withdrawn") or record.get("withdrawn_at"):
            raise RangeEvidenceError("withdrawn_source_record")
        if record.get("normalization_issues"):
            raise RangeEvidenceError("incomplete_normalized_evidence")
        ranges = record.get("affected_ranges")
        versions = record.get("affected_versions")
        if not isinstance(ranges, list) or not isinstance(versions, list):
            raise RangeEvidenceError("malformed_release_evidence")
        intervals: list[ReleaseInterval] = []
        fixed: set[Version] = set()
        release_range_count = 0
        for entry in ranges:
            if not isinstance(entry, dict):
                raise RangeEvidenceError("invalid_range")
            kind = entry.get("type")
            if kind == "ECOSYSTEM":
                parsed, boundaries = parse_ecosystem_range(entry)
                intervals.extend(parsed)
                fixed.update(boundaries)
                release_range_count += 1
            elif kind == "GIT":
                result["supplemental_range_types"].append("GIT")
            else:
                raise RangeEvidenceError("unsupported_release_range_type")
        intervals = union_intervals(intervals)
        result["release_intervals"] = [item.as_dict() for item in intervals]
        explicit = {canonical_version(value) for value in versions}
        outside = {value for value in explicit
                   if not any(item.contains(value) for item in intervals)}
        result["mapped_versions_outside_release_ranges"] = [
            str(value) for value in sorted(outside)]
        affected = union_intervals(intervals + [
            ReleaseInterval(value, value, True) for value in explicit])
        result["affected_release_intervals"] = [item.as_dict() for item in affected]
        # A fix for one segment is not necessarily a globally safe release.
        result["fixed_versions"] = [str(value) for value in sorted(fixed)
                                    if not any(item.contains(value) for item in affected)]
        # Keep observed release-label spellings for consumers which look up
        # release artifacts by label; canonical ordering keys are internal.
        result["fixed_version_spellings"] = sorted({
            str(Version(event["fixed"])) for entry in ranges if entry["type"] == "ECOSYSTEM"
            for event in entry["events"] if "fixed" in event
            and str(canonical_version(event["fixed"])) in result["fixed_versions"]
        }, key=lambda text: (Version(text), text))
        if not release_range_count:
            raise RangeEvidenceError("release_range_evidence_missing")
        if not intervals:
            raise RangeEvidenceError("empty_release_range")
        if fixed & outside:
            raise RangeEvidenceError("inconsistent_fixed_release_evidence")
    except RangeEvidenceError as error:
        result["status"] = str(error)
    result["supplemental_range_types"] = sorted(set(result["supplemental_range_types"]))
    return result


def interval_specifier(interval: dict[str, Any]) -> str:
    parts: list[str] = []
    if interval["lower"] is not None:
        parts.append(f">={interval['lower']}")
    upper = interval["upper"]
    if upper is not None:
        parts.append(f"<={upper}")
        if not interval["upper_inclusive"]:
            # Unlike <V, this also admits V's earlier prereleases. !=V keeps
            # the fixed release (and its local labels) out of the affected set.
            parts.append(f"!={upper}")
    text = ",".join(parts) if parts else ">=0.dev0"
    SpecifierSet(text)  # Validate the compatibility representation.
    return text


def analyze_sources(records: list[dict[str, Any]], ecosystem: str = "PyPI") -> dict[str, Any]:
    sources = sorted((analyze_source(record, ecosystem) for record in records),
                     key=lambda row: (_key(row["source_record_id"]), _key(row)))
    usable = [row for row in sources if row["status"] == "resolved"]
    range_keys = {_key(row["release_intervals"]) for row in usable}
    set_keys = {_key(row["affected_release_intervals"]) for row in usable}
    result: dict[str, Any] = {
        "analysis_version": ANALYSIS_VERSION,
        "release_version_domain": "public_pep440",
        "range_disagreement": len(range_keys) > 1,
        "affected_release_set_disagreement": len(set_keys) > 1,
        "source_evidence": sources, "constraint_status": "resolved",
        "classification": "consistent_release_evidence",
        "affected_release_intervals": [], "affected_version_specifier": "",
        "fixed_version_specifier": "", "fixed_versions": [],
        "affected_versions": [],
        "supplemental_git_evidence_unmapped": any(
            "GIT" in row["supplemental_range_types"] for row in sources),
    }
    if len(range_keys) > 1:
        result.update(classification="true_release_range_conflict",
                      constraint_status="source_range_disagreement")
    elif len(set_keys) > 1:
        result.update(classification="mapped_release_list_conflict",
                      constraint_status="source_affected_version_list_disagreement")
    elif not sources or len(usable) != len(sources):
        statuses = {row["status"] for row in sources if row["status"] != "resolved"}
        result.update(classification="insufficient_or_unsupported_release_evidence",
                      constraint_status=(next(iter(statuses)) if len(statuses) == 1
                                         else "source_release_evidence_unresolved"))
    else:
        raw_release_keys = {_key(sorted([
            entry for entry in row["affected_ranges"] if entry["type"] == "ECOSYSTEM"
        ], key=_key)) for row in sources}
        supplemental_keys = {_key(sorted([
            entry for entry in row["affected_ranges"] if entry["type"] == "GIT"
        ], key=_key)) for row in sources}
        if len(raw_release_keys) > 1:
            result["classification"] = "equivalent_release_ranges_normalized_representation"
        elif len(supplemental_keys) > 1:
            result["classification"] = "equivalent_release_ranges_with_supplemental_git"
        elif len({_key(sorted(row["affected_versions"])) for row in sources}) > 1:
            result["classification"] = "equivalent_explicit_version_lists"
        intervals = usable[0]["affected_release_intervals"]
        result["affected_release_intervals"] = copy.deepcopy(intervals)
        if len(intervals) != 1:
            result["constraint_status"] = "unsupported_multi_interval_release_set"
        else:
            result["affected_version_specifier"] = interval_specifier(intervals[0])
            result["affected_versions"] = sorted({
                value for row in sources for value in row["affected_versions"]
            }, key=lambda text: (Version(text), text))
            fixed = sorted({value for row in sources for value in row["fixed_version_spellings"]},
                           key=lambda text: (Version(text), text))
            result["fixed_versions"] = fixed
            upper = intervals[0]["upper"]
            # Only a globally terminal, explicitly attested fix supports >=V.
            if upper is not None and not intervals[0]["upper_inclusive"]:
                if all(upper in row["fixed_versions"] for row in sources):
                    result["fixed_version_specifier"] = f">={upper}"
    return result
