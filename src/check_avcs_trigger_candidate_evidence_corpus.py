from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

DEFAULT_PLAN = (
    ROOT
    / "output"
    / "avcs_trigger_source_acquisition_plan_v0.json"
)

DEFAULT_CORPUS = (
    ROOT
    / "output"
    / "avcs_trigger_candidate_evidence_corpus_v0.json"
)

EXPECTED_SCHEMA_VERSION = (
    "avcs_trigger_candidate_evidence_corpus_v0.1"
)

EXPECTED_BUILDER_VERSION = (
    "trigger_candidate_evidence_corpus_builder_v0.1"
)

STRUCTURED_PHASES = {
    "phase_1_structured_evidence",
    "phase_2_structured_metadata",
}

GENERIC_WEB_PHASE = (
    "phase_3_generic_web"
)

LOCAL_BACKENDS = {
    "local_evidence_file",
    "osv_api_record",
}

GITHUB_FILE_BACKENDS = {
    "github_blob_url",
    "github_repository_file",
}

GITHUB_COMMIT_BACKENDS = {
    "github_commit_url",
    "github_repository_commit",
}

GITHUB_METADATA_BACKENDS = {
    "github_security_advisory_url",
    "github_pull_request_url",
    "github_issue_url",
    "github_release_url",
}

SUPPORTED_BACKENDS = (
    LOCAL_BACKENDS
    | GITHUB_FILE_BACKENDS
    | GITHUB_COMMIT_BACKENDS
    | GITHUB_METADATA_BACKENDS
)

EXPECTED_DATASET_BY_BACKEND = {
    "local_evidence_file":
        "local_structured",

    "osv_api_record":
        "local_structured",

    "github_blob_url":
        "github_file",

    "github_repository_file":
        "github_file",

    "github_commit_url":
        "github_commit",

    "github_repository_commit":
        "github_commit",

    "github_security_advisory_url":
        "github_metadata",

    "github_pull_request_url":
        "github_metadata",

    "github_issue_url":
        "github_metadata",

    "github_release_url":
        "github_metadata",
}

ALLOWED_UNIT_KINDS_BY_BACKEND = {
    "local_evidence_file": {
        "structured_json_summary",
        "structured_json_details",
        "structured_json_record",
    },

    "osv_api_record": {
        "structured_json_summary",
        "structured_json_details",
        "structured_json_record",
    },

    "github_blob_url": {
        "github_source_file_text",
    },

    "github_repository_file": {
        "github_source_file_text",
    },

    "github_commit_url": {
        "github_commit_message",
        "github_commit_patch",
    },

    "github_repository_commit": {
        "github_commit_message",
        "github_commit_patch",
    },

    "github_security_advisory_url": {
        "github_advisory_summary",
        "github_advisory_description",
    },

    "github_pull_request_url": {
        "github_pull_request_title",
        "github_pull_request_body",
    },

    "github_issue_url": {
        "github_issue_title",
        "github_issue_body",
    },

    "github_release_url": {
        "github_release_title",
        "github_release_body",
    },
}


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


def clean_text(
    value: Any,
) -> str:
    return str(
        value
        if value is not None
        else ""
    ).strip()


def sha256_bytes(
    payload: bytes,
) -> str:
    return (
        "sha256:"
        + hashlib.sha256(
            payload
        ).hexdigest()
    )


def sha256_text(
    text: str,
) -> str:
    return sha256_bytes(
        text.encode(
            "utf-8"
        )
    )


def is_sha256(
    value: Any,
) -> bool:
    text = clean_text(
        value
    )

    if not text.startswith(
        "sha256:"
    ):
        return False

    digest = text[
        len(
            "sha256:"
        ):
    ]

    return (
        len(
            digest
        )
        == 64
        and all(
            char
            in "0123456789abcdefABCDEF"
            for char in digest
        )
    )


def resolve_project_path(
    value: Any,
) -> Path | None:
    text = clean_text(
        value
    )

    if not text:
        return None

    candidate = (
        ROOT
        / Path(
            text
        )
    ).resolve()

    try:
        candidate.relative_to(
            ROOT.resolve()
        )

    except ValueError:
        return None

    return candidate


def source_key_set(
    rows: list[dict[str, Any]],
) -> set[str]:
    return {
        clean_text(
            row.get(
                "source_key"
            )
        )
        for row in rows
        if clean_text(
            row.get(
                "source_key"
            )
        )
    }


def dict_rows(
    value: Any,
) -> list[dict[str, Any]]:
    if not isinstance(
        value,
        list,
    ):
        return []

    return [
        item
        for item in value
        if isinstance(
            item,
            dict,
        )
    ]


class Checker:
    def __init__(
        self,
    ) -> None:
        self.passed = 0
        self.failed = 0

    def check(
        self,
        condition: bool,
        name: str,
        detail: str = "",
    ) -> None:
        if condition:
            self.passed += 1

            print(
                f"[PASS] {name}"
            )

        else:
            self.failed += 1

            if detail:
                print(
                    f"[FAIL] {name} | {detail}"
                )

            else:
                print(
                    f"[FAIL] {name}"
                )

    def finish(
        self,
    ) -> int:
        total = (
            self.passed
            + self.failed
        )

        print()
        print(
            "=" * 60
        )

        print(
            "AVCS TRIGGER CANDIDATE EVIDENCE "
            "CORPUS CHECK SUMMARY"
        )

        print(
            "=" * 60
        )

        print(
            f"[SUMMARY] "
            f"{self.passed}/{total} PASS"
        )

        print(
            f"[SUMMARY] "
            f"{self.failed} FAIL"
        )

        return (
            0
            if self.failed == 0
            else 1
        )


def validate_artifact_provenance(
    checker: Checker,
    source_key: str,
    provenance: dict[str, Any],
) -> None:
    checker.check(
        provenance.get(
            "verified"
        )
        is True,
        (
            f"{source_key}: "
            "artifact verified"
        ),
    )

    checker.check(
        provenance.get(
            "status"
        )
        == "resolved",
        (
            f"{source_key}: "
            "artifact provenance resolved"
        ),
    )

    path_text = clean_text(
        provenance.get(
            "path"
        )
    )

    checker.check(
        path_text
        != "",
        (
            f"{source_key}: "
            "artifact path present"
        ),
    )

    path = resolve_project_path(
        path_text
    )

    checker.check(
        path is not None,
        (
            f"{source_key}: "
            "artifact path stays under project root"
        ),
    )

    exists = (
        path is not None
        and path.exists()
        and path.is_file()
    )

    checker.check(
        exists,
        (
            f"{source_key}: "
            "artifact file exists"
        ),
    )

    expected_sha256 = clean_text(
        provenance.get(
            "expected_sha256"
        )
    )

    actual_sha256 = clean_text(
        provenance.get(
            "actual_sha256"
        )
    )

    checker.check(
        is_sha256(
            expected_sha256
        ),
        (
            f"{source_key}: "
            "expected artifact SHA256 valid"
        ),
    )

    checker.check(
        is_sha256(
            actual_sha256
        ),
        (
            f"{source_key}: "
            "actual artifact SHA256 valid"
        ),
    )

    checker.check(
        expected_sha256
        == actual_sha256,
        (
            f"{source_key}: "
            "expected and actual artifact SHA256 match"
        ),
        (
            f"expected={expected_sha256}, "
            f"actual={actual_sha256}"
        ),
    )

    expected_size = provenance.get(
        "expected_size_bytes"
    )

    actual_size = provenance.get(
        "actual_size_bytes"
    )

    checker.check(
        isinstance(
            expected_size,
            int,
        )
        and expected_size > 0,
        (
            f"{source_key}: "
            "expected artifact size positive"
        ),
    )

    checker.check(
        isinstance(
            actual_size,
            int,
        )
        and actual_size > 0,
        (
            f"{source_key}: "
            "actual artifact size positive"
        ),
    )

    checker.check(
        expected_size
        == actual_size,
        (
            f"{source_key}: "
            "expected and actual artifact size match"
        ),
    )

    if exists and path is not None:
        try:
            payload = path.read_bytes()

        except OSError:
            payload = b""

        live_sha256 = (
            sha256_bytes(
                payload
            )
            if payload
            else ""
        )

        live_size = len(
            payload
        )

        checker.check(
            live_sha256
            == actual_sha256,
            (
                f"{source_key}: "
                "live artifact SHA256 matches corpus provenance"
            ),
            (
                f"live={live_sha256}, "
                f"corpus={actual_sha256}"
            ),
        )

        checker.check(
            live_size
            == actual_size,
            (
                f"{source_key}: "
                "live artifact size matches corpus provenance"
            ),
        )


def validate_units(
    checker: Checker,
    source_key: str,
    backend: str,
    units: list[dict[str, Any]],
    global_unit_ids: set[str],
) -> tuple[
    int,
    int,
    Counter[str],
]:
    checker.check(
        len(
            units
        )
        > 0,
        (
            f"{source_key}: "
            "at least one evidence unit"
        ),
    )

    allowed_kinds = (
        ALLOWED_UNIT_KINDS_BY_BACKEND.get(
            backend,
            set(),
        )
    )

    evidence_chars = 0

    unit_kind_counter: Counter[
        str
    ] = Counter()

    for unit in units:
        unit_id = clean_text(
            unit.get(
                "unit_id"
            )
        )

        unit_kind = clean_text(
            unit.get(
                "unit_kind"
            )
        )

        text = unit.get(
            "text"
        )

        text_sha256 = clean_text(
            unit.get(
                "text_sha256"
            )
        )

        size_chars = unit.get(
            "size_chars"
        )

        locator = unit.get(
            "locator"
        )

        checker.check(
            unit_id
            != "",
            (
                f"{source_key}: "
                "unit ID present"
            ),
        )

        checker.check(
            unit_id.startswith(
                source_key
                + "::unit_"
            ),
            (
                f"{source_key}: "
                f"{unit_id or '<missing>'} "
                "unit ID belongs to source"
            ),
        )

        checker.check(
            unit_id
            not in global_unit_ids,
            (
                f"{source_key}: "
                f"{unit_id or '<missing>'} "
                "unit ID globally unique"
            ),
        )

        if unit_id:
            global_unit_ids.add(
                unit_id
            )

        checker.check(
            unit_kind
            in allowed_kinds,
            (
                f"{source_key}: "
                f"{unit_kind or '<missing>'} "
                "unit kind allowed for backend"
            ),
            (
                f"backend={backend}"
            ),
        )

        checker.check(
            isinstance(
                text,
                str,
            )
            and bool(
                text.strip()
            ),
            (
                f"{source_key}: "
                f"{unit_id or '<missing>'} "
                "unit text non-empty"
            ),
        )

        checker.check(
            is_sha256(
                text_sha256
            ),
            (
                f"{source_key}: "
                f"{unit_id or '<missing>'} "
                "unit SHA256 valid"
            ),
        )

        if isinstance(
            text,
            str,
        ):
            computed_sha256 = (
                sha256_text(
                    text
                )
            )

            computed_size = len(
                text
            )

        else:
            computed_sha256 = ""
            computed_size = 0

        checker.check(
            text_sha256
            == computed_sha256,
            (
                f"{source_key}: "
                f"{unit_id or '<missing>'} "
                "unit SHA256 matches text"
            ),
        )

        checker.check(
            isinstance(
                size_chars,
                int,
            )
            and size_chars
            == computed_size,
            (
                f"{source_key}: "
                f"{unit_id or '<missing>'} "
                "unit size matches text"
            ),
        )

        checker.check(
            isinstance(
                locator,
                dict,
            ),
            (
                f"{source_key}: "
                f"{unit_id or '<missing>'} "
                "unit locator is object"
            ),
        )

        evidence_chars += (
            computed_size
        )

        unit_kind_counter[
            unit_kind
        ] += 1

    return (
        len(
            units
        ),
        evidence_chars,
        unit_kind_counter,
    )


def validate_entry(
    checker: Checker,
    entry: dict[str, Any],
    plan_source: dict[str, Any],
    global_unit_ids: set[str],
) -> tuple[
    int,
    int,
    Counter[str],
]:
    source_key = clean_text(
        entry.get(
            "source_key"
        )
    )

    backend = clean_text(
        entry.get(
            "acquisition_backend"
        )
    )

    phase = clean_text(
        entry.get(
            "acquisition_phase"
        )
    )

    checker.check(
        entry.get(
            "corpus_status"
        )
        == "resolved",
        (
            f"{source_key}: "
            "corpus entry resolved"
        ),
    )

    checker.check(
        clean_text(
            entry.get(
                "reason"
            )
        )
        == "",
        (
            f"{source_key}: "
            "no unresolved reason"
        ),
    )

    for field in (
        "distribution",
        "source_id",
        "source_type",
        "acquisition_phase",
        "acquisition_backend",
    ):
        expected = plan_source.get(
            field
        )

        actual = entry.get(
            field
        )

        checker.check(
            actual
            == expected,
            (
                f"{source_key}: "
                f"{field} matches plan"
            ),
            (
                f"expected={expected!r}, "
                f"actual={actual!r}"
            ),
        )

    checker.check(
        entry.get(
            "vulnerability_ids"
        )
        == plan_source.get(
            "vulnerability_ids"
        ),
        (
            f"{source_key}: "
            "vulnerability IDs match plan"
        ),
    )

    checker.check(
        entry.get(
            "target"
        )
        == plan_source.get(
            "target"
        ),
        (
            f"{source_key}: "
            "acquisition target matches plan"
        ),
    )

    checker.check(
        phase
        in STRUCTURED_PHASES,
        (
            f"{source_key}: "
            "entry belongs to structured phase"
        ),
    )

    checker.check(
        backend
        in SUPPORTED_BACKENDS,
        (
            f"{source_key}: "
            "entry backend supported"
        ),
    )

    expected_dataset = (
        EXPECTED_DATASET_BY_BACKEND.get(
            backend,
            "",
        )
    )

    actual_dataset = clean_text(
        entry.get(
            "acquisition_dataset"
        )
    )

    checker.check(
        actual_dataset
        == expected_dataset,
        (
            f"{source_key}: "
            "acquisition dataset matches backend"
        ),
        (
            f"expected={expected_dataset}, "
            f"actual={actual_dataset}"
        ),
    )

    checker.check(
        entry.get(
            "acquisition_status"
        )
        == "resolved",
        (
            f"{source_key}: "
            "source acquisition resolved"
        ),
    )

    canonical_identity = entry.get(
        "canonical_identity"
    )

    checker.check(
        isinstance(
            canonical_identity,
            dict,
        )
        and bool(
            canonical_identity
        ),
        (
            f"{source_key}: "
            "canonical identity present"
        ),
    )

    provenance = entry.get(
        "provenance"
    )

    checker.check(
        isinstance(
            provenance,
            dict,
        ),
        (
            f"{source_key}: "
            "provenance object present"
        ),
    )

    if isinstance(
        provenance,
        dict,
    ):
        validate_artifact_provenance(
            checker=checker,
            source_key=source_key,
            provenance=provenance,
        )

    raw_units = entry.get(
        "evidence_units"
    )

    checker.check(
        isinstance(
            raw_units,
            list,
        ),
        (
            f"{source_key}: "
            "evidence_units is list"
        ),
    )

    units = dict_rows(
        raw_units
    )

    checker.check(
        len(
            units
        )
        == (
            len(
                raw_units
            )
            if isinstance(
                raw_units,
                list,
            )
            else 0
        ),
        (
            f"{source_key}: "
            "all evidence units are objects"
        ),
    )

    return validate_units(
        checker=checker,
        source_key=source_key,
        backend=backend,
        units=units,
        global_unit_ids=global_unit_ids,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Validate the unified AVCS "
            "Trigger Candidate Evidence Corpus."
        )
    )

    parser.add_argument(
        "--plan",
        type=Path,
        default=DEFAULT_PLAN,
    )

    parser.add_argument(
        "--corpus",
        type=Path,
        default=DEFAULT_CORPUS,
    )

    args = parser.parse_args()

    checker = Checker()

    plan = load_json(
        args.plan
    )

    corpus = load_json(
        args.corpus
    )

    plan_sources = dict_rows(
        plan.get(
            "sources"
        )
    )

    structured_plan_sources = [
        source
        for source in plan_sources
        if clean_text(
            source.get(
                "acquisition_phase"
            )
        )
        in STRUCTURED_PHASES
    ]

    generic_web_sources = [
        source
        for source in plan_sources
        if clean_text(
            source.get(
                "acquisition_phase"
            )
        )
        == GENERIC_WEB_PHASE
    ]

    entries = dict_rows(
        corpus.get(
            "entries"
        )
    )

    checker.check(
        corpus.get(
            "schema_version"
        )
        == EXPECTED_SCHEMA_VERSION,
        "corpus schema version correct",
    )

    checker.check(
        corpus.get(
            "builder_version"
        )
        == EXPECTED_BUILDER_VERSION,
        "corpus builder version correct",
    )

    checker.check(
        corpus.get(
            "status"
        )
        == "resolved",
        "corpus status resolved",
    )

    checker.check(
        corpus.get(
            "source_mode"
        )
        == (
            "structured_trigger_evidence_"
            "candidate_corpus"
        ),
        "corpus source mode correct",
    )

    semantic_boundary = corpus.get(
        "semantic_boundary",
        {},
    )

    if not isinstance(
        semantic_boundary,
        dict,
    ):
        semantic_boundary = {}

    checker.check(
        semantic_boundary.get(
            "contains_acquired_source_text"
        )
        is True,
        "corpus contains acquired source text",
    )

    checker.check(
        semantic_boundary.get(
            "infers_trigger_semantics"
        )
        is False,
        "corpus does not infer trigger semantics",
    )

    checker.check(
        semantic_boundary.get(
            "creates_resolved_trigger_rules"
        )
        is False,
        "corpus does not create resolved trigger rules",
    )

    checker.check(
        semantic_boundary.get(
            "intended_next_stage"
        )
        == "candidate_fact_extraction",
        "corpus next stage is candidate fact extraction",
    )

    expected_source_keys = (
        source_key_set(
            structured_plan_sources
        )
    )

    actual_source_keys = (
        source_key_set(
            entries
        )
    )

    checker.check(
        len(
            expected_source_keys
        )
        == len(
            structured_plan_sources
        ),
        "structured plan source keys unique",
    )

    checker.check(
        len(
            actual_source_keys
        )
        == len(
            entries
        ),
        "corpus source keys unique",
    )

    checker.check(
        actual_source_keys
        == expected_source_keys,
        "corpus source coverage exactly matches structured plan",
        (
            f"expected={len(expected_source_keys)}, "
            f"actual={len(actual_source_keys)}"
        ),
    )

    plan_index = {
        clean_text(
            source.get(
                "source_key"
            )
        ):
            source
        for source
        in structured_plan_sources
        if clean_text(
            source.get(
                "source_key"
            )
        )
    }

    summary = corpus.get(
        "summary",
        {},
    )

    if not isinstance(
        summary,
        dict,
    ):
        summary = {}

    issues = corpus.get(
        "issues",
        {},
    )

    if not isinstance(
        issues,
        dict,
    ):
        issues = {}

    duplicate_sources = issues.get(
        "duplicate_acquisition_sources",
        {},
    )

    orphan_keys = issues.get(
        "orphan_acquisition_source_keys",
        [],
    )

    non_resolved_entries = issues.get(
        "non_resolved_entries",
        [],
    )

    checker.check(
        isinstance(
            duplicate_sources,
            dict,
        )
        and not duplicate_sources,
        "no duplicate acquisition sources",
    )

    checker.check(
        isinstance(
            orphan_keys,
            list,
        )
        and not orphan_keys,
        "no orphan acquisition source keys",
    )

    checker.check(
        isinstance(
            non_resolved_entries,
            list,
        )
        and not non_resolved_entries,
        "no non-resolved corpus entries",
    )

    print()
    print(
        "-" * 60
    )

    print(
        "Validate corpus entries"
    )

    print(
        "-" * 60
    )

    global_unit_ids: set[
        str
    ] = set()

    actual_phase_counter: Counter[
        str
    ] = Counter()

    actual_backend_counter: Counter[
        str
    ] = Counter()

    actual_unit_kind_counter: Counter[
        str
    ] = Counter()

    actual_status_counter: Counter[
        str
    ] = Counter()

    actual_unit_count = 0
    actual_text_chars = 0

    for entry in sorted(
        entries,
        key=lambda item: clean_text(
            item.get(
                "source_key"
            )
        ),
    ):
        source_key = clean_text(
            entry.get(
                "source_key"
            )
        )

        plan_source = plan_index.get(
            source_key
        )

        checker.check(
            plan_source
            is not None,
            (
                f"{source_key}: "
                "matching plan source exists"
            ),
        )

        if plan_source is None:
            continue

        (
            unit_count,
            text_chars,
            unit_kind_counter,
        ) = validate_entry(
            checker=checker,
            entry=entry,
            plan_source=plan_source,
            global_unit_ids=global_unit_ids,
        )

        actual_unit_count += (
            unit_count
        )

        actual_text_chars += (
            text_chars
        )

        actual_unit_kind_counter.update(
            unit_kind_counter
        )

        actual_phase_counter[
            clean_text(
                entry.get(
                    "acquisition_phase"
                )
            )
        ] += 1

        actual_backend_counter[
            clean_text(
                entry.get(
                    "acquisition_backend"
                )
            )
        ] += 1

        actual_status_counter[
            clean_text(
                entry.get(
                    "corpus_status"
                )
            )
        ] += 1

    expected_phase_counter = Counter(
        clean_text(
            source.get(
                "acquisition_phase"
            )
        )
        for source
        in structured_plan_sources
    )

    expected_backend_counter = Counter(
        clean_text(
            source.get(
                "acquisition_backend"
            )
        )
        for source
        in structured_plan_sources
    )

    print()
    print(
        "-" * 60
    )

    print(
        "Validate corpus summary"
    )

    print(
        "-" * 60
    )

    checker.check(
        summary.get(
            "plan_source_count"
        )
        == len(
            plan_sources
        ),
        "summary plan source count consistent",
    )

    checker.check(
        summary.get(
            "structured_plan_source_count"
        )
        == len(
            structured_plan_sources
        ),
        "summary structured source count consistent",
    )

    checker.check(
        summary.get(
            "generic_web_source_count_deferred"
        )
        == len(
            generic_web_sources
        ),
        "summary deferred generic web count consistent",
    )

    checker.check(
        summary.get(
            "corpus_entry_count"
        )
        == len(
            entries
        ),
        "summary corpus entry count consistent",
    )

    checker.check(
        summary.get(
            "resolved_entry_count"
        )
        == actual_status_counter.get(
            "resolved",
            0,
        ),
        "summary resolved entry count consistent",
    )

    checker.check(
        summary.get(
            "partial_entry_count"
        )
        == actual_status_counter.get(
            "partial",
            0,
        ),
        "summary partial entry count consistent",
    )

    checker.check(
        summary.get(
            "unresolved_entry_count"
        )
        == actual_status_counter.get(
            "unresolved",
            0,
        ),
        "summary unresolved entry count consistent",
    )

    checker.check(
        summary.get(
            "evidence_unit_count"
        )
        == actual_unit_count,
        "summary evidence unit count consistent",
    )

    checker.check(
        summary.get(
            "evidence_text_chars"
        )
        == actual_text_chars,
        "summary evidence text chars consistent",
    )

    checker.check(
        summary.get(
            "phase_counts"
        )
        == dict(
            sorted(
                actual_phase_counter.items()
            )
        ),
        "summary phase counts consistent",
    )

    checker.check(
        actual_phase_counter
        == expected_phase_counter,
        "corpus phase counts match acquisition plan",
    )

    checker.check(
        summary.get(
            "backend_counts"
        )
        == dict(
            sorted(
                actual_backend_counter.items()
            )
        ),
        "summary backend counts consistent",
    )

    checker.check(
        actual_backend_counter
        == expected_backend_counter,
        "corpus backend counts match acquisition plan",
    )

    checker.check(
        summary.get(
            "unit_kind_counts"
        )
        == dict(
            sorted(
                actual_unit_kind_counter.items()
            )
        ),
        "summary unit kind counts consistent",
    )

    checker.check(
        summary.get(
            "duplicate_acquisition_source_count"
        )
        == 0,
        "summary duplicate acquisition count zero",
    )

    checker.check(
        summary.get(
            "orphan_acquisition_source_count"
        )
        == 0,
        "summary orphan acquisition count zero",
    )

    checker.check(
        len(
            global_unit_ids
        )
        == actual_unit_count,
        "all evidence unit IDs globally unique",
    )

    print()
    print(
        "-" * 60
    )

    print(
        "Corpus boundary summary"
    )

    print(
        "-" * 60
    )

    print(
        "[INFO] plan sources:",
        len(
            plan_sources
        ),
    )

    print(
        "[INFO] structured corpus sources:",
        len(
            structured_plan_sources
        ),
    )

    print(
        "[INFO] deferred generic web sources:",
        len(
            generic_web_sources
        ),
    )

    print(
        "[INFO] evidence units:",
        actual_unit_count,
    )

    print(
        "[INFO] evidence text chars:",
        actual_text_chars,
    )

    sys.exit(
        checker.finish()
    )


if __name__ == "__main__":
    main()