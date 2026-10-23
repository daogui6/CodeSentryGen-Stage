from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

DEFAULT_PLAN = (
    ROOT
    / "output"
    / "avcs_trigger_source_acquisition_plan_v0.json"
)

DEFAULT_METADATA = (
    ROOT
    / "output"
    / "avcs_trigger_github_metadata_acquisition_v0.json"
)

PHASE_2 = (
    "phase_2_structured_metadata"
)

SUPPORTED_PHASE_2_BACKENDS = {
    "github_security_advisory_url",
    "github_pull_request_url",
    "github_issue_url",
    "github_release_url",
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


def normalize_repository(
    value: Any,
) -> str:
    return clean_text(
        value
    ).strip(
        "/"
    ).lower()


def normalize_ghsa_id(
    value: Any,
) -> str:
    return clean_text(
        value
    ).upper()


def result_rows(
    data: dict[str, Any],
) -> list[dict[str, Any]]:
    rows = data.get(
        "results",
        [],
    )

    if not isinstance(
        rows,
        list,
    ):
        return []

    return [
        row
        for row in rows
        if isinstance(
            row,
            dict,
        )
    ]


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
            "============================================================"
        )
        print(
            "AVCS TRIGGER PHASE-2 ACQUISITION CHECK SUMMARY"
        )
        print(
            "============================================================"
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


def validate_common_row(
    checker: Checker,
    row: dict[str, Any],
) -> None:
    source_key = clean_text(
        row.get(
            "source_key"
        )
    )

    backend = clean_text(
        row.get(
            "acquisition_backend"
        )
    )

    checker.check(
        source_key
        != "",
        (
            f"{source_key or '<missing>'}: "
            "source key present"
        ),
    )

    checker.check(
        row.get(
            "status"
        )
        == "resolved",
        (
            f"{source_key}: "
            "status resolved"
        ),
    )

    checker.check(
        clean_text(
            row.get(
                "acquisition_phase"
            )
        )
        == PHASE_2,
        (
            f"{source_key}: "
            "Phase-2 acquisition phase"
        ),
    )

    checker.check(
        backend
        in SUPPORTED_PHASE_2_BACKENDS,
        (
            f"{source_key}: "
            "backend supported"
        ),
        (
            "backend="
            + backend
        ),
    )

    checker.check(
        clean_text(
            row.get(
                "api_url"
            )
        ).startswith(
            "https://api.github.com/"
        ),
        (
            f"{source_key}: "
            "GitHub API URL present"
        ),
    )

    checker.check(
        clean_text(
            row.get(
                "cache_metadata_path"
            )
        )
        != "",
        (
            f"{source_key}: "
            "cache metadata path present"
        ),
    )

    checker.check(
        clean_text(
            row.get(
                "cache_response_path"
            )
        )
        != "",
        (
            f"{source_key}: "
            "cache response path present"
        ),
    )

    checker.check(
        clean_text(
            row.get(
                "response_sha256"
            )
        ).startswith(
            "sha256:"
        ),
        (
            f"{source_key}: "
            "response SHA256 provenance present"
        ),
    )

    response_size = row.get(
        "response_size_bytes"
    )

    checker.check(
        isinstance(
            response_size,
            int,
        )
        and response_size > 0,
        (
            f"{source_key}: "
            "response size positive"
        ),
    )

    checker.check(
        isinstance(
            row.get(
                "cache_hit"
            ),
            bool,
        ),
        (
            f"{source_key}: "
            "cache_hit is boolean"
        ),
    )

    checker.check(
        isinstance(
            row.get(
                "network_fetch"
            ),
            bool,
        ),
        (
            f"{source_key}: "
            "network_fetch is boolean"
        ),
    )

    checker.check(
        isinstance(
            row.get(
                "requested_target"
            ),
            dict,
        ),
        (
            f"{source_key}: "
            "requested target present"
        ),
    )

    checker.check(
        isinstance(
            row.get(
                "canonical_identity"
            ),
            dict,
        ),
        (
            f"{source_key}: "
            "canonical identity present"
        ),
    )

    checker.check(
        isinstance(
            row.get(
                "metadata"
            ),
            dict,
        ),
        (
            f"{source_key}: "
            "metadata summary present"
        ),
    )


def validate_advisory_row(
    checker: Checker,
    row: dict[str, Any],
) -> None:
    source_key = clean_text(
        row.get(
            "source_key"
        )
    )

    requested = row.get(
        "requested_target",
        {},
    )

    canonical = row.get(
        "canonical_identity",
        {},
    )

    metadata = row.get(
        "metadata",
        {},
    )

    if not isinstance(
        requested,
        dict,
    ):
        requested = {}

    if not isinstance(
        canonical,
        dict,
    ):
        canonical = {}

    if not isinstance(
        metadata,
        dict,
    ):
        metadata = {}

    requested_id = normalize_ghsa_id(
        requested.get(
            "advisory_id"
        )
    )

    canonical_id = normalize_ghsa_id(
        canonical.get(
            "advisory_id"
        )
    )

    metadata_id = normalize_ghsa_id(
        metadata.get(
            "ghsa_id"
        )
    )

    scope = clean_text(
        requested.get(
            "advisory_scope"
        )
    )

    checker.check(
        requested_id
        != "",
        (
            f"{source_key}: "
            "requested advisory ID present"
        ),
    )

    checker.check(
        scope
        in {
            "global",
            "repository",
        },
        (
            f"{source_key}: "
            "advisory scope valid"
        ),
    )

    if scope == "repository":
        checker.check(
            normalize_repository(
                requested.get(
                    "repository"
                )
            )
            != "",
            (
                f"{source_key}: "
                "repository advisory target present"
            ),
        )

    checker.check(
        canonical_id
        == requested_id,
        (
            f"{source_key}: "
            "canonical advisory ID matches target"
        ),
        (
            "requested="
            + requested_id
            + ", canonical="
            + canonical_id
        ),
    )

    checker.check(
        metadata.get(
            "kind"
        )
        == "security_advisory",
        (
            f"{source_key}: "
            "metadata kind security_advisory"
        ),
    )

    checker.check(
        metadata_id
        == requested_id,
        (
            f"{source_key}: "
            "metadata GHSA ID matches target"
        ),
        (
            "requested="
            + requested_id
            + ", metadata="
            + metadata_id
        ),
    )

    checker.check(
        clean_text(
            metadata.get(
                "summary"
            )
        )
        != "",
        (
            f"{source_key}: "
            "advisory summary present"
        ),
    )

    description_size = metadata.get(
        "description_size_chars"
    )

    checker.check(
        isinstance(
            description_size,
            int,
        )
        and description_size > 0,
        (
            f"{source_key}: "
            "advisory description present"
        ),
    )

    checker.check(
        clean_text(
            metadata.get(
                "description_sha256"
            )
        ).startswith(
            "sha256:"
        ),
        (
            f"{source_key}: "
            "advisory description SHA256 present"
        ),
    )


def validate_pull_request_row(
    checker: Checker,
    row: dict[str, Any],
) -> None:
    source_key = clean_text(
        row.get(
            "source_key"
        )
    )

    requested = row.get(
        "requested_target",
        {},
    )

    canonical = row.get(
        "canonical_identity",
        {},
    )

    metadata = row.get(
        "metadata",
        {},
    )

    if not isinstance(
        requested,
        dict,
    ):
        requested = {}

    if not isinstance(
        canonical,
        dict,
    ):
        canonical = {}

    if not isinstance(
        metadata,
        dict,
    ):
        metadata = {}

    requested_repository = normalize_repository(
        requested.get(
            "repository"
        )
    )

    canonical_repository = normalize_repository(
        canonical.get(
            "repository"
        )
    )

    requested_number = requested.get(
        "pull_number"
    )

    canonical_number = canonical.get(
        "pull_number"
    )

    metadata_number = metadata.get(
        "number"
    )

    checker.check(
        requested_repository
        != "",
        (
            f"{source_key}: "
            "requested PR repository present"
        ),
    )

    checker.check(
        isinstance(
            requested_number,
            int,
        )
        and requested_number > 0,
        (
            f"{source_key}: "
            "requested PR number valid"
        ),
    )

    checker.check(
        canonical_repository
        == requested_repository,
        (
            f"{source_key}: "
            "canonical PR repository matches target"
        ),
        (
            "requested="
            + requested_repository
            + ", canonical="
            + canonical_repository
        ),
    )

    checker.check(
        canonical_number
        == requested_number,
        (
            f"{source_key}: "
            "canonical PR number matches target"
        ),
    )

    checker.check(
        metadata.get(
            "kind"
        )
        == "pull_request",
        (
            f"{source_key}: "
            "metadata kind pull_request"
        ),
    )

    checker.check(
        metadata_number
        == requested_number,
        (
            f"{source_key}: "
            "metadata PR number matches target"
        ),
    )

    checker.check(
        clean_text(
            metadata.get(
                "title"
            )
        )
        != "",
        (
            f"{source_key}: "
            "PR title present"
        ),
    )

    checker.check(
        clean_text(
            metadata.get(
                "html_url"
            )
        )
        != "",
        (
            f"{source_key}: "
            "PR HTML URL present"
        ),
    )


def validate_issue_row(
    checker: Checker,
    row: dict[str, Any],
) -> None:
    source_key = clean_text(
        row.get(
            "source_key"
        )
    )

    requested = row.get(
        "requested_target",
        {},
    )

    canonical = row.get(
        "canonical_identity",
        {},
    )

    metadata = row.get(
        "metadata",
        {},
    )

    if not isinstance(
        requested,
        dict,
    ):
        requested = {}

    if not isinstance(
        canonical,
        dict,
    ):
        canonical = {}

    if not isinstance(
        metadata,
        dict,
    ):
        metadata = {}

    requested_repository = normalize_repository(
        requested.get(
            "repository"
        )
    )

    canonical_repository = normalize_repository(
        canonical.get(
            "repository"
        )
    )

    requested_number = requested.get(
        "issue_number"
    )

    canonical_number = canonical.get(
        "issue_number"
    )

    metadata_number = metadata.get(
        "number"
    )

    checker.check(
        requested_repository
        != "",
        (
            f"{source_key}: "
            "requested issue repository present"
        ),
    )

    checker.check(
        isinstance(
            requested_number,
            int,
        )
        and requested_number > 0,
        (
            f"{source_key}: "
            "requested issue number valid"
        ),
    )

    checker.check(
        canonical_repository
        == requested_repository,
        (
            f"{source_key}: "
            "canonical issue repository matches target"
        ),
    )

    checker.check(
        canonical_number
        == requested_number,
        (
            f"{source_key}: "
            "canonical issue number matches target"
        ),
    )

    checker.check(
        metadata.get(
            "kind"
        )
        == "issue",
        (
            f"{source_key}: "
            "metadata kind issue"
        ),
    )

    checker.check(
        metadata_number
        == requested_number,
        (
            f"{source_key}: "
            "metadata issue number matches target"
        ),
    )

    checker.check(
        clean_text(
            metadata.get(
                "title"
            )
        )
        != "",
        (
            f"{source_key}: "
            "issue title present"
        ),
    )

    checker.check(
        clean_text(
            metadata.get(
                "html_url"
            )
        )
        != "",
        (
            f"{source_key}: "
            "issue HTML URL present"
        ),
    )


def validate_release_row(
    checker: Checker,
    row: dict[str, Any],
) -> None:
    source_key = clean_text(
        row.get(
            "source_key"
        )
    )

    requested = row.get(
        "requested_target",
        {},
    )

    canonical = row.get(
        "canonical_identity",
        {},
    )

    metadata = row.get(
        "metadata",
        {},
    )

    if not isinstance(
        requested,
        dict,
    ):
        requested = {}

    if not isinstance(
        canonical,
        dict,
    ):
        canonical = {}

    if not isinstance(
        metadata,
        dict,
    ):
        metadata = {}

    requested_repository = normalize_repository(
        requested.get(
            "repository"
        )
    )

    canonical_repository = normalize_repository(
        canonical.get(
            "repository"
        )
    )

    requested_tag = clean_text(
        requested.get(
            "tag"
        )
    )

    canonical_tag = clean_text(
        canonical.get(
            "tag"
        )
    )

    metadata_tag = clean_text(
        metadata.get(
            "tag_name"
        )
    )

    checker.check(
        requested_repository
        != "",
        (
            f"{source_key}: "
            "requested release repository present"
        ),
    )

    checker.check(
        requested_tag
        != "",
        (
            f"{source_key}: "
            "requested release tag present"
        ),
    )

    checker.check(
        canonical_repository
        == requested_repository,
        (
            f"{source_key}: "
            "canonical release repository matches target"
        ),
    )

    checker.check(
        canonical_tag
        == requested_tag,
        (
            f"{source_key}: "
            "canonical release tag matches target"
        ),
    )

    checker.check(
        metadata.get(
            "kind"
        )
        == "release",
        (
            f"{source_key}: "
            "metadata kind release"
        ),
    )

    checker.check(
        metadata_tag
        == requested_tag,
        (
            f"{source_key}: "
            "metadata release tag matches target"
        ),
    )

    checker.check(
        isinstance(
            metadata.get(
                "release_id"
            ),
            int,
        ),
        (
            f"{source_key}: "
            "release ID present"
        ),
    )

    checker.check(
        clean_text(
            metadata.get(
                "html_url"
            )
        )
        != "",
        (
            f"{source_key}: "
            "release HTML URL present"
        ),
    )

    body_size = metadata.get(
        "body_size_chars"
    )

    checker.check(
        isinstance(
            body_size,
            int,
        )
        and body_size > 0,
        (
            f"{source_key}: "
            "release body present"
        ),
    )

    checker.check(
        clean_text(
            metadata.get(
                "body_sha256"
            )
        ).startswith(
            "sha256:"
        ),
        (
            f"{source_key}: "
            "release body SHA256 present"
        ),
    )


def validate_row(
    checker: Checker,
    row: dict[str, Any],
) -> None:
    validate_common_row(
        checker,
        row,
    )

    backend = clean_text(
        row.get(
            "acquisition_backend"
        )
    )

    if (
        backend
        == "github_security_advisory_url"
    ):
        validate_advisory_row(
            checker,
            row,
        )

    elif (
        backend
        == "github_pull_request_url"
    ):
        validate_pull_request_row(
            checker,
            row,
        )

    elif (
        backend
        == "github_issue_url"
    ):
        validate_issue_row(
            checker,
            row,
        )

    elif (
        backend
        == "github_release_url"
    ):
        validate_release_row(
            checker,
            row,
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Validate AVCS Trigger Evidence "
            "Phase-2 GitHub structured metadata "
            "acquisition."
        )
    )

    parser.add_argument(
        "--plan",
        type=Path,
        default=DEFAULT_PLAN,
    )

    parser.add_argument(
        "--metadata",
        type=Path,
        default=DEFAULT_METADATA,
    )

    args = parser.parse_args()

    checker = Checker()

    plan = load_json(
        args.plan
    )

    metadata_data = load_json(
        args.metadata
    )

    plan_sources = plan.get(
        "sources",
        [],
    )

    if not isinstance(
        plan_sources,
        list,
    ):
        raise ValueError(
            "Plan field 'sources' "
            "must be a list."
        )

    phase_2_sources = [
        row
        for row in plan_sources
        if (
            isinstance(
                row,
                dict,
            )
            and clean_text(
                row.get(
                    "acquisition_phase"
                )
            )
            == PHASE_2
        )
    ]

    expected_phase_2_keys = (
        source_key_set(
            phase_2_sources
        )
    )

    phase_2_backends = {
        clean_text(
            row.get(
                "acquisition_backend"
            )
        )
        for row in phase_2_sources
    }

    checker.check(
        plan.get(
            "status"
        )
        == "resolved",
        "acquisition plan resolved",
    )

    unsupported_backends = sorted(
        phase_2_backends
        - SUPPORTED_PHASE_2_BACKENDS
    )

    checker.check(
        phase_2_backends
        <= SUPPORTED_PHASE_2_BACKENDS,
        "all Phase-2 backends supported",
        (
            "unsupported="
            + str(
                unsupported_backends
            )
        ),
    )

    checker.check(
        len(
            expected_phase_2_keys
        )
        == len(
            phase_2_sources
        ),
        "Phase-2 source keys unique",
    )

    rows = result_rows(
        metadata_data
    )

    actual_phase_2_keys = (
        source_key_set(
            rows
        )
    )

    checker.check(
        metadata_data.get(
            "status"
        )
        == "resolved",
        "GitHub metadata acquisition resolved",
    )

    checker.check(
        clean_text(
            metadata_data.get(
                "acquisition_phase"
            )
        )
        == PHASE_2,
        "metadata acquisition phase correct",
    )

    checker.check(
        actual_phase_2_keys
        == expected_phase_2_keys,
        "Phase-2 source coverage exact",
        (
            "expected="
            + str(
                len(
                    expected_phase_2_keys
                )
            )
            + ", actual="
            + str(
                len(
                    actual_phase_2_keys
                )
            )
        ),
    )

    checker.check(
        metadata_data.get(
            "selected_source_count"
        )
        == len(
            phase_2_sources
        ),
        "selected source count consistent",
    )

    checker.check(
        metadata_data.get(
            "resolved_source_count"
        )
        == len(
            rows
        ),
        "resolved source count consistent",
    )

    checker.check(
        metadata_data.get(
            "unresolved_source_count"
        )
        == 0,
        "no unresolved Phase-2 sources",
    )

    result_backend_set = {
        clean_text(
            row.get(
                "acquisition_backend"
            )
        )
        for row in rows
    }

    checker.check(
        result_backend_set
        == phase_2_backends,
        "Phase-2 backend coverage exact",
    )

    print()
    print(
        "------------------------------------------------------------"
    )
    print(
        "Validate GitHub structured metadata"
    )
    print(
        "------------------------------------------------------------"
    )

    for row in sorted(
        rows,
        key=lambda item: clean_text(
            item.get(
                "source_key"
            )
        ),
    ):
        validate_row(
            checker,
            row,
        )

    all_source_count = int(
        plan.get(
            "source_count",
            0,
        )
        or 0
    )

    phase_1_count = sum(
        1
        for row in plan_sources
        if (
            isinstance(
                row,
                dict,
            )
            and clean_text(
                row.get(
                    "acquisition_phase"
                )
            )
            == "phase_1_structured_evidence"
        )
    )

    phase_2_count = len(
        phase_2_sources
    )

    structured_count = (
        phase_1_count
        + phase_2_count
    )

    structured_ratio = (
        structured_count
        / all_source_count
        if all_source_count > 0
        else 0.0
    )

    print()
    print(
        "------------------------------------------------------------"
    )
    print(
        "Structured acquisition coverage"
    )
    print(
        "------------------------------------------------------------"
    )

    print(
        "[INFO] Phase-1 sources:",
        phase_1_count,
    )

    print(
        "[INFO] Phase-2 sources:",
        phase_2_count,
    )

    print(
        "[INFO] structured total:",
        structured_count,
    )

    print(
        "[INFO] all trigger sources:",
        all_source_count,
    )

    print(
        "[INFO] structured coverage ratio:",
        structured_ratio,
    )

    sys.exit(
        checker.finish()
    )


if __name__ == "__main__":
    main()