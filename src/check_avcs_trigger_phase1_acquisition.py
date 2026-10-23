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

DEFAULT_LOCAL = (
    ROOT
    / "output"
    / "avcs_trigger_local_structured_acquisition_v0.json"
)

DEFAULT_GITHUB_FILES = (
    ROOT
    / "output"
    / "avcs_trigger_github_file_acquisition_v0.json"
)

DEFAULT_GITHUB_COMMITS = (
    ROOT
    / "output"
    / "avcs_trigger_github_commit_acquisition_v0.json"
)


PHASE_1 = (
    "phase_1_structured_evidence"
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

SUPPORTED_PHASE_1_BACKENDS = (
    LOCAL_BACKENDS
    | GITHUB_FILE_BACKENDS
    | GITHUB_COMMIT_BACKENDS
)


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
            "AVCS TRIGGER PHASE-1 ACQUISITION CHECK SUMMARY"
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


def validate_local_row(
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
        row.get(
            "status"
        )
        == "resolved",
        (
            f"{source_key}: "
            "local status resolved"
        ),
    )

    checker.check(
        clean_text(
            row.get(
                "local_path"
            )
        )
        != "",
        (
            f"{source_key}: "
            "local path present"
        ),
    )

    checker.check(
        clean_text(
            row.get(
                "sha256"
            )
        ).startswith(
            "sha256:"
        ),
        (
            f"{source_key}: "
            "SHA256 provenance present"
        ),
    )

    if backend == "osv_api_record":
        checker.check(
            clean_text(
                row.get(
                    "requested_vulnerability_id"
                )
            )
            != "",
            (
                f"{source_key}: "
                "requested vulnerability id present"
            ),
        )

        checker.check(
            clean_text(
                row.get(
                    "matched_record_id"
                )
            )
            != "",
            (
                f"{source_key}: "
                "matched OSV record id present"
            ),
        )

        checker.check(
            row.get(
                "matched_via"
            )
            in {
                "primary_id",
                "alias",
            },
            (
                f"{source_key}: "
                "OSV identity match mode valid"
            ),
        )


def validate_github_file_row(
    checker: Checker,
    row: dict[str, Any],
) -> None:
    source_key = clean_text(
        row.get(
            "source_key"
        )
    )

    checker.check(
        row.get(
            "status"
        )
        == "resolved",
        (
            f"{source_key}: "
            "GitHub file status resolved"
        ),
    )

    for field in (
        "repository",
        "ref",
        "path",
        "github_blob_sha",
        "cache_metadata_path",
        "cache_content_path",
    ):
        checker.check(
            clean_text(
                row.get(
                    field
                )
            )
            != "",
            (
                f"{source_key}: "
                f"{field} present"
            ),
        )

    checker.check(
        clean_text(
            row.get(
                "content_sha256"
            )
        ).startswith(
            "sha256:"
        ),
        (
            f"{source_key}: "
            "content SHA256 present"
        ),
    )

    checker.check(
        isinstance(
            row.get(
                "content_size_bytes"
            ),
            int,
        )
        and int(
            row.get(
                "content_size_bytes",
                0,
            )
        )
        > 0,
        (
            f"{source_key}: "
            "content size positive"
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


def validate_github_commit_row(
    checker: Checker,
    row: dict[str, Any],
) -> None:
    source_key = clean_text(
        row.get(
            "source_key"
        )
    )

    requested_commit = clean_text(
        row.get(
            "requested_commit"
        )
    )

    canonical_commit = clean_text(
        row.get(
            "canonical_commit_sha"
        )
    )

    checker.check(
        row.get(
            "status"
        )
        == "resolved",
        (
            f"{source_key}: "
            "GitHub commit status resolved"
        ),
    )

    checker.check(
        clean_text(
            row.get(
                "repository"
            )
        )
        != "",
        (
            f"{source_key}: "
            "repository present"
        ),
    )

    checker.check(
        requested_commit
        != "",
        (
            f"{source_key}: "
            "requested commit present"
        ),
    )

    checker.check(
        canonical_commit
        != "",
        (
            f"{source_key}: "
            "canonical commit present"
        ),
    )

    checker.check(
        requested_commit.lower()
        == canonical_commit.lower(),
        (
            f"{source_key}: "
            "requested commit equals canonical commit"
        ),
        (
            f"requested={requested_commit}, "
            f"canonical={canonical_commit}"
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
            "commit response SHA256 present"
        ),
    )

    changed_file_count = int(
        row.get(
            "changed_file_count",
            0,
        )
        or 0
    )

    patch_present_count = int(
        row.get(
            "patch_present_count",
            0,
        )
        or 0
    )

    patch_missing_count = int(
        row.get(
            "patch_missing_count",
            0,
        )
        or 0
    )

    files = row.get(
        "files",
        [],
    )

    if not isinstance(
        files,
        list,
    ):
        files = []

    checker.check(
        changed_file_count
        > 0,
        (
            f"{source_key}: "
            "changed files present"
        ),
    )

    checker.check(
        changed_file_count
        == len(
            files
        ),
        (
            f"{source_key}: "
            "changed file count consistent"
        ),
    )

    checker.check(
        (
            patch_present_count
            + patch_missing_count
        )
        == changed_file_count,
        (
            f"{source_key}: "
            "patch accounting consistent"
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


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Validate AVCS Trigger Evidence "
            "Phase-1 structured acquisition."
        )
    )

    parser.add_argument(
        "--plan",
        type=Path,
        default=DEFAULT_PLAN,
    )

    parser.add_argument(
        "--local",
        type=Path,
        default=DEFAULT_LOCAL,
    )

    parser.add_argument(
        "--github-files",
        type=Path,
        default=DEFAULT_GITHUB_FILES,
    )

    parser.add_argument(
        "--github-commits",
        type=Path,
        default=DEFAULT_GITHUB_COMMITS,
    )

    args = parser.parse_args()

    checker = Checker()

    plan = load_json(
        args.plan
    )

    local_data = load_json(
        args.local
    )

    github_file_data = load_json(
        args.github_files
    )

    github_commit_data = load_json(
        args.github_commits
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

    phase_1_sources = [
        row
        for row in plan_sources
        if (
            isinstance(
                row,
                dict,
            )
            and row.get(
                "acquisition_phase"
            )
            == PHASE_1
        )
    ]

    expected_phase_1_keys = (
        source_key_set(
            phase_1_sources
        )
    )

    expected_local_keys = (
        source_key_set(
            [
                row
                for row
                in phase_1_sources
                if clean_text(
                    row.get(
                        "acquisition_backend"
                    )
                )
                in LOCAL_BACKENDS
            ]
        )
    )

    expected_file_keys = (
        source_key_set(
            [
                row
                for row
                in phase_1_sources
                if clean_text(
                    row.get(
                        "acquisition_backend"
                    )
                )
                in GITHUB_FILE_BACKENDS
            ]
        )
    )

    expected_commit_keys = (
        source_key_set(
            [
                row
                for row
                in phase_1_sources
                if clean_text(
                    row.get(
                        "acquisition_backend"
                    )
                )
                in GITHUB_COMMIT_BACKENDS
            ]
        )
    )

    phase_1_backends = {
        clean_text(
            row.get(
                "acquisition_backend"
            )
        )
        for row
        in phase_1_sources
    }

    checker.check(
        plan.get(
            "status"
        )
        == "resolved",
        "acquisition plan resolved",
    )

    unsupported_phase_1_backends = sorted(
        phase_1_backends
        - SUPPORTED_PHASE_1_BACKENDS
    )

    checker.check(
        phase_1_backends
        <= SUPPORTED_PHASE_1_BACKENDS,
        "all Phase-1 backends supported",
        (
                "unsupported="
                + str(
            unsupported_phase_1_backends
        )
        ),
    )

    checker.check(
        len(
            expected_phase_1_keys
        )
        == len(
            phase_1_sources
        ),
        "Phase-1 source keys unique",
    )

    local_rows = result_rows(
        local_data
    )

    file_rows = result_rows(
        github_file_data
    )

    commit_rows = result_rows(
        github_commit_data
    )

    actual_local_keys = (
        source_key_set(
            local_rows
        )
    )

    actual_file_keys = (
        source_key_set(
            file_rows
        )
    )

    actual_commit_keys = (
        source_key_set(
            commit_rows
        )
    )

    checker.check(
        local_data.get(
            "status"
        )
        == "resolved",
        "local/OSV acquisition resolved",
    )

    checker.check(
        github_file_data.get(
            "status"
        )
        == "resolved",
        "GitHub file acquisition resolved",
    )

    checker.check(
        github_commit_data.get(
            "status"
        )
        == "resolved",
        "GitHub commit acquisition resolved",
    )

    checker.check(
        actual_local_keys
        == expected_local_keys,
        "local/OSV source coverage exact",
        (
            f"expected={len(expected_local_keys)}, "
            f"actual={len(actual_local_keys)}"
        ),
    )

    checker.check(
        actual_file_keys
        == expected_file_keys,
        "GitHub file source coverage exact",
        (
            f"expected={len(expected_file_keys)}, "
            f"actual={len(actual_file_keys)}"
        ),
    )

    checker.check(
        actual_commit_keys
        == expected_commit_keys,
        "GitHub commit source coverage exact",
        (
            f"expected={len(expected_commit_keys)}, "
            f"actual={len(actual_commit_keys)}"
        ),
    )

    actual_all_keys = (
        actual_local_keys
        | actual_file_keys
        | actual_commit_keys
    )

    checker.check(
        actual_all_keys
        == expected_phase_1_keys,
        "Phase-1 total source coverage exact",
        (
            f"expected={len(expected_phase_1_keys)}, "
            f"actual={len(actual_all_keys)}"
        ),
    )

    checker.check(
        not (
            actual_local_keys
            & actual_file_keys
        ),
        "local and GitHub-file sources do not overlap",
    )

    checker.check(
        not (
            actual_local_keys
            & actual_commit_keys
        ),
        "local and GitHub-commit sources do not overlap",
    )

    checker.check(
        not (
            actual_file_keys
            & actual_commit_keys
        ),
        "GitHub-file and commit sources do not overlap",
    )

    print()
    print(
        "------------------------------------------------------------"
    )
    print(
        "Validate local / OSV evidence"
    )
    print(
        "------------------------------------------------------------"
    )

    for row in local_rows:
        validate_local_row(
            checker,
            row,
        )

    print()
    print(
        "------------------------------------------------------------"
    )
    print(
        "Validate GitHub historical-file evidence"
    )
    print(
        "------------------------------------------------------------"
    )

    for row in file_rows:
        validate_github_file_row(
            checker,
            row,
        )

    print()
    print(
        "------------------------------------------------------------"
    )
    print(
        "Validate GitHub fix-commit evidence"
    )
    print(
        "------------------------------------------------------------"
    )

    for row in commit_rows:
        validate_github_commit_row(
            checker,
            row,
        )

    print()
    print(
        "------------------------------------------------------------"
    )
    print(
        "Phase-1 coverage"
    )
    print(
        "------------------------------------------------------------"
    )

    print(
        "[INFO] local / OSV:",
        len(
            actual_local_keys
        ),
    )

    print(
        "[INFO] GitHub files:",
        len(
            actual_file_keys
        ),
    )

    print(
        "[INFO] GitHub commits:",
        len(
            actual_commit_keys
        ),
    )

    print(
        "[INFO] Phase-1 total:",
        len(
            actual_all_keys
        ),
    )

    print(
        "[INFO] all trigger sources:",
        plan.get(
            "source_count"
        ),
    )

    total_sources = int(
        plan.get(
            "source_count",
            0,
        )
        or 0
    )

    phase_1_count = len(
        actual_all_keys
    )

    coverage_ratio = (
        phase_1_count
        / total_sources
        if total_sources
        else 0.0
    )

    print(
        "[INFO] Phase-1 coverage ratio:",
        round(
            coverage_ratio,
            6,
        ),
    )

    sys.exit(
        checker.finish()
    )


if __name__ == "__main__":
    main()