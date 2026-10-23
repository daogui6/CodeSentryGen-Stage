from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

from compile_trigger_source_acquisition_plan import classify_url_source


ROOT = Path(__file__).resolve().parents[1]

DISCOVERY_SCHEMA_VERSION = (
    "avcs_trigger_osv_reference_discovery_v0.1"
)

EXPANDED_SCHEMA_VERSION = (
    "avcs_trigger_heldout_expanded_source_inventory_v0.1"
)

DISCOVERY_VERSION = (
    "osv_reference_discovery_v0.1"
)

STRUCTURED_PHASES = {
    "phase_1_structured_evidence",
    "phase_2_structured_metadata",
}

SOURCE_TYPE_BY_BACKEND = {
    "osv_api_record":
        "osv_advisory_reference",

    "github_security_advisory_url":
        "github_security_advisory_reference",

    "github_blob_url":
        "github_source_file_reference",

    "github_commit_url":
        "github_commit_reference",

    "github_pull_request_url":
        "github_pull_request_reference",

    "github_issue_url":
        "github_issue_reference",

    "github_release_url":
        "github_release_reference",

    "github_web_url":
        "github_web_reference",

    "generic_http_url":
        "generic_web_reference",
}


def clean(
    value: Any,
) -> str:
    return str(
        value
        if value is not None
        else ""
    ).strip()


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


def write_json(
    path: Path,
    data: dict[str, Any],
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        json.dumps(
            data,
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def canonical_url(
    value: Any,
) -> str:
    text = clean(
        value
    )

    if not text:
        return ""

    try:
        parsed = urlparse(
            text
        )
    except ValueError:
        return ""

    scheme = (
        parsed.scheme.lower()
    )

    netloc = (
        parsed.netloc.lower()
    )

    if (
        scheme
        not in {
            "http",
            "https",
        }
        or not netloc
    ):
        return ""

    path = (
        parsed.path
        or "/"
    )

    if path != "/":
        path = path.rstrip(
            "/"
        )

    return urlunparse(
        (
            scheme,
            netloc,
            path,
            "",
            parsed.query,
            "",
        )
    )


def stable_source_id(
    backend: str,
    url: str,
) -> str:
    digest = (
        hashlib.sha256(
            url.encode(
                "utf-8"
            )
        )
        .hexdigest()[:12]
    )

    kind = (
        backend
        .replace(
            "_url",
            "",
        )
        .replace(
            "_record",
            "",
        )
    )

    return (
        f"osvref_{kind}_{digest}"
    )


def load_project_json(
    path_text: Any,
) -> dict[str, Any]:
    path = Path(
        clean(
            path_text
        )
    )

    if not path.is_absolute():
        path = (
            ROOT
            / path
        )

    path = path.resolve()

    try:
        path.relative_to(
            ROOT.resolve()
        )

    except ValueError as exc:
        raise ValueError(
            (
                "Artifact outside "
                f"project root: {path}"
            )
        ) from exc

    return load_json(
        path
    )


def record_identifiers(
    record: dict[str, Any],
) -> set[str]:
    values = {
        clean(
            record.get(
                "id"
            )
        ).upper()
    }

    aliases = record.get(
        "aliases",
        [],
    )

    if isinstance(
        aliases,
        list,
    ):
        values.update(
            clean(
                value
            ).upper()
            for value in aliases
        )

    return {
        value
        for value in values
        if value
    }


def acquisition_index(
    acquisition: dict[str, Any],
) -> dict[
    str,
    dict[str, Any],
]:
    rows = acquisition.get(
        "results",
        [],
    )

    if not isinstance(
        rows,
        list,
    ):
        raise ValueError(
            (
                "Acquisition field "
                "'results' must be a list."
            )
        )

    result: dict[
        str,
        dict[str, Any],
    ] = {}

    for row in rows:
        if not isinstance(
            row,
            dict,
        ):
            continue

        source_key = clean(
            row.get(
                "source_key"
            )
        )

        if source_key:
            result[
                source_key
            ] = row

    return result


def seed_osv_sources(
    case: dict[str, Any],
) -> list[
    dict[str, Any]
]:
    sources = case.get(
        "sources",
        [],
    )

    if not isinstance(
        sources,
        list,
    ):
        return []

    result: list[
        dict[str, Any]
    ] = []

    for source in sources:
        if not isinstance(
            source,
            dict,
        ):
            continue

        if clean(
            source.get(
                "locator_kind"
            )
        ) != "url":
            continue

        (
            backend,
            _,
            _,
        ) = classify_url_source(
            clean(
                source.get(
                    "url"
                )
            )
        )

        if (
            backend
            == "osv_api_record"
        ):
            result.append(
                source
            )

    return result


def discovered_source(
    reference: dict[str, Any],
    record_id: str,
) -> (
    dict[str, Any]
    | None
):
    url = canonical_url(
        reference.get(
            "url"
        )
    )

    if not url:
        return None

    (
        backend,
        phase,
        _,
    ) = classify_url_source(
        url
    )

    reference_type = (
        clean(
            reference.get(
                "type"
            )
        ).upper()
    )

    return {
        "source_id":
            stable_source_id(
                backend,
                url,
            ),

        "source_type":
            SOURCE_TYPE_BY_BACKEND.get(
                backend,
                "discovered_reference",
            ),

        "locator_kind":
            "url",

        "url":
            url,

        "domain":
            (
                urlparse(
                    url
                ).hostname
                or ""
            ).lower(),

        "locator":
            (
                "Discovered from OSV "
                f"record {record_id}"
                + (
                    "; reference type="
                    f"{reference_type}"
                    if reference_type
                    else ""
                )
            ),

        "has_claim":
            False,

        "discovery_method":
            "osv_references_field",

        "discovered_from_record_id":
            record_id,

        "osv_reference_type":
            reference_type,

        "predicted_acquisition_backend":
            backend,

        "predicted_acquisition_phase":
            phase,
    }


def discover(
    seed_inventory: dict[str, Any],
    local_acquisition: dict[str, Any],
) -> tuple[
    dict[str, Any],
    dict[str, Any],
]:
    raw_cases = seed_inventory.get(
        "cases",
        [],
    )

    if not isinstance(
        raw_cases,
        list,
    ):
        raise ValueError(
            (
                "Seed inventory field "
                "'cases' must be a list."
            )
        )

    acq_by_key = (
        acquisition_index(
            local_acquisition
        )
    )

    expanded_cases: list[
        dict[str, Any]
    ] = []

    report_cases: list[
        dict[str, Any]
    ] = []

    all_issues: list[str] = []

    total_phase_counts: Counter[
        str
    ] = Counter()

    total_backend_counts: Counter[
        str
    ] = Counter()

    for case in raw_cases:
        if not isinstance(
            case,
            dict,
        ):
            all_issues.append(
                "seed_case_not_object"
            )
            continue

        distribution = clean(
            case.get(
                "distribution"
            )
        )

        vulnerability_ids = (
            case.get(
                "vulnerability_ids",
                [],
            )
        )

        if not isinstance(
            vulnerability_ids,
            list,
        ):
            vulnerability_ids = []

        case_ids = {
            clean(
                value
            ).upper()
            for value
            in vulnerability_ids
            if clean(
                value
            )
        }

        original_sources = (
            case.get(
                "sources",
                [],
            )
        )

        if not isinstance(
            original_sources,
            list,
        ):
            original_sources = []

        expanded_sources = [
            dict(
                source
            )
            for source
            in original_sources
            if isinstance(
                source,
                dict,
            )
        ]

        seen_urls = {
            canonical_url(
                source.get(
                    "url"
                )
            )
            for source
            in expanded_sources
            if canonical_url(
                source.get(
                    "url"
                )
            )
        }

        references: list[
            dict[str, Any]
        ] = []

        issues: list[str] = []

        raw_reference_count = 0
        duplicate_count = 0
        invalid_count = 0
        resolved_seed_count = 0

        osv_sources = (
            seed_osv_sources(
                case
            )
        )

        if not osv_sources:
            issues.append(
                "no_osv_seed_source"
            )

        for seed_source in (
            osv_sources
        ):
            source_id = clean(
                seed_source.get(
                    "source_id"
                )
            )

            source_key = (
                f"{distribution}::"
                f"{source_id}"
            )

            acquisition_row = (
                acq_by_key.get(
                    source_key
                )
            )

            if acquisition_row is None:
                issues.append(
                    (
                        "missing_seed_acquisition:"
                        f"{source_key}"
                    )
                )
                continue

            if clean(
                acquisition_row.get(
                    "status"
                )
            ) != "resolved":
                issues.append(
                    (
                        "unresolved_seed_acquisition:"
                        f"{source_key}"
                    )
                )
                continue

            try:
                record = (
                    load_project_json(
                        acquisition_row.get(
                            "local_path"
                        )
                    )
                )

            except (
                OSError,
                ValueError,
                json.JSONDecodeError,
            ) as exc:
                issues.append(
                    (
                        "seed_record_load_error:"
                        f"{source_key}:"
                        f"{type(exc).__name__}"
                    )
                )
                continue

            record_id = clean(
                record.get(
                    "id"
                )
            )

            if (
                case_ids
                and not (
                    case_ids
                    & record_identifiers(
                        record
                    )
                )
            ):
                issues.append(
                    (
                        "seed_record_identity_mismatch:"
                        f"{source_key}"
                    )
                )
                continue

            resolved_seed_count += 1

            raw_references = (
                record.get(
                    "references",
                    [],
                )
            )

            if not isinstance(
                raw_references,
                list,
            ):
                issues.append(
                    (
                        "references_not_list:"
                        f"{record_id}"
                    )
                )
                continue

            for reference in (
                raw_references
            ):
                if not isinstance(
                    reference,
                    dict,
                ):
                    invalid_count += 1
                    continue

                raw_reference_count += 1

                source = (
                    discovered_source(
                        reference,
                        record_id,
                    )
                )

                if source is None:
                    invalid_count += 1
                    continue

                url = clean(
                    source.get(
                        "url"
                    )
                )

                if url in seen_urls:
                    duplicate_count += 1
                    continue

                seen_urls.add(
                    url
                )

                expanded_sources.append(
                    source
                )

                references.append(
                    source
                )

        phase_counts = Counter(
            clean(
                reference.get(
                    "predicted_acquisition_phase"
                )
            )
            for reference
            in references
        )

        backend_counts = Counter(
            clean(
                reference.get(
                    "predicted_acquisition_backend"
                )
            )
            for reference
            in references
        )

        total_phase_counts.update(
            phase_counts
        )

        total_backend_counts.update(
            backend_counts
        )

        structured_count = sum(
            1
            for reference
            in references
            if clean(
                reference.get(
                    "predicted_acquisition_phase"
                )
            )
            in STRUCTURED_PHASES
        )

        generic_count = sum(
            1
            for reference
            in references
            if clean(
                reference.get(
                    "predicted_acquisition_phase"
                )
            )
            == "phase_3_generic_web"
        )

        expanded_case = dict(
            case
        )

        expanded_case[
            "sources"
        ] = expanded_sources

        expanded_case[
            "source_discovery"
        ] = {
            "seed_osv_source_count":
                len(
                    osv_sources
                ),

            "resolved_seed_record_count":
                resolved_seed_count,

            "raw_reference_count":
                raw_reference_count,

            "discovered_source_count":
                len(
                    references
                ),

            "structured_discovered_source_count":
                structured_count,

            "generic_discovered_source_count":
                generic_count,

            "duplicate_reference_count":
                duplicate_count,

            "invalid_reference_count":
                invalid_count,
        }

        expanded_cases.append(
            expanded_case
        )

        report_cases.append(
            {
                "case_id":
                    clean(
                        case.get(
                            "case_id"
                        )
                    ),

                "distribution":
                    distribution,

                "resolved_seed_record_count":
                    resolved_seed_count,

                "raw_reference_count":
                    raw_reference_count,

                "discovered_source_count":
                    len(
                        references
                    ),

                "structured_discovered_source_count":
                    structured_count,

                "generic_discovered_source_count":
                    generic_count,

                "duplicate_reference_count":
                    duplicate_count,

                "invalid_reference_count":
                    invalid_count,

                "phase_counts":
                    dict(
                        sorted(
                            phase_counts.items()
                        )
                    ),

                "backend_counts":
                    dict(
                        sorted(
                            backend_counts.items()
                        )
                    ),

                "references":
                    references,

                "issues":
                    sorted(
                        set(
                            issues
                        )
                    ),
            }
        )

        all_issues.extend(
            issues
        )

    cases_with_resolved_seed = sum(
        1
        for case
        in report_cases
        if (
            case[
                "resolved_seed_record_count"
            ]
            > 0
        )
    )

    discovered_count = sum(
        case[
            "discovered_source_count"
        ]
        for case
        in report_cases
    )

    structured_count = sum(
        case[
            "structured_discovered_source_count"
        ]
        for case
        in report_cases
    )

    generic_count = sum(
        case[
            "generic_discovered_source_count"
        ]
        for case
        in report_cases
    )

    status = (
        "resolved"
        if (
            len(
                report_cases
            )
            == len(
                raw_cases
            )
            and cases_with_resolved_seed
            == len(
                raw_cases
            )
            and not all_issues
        )
        else "partial"
    )

    report = {
        "schema_version":
            DISCOVERY_SCHEMA_VERSION,

        "discovery_version":
            DISCOVERY_VERSION,

        "status":
            status,

        "case_count":
            len(
                report_cases
            ),

        "cases_with_resolved_osv_seed":
            cases_with_resolved_seed,

        "cases_with_discovered_references":
            sum(
                1
                for case
                in report_cases
                if (
                    case[
                        "discovered_source_count"
                    ]
                    > 0
                )
            ),

        "raw_osv_reference_count":
            sum(
                case[
                    "raw_reference_count"
                ]
                for case
                in report_cases
            ),

        "discovered_source_count":
            discovered_count,

        "structured_discovered_source_count":
            structured_count,

        "generic_discovered_source_count":
            generic_count,

        "duplicate_reference_count":
            sum(
                case[
                    "duplicate_reference_count"
                ]
                for case
                in report_cases
            ),

        "invalid_reference_count":
            sum(
                case[
                    "invalid_reference_count"
                ]
                for case
                in report_cases
            ),

        "phase_counts":
            dict(
                sorted(
                    total_phase_counts.items()
                )
            ),

        "backend_counts":
            dict(
                sorted(
                    total_backend_counts.items()
                )
            ),

        "cases":
            report_cases,

        "issues":
            sorted(
                set(
                    all_issues
                )
            ),

        "semantic_boundary": {
            "input_is_osv_seed_evidence_only":
                True,

            "references_are_discovered_from_osv":
                True,

            "trigger_semantics_inferred":
                False,

            "safe_alternatives_inferred":
                False,

            "reference_presence_treated_as_truth":
                False,
        },
    }

    expanded_inventory = dict(
        seed_inventory
    )

    expanded_inventory[
        "schema_version"
    ] = (
        EXPANDED_SCHEMA_VERSION
    )

    expanded_inventory[
        "status"
    ] = (
        "expanded_from_osv_references"
    )

    expanded_inventory[
        "source_discovery"
    ] = {
        "discovery_version":
            DISCOVERY_VERSION,

        "discovery_status":
            status,

        "discovered_source_count":
            discovered_count,

        "structured_discovered_source_count":
            structured_count,

        "generic_discovered_source_count":
            generic_count,
    }

    expanded_inventory[
        "cases"
    ] = expanded_cases

    return (
        report,
        expanded_inventory,
    )


def main() -> None:
    parser = (
        argparse.ArgumentParser(
            description=(
                "Discover follow-up source "
                "locators from resolved "
                "OSV seed records."
            )
        )
    )

    parser.add_argument(
        "--seed-inventory",
        type=Path,
        required=True,
    )

    parser.add_argument(
        "--local-acquisition",
        type=Path,
        required=True,
    )

    parser.add_argument(
        "--out",
        type=Path,
        required=True,
    )

    parser.add_argument(
        "--out-inventory",
        type=Path,
        required=True,
    )

    args = parser.parse_args()

    (
        report,
        expanded_inventory,
    ) = discover(
        load_json(
            args.seed_inventory
        ),
        load_json(
            args.local_acquisition
        ),
    )

    write_json(
        args.out,
        report,
    )

    write_json(
        args.out_inventory,
        expanded_inventory,
    )

    print(
        "=" * 60
    )

    print(
        "OSV REFERENCE DISCOVERY SUMMARY"
    )

    print(
        "=" * 60
    )

    print(
        "[OK] schema:",
        report[
            "schema_version"
        ],
    )

    print(
        "[OK] status:",
        report[
            "status"
        ],
    )

    print(
        "[OK] cases:",
        report[
            "case_count"
        ],
    )

    print(
        "[OK] cases with resolved OSV seed:",
        report[
            "cases_with_resolved_osv_seed"
        ],
    )

    print(
        "[OK] cases with references:",
        report[
            "cases_with_discovered_references"
        ],
    )

    print(
        "[OK] raw OSV references:",
        report[
            "raw_osv_reference_count"
        ],
    )

    print(
        "[OK] discovered sources:",
        report[
            "discovered_source_count"
        ],
    )

    print(
        "[OK] structured discovered:",
        report[
            "structured_discovered_source_count"
        ],
    )

    print(
        "[OK] generic discovered:",
        report[
            "generic_discovered_source_count"
        ],
    )

    print(
        "[OK] duplicate references:",
        report[
            "duplicate_reference_count"
        ],
    )

    print(
        "[OK] invalid references:",
        report[
            "invalid_reference_count"
        ],
    )

    print(
        "[OK] phases:",
        json.dumps(
            report[
                "phase_counts"
            ],
            ensure_ascii=False,
            sort_keys=True,
        ),
    )

    print(
        "[OK] backends:",
        json.dumps(
            report[
                "backend_counts"
            ],
            ensure_ascii=False,
            sort_keys=True,
        ),
    )

    print(
        "[OK] issues:",
        len(
            report[
                "issues"
            ]
        ),
    )

    print(
        "[OK] report saved:",
        args.out,
    )

    print(
        "[OK] expanded inventory saved:",
        args.out_inventory,
    )


if __name__ == "__main__":
    main()