from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse


ROOT = Path(__file__).resolve().parents[1]

SCHEMA_VERSION = (
    "avcs_trigger_source_acquisition_plan_v0.1"
)

DEFAULT_INVENTORY = (
    ROOT
    / "output"
    / "avcs_trigger_raw_inventory_v0.json"
)

DEFAULT_OUTPUT = (
    ROOT
    / "output"
    / "avcs_trigger_source_acquisition_plan_v0.json"
)


PHASE_STRUCTURED_EVIDENCE = (
    "phase_1_structured_evidence"
)

PHASE_STRUCTURED_METADATA = (
    "phase_2_structured_metadata"
)

PHASE_GENERIC_WEB = (
    "phase_3_generic_web"
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


def clean_text(
    value: Any,
) -> str:
    return str(
        value
        if value is not None
        else ""
    ).strip()


def parse_url(
    url: str,
) -> tuple[
    str,
    list[str],
]:
    try:
        parsed = urlparse(
            url
        )
    except ValueError:
        return "", []

    domain = (
        parsed.hostname
        or ""
    ).lower()

    segments = [
        unquote(
            segment
        )
        for segment in (
            parsed.path.split("/")
        )
        if segment
    ]

    return (
        domain,
        segments,
    )


def osv_vulnerability_id_from_url(
    url: str,
) -> str:
    domain, segments = (
        parse_url(
            url
        )
    )

    if domain != "osv.dev":
        return ""

    if (
        len(
            segments
        )
        >= 2
        and segments[0]
        == "vulnerability"
    ):
        return segments[1]

    return ""


def classify_github_url(
    url: str,
) -> tuple[
    str,
    str,
]:
    """
    对 github.com URL 做保守路由。

    这里只决定未来使用哪种 acquisition backend，
    不在这里真正访问 GitHub，也不解析漏洞语义。
    """
    domain, segments = (
        parse_url(
            url
        )
    )

    if domain != "github.com":
        return (
            "generic_http_url",
            PHASE_GENERIC_WEB,
        )

    # --------------------------------------------
    # Global GitHub Advisory:
    #
    # github.com/advisories/GHSA-...
    # --------------------------------------------

    if (
        len(
            segments
        )
        >= 2
        and segments[0]
        == "advisories"
    ):
        return (
            "github_security_advisory_url",
            PHASE_STRUCTURED_METADATA,
        )

    if len(
        segments
    ) < 2:
        return (
            "github_web_url",
            PHASE_GENERIC_WEB,
        )

    remaining = (
        segments[2:]
    )

    # --------------------------------------------
    # Repository file:
    #
    # owner/repo/blob/ref/path
    # --------------------------------------------

    if (
        len(
            remaining
        )
        >= 3
        and remaining[0]
        == "blob"
    ):
        return (
            "github_blob_url",
            PHASE_STRUCTURED_EVIDENCE,
        )

    # --------------------------------------------
    # Commit:
    #
    # owner/repo/commit/<sha>
    # --------------------------------------------

    if (
        len(
            remaining
        )
        >= 2
        and remaining[0]
        == "commit"
    ):
        return (
            "github_commit_url",
            PHASE_STRUCTURED_EVIDENCE,
        )

    # --------------------------------------------
    # Pull request:
    #
    # owner/repo/pull/<number>
    # --------------------------------------------

    if (
        len(
            remaining
        )
        >= 2
        and remaining[0]
        == "pull"
    ):
        return (
            "github_pull_request_url",
            PHASE_STRUCTURED_METADATA,
        )

    # --------------------------------------------
    # Issue:
    #
    # owner/repo/issues/<number>
    # --------------------------------------------

    if (
        len(
            remaining
        )
        >= 2
        and remaining[0]
        == "issues"
    ):
        return (
            "github_issue_url",
            PHASE_STRUCTURED_METADATA,
        )

    # --------------------------------------------
    # Repository Security Advisory:
    #
    # owner/repo/security/advisories/GHSA-...
    # --------------------------------------------

    if (
        len(
            remaining
        )
        >= 3
        and remaining[0]
        == "security"
        and remaining[1]
        == "advisories"
    ):
        return (
            "github_security_advisory_url",
            PHASE_STRUCTURED_METADATA,
        )

    # --------------------------------------------
    # Release page:
    #
    # owner/repo/releases/tag/<tag>
    # --------------------------------------------

    if (
        len(
            remaining
        )
        >= 3
        and remaining[0]
        == "releases"
        and remaining[1]
        == "tag"
    ):
        return (
            "github_release_url",
            PHASE_STRUCTURED_METADATA,
        )

    return (
        "github_web_url",
        PHASE_GENERIC_WEB,
    )


def compile_github_url_target(
    url: str,
    backend: str,
) -> dict[str, Any]:
    """
    将已经分类完成的 github.com URL
    编译成 acquisition backend 可直接使用的
    结构化 target。

    这一层只解析 URL 结构，不访问 GitHub，
    也不判断 source 中的安全语义是否正确。
    """
    domain, segments = parse_url(
        url
    )

    target: dict[
        str,
        Any,
    ] = {
        "url":
            url,
    }

    if domain != "github.com":
        return target

    # --------------------------------------------
    # Global GitHub Advisory:
    #
    # github.com/advisories/GHSA-...
    # --------------------------------------------

    if (
        backend
        == "github_security_advisory_url"
        and len(
            segments
        )
        >= 2
        and segments[0]
        == "advisories"
    ):
        target.update(
            {
                "advisory_scope":
                    "global",

                "advisory_id":
                    segments[1],
            }
        )

        return target

    # 下面这些类型都要求 owner/repository。
    if len(
        segments
    ) < 2:
        return target

    repository = (
        f"{segments[0]}/"
        f"{segments[1]}"
    )

    target[
        "repository"
    ] = repository

    # --------------------------------------------
    # Repository Security Advisory:
    #
    # owner/repo/security/advisories/GHSA-...
    # --------------------------------------------

    if (
        backend
        == "github_security_advisory_url"
        and len(
            segments
        )
        >= 5
        and segments[2]
        == "security"
        and segments[3]
        == "advisories"
    ):
        target.update(
            {
                "advisory_scope":
                    "repository",

                "advisory_id":
                    segments[4],
            }
        )

        return target

    # --------------------------------------------
    # Repository file:
    #
    # owner/repo/blob/ref/path/to/file
    #
    # 当前 frozen Trigger Evidence 使用的是
    # tag / simple ref，因此这里把 blob 后
    # 第一段作为 ref。
    #
    # 含 "/" 的复杂 branch ref 暂不自动猜测，
    # 后续需要时再扩展。
    # --------------------------------------------

    if (
        backend
        == "github_blob_url"
        and len(
            segments
        )
        >= 5
        and segments[2]
        == "blob"
    ):
        target.update(
            {
                "ref":
                    segments[3],

                "path":
                    "/".join(
                        segments[4:]
                    ),
            }
        )

        return target

    # --------------------------------------------
    # Commit:
    #
    # owner/repo/commit/<sha>
    # --------------------------------------------

    if (
        backend
        == "github_commit_url"
        and len(
            segments
        )
        >= 4
        and segments[2]
        == "commit"
    ):
        target[
            "commit"
        ] = segments[3]

        return target

    # --------------------------------------------
    # Pull request:
    #
    # owner/repo/pull/<number>
    # --------------------------------------------

    if (
        backend
        == "github_pull_request_url"
        and len(
            segments
        )
        >= 4
        and segments[2]
        == "pull"
    ):
        pull_number_text = (
            segments[3]
        )

        if pull_number_text.isdigit():
            target[
                "pull_number"
            ] = int(
                pull_number_text
            )

        else:
            target[
                "pull_number_raw"
            ] = pull_number_text

        return target

    # --------------------------------------------
    # Issue:
    #
    # owner/repo/issues/<number>
    # --------------------------------------------

    if (
        backend
        == "github_issue_url"
        and len(
            segments
        )
        >= 4
        and segments[2]
        == "issues"
    ):
        issue_number_text = (
            segments[3]
        )

        if issue_number_text.isdigit():
            target[
                "issue_number"
            ] = int(
                issue_number_text
            )

        else:
            target[
                "issue_number_raw"
            ] = issue_number_text

        return target

    # --------------------------------------------
    # Release:
    #
    # owner/repo/releases/tag/<tag>
    # --------------------------------------------

    if (
        backend
        == "github_release_url"
        and len(
            segments
        )
        >= 5
        and segments[2]
        == "releases"
        and segments[3]
        == "tag"
    ):
        target[
            "tag"
        ] = "/".join(
            segments[4:]
        )

        return target

    return target


def classify_url_source(
    url: str,
) -> tuple[
    str,
    str,
    dict[str, Any],
]:
    domain, _ = parse_url(
        url
    )

    osv_vulnerability_id = (
        osv_vulnerability_id_from_url(
            url
        )
    )

    if osv_vulnerability_id:
        return (
            "osv_api_record",
            PHASE_STRUCTURED_EVIDENCE,
            {
                "vulnerability_id":
                    osv_vulnerability_id,

                "source_url":
                    url,
            },
        )

    if domain == "github.com":
        (
            backend,
            phase,
        ) = classify_github_url(
            url
        )

        target = (
            compile_github_url_target(
                url=url,
                backend=backend,
            )
        )

        return (
            backend,
            phase,
            target,
        )

    return (
        "generic_http_url",
        PHASE_GENERIC_WEB,
        {
            "url":
                url,

            "domain":
                domain,
        },
    )


def compile_source_plan(
    distribution: str,
    vulnerability_ids: list[str],
    source: dict[str, Any],
) -> dict[str, Any]:
    source_id = clean_text(
        source.get(
            "source_id"
        )
    )

    source_type = clean_text(
        source.get(
            "source_type"
        )
    )

    locator_kind = clean_text(
        source.get(
            "locator_kind"
        )
    )

    url = clean_text(
        source.get(
            "url"
        )
    )

    local_evidence_file = (
        clean_text(
            source.get(
                "local_evidence_file"
            )
        )
    )

    repository = clean_text(
        source.get(
            "repository"
        )
    )

    ref = clean_text(
        source.get(
            "ref"
        )
    )

    commit = clean_text(
        source.get(
            "commit"
        )
    )

    source_path = clean_text(
        source.get(
            "source_path"
        )
    )

    backend = ""

    phase = ""

    target: dict[
        str,
        Any,
    ] = {}

    if (
        locator_kind
        == "local_evidence_file"
    ):
        backend = (
            "local_evidence_file"
        )

        phase = (
            PHASE_STRUCTURED_EVIDENCE
        )

        target = {
            "path":
                local_evidence_file,
        }

    elif (
        locator_kind
        == "github_repository_file"
    ):
        backend = (
            "github_repository_file"
        )

        phase = (
            PHASE_STRUCTURED_EVIDENCE
        )

        target = {
            "repository":
                repository,

            "ref":
                ref,

            "path":
                source_path,
        }

    elif (
        locator_kind
        == "github_repository_commit"
    ):
        backend = (
            "github_repository_commit"
        )

        phase = (
            PHASE_STRUCTURED_EVIDENCE
        )

        target = {
            "repository":
                repository,

            "commit":
                commit,
        }

    elif locator_kind == "url":
        (
            backend,
            phase,
            target,
        ) = classify_url_source(
            url
        )

    else:
        backend = (
            "unresolved_locator"
        )

        phase = (
            "unresolved"
        )

    network_required = (
        backend
        not in {
            "local_evidence_file",
            "unresolved_locator",
        }
    )

    structured_backend = (
        phase
        in {
            PHASE_STRUCTURED_EVIDENCE,
            PHASE_STRUCTURED_METADATA,
        }
    )

    return {
        "source_key":
            (
                f"{distribution}"
                f"::{source_id}"
            ),

        "distribution":
            distribution,

        "vulnerability_ids":
            vulnerability_ids,

        "source_id":
            source_id,

        "source_type":
            source_type,

        "original_locator_kind":
            locator_kind,

        "original_domain":
            clean_text(
                source.get(
                    "domain"
                )
            ),

        "acquisition_phase":
            phase,

        "acquisition_backend":
            backend,

        "network_required":
            network_required,

        "structured_backend":
            structured_backend,

        "target":
            target,

        "locator_note":
            clean_text(
                source.get(
                    "locator"
                )
            ),

        "has_claim":
            bool(
                source.get(
                    "has_claim"
                )
            ),
    }


def compile_plan(
    inventory: dict[str, Any],
) -> dict[str, Any]:
    cases = inventory.get(
        "cases",
        [],
    )

    if not isinstance(
        cases,
        list,
    ):
        raise ValueError(
            "Inventory field 'cases' "
            "must be a list."
        )

    sources: list[
        dict[str, Any]
    ] = []

    seen_source_keys: set[
        str
    ] = set()

    issues: list[str] = []

    for case in cases:
        if not isinstance(
            case,
            dict,
        ):
            issues.append(
                "case_not_object"
            )
            continue

        distribution = clean_text(
            case.get(
                "distribution"
            )
        )

        raw_vulnerability_ids = (
            case.get(
                "vulnerability_ids",
                [],
            )
        )

        vulnerability_ids = [
            clean_text(
                value
            )
            for value
            in (
                raw_vulnerability_ids
                if isinstance(
                    raw_vulnerability_ids,
                    list,
                )
                else []
            )
            if clean_text(
                value
            )
        ]

        case_sources = case.get(
            "sources",
            [],
        )

        if not isinstance(
            case_sources,
            list,
        ):
            issues.append(
                (
                    "case_sources_not_list:"
                    f"{distribution}"
                )
            )
            continue

        for source in case_sources:
            if not isinstance(
                source,
                dict,
            ):
                issues.append(
                    (
                        "source_not_object:"
                        f"{distribution}"
                    )
                )
                continue

            item = compile_source_plan(
                distribution=distribution,
                vulnerability_ids=vulnerability_ids,
                source=source,
            )

            source_key = clean_text(
                item.get(
                    "source_key"
                )
            )

            if not source_key:
                issues.append(
                    (
                        "missing_source_key:"
                        f"{distribution}"
                    )
                )
                continue

            if (
                source_key
                in seen_source_keys
            ):
                issues.append(
                    (
                        "duplicate_source_key:"
                        f"{source_key}"
                    )
                )
                continue

            seen_source_keys.add(
                source_key
            )

            sources.append(
                item
            )

    backend_counter = Counter(
        clean_text(
            item.get(
                "acquisition_backend"
            )
        )
        for item in sources
    )

    phase_counter = Counter(
        clean_text(
            item.get(
                "acquisition_phase"
            )
        )
        for item in sources
    )

    unresolved_sources = [
        item.get(
            "source_key"
        )
        for item in sources
        if (
            item.get(
                "acquisition_backend"
            )
            == "unresolved_locator"
        )
    ]

    network_required_count = sum(
        1
        for item in sources
        if item.get(
            "network_required"
        )
        is True
    )

    structured_backend_count = sum(
        1
        for item in sources
        if item.get(
            "structured_backend"
        )
        is True
    )

    status = (
        "resolved"
        if (
            not issues
            and not unresolved_sources
        )
        else "partial"
    )

    return {
        "schema_version":
            SCHEMA_VERSION,

        "status":
            status,

        "source_inventory_schema_version":
            clean_text(
                inventory.get(
                    "schema_version"
                )
            ),

        "case_count":
            len(
                cases
            ),

        "source_count":
            len(
                sources
            ),

        "network_required_count":
            network_required_count,

        "structured_backend_count":
            structured_backend_count,

        "unresolved_source_count":
            len(
                unresolved_sources
            ),

        "backend_counts":
            dict(
                sorted(
                    backend_counter.items()
                )
            ),

        "phase_counts":
            dict(
                sorted(
                    phase_counter.items()
                )
            ),

        "unresolved_sources":
            unresolved_sources,

        "issues":
            sorted(
                set(
                    issues
                )
            ),

        "sources":
            sources,

        "limitations": [
            (
                "This v0 compiles source acquisition "
                "routing only; it does not fetch content."
            ),
            (
                "Generic HTTP evidence remains "
                "phase-3 evidence and must not be "
                "treated as automatically validated."
            ),
            (
                "A successful acquisition does not "
                "prove that a source claim or trigger "
                "semantic is correct."
            ),
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Compile AVCS Trigger Evidence "
            "sources into an auditable "
            "acquisition plan."
        )
    )

    parser.add_argument(
        "--inventory",
        type=Path,
        default=DEFAULT_INVENTORY,
    )

    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUTPUT,
    )

    args = parser.parse_args()

    inventory = load_json(
        args.inventory
    )

    plan = compile_plan(
        inventory
    )

    write_json(
        args.out,
        plan,
    )

    print(
        "============================================================"
    )
    print(
        "TRIGGER SOURCE ACQUISITION PLAN SUMMARY"
    )
    print(
        "============================================================"
    )

    print(
        "[OK] schema:",
        plan.get(
            "schema_version"
        ),
    )

    print(
        "[OK] status:",
        plan.get(
            "status"
        ),
    )

    print(
        "[OK] cases:",
        plan.get(
            "case_count"
        ),
    )

    print(
        "[OK] sources:",
        plan.get(
            "source_count"
        ),
    )

    print(
        "[OK] structured backends:",
        plan.get(
            "structured_backend_count"
        ),
    )

    print(
        "[OK] network required:",
        plan.get(
            "network_required_count"
        ),
    )

    print(
        "[OK] unresolved sources:",
        plan.get(
            "unresolved_source_count"
        ),
    )

    print(
        "[OK] phases:",
        json.dumps(
            plan.get(
                "phase_counts",
                {},
            ),
            ensure_ascii=False,
            sort_keys=True,
        ),
    )

    print(
        "[OK] backends:",
        json.dumps(
            plan.get(
                "backend_counts",
                {},
            ),
            ensure_ascii=False,
            sort_keys=True,
        ),
    )

    print(
        "[OK] saved:",
        args.out,
    )


if __name__ == "__main__":
    main()