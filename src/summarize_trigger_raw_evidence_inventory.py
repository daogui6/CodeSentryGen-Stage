from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]

OUTPUT_SCHEMA_VERSION = (
    "avcs_trigger_raw_inventory_v0.1"
)

DEFAULT_RAW_DIR = (
    ROOT
    / "data"
    / "avcs_validation"
    / "trigger_raw"
)

DEFAULT_OUTPUT = (
    ROOT
    / "output"
    / "avcs_trigger_raw_inventory_v0.json"
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


def as_string_list(
    value: Any,
) -> list[str]:
    if not isinstance(
        value,
        list,
    ):
        return []

    result: list[str] = []

    for item in value:
        text = str(
            item
        ).strip()

        if text:
            result.append(
                text
            )

    return result


def source_domain(
    url: str,
) -> str:
    url = str(
        url
    ).strip()

    if not url:
        return ""

    try:
        parsed = urlparse(
            url
        )
    except ValueError:
        return ""

    return (
        parsed.hostname
        or ""
    ).lower()


def source_locator_kind(
    source: dict[str, Any],
) -> str:
    """
    判断一条 Trigger source 使用哪种可获取定位方式。

    当前支持：

    1. url
    2. local_evidence_file
    3. repository + commit
    4. repository + ref + source_path
    5. repository + ref
    6. repository

    inventory 只识别定位方式，
    不在这里真正抓取证据。
    """
    url = str(
        source.get(
            "url",
            "",
        )
    ).strip()

    if url:
        return "url"

    local_evidence_file = str(
        source.get(
            "local_evidence_file",
            "",
        )
    ).strip()

    if local_evidence_file:
        return "local_evidence_file"

    repository = str(
        source.get(
            "repository",
            "",
        )
    ).strip()

    commit = str(
        source.get(
            "commit",
            "",
        )
    ).strip()

    ref = str(
        source.get(
            "ref",
            "",
        )
    ).strip()

    source_path = str(
        source.get(
            "source_path",
            "",
        )
    ).strip()

    if (
        repository
        and commit
    ):
        return (
            "github_repository_commit"
        )

    if (
        repository
        and ref
        and source_path
    ):
        return (
            "github_repository_file"
        )

    if (
        repository
        and ref
    ):
        return (
            "github_repository_ref"
        )

    if repository:
        return "github_repository"

    return "unresolved"


def source_record_domain(
    source: dict[str, Any],
) -> str:
    """
    为 inventory 提取来源域名。

    URL source 直接解析 hostname。

    repository 型定位当前明确表示 GitHub 仓库，
    因而记为 github.com。

    local_evidence_file 是本地冻结证据，
    不伪造外部 domain。
    """
    url = str(
        source.get(
            "url",
            "",
        )
    ).strip()

    domain = source_domain(
        url
    )

    if domain:
        return domain

    repository = str(
        source.get(
            "repository",
            "",
        )
    ).strip()

    if repository:
        return "github.com"

    return ""


def collect_evidence_refs(
    value: Any,
) -> set[str]:
    """
    递归收集 raw evidence 中所有 evidence_refs。

    这里不假设 evidence_refs 只会出现在
    trigger_candidates 或 fix_evidence，
    从而避免未来 schema 增加其他证据块后漏掉。
    """
    result: set[str] = set()

    if isinstance(
        value,
        dict,
    ):
        for (
            key,
            child,
        ) in value.items():

            if (
                key
                == "evidence_refs"
                and isinstance(
                    child,
                    list,
                )
            ):
                for item in child:
                    text = str(
                        item
                    ).strip()

                    if text:
                        result.add(
                            text
                        )

                continue

            result.update(
                collect_evidence_refs(
                    child
                )
            )

    elif isinstance(
        value,
        list,
    ):
        for child in value:
            result.update(
                collect_evidence_refs(
                    child
                )
            )

    return result


def summarize_sources(
    sources: Any,
) -> tuple[
    list[dict[str, Any]],
    list[str],
]:
    if not isinstance(
        sources,
        list,
    ):
        return (
            [],
            [
                "sources_not_list"
            ],
        )

    summaries: list[
        dict[str, Any]
    ] = []

    issues: list[str] = []

    seen_source_ids: set[str] = set()

    for index, source in enumerate(
        sources
    ):
        if not isinstance(
            source,
            dict,
        ):
            issues.append(
                (
                    "source_not_object:"
                    f"{index}"
                )
            )
            continue

        source_id = str(
            source.get(
                "source_id",
                "",
            )
        ).strip()

        source_type = str(
            source.get(
                "source_type",
                "",
            )
        ).strip()

        url = str(
            source.get(
                "url",
                "",
            )
        ).strip()

        local_evidence_file = str(
            source.get(
                "local_evidence_file",
                "",
            )
        ).strip()

        repository = str(
            source.get(
                "repository",
                "",
            )
        ).strip()

        ref = str(
            source.get(
                "ref",
                "",
            )
        ).strip()

        commit = str(
            source.get(
                "commit",
                "",
            )
        ).strip()

        source_path = str(
            source.get(
                "source_path",
                "",
            )
        ).strip()

        locator = str(
            source.get(
                "locator",
                "",
            )
        ).strip()

        claim = str(
            source.get(
                "claim",
                "",
            )
        ).strip()

        locator_kind = (
            source_locator_kind(
                source
            )
        )

        if not source_id:
            issues.append(
                (
                    "missing_source_id:"
                    f"{index}"
                )
            )

        elif (
            source_id
            in seen_source_ids
        ):
            issues.append(
                (
                    "duplicate_source_id:"
                    f"{source_id}"
                )
            )

        if source_id:
            seen_source_ids.add(
                source_id
            )

        if not source_type:
            issues.append(
                (
                    "missing_source_type:"
                    f"{source_id or index}"
                )
            )

        if (
            locator_kind
            == "unresolved"
        ):
            issues.append(
                (
                    "missing_source_locator:"
                    f"{source_id or index}"
                )
            )

        summaries.append(
            {
                "source_id":
                    source_id,

                "source_type":
                    source_type,

                "locator_kind":
                    locator_kind,

                "url":
                    url,

                "local_evidence_file":
                    local_evidence_file,

                "repository":
                    repository,

                "ref":
                    ref,

                "commit":
                    commit,

                "source_path":
                    source_path,

                "domain":
                    source_record_domain(
                        source
                    ),

                "locator":
                    locator,

                "has_claim":
                    bool(
                        claim
                    ),
            }
        )

    return (
        summaries,
        issues,
    )


def summarize_case(
    path: Path,
) -> dict[str, Any]:
    raw = load_json(
        path
    )

    issues: list[str] = []

    distribution = str(
        raw.get(
            "distribution",
            "",
        )
    ).strip()

    ecosystem = str(
        raw.get(
            "ecosystem",
            "",
        )
    ).strip()

    raw_schema_version = str(
        raw.get(
            "schema_version",
            "",
        )
    ).strip()

    vulnerability_ids = (
        as_string_list(
            raw.get(
                "vulnerability_ids"
            )
        )
    )

    trigger_candidates = raw.get(
        "trigger_candidates",
        [],
    )

    safe_alternatives = raw.get(
        "safe_alternatives",
        [],
    )

    if not distribution:
        issues.append(
            "missing_distribution"
        )

    if not ecosystem:
        issues.append(
            "missing_ecosystem"
        )

    if not vulnerability_ids:
        issues.append(
            "missing_vulnerability_ids"
        )

    if not isinstance(
        trigger_candidates,
        list,
    ):
        issues.append(
            "trigger_candidates_not_list"
        )
        trigger_candidates = []

    if not trigger_candidates:
        issues.append(
            "missing_trigger_candidates"
        )

    if not isinstance(
        safe_alternatives,
        list,
    ):
        issues.append(
            "safe_alternatives_not_list"
        )
        safe_alternatives = []

    trigger_kinds: list[str] = []

    trigger_ids: list[str] = []

    for candidate in (
        trigger_candidates
    ):
        if not isinstance(
            candidate,
            dict,
        ):
            issues.append(
                "trigger_candidate_not_object"
            )
            continue

        trigger_id = str(
            candidate.get(
                "trigger_id",
                "",
            )
        ).strip()

        kind = str(
            candidate.get(
                "kind",
                "",
            )
        ).strip()

        if trigger_id:
            trigger_ids.append(
                trigger_id
            )

        if kind:
            trigger_kinds.append(
                kind
            )

    (
        source_summaries,
        source_issues,
    ) = summarize_sources(
        raw.get(
            "sources",
            []
        )
    )

    issues.extend(
        source_issues
    )

    source_ids = {
        source.get(
            "source_id",
            ""
        )
        for source
        in source_summaries
        if source.get(
            "source_id"
        )
    }

    referenced_source_ids = (
        collect_evidence_refs(
            raw
        )
    )

    missing_referenced_source_ids = (
        sorted(
            referenced_source_ids
            - source_ids
        )
    )

    for source_id in (
        missing_referenced_source_ids
    ):
        issues.append(
            (
                "missing_referenced_source:"
                f"{source_id}"
            )
        )

    source_types = sorted(
        {
            str(
                source.get(
                    "source_type",
                    "",
                )
            )
            for source
            in source_summaries
            if source.get(
                "source_type"
            )
        }
    )

    source_domains = sorted(
        {
            str(
                source.get(
                    "domain",
                    "",
                )
            )
            for source
            in source_summaries
            if source.get(
                "domain"
            )
        }
    )

    return {
        "file":
            path.name,

        "raw_schema_version":
            raw_schema_version,

        "ecosystem":
            ecosystem,

        "distribution":
            distribution,

        "vulnerability_ids":
            vulnerability_ids,

        "trigger_candidate_count":
            len(
                trigger_candidates
            ),

        "trigger_ids":
            sorted(
                trigger_ids
            ),

        "trigger_kinds":
            sorted(
                trigger_kinds
            ),

        "safe_alternative_count":
            len(
                safe_alternatives
            ),

        "source_count":
            len(
                source_summaries
            ),

        "source_types":
            source_types,

        "source_domains":
            source_domains,

        "referenced_source_ids":
            sorted(
                referenced_source_ids
            ),

        "missing_referenced_source_ids":
            missing_referenced_source_ids,

        "sources":
            source_summaries,

        "status":
            (
                "resolved"
                if not issues
                else "partial"
            ),

        "issues":
            sorted(
                set(
                    issues
                )
            ),
    }


def build_inventory(
    raw_dir: Path,
) -> dict[str, Any]:
    paths = sorted(
        raw_dir.glob(
            "*_trigger_raw_v0.json"
        )
    )

    if not paths:
        raise FileNotFoundError(
            (
                "No trigger raw evidence "
                f"files found in {raw_dir}"
            )
        )

    cases: list[
        dict[str, Any]
    ] = []

    source_type_counter: Counter[
        str
    ] = Counter()

    source_domain_counter: Counter[
        str
    ] = Counter()

    source_locator_kind_counter: Counter[
        str
    ] = Counter()

    trigger_kind_counter: Counter[
        str
    ] = Counter()

    raw_schema_counter: Counter[
        str
    ] = Counter()

    total_sources = 0

    total_trigger_candidates = 0

    total_missing_refs = 0

    partial_case_count = 0

    for path in paths:
        case = summarize_case(
            path
        )

        cases.append(
            case
        )

        raw_schema_counter.update(
            [
                str(
                    case.get(
                        "raw_schema_version",
                        "",
                    )
                )
            ]
        )

        source_type_counter.update(
            str(
                source.get(
                    "source_type",
                    "",
                )
            )
            for source
            in case.get(
                "sources",
                [],
            )
            if source.get(
                "source_type"
            )
        )

        source_domain_counter.update(
            source.get(
                "domain",
                ""
            )
            for source
            in case.get(
                "sources",
                [],
            )
            if source.get(
                "domain"
            )
        )

        source_locator_kind_counter.update(
            str(
                source.get(
                    "locator_kind",
                    "",
                )
            )
            for source
            in case.get(
                "sources",
                [],
            )
            if source.get(
                "locator_kind"
            )
        )

        trigger_kind_counter.update(
            case.get(
                "trigger_kinds",
                [],
            )
        )

        total_sources += int(
            case.get(
                "source_count",
                0,
            )
        )

        total_trigger_candidates += int(
            case.get(
                "trigger_candidate_count",
                0,
            )
        )

        total_missing_refs += len(
            case.get(
                "missing_referenced_source_ids",
                [],
            )
        )

        if (
            case.get(
                "status"
            )
            != "resolved"
        ):
            partial_case_count += 1

    overall_status = (
        "resolved"
        if (
            partial_case_count == 0
            and total_missing_refs == 0
        )
        else "partial"
    )

    return {
        "schema_version":
            OUTPUT_SCHEMA_VERSION,

        "status":
            overall_status,

        "raw_directory":
            str(
                raw_dir
            ),

        "case_count":
            len(
                cases
            ),

        "source_count":
            total_sources,

        "trigger_candidate_count":
            total_trigger_candidates,

        "partial_case_count":
            partial_case_count,

        "missing_referenced_source_id_count":
            total_missing_refs,

        "raw_schema_counts":
            dict(
                sorted(
                    raw_schema_counter.items()
                )
            ),

        "trigger_kind_counts":
            dict(
                sorted(
                    trigger_kind_counter.items()
                )
            ),

        "source_type_counts":
            dict(
                sorted(
                    source_type_counter.items()
                )
            ),

        "source_locator_kind_counts":
            dict(
                sorted(
                    source_locator_kind_counter.items()
                )
            ),

        "source_domain_counts":
            dict(
                sorted(
                    source_domain_counter.items()
                )
            ),

        "cases":
            cases,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Summarize existing AVCS "
            "Trigger Raw Evidence fixtures."
        )
    )

    parser.add_argument(
        "--raw-dir",
        type=Path,
        default=DEFAULT_RAW_DIR,
    )

    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUTPUT,
    )

    args = parser.parse_args()

    inventory = build_inventory(
        args.raw_dir
    )

    args.out.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    args.out.write_text(
        json.dumps(
            inventory,
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    print(
        "============================================================"
    )
    print(
        "TRIGGER RAW EVIDENCE INVENTORY SUMMARY"
    )
    print(
        "============================================================"
    )

    print(
        "[OK] schema:",
        inventory.get(
            "schema_version"
        ),
    )

    print(
        "[OK] status:",
        inventory.get(
            "status"
        ),
    )

    print(
        "[OK] cases:",
        inventory.get(
            "case_count"
        ),
    )

    print(
        "[OK] sources:",
        inventory.get(
            "source_count"
        ),
    )

    print(
        "[OK] trigger candidates:",
        inventory.get(
            "trigger_candidate_count"
        ),
    )

    print(
        "[OK] partial cases:",
        inventory.get(
            "partial_case_count"
        ),
    )

    print(
        "[OK] missing referenced source ids:",
        inventory.get(
            "missing_referenced_source_id_count"
        ),
    )

    print(
        "[OK] trigger kinds:",
        json.dumps(
            inventory.get(
                "trigger_kind_counts",
                {},
            ),
            ensure_ascii=False,
            sort_keys=True,
        ),
    )

    print(
        "[OK] source types:",
        json.dumps(
            inventory.get(
                "source_type_counts",
                {},
            ),
            ensure_ascii=False,
            sort_keys=True,
        ),
    )

    print(
        "[OK] source locator kinds:",
        json.dumps(
            inventory.get(
                "source_locator_kind_counts",
                {},
            ),
            ensure_ascii=False,
            sort_keys=True,
        ),
    )

    print(
        "[OK] source domains:",
        json.dumps(
            inventory.get(
                "source_domain_counts",
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