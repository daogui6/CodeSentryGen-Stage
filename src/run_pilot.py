"""
run_pilot.py

作用：
    CodeSentry-Gen 第一阶段主检测入口。
    读取 generated sample JSONL，对每条生成代码进行依赖抽取、包名规范化、
    false positive 过滤、PyPI 查询、初始状态判断和初始 Risk Card 生成。

输入：
    - data/samples/*.jsonl
      每条 sample 通常包含：
        sample_id
        prompt_id
        model
        generation_time
        generated_code
        requirements_text

输出：
    - output/*_results.jsonl
      所有依赖检测记录，每条记录对应一个 dependency entity。
    - output/*risk_cards*.jsonl
      第一阶段生成的初始 Risk Card。
    - output/summary_report.md
    - output/gen_dep_risk_bench_sample.jsonl
    - output/benchmark_summary.md
    - output/manual_review_template.csv

在整体流程中的位置：
    generate_code_from_prompts.py
        ↓
    run_pilot.py
        ↓
    check_pilot50_against_reference.py
        ↓
    enrich_temporal_status.py
        ↓
    enrich_reachability_v2.py
        ↓
    build_temporal_risk_cards.py

注意：
    这里生成的是第一阶段 status 和初始 Risk Card。
    后续 THO v2 的 temporal_status_v2、install_reachability_v2 和最终 Risk Card v2
    由后处理脚本继续增强。
"""

from __future__ import annotations

import sys
import ast
import argparse
import json
from pathlib import Path
from typing import Any, Dict, List

from extractor import (
    DependencyEntity,
    deduplicate_entities,
    extract_imports_from_code,
    extract_requirements,
    extract_requirements_from_text,
    find_local_modules,
)
from normalizer import pep503_normalize
from package_identity_v1 import (
    DEFAULT_POLICY as DEFAULT_IDENTITY_POLICY,
    PackageIdentityService,
)
from project_dependency_facts_v1 import collect_project_dependency_facts
from pypi_client import (
    DEFAULT_NEGATIVE_TTL_SECONDS,
    DEFAULT_POSITIVE_TTL_SECONDS,
    query_pypi,
)
from risk_card import build_risk_card, classify_package_status, infer_reachability
from report_writer import write_summary_report
from benchmark_writer import write_benchmark_jsonl
from benchmark_summary_writer import write_benchmark_summary
from review_template_writer import write_manual_review_template


# 项目根目录。当前文件位于 src/ 下，因此 parents[1] 回到项目根目录。
ROOT = Path(__file__).resolve().parents[1]

def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    """
    读取 JSONL 文件。

    JSONL 是一行一个 JSON 对象。
    本函数用于读取 generated samples 文件，例如：
        data/samples/generated_codes_pilot50.jsonl
        data/samples/auto_qwen37_100_generated_codes.jsonl
        data/samples/risk_seed_validation_dataset.jsonl
    """
    rows = []

    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if line:
                rows.append(json.loads(line))

    return rows


def write_jsonl(path: Path, rows: List[Dict[str, Any]]) -> None:
    """
    将字典列表写入 JSONL 文件。

    用于输出：
        - 所有依赖检测记录 all_rows
        - 初始 Risk Card risk_rows
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def main() -> None:
    """
    主流程：
    1. 解析命令行参数
    2. 加载 import mapping 和 false positive 配置
    3. 读取 generated samples
    4. 逐条样本抽取 import 和 requirements 依赖
    5. 对依赖实体做包名映射、规范化、标准库过滤、本地模块过滤
    6. 对第三方依赖查询 PyPI
    7. 生成第一阶段依赖检测记录和初始 Risk Card
    8. 输出结果、summary、benchmark 和人工复核模板
    """

    # =========================
    # 1. 命令行参数
    # =========================
    parser = argparse.ArgumentParser(
        description="CodeSentry-Gen first-stage Python/PyPI pilot runner"
    )

    # 输入样本 JSONL，里面包含 generated_code / requirements_text / generation_time
    parser.add_argument(
        "--samples",
        default=str(ROOT / "data" / "samples" / "sample_generated_codes.jsonl"),
        help="JSONL samples path",
    )

    # 可选：额外传入一个全局 requirements.txt
    # 当前多数实验主要使用 sample 内部的 requirements_text
    parser.add_argument(
        "--requirements",
        default="",
        help="Optional requirements.txt path",
    )

    # 可选：传入 repo 路径，用于识别本地模块，避免把本地 .py 文件误当成 PyPI 包
    parser.add_argument(
        "--repo",
        default="",
        help=(
            "Legacy single-project root. Prefer --project-snapshots-dir "
            "for generated multi-sample E2E runs."
        ),
    )
    parser.add_argument(
        "--project-snapshots-dir",
        default="",
        help=(
            "Optional directory containing one project snapshot per sample_id. "
            "The shared PackageIdentityService uses it for local-module filtering."
        ),
    )
    parser.add_argument(
        "--identity-policy",
        default=str(DEFAULT_IDENTITY_POLICY),
        help="Unified PackageIdentityService policy.",
    )
    parser.add_argument(
        "--import-mapping-overlay",
        default="",
        help=(
            "Optional JSON mapping overlay applied after the frozen base "
            "import_mapping.json. Intended for versioned evaluation fixes "
            "without mutating frozen historical configuration."
        ),
    )
    parser.add_argument(
        "--manifest-identity-literal",
        action="store_true",
        help=(
            "Treat manifest/requirements names as literal distribution "
            "identities instead of applying import-name mappings."
        ),
    )

    # 输出所有依赖检测记录
    parser.add_argument(
        "--out",
        default=str(ROOT / "output" / "pilot_results.jsonl"),
        help="Output JSONL path",
    )

    # 输出第一阶段 Risk Card
    parser.add_argument(
        "--risk-out",
        default=str(ROOT / "output" / "risk_cards.jsonl"),
        help="Risk cards JSONL path",
    )

    # Registry evidence is run-scoped by default on the repair line.
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable PyPI query cache; raw registry snapshots are still saved.",
    )
    parser.add_argument(
        "--registry-cache-dir",
        default="",
        help=(
            "Optional registry cache directory. Defaults to a run-scoped "
            "registry_cache directory beside --out."
        ),
    )
    parser.add_argument(
        "--registry-snapshot-dir",
        default="",
        help=(
            "Optional immutable raw registry evidence directory. Defaults to "
            "a run-scoped registry_snapshot directory beside --out."
        ),
    )
    parser.add_argument(
        "--registry-run-id",
        default="",
        help=(
            "Explicit registry evidence run identity. Defaults to the parent "
            "directory name of --out."
        ),
    )
    parser.add_argument(
        "--registry-positive-ttl-seconds",
        type=int,
        default=DEFAULT_POSITIVE_TTL_SECONDS,
        help="TTL for successful registry metadata; default 24h.",
    )
    parser.add_argument(
        "--registry-negative-ttl-seconds",
        type=int,
        default=DEFAULT_NEGATIVE_TTL_SECONDS,
        help="TTL for explicit 404 package absence; default 6h.",
    )
    parser.add_argument(
        "--summary-out",
        default=str(ROOT / "output" / "summary_report.md"),
        help="Markdown summary output path.",
    )
    parser.add_argument(
        "--benchmark-out",
        default=str(ROOT / "output" / "gen_dep_risk_bench_sample.jsonl"),
        help="GenDepRiskBench-style JSONL output path.",
    )
    parser.add_argument(
        "--benchmark-summary-out",
        default=str(ROOT / "output" / "benchmark_summary.md"),
        help="Benchmark summary Markdown output path.",
    )
    parser.add_argument(
        "--review-template-out",
        default=str(ROOT / "output" / "manual_review_template.csv"),
        help="Manual review CSV output path.",
    )

    args = parser.parse_args()

    # =========================
    # 2. 加载配置
    # =========================

    # import 名到 PyPI distribution 名的映射。
    # 例如：
    #   yaml -> pyyaml
    #   bs4 -> beautifulsoup4
    #   googleapiclient -> google-api-python-client
    identity_policy_path = Path(args.identity_policy)
    if not identity_policy_path.is_absolute():
        identity_policy_path = ROOT / identity_policy_path

    project_snapshots_dir = (
        Path(args.project_snapshots_dir)
        if args.project_snapshots_dir
        else None
    )
    if (
        project_snapshots_dir is not None
        and not project_snapshots_dir.is_absolute()
    ):
        project_snapshots_dir = ROOT / project_snapshots_dir

    legacy_repo = Path(args.repo) if args.repo else None
    if legacy_repo is not None and not legacy_repo.is_absolute():
        legacy_repo = ROOT / legacy_repo

    # Legacy Step9 v2 flags may still appear in historical commands, but the
    # repair line has one shared identity policy. They must not create a
    # second mapping path.
    if args.import_mapping_overlay:
        overlay_path = Path(args.import_mapping_overlay)
        if not overlay_path.is_absolute():
            overlay_path = ROOT / overlay_path
        overlay = json.loads(overlay_path.read_text(encoding="utf-8"))
        active_service = PackageIdentityService(
            policy_path=identity_policy_path,
        )
        for key, value in overlay.items():
            if active_service.mapping.get(key) != value:
                raise ValueError(
                    "Legacy import mapping overlay conflicts with the active "
                    f"PackageIdentityService policy: {key}"
                )

    if args.manifest_identity_literal is False:
        # Active v1 policy is literal for manifest identity regardless of the
        # historical CLI flag; leaving the flag unset must not re-enable the
        # old import-mapping behavior for manifests.
        pass

    # PyPI registry evidence directories are scoped to this run/output.
    # Historical global output/pypi_cache remains untouched but is no longer
    # the default evidence source.
    out_path = Path(args.out)
    if not out_path.is_absolute():
        out_path = ROOT / out_path
    run_artifact_root = out_path.parent

    if args.registry_cache_dir:
        cache_dir = Path(args.registry_cache_dir)
        if not cache_dir.is_absolute():
            cache_dir = ROOT / cache_dir
    elif args.no_cache:
        cache_dir = None
    else:
        cache_dir = run_artifact_root / "registry_cache"

    if args.registry_snapshot_dir:
        registry_snapshot_dir = Path(args.registry_snapshot_dir)
        if not registry_snapshot_dir.is_absolute():
            registry_snapshot_dir = ROOT / registry_snapshot_dir
    else:
        registry_snapshot_dir = run_artifact_root / "registry_snapshot"

    registry_snapshot_dir.mkdir(parents=True, exist_ok=True)
    if cache_dir is not None:
        cache_dir.mkdir(parents=True, exist_ok=True)
    registry_run_id = (
        str(args.registry_run_id).strip()
        or run_artifact_root.name
        or "run"
    )

    # =========================
    # 3. 读取输入样本
    # =========================

    samples = read_jsonl(Path(args.samples))

    # all_rows：保存所有依赖检测记录。
    # risk_rows：保存第一阶段生成的初始 Risk Card。
    all_rows: List[Dict[str, Any]] = []
    risk_rows: List[Dict[str, Any]] = []

    # 如果命令行传入全局 requirements，则先抽取这些依赖。
    # 大多数当前样本使用 sample 自带 requirements_text，所以这里通常为空。
    req_entities = []
    if args.requirements:
        req_entities = extract_requirements(Path(args.requirements))

    # =========================
    # 4. 逐条处理 sample
    # =========================

    for sample in samples:
        sample_id = sample.get("sample_id", "unknown_sample")
        generation_time = sample.get("generation_time")
        code = sample.get("generated_code", "")

        sample_project_root = None
        if project_snapshots_dir is not None:
            candidate_root = project_snapshots_dir / str(sample_id)
            if candidate_root.exists():
                sample_project_root = candidate_root
        elif legacy_repo is not None:
            sample_project_root = legacy_repo

        identity_service = PackageIdentityService(
            policy_path=identity_policy_path,
            project_root=sample_project_root,
        )

        # 记录代码语法解析状态。
        # 即使语法错误，也仍然尝试进入后续流程，但会在记录中保留 parse error。
        code_parse_status = "ok"
        code_parse_error = ""

        try:
            ast.parse(code)
        except SyntaxError as e:
            code_parse_status = "syntax_error"
            code_parse_error = f"{e.msg} at line {e.lineno}, column {e.offset}"

        # 4.1 从 generated_code 中抽取 import 依赖。
        # extractor.py 内部使用 AST，只会抽真实 import，不会抽注释或字符串里的假包名。
        import_entities = extract_imports_from_code(
            code,
            file_name=f"{sample_id}.py",
        )

        # 4.2 Manifest dependency facts use the project snapshot as the
        # repair-line authority. This covers requirements.txt, pyproject.toml,
        # setup.cfg, literal setup.py install_requires, and Pipfile. Legacy
        # runs without a project snapshot keep the historical requirements_text
        # fallback.
        project_manifest_fact_index: dict[
            tuple[str, str, int], dict[str, Any]
        ] = {}
        if sample_project_root is not None:
            project_facts = collect_project_dependency_facts(
                sample_project_root,
                identity_policy_path=identity_policy_path,
            )
            sample_req_entities = []
            for rows in project_facts.get("manifests", {}).values():
                for fact in rows:
                    raw_name = str(fact.get("raw_name") or "").strip()
                    file_name = str(fact.get("file") or "manifest")
                    line = int(fact.get("line") or 0)
                    if not raw_name:
                        continue
                    entity = DependencyEntity(
                        raw_name=raw_name,
                        source_type="manifest",
                        file=file_name,
                        line=line,
                        original_text=(
                            raw_name
                            + str(fact.get("raw_specifier") or "")
                        ),
                    )
                    sample_req_entities.append(entity)
                    project_manifest_fact_index[
                        (raw_name, file_name, line)
                    ] = fact
        else:
            sample_req_entities = extract_requirements_from_text(
                sample.get("requirements_text", ""),
                file_name=f"{sample_id}_requirements.txt",
            )

        # 4.3 合并全局 requirements 和 sample/project manifest 依赖。
        manifest_entities = list(req_entities) + sample_req_entities

        # manifest_names 是 requirements 中声明过的包名集合。
        # 后面用于判断某个依赖是否 manifest_declared。
        manifest_names = {
            identity_service.resolve(
                raw_name=e.raw_name,
                source_type=e.source_type,
                import_path=e.import_path,
            ).normalized_distribution
            for e in manifest_entities
        }

        # Import and manifest identity now use the same versioned service.
        import_names = {
            identity_service.resolve(
                raw_name=e.raw_name,
                source_type=e.source_type,
                import_path=e.import_path,
            ).normalized_distribution
            for e in import_entities
        }

        manifest_only_entities = [
            e
            for e in manifest_entities
            if identity_service.resolve(
                raw_name=e.raw_name,
                source_type=e.source_type,
                import_path=e.import_path,
            ).normalized_distribution
            not in import_names
        ]

        # 合并 import 依赖和 manifest-only 依赖，并去重。
        entities = import_entities + manifest_only_entities
        entities = deduplicate_entities(entities)

        # =========================
        # 5. 逐个处理依赖实体
        # =========================

        for entity in entities:
            project_dependency_fact = project_manifest_fact_index.get(
                (entity.raw_name, entity.file, entity.line)
            )
            # 5.1 import 名映射到 PyPI distribution 名，并进行 PEP503 规范化。
            identity = identity_service.resolve(
                raw_name=entity.raw_name,
                source_type=entity.source_type,
                import_path=entity.import_path,
            )
            normalized = identity.normalized_distribution

            entity.mapped_name = normalized
            entity.normalized_name = normalized
            entity.is_local_module = (
                identity.identity_status == "local_module"
            )
            entity.is_false_positive = (
                identity.identity_status == "stdlib"
            )

            # All pipelines share these exclusion semantics.
            if identity.identity_status != "distribution_candidate":
                if identity.identity_status == "local_module":
                    status = "local_module"
                elif identity.identity_status == "private_unknown":
                    status = "private_unknown"
                else:
                    status = "filtered_false_positive"

                row = {
                    "sample_id": sample_id,
                    "prompt_id": sample.get("prompt_id"),
                    "model": sample.get("model"),
                    "generation_time": generation_time,
                    "raw_name": entity.raw_name,
                    "code_parse_status": code_parse_status,
                    "code_parse_error": code_parse_error,
                    "package": entity.mapped_name,
                    "package_identity": identity.to_dict(),
                    "identity_policy_version": identity.policy_version,
                    "legacy_false_positive_hint": (
                        identity.legacy_false_positive_hint
                    ),
                    "source_type": entity.source_type,
                    "project_dependency_fact": project_dependency_fact,
                    "location": {"file": entity.file, "line": entity.line},
                    "install_reachability": (
                        "manifest_declared"
                        if normalized in manifest_names
                        else infer_reachability(entity.source_type)
                    ),
                    "status": status,
                    "false_positive_filtered": entity.is_false_positive,
                    "local_module_filtered": entity.is_local_module,
                    "pypi": None,
                }

                all_rows.append(row)
                continue

            # =========================
            # 6. 查询 PyPI 并分类状态
            # =========================

            # 6.1 查询 PyPI，得到 exists_now、first_release_time、latest_version 等证据。
            pypi_evidence = query_pypi(
                entity.mapped_name,
                cache_dir=cache_dir,
                snapshot_dir=registry_snapshot_dir,
                positive_ttl_seconds=args.registry_positive_ttl_seconds,
                negative_ttl_seconds=args.registry_negative_ttl_seconds,
                not_before=generation_time,
                run_id=registry_run_id,
            )

            # 6.2 根据 PyPI 证据和 generation_time 生成第一阶段 status。
            # 注意：
            #   这里是第一阶段 status；
            #   后续 enrich_temporal_status.py 会进一步生成 temporal_status_v2。
            status = classify_package_status(
                exists_now=pypi_evidence.exists_now,
                first_release_time=pypi_evidence.first_release_time,
                generation_time=generation_time,
                error=pypi_evidence.error,
            )

            # 6.3 初始安装可达性。
            # 如果该包在 requirements 中出现，则是 manifest_declared；
            # 否则根据来源判断，多数 import 来源为 import_only。
            reachability = (
                "manifest_declared"
                if normalized in manifest_names
                else infer_reachability(entity.source_type)
            )

            # 6.4 构建依赖检测记录。
            row = {
                "sample_id": sample_id,
                "prompt_id": sample.get("prompt_id"),
                "model": sample.get("model"),
                "generation_time": generation_time,
                "raw_name": entity.raw_name,
                "code_parse_status": code_parse_status,
                "code_parse_error": code_parse_error,
                "package": entity.mapped_name,
                "package_identity": identity.to_dict(),
                "identity_policy_version": identity.policy_version,
                "source_type": entity.source_type,
                "project_dependency_fact": project_dependency_fact,
                "location": {"file": entity.file, "line": entity.line},
                "install_reachability": reachability,
                "status": status,
                "false_positive_filtered": False,
                "local_module_filtered": False,
                "pypi": pypi_evidence.to_dict(),
            }

            all_rows.append(row)

            # =========================
            # 7. 生成第一阶段 Risk Card
            # =========================

            # build_risk_card 会根据当前 status、PyPI 证据和 reachability 判断是否需要报警。
            # 如果没有风险，返回 None。
            card = build_risk_card(
                sample_id,
                entity,
                pypi_evidence,
                generation_time,
                reachability_override=reachability,
            )

            if card is not None:
                risk_rows.append(card.to_dict())

    # =========================
    # 8. 输出结果文件
    # =========================

    # 输出所有依赖检测记录
    write_jsonl(out_path, all_rows)

    # 输出第一阶段 Risk Card
    write_jsonl(Path(args.risk_out), risk_rows)

    summary_out = Path(args.summary_out)
    benchmark_out = Path(args.benchmark_out)
    benchmark_summary_out = Path(args.benchmark_summary_out)
    review_template_out = Path(args.review_template_out)

    # 输出 Markdown 汇总报告
    write_summary_report(
        summary_out,
        all_rows,
        risk_rows,
    )

    # 输出 GenDepRiskBench 风格 JSONL
    write_benchmark_jsonl(
        benchmark_out,
        all_rows,
        risk_rows,
    )

    # 输出 benchmark summary
    write_benchmark_summary(
        benchmark_out,
        benchmark_summary_out,
    )

    # 输出人工复核 CSV 模板
    write_manual_review_template(
        benchmark_out,
        review_template_out,
    )

    # =========================
    # 9. 打印运行统计
    # =========================

    print(
        f"[OK] package identity policy: "
        f"{PackageIdentityService(policy_path=identity_policy_path).policy_version}"
    )
    print(f"[OK] registry run id: {registry_run_id}")
    print(f"[OK] registry snapshot dir: {registry_snapshot_dir}")
    print(
        "[OK] registry cache dir: "
        + (str(cache_dir) if cache_dir is not None else "disabled")
    )
    print(f"[OK] total dependency records: {len(all_rows)}")
    print(f"[OK] risk cards: {len(risk_rows)}")
    print(f"[OK] result saved to: {args.out}")
    print(f"[OK] risk cards saved to: {args.risk_out}")
    print(f"[OK] summary report saved to: {summary_out}")
    print(f"[OK] benchmark samples saved to: {benchmark_out}")
    print(f"[OK] benchmark summary saved to: {benchmark_summary_out}")
    print(f"[OK] manual review template saved to: {review_template_out}")


if __name__ == "__main__":
    main()
