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
    deduplicate_entities,
    extract_imports_from_code,
    extract_requirements,
    extract_requirements_from_text,
    find_local_modules,
)
from normalizer import (
    load_false_positive_packages,
    load_import_mapping,
    map_import_path_to_distribution,
    map_import_to_distribution,
    pep503_normalize,
)
from pypi_client import query_pypi
from risk_card import build_risk_card, classify_package_status, infer_reachability
from report_writer import write_summary_report
from benchmark_writer import write_benchmark_jsonl
from benchmark_summary_writer import write_benchmark_summary
from review_template_writer import write_manual_review_template


# 项目根目录。当前文件位于 src/ 下，因此 parents[1] 回到项目根目录。
ROOT = Path(__file__).resolve().parents[1]

def map_dependency_entity(entity, mapping: Dict[str, str]) -> str:
    """
    将 DependencyEntity 映射到 PyPI distribution 名。

    import 来源：
        优先使用完整 import_path 做最长前缀匹配。

    manifest 来源：
        requirements 中本身就是 distribution 名，
        继续使用原来的 raw_name 映射。
    """
    if entity.source_type == "import":
        return map_import_path_to_distribution(
            raw_name=entity.raw_name,
            import_path=entity.import_path,
            mapping=mapping,
        )

    return map_import_to_distribution(
        entity.raw_name,
        mapping,
    )

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
        help="Optional repo path for local module filtering",
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

    # 是否禁用 PyPI 查询缓存
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable PyPI query cache",
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
    mapping = load_import_mapping(ROOT / "config" / "import_mapping.json")

    # false positive 过滤列表。
    # 用于过滤一些已知不应该作为 PyPI 第三方依赖风险分析的名称。
    false_positive_packages = load_false_positive_packages(
        ROOT / "config" / "false_positive_packages.csv"
    )

    # 如果提供 repo 路径，则扫描本地模块。
    # 例如项目里有 utils.py，则 import utils 不应该被当成 PyPI 包。
    local_modules = find_local_modules(Path(args.repo)) if args.repo else set()

    # PyPI 查询缓存目录。
    # 默认启用缓存，避免同一个包反复请求 PyPI。
    cache_dir = None if args.no_cache else ROOT / "output" / "pypi_cache"

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

        # 4.2 从当前 sample 的 requirements_text 中抽取 manifest 依赖。
        sample_req_entities = extract_requirements_from_text(
            sample.get("requirements_text", ""),
            file_name=f"{sample_id}_requirements.txt",
        )

        # 4.3 合并全局 requirements 和 sample 级 requirements。
        manifest_entities = list(req_entities) + sample_req_entities

        # manifest_names 是 requirements 中声明过的包名集合。
        # 后面用于判断某个依赖是否 manifest_declared。
        manifest_names = {
            pep503_normalize(map_dependency_entity(e, mapping))
            for e in manifest_entities
        }

        # import_names 是代码 import 中出现过的包名集合。
        import_names = {
            pep503_normalize(map_dependency_entity(e, mapping))
            for e in import_entities
        }

        # 只在 requirements 里出现，但没有在代码 import 中出现的依赖，也需要保留。
        # 例如 requirements 里声明了某个包，但代码中暂时没有 import。
        manifest_only_entities = [
            e
            for e in manifest_entities
            if pep503_normalize(
                map_dependency_entity(e, mapping)
            )
               not in import_names
        ]

        # 合并 import 依赖和 manifest-only 依赖，并去重。
        entities = import_entities + manifest_only_entities
        entities = deduplicate_entities(entities)

        # =========================
        # 5. 逐个处理依赖实体
        # =========================

        for entity in entities:
            # 5.1 import 名映射到 PyPI distribution 名，并进行 PEP503 规范化。
            mapped = map_dependency_entity(
                entity,
                mapping,
            )
            normalized = pep503_normalize(mapped)

            entity.mapped_name = normalized
            entity.normalized_name = normalized

            # 5.2 检查是否是 Python 标准库。
            # 例如 os / sys / json / pathlib 不应该进入 PyPI 风险判断。
            top_level_name = entity.raw_name.split(".")[0]
            is_stdlib = top_level_name in sys.stdlib_module_names

            # 5.3 检查是否是本地模块。
            # 例如项目中有 utils.py，则 import utils 应该视为本地模块。
            normalized_local_modules = {pep503_normalize(x) for x in local_modules}
            entity.is_local_module = (
                entity.raw_name in local_modules
                or normalized in normalized_local_modules
            )

            # 5.4 标记 false positive。
            # 标准库、配置文件中的 false positive，都不进入 PyPI 查询。
            entity.is_false_positive = (
                is_stdlib
                or normalized in false_positive_packages
                or pep503_normalize(entity.raw_name) in false_positive_packages
            )

            # 5.5 如果是标准库 / false positive / 本地模块，则跳过 PyPI 查询。
            # 这样可以避免把 os、json、pathlib、本地 utils 等误判成不存在的 PyPI 包。
            if entity.is_false_positive or entity.is_local_module:
                status = (
                    "filtered_false_positive"
                    if entity.is_false_positive
                    else "local_module"
                )

                row = {
                    "sample_id": sample_id,
                    "prompt_id": sample.get("prompt_id"),
                    "model": sample.get("model"),
                    "generation_time": generation_time,
                    "raw_name": entity.raw_name,
                    "code_parse_status": code_parse_status,
                    "code_parse_error": code_parse_error,
                    "package": entity.mapped_name,
                    "source_type": entity.source_type,
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
            pypi_evidence = query_pypi(entity.mapped_name, cache_dir=cache_dir)

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
                "source_type": entity.source_type,
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
    write_jsonl(Path(args.out), all_rows)

    # 输出第一阶段 Risk Card
    write_jsonl(Path(args.risk_out), risk_rows)

    # 输出 Markdown 汇总报告
    write_summary_report(
        ROOT / "output" / "summary_report.md",
        all_rows,
        risk_rows,
    )

    # 输出 GenDepRiskBench 风格 JSONL
    write_benchmark_jsonl(
        ROOT / "output" / "gen_dep_risk_bench_sample.jsonl",
        all_rows,
        risk_rows,
    )

    # 输出 benchmark summary
    write_benchmark_summary(
        ROOT / "output" / "gen_dep_risk_bench_sample.jsonl",
        ROOT / "output" / "benchmark_summary.md",
    )

    # 输出人工复核 CSV 模板
    write_manual_review_template(
        ROOT / "output" / "gen_dep_risk_bench_sample.jsonl",
        ROOT / "output" / "manual_review_template.csv",
    )

    # =========================
    # 9. 打印运行统计
    # =========================

    print(f"[OK] total dependency records: {len(all_rows)}")
    print(f"[OK] risk cards: {len(risk_rows)}")
    print(f"[OK] result saved to: {args.out}")
    print(f"[OK] risk cards saved to: {args.risk_out}")
    print(f"[OK] summary report saved to: {ROOT / 'output' / 'summary_report.md'}")
    print(f"[OK] benchmark samples saved to: {ROOT / 'output' / 'gen_dep_risk_bench_sample.jsonl'}")
    print(f"[OK] benchmark summary saved to: {ROOT / 'output' / 'benchmark_summary.md'}")
    print(f"[OK] manual review template saved to: {ROOT / 'output' / 'manual_review_template.csv'}")


if __name__ == "__main__":
    main()
