"""
build_temporal_risk_cards.py

作用：
    CodeSentry-Gen 的最终 THO Risk Card v2 生成模块。
    根据 temporal_status_v2 和 install_reachability_v2 判断是否生成风险卡。

输入：
    - temporal / reachability enriched JSONL
      推荐输入：
        output/pilot50_reachability_v2_enriched.jsonl
        output/risk_seed_validation_reachability_v2_enriched.jsonl

输出：
    - temporal risk cards JSONL
      每一行是一张 Risk Card
    - temporal risk summary Markdown

核心输入字段：
    - temporal_status_v2：
      由 enrich_temporal_status.py 生成，用于判断时态状态。
    - install_reachability_v2：
      由 enrich_reachability_v2.py 生成，用于判断安装可达性。
    - pypi：
      PyPI 查询证据，包括 exists_now、first_release_time、audit_time 等。
    - reachability_v2_evidence：
      requirements / Docker / CI 证据链。

主要风险规则：
    - nonexistent_now：
      包当前在 PyPI 明确不存在，生成 temporal_package_hallucination。
    - created_after_tg：
      包首次发布时间晚于代码生成时间，生成 hijackable_dependency 子类型。
    - existed_at_tg / filtered_false_positive / registry_query_error：
      不生成风险卡。

在整体流程中的位置：
    enrich_temporal_status.py
        ↓
    enrich_reachability_v2.py
        ↓
    build_temporal_risk_cards.py
        ↓
    validation summary

注意：
    本输出用于 pilot 阶段验证风险检测链路。
    风险种子样本用于验证“该报能报”，不用于估计真实 LLM 风险比例。
"""

import json
import argparse
import hashlib
from pathlib import Path
from collections import Counter


BASE_DIR = Path(__file__).resolve().parent.parent

# 默认输入输出路径配置
DEFAULT_INPUT_PATH = BASE_DIR / "output" / "pilot50_reachability_v2_enriched.jsonl"
DEFAULT_OUTPUT_PATH = BASE_DIR / "output" / "temporal_risk_cards_v2_pilot50_reachability_v2.jsonl"
DEFAULT_SUMMARY_PATH = BASE_DIR / "output" / "temporal_risk_summary_pilot50_reachability_v2.md"


# 高可达性级别集合：表示包可以通过某种方式安装
HIGH_REACHABILITY = {
    "manifest_declared",      # 在依赖清单中声明
    "lockfile_resolved",      # 在锁文件中解析
    "docker_installable",     # docker 环境中可安装
    "ci_installable",         # CI 环境中可安装
    "install_script_executable",  # 安装脚本可执行
}

def get_reachability(record):
    """
    优先使用 install_reachability_v2。
    如果没有 v2 字段，则回退到旧的 install_reachability。
    """
    return record.get("install_reachability_v2") or record.get("install_reachability", "unknown")

def is_manifest_only_without_import(record):
    """
    判断是否是 manifest-only dependency mismatch。

    当前 run_pilot.py 里有一个特点：
    - 如果一个包只出现在 requirements / manifest 里，source_type 通常是 manifest；
    - 如果一个包同时出现在 import 和 requirements 里，source_type 通常还是 import，
      只是 reachability 会变成 manifest_declared。

    所以这里用 source_type == manifest / requirements 来判断：
    这个包是 requirements 里声明了，但代码里没有 import。
    """
    source_type = record.get("source_type")
    reachability = get_reachability(record)

    return (
        source_type in {"manifest", "requirements"}
        and reachability == "manifest_declared"
    )

def get_manifest_only_evidence(record):
    """
    读取 manifest-only 自动校准结果。

    没有经过 evidence enrichment 的旧数据会返回空标签，
    后续继续使用原来的兼容规则。
    """
    evidence = record.get(
        "manifest_only_evidence"
    )

    if not isinstance(evidence, dict):
        evidence = {}

    label = (
        record.get(
            "manifest_only_evidence_label"
        )
        or evidence.get("label")
        or ""
    )

    return {
        "label": label,
        "risk_candidate": record.get(
            "manifest_only_risk_candidate"
        ),
        "evidence_level": (
                record.get(
                    "manifest_only_evidence_level"
                )
                or evidence.get(
            "recommended_evidence_level"
        )
                or ""
        ),
        "review_priority": (
                record.get(
                    "manifest_only_review_priority"
                )
                or evidence.get(
            "recommended_review_priority"
        )
                or ""
        ),
        "evidence": evidence,
    }

def read_jsonl(path: Path):
    """读取 JSONL 文件，逐行返回解析后的字典对象"""
    if not path.exists():
        raise FileNotFoundError(f"找不到文件：{path}")

    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def make_risk_id(record: dict) -> str:
    """
    基于记录的关键字段生成唯一的风险 ID
    
    使用 sample_id、package、source_type、location 等信息的哈希值
    确保同一风险点在不同运行中产生相同的 ID
    """
    base = "|".join([
        str(record.get("sample_id", "")),
        str(record.get("package", "")),
        str(record.get("source_type", "")),
        str((record.get("location") or {}).get("file", "")),
        str((record.get("location") or {}).get("line", "")),
        str(record.get("temporal_status_v2", "")),
    ])
    return hashlib.sha256(base.encode("utf-8")).hexdigest()[:16]


def classify_risk(record: dict):
    """
    根据 temporal_status_v2 和安装可达性进行风险分类。

    THO 最小版本分类规则：
    1. nonexistent_now + manifest_declared 及以上 => high severity
    2. created_after_tg + manifest_declared 及以上 => high severity  
    3. nonexistent_now / created_after_tg + import_only => medium severity
    4. existed_at_tg / filtered_false_positive 不生成风险卡

    Returns:
        dict: 风险分类决策，包含 risk_type、severity、confidence 等字段
        None: 如果该记录不应生成风险卡
    """
    temporal_status = record.get("temporal_status_v2") or record.get("status")
    reachability = get_reachability(record)

    # 过滤掉误报和本地私有包，不生成风险卡
    if temporal_status in {"filtered_false_positive", "local_or_private_unknown"}:
        return None

    # 新增规则：
    # 如果依赖只出现在 requirements / manifest 中，
    # 但是没有出现在 generated code 的 import 中，
    # 则认为 requirements 与代码引用不一致，生成 Risk Card。
    #
    # 注意：
    # 这个风险不是“包不存在”，而是“依赖声明和代码使用不一致”。
    if (
            temporal_status == "existed_at_tg"
            and is_manifest_only_without_import(record)
    ):
        manifest_evidence = (
            get_manifest_only_evidence(record)
        )

        evidence_label = manifest_evidence[
            "label"
        ]

        evidence_level = str(
            manifest_evidence.get(
                "evidence_level",
                "",
            )
            or "unknown"
        )

        review_priority = str(
            manifest_evidence.get(
                "review_priority",
                "",
            )
            or "medium"
        )

        # 已经找到直接 import 证据。
        # 原来的 mismatch 是 import-to-distribution
        # 映射不完整产生的误报，不生成 Risk Card。
        if evidence_label == "direct_import_backed":
            return None

        # 没有直接 import，但它是代码实际使用包的
        # 必要间接依赖。保留低风险提示。
        if (
                evidence_label
                == "transitive_dependency_backed"
        ):
            return {
                "risk_type": (
                    "dependency_declaration_mismatch"
                ),
                "subtype": (
                    "manifest_only_transitive_backed"
                ),
                "status": "weak",
                "severity": "low",
                "evidence_level": evidence_level,
                "review_priority": review_priority,
                "reason": (
                    "A required dependency path from a "
                    "directly used distribution supports "
                    "the manifest declaration."
                ),
            }

        # 没有直接 import，但它是直接使用包的
        # 可选 extra 依赖。
        if (
                evidence_label
                == "optional_extra_dependency"
        ):
            return {
                "risk_type": (
                    "dependency_declaration_mismatch"
                ),
                "subtype": (
                    "manifest_only_optional_extra"
                ),
                "status": "weak",
                "severity": "low",
                "evidence_level": evidence_level,
                "review_priority": review_priority,
                "reason": (
                        "An optional-extra dependency path "
                        "supports the manifest declaration, "
                        "but only when the corresponding "
                        "extra is selected."
                ),
            }

        if (
                evidence_label
                == "conditional_dependency_backed"
        ):
            return {
                "risk_type": (
                    "dependency_declaration_mismatch"
                ),
                "subtype": (
                    "manifest_only_conditional_backed"
                ),
                "status": "weak",
                "severity": "low",
                "evidence_level": evidence_level,
                "review_priority": review_priority,
                "reason": (
                    "A conditional dependency path "
                    "supports the manifest declaration, "
                    "subject to environment markers."
                ),
            }

        # 没找到直接、间接、可选或条件依赖证据。
        if evidence_label == "no_dependency_evidence":
            return {
                "risk_type": (
                    "dependency_declaration_mismatch"
                ),
                "subtype": (
                    "manifest_only_unexplained"
                ),
                "status": "probable",
                "severity": "medium",
                "evidence_level": evidence_level,
                "review_priority": review_priority,
                "reason": (
                    "The package is declared in the "
                    "manifest, but no direct import or "
                    "dependency-chain evidence was found."
                ),
            }

        # 兼容尚未执行 evidence enrichment 的旧数据集，
        # 例如当前 controlled boundary validation。
        return {
            "risk_type": (
                "dependency_declaration_mismatch"
            ),
            "subtype": (
                "manifest_only_without_import"
            ),
            "status": "probable",
            "severity": "medium",
            "evidence_level": "unknown",
            "review_priority": "high",
            "reason": (
                "Package is declared in requirements or "
                "manifest, but no corresponding import "
                "is found in the generated code. "
                "No enriched dependency evidence is available."
            ),
        }

    # 包在生成时已存在，且不是 manifest-only mismatch，则无风险
    if temporal_status == "existed_at_tg":
        return None

    # 包在审计时不存在于 PyPI
    if temporal_status == "nonexistent_now":
        if reachability in HIGH_REACHABILITY:
            # 高可达性：高风险，可能是幻觉包但可通过其他方式安装
            return {
                "risk_type": "temporal_package_hallucination",
                "subtype": None,
                "status": "confirmed",
                "severity": "high",
                "confidence": 0.95,
                "reason": "Package is install-reachable but does not exist in PyPI at audit time."
            }
        else:
            # 低可达性：中等风险，仅被导入但无法安装
            return {
                "risk_type": "temporal_package_hallucination",
                "subtype": None,
                "status": "probable",
                "severity": "medium",
                "confidence": 0.80,
                "reason": "Package is imported but does not exist in PyPI at audit time."
            }

    # 包在生成时间之后创建，存在劫持风险
    if temporal_status == "created_after_tg":
        if reachability in HIGH_REACHABILITY:
            # 高可达性：高风险，新发布的包可能被恶意劫持
            return {
                "risk_type": "temporal_package_hallucination",
                "subtype": "hijackable_dependency",
                "status": "probable",
                "severity": "high",
                "confidence": 0.90,
                "reason": "Package exists now, but its first release time is later than generation_time and it is install-reachable."
            }
        else:
            # 低可达性：中等风险
            return {
                "risk_type": "temporal_package_hallucination",
                "subtype": "hijackable_dependency",
                "status": "probable",
                "severity": "medium",
                "confidence": 0.75,
                "reason": "Package exists now, but its first release time is later than generation_time."
            }

    # 时序状态不确定
    if temporal_status == "temporal_unknown":
        return {
            "risk_type": "temporal_package_hallucination",
            "subtype": None,
            "status": "weak",
            "severity": "low",
            "confidence": 0.50,
            "reason": "Package temporal status is uncertain because release time overlaps with generation time uncertainty."
        }

    return None


def build_risk_card(record: dict, decision: dict) -> dict:
    """
    构建完整的风险卡片数据结构
    
    Args:
        record: 原始记录数据
        decision: classify_risk 返回的风险分类决策
        
    Returns:
        dict: 包含完整风险信息的卡片结构
    """
    pypi = record.get("pypi") or {}
    location = record.get("location") or {}

    temporal_status = record.get("temporal_status_v2") or record.get("status")

    if decision["risk_type"] == "dependency_declaration_mismatch":
        title = f"Dependency declaration mismatch: {record.get('package')}"
    else:
        title = f"Temporal dependency risk: {record.get('package')}"

    card = {
        "schema_version": "pilot_v0.2",  # 风险卡片 schema 版本
        "risk_id": make_risk_id(record),  # 唯一风险标识
        "sample_id": record.get("sample_id"),
        "prompt_id": record.get("prompt_id"),
        "model": record.get("model"),
        "title": title,
        "type": decision["risk_type"],
        "subtype": decision["subtype"],
        "status": decision["status"],
        "severity": decision["severity"],
        # 风险引入位置信息
        "introduced_by": {
            "file": location.get("file"),
            "line": location.get("line"),
            "entity": record.get("package"),
            "raw_name": record.get("raw_name"),
            "source_type": record.get("source_type"),
        },
        # 安装可达性信息
        "install_reachability": {
        "level": get_reachability(record),
        "original_level": record.get("install_reachability"),
        "v2_level": record.get("install_reachability_v2"),
        "evidence": record.get("reachability_v2_evidence"),
        },
        # 证据链：结构化、时序、生态系统三个维度
        "evidence": {
            "structural": [
                {
                    "kind": record.get("source_type"),
                    "file": location.get("file"),
                    "line": location.get("line"),
                    "raw_name": record.get("raw_name"),
                    "package": record.get("package"),
                }
            ],
            "temporal": [
                {
                    "generation_time": record.get("generation_time"),
                    "first_release_time": pypi.get("first_release_time"),
                    "audit_time": pypi.get("audit_time"),
                    "temporal_status": temporal_status,
                }
            ],
            "ecosystem": [
                {
                    "ecosystem": "pypi",
                    "exists_now": pypi.get("exists_now"),
                    "query_url": pypi.get("query_url"),
                    "status_code": pypi.get("status_code"),
                    "offline_pypi_exists": record.get("offline_pypi_exists"),
                    "reference_false_positive": record.get("reference_false_positive"),
                }
            ],
            "manifest_only": (
                record.get(
                    "manifest_only_evidence"
                )
                if isinstance(
                    record.get(
                        "manifest_only_evidence"
                    ),
                    dict,
                )
                else None
            ),
            "reason": decision["reason"],
        },
        # 归因分析：可观察标签和假设
        "attribution": {
            "observable_labels": build_observable_labels(record),
            "hypotheses": build_hypotheses(record),
        },
        # 修复建议
        "repair": build_repair(record),
    }

    # THO 时态风险目前仍保留原有 numeric confidence。
    # manifest-only 声明一致性风险改用离散证据等级，
    # 不再强行提供没有实验依据的概率数值。
    if "confidence" in decision:
        card["confidence"] = decision[
            "confidence"
        ]

    if "evidence_level" in decision:
        card["evidence_level"] = decision[
            "evidence_level"
        ]

    if "review_priority" in decision:
        card["review_priority"] = decision[
            "review_priority"
        ]

    return card


def build_observable_labels(record: dict):
    """
    构建可观察标签列表
    
    根据时序状态、可达性、模型类型等生成人类可读的标签
    """
    labels = []

    temporal_status = record.get("temporal_status_v2") or record.get("status")

    if temporal_status == "nonexistent_now":
        labels.append("nonexistent_now")

    if temporal_status == "created_after_tg":
        labels.append("created_after_generation")

    if get_reachability(record) in HIGH_REACHABILITY:
        labels.append("install_reachable")

    if record.get("model") == "controlled_seed_manual":
        labels.append("controlled_seed")

    if is_manifest_only_without_import(record):
        labels.append(
            "manifest_only_without_import"
        )
        labels.append(
            "dependency_declaration_mismatch"
        )

        evidence_label = (
            get_manifest_only_evidence(
                record
            )["label"]
        )

        if evidence_label:
            labels.append(
                evidence_label
            )

    return labels


def build_hypotheses(record: dict):
    """
    构建风险归因假设列表
    
    根据不同时序状态提供最可能的风险原因假设，按可能性排序
    """
    temporal_status = record.get("temporal_status_v2") or record.get("status")

    if temporal_status == "created_after_tg":
        # 生成后创建的包：可能是注册劫持或 LLM 幻觉
        return [
            {
                "name": "registry_hijack",
                "rank": 1,
                "rationale": "The package was first released after generation_time and is install-reachable."
            },
            {
                "name": "llm_hallucination",
                "rank": 2,
                "rationale": "The package name appeared in generated code before it existed in PyPI."
            }
        ]

    if temporal_status == "nonexistent_now":
        # 当前不存在的包：主要是 LLM 幻觉
        return [
            {
                "name": "llm_hallucination",
                "rank": 1,
                "rationale": "The package is referenced by generated code but does not exist in PyPI at audit time."
            }
        ]

    # 其他情况：未知原因
    return [
        {
            "name": "unknown",
            "rank": 1,
            "rationale": "Insufficient evidence for a stronger attribution hypothesis."
        }
    ]


def build_repair(record: dict):
    """
    构建修复建议
    
    根据时序状态提供相应的修复动作和验证步骤
    """
    temporal_status = record.get("temporal_status_v2") or record.get("status")

    if is_manifest_only_without_import(record):
        return {
            "action": "review_or_remove_manifest_dependency",
            "command": None,
            "patch": None,
            "verify": "Check whether this dependency is actually used by the generated code. If not used, remove it from requirements or add the missing import/use if it is intended."
        }

    if temporal_status == "nonexistent_now":
        # 不存在的包：建议移除或审查
        return {
            "action": "remove_or_review",
            "command": None,
            "patch": None,
            "verify": "Remove or replace this dependency, then rerun dependency installation and tests."
        }

    if temporal_status == "created_after_tg":
        # 生成后创建的包：需要人工审查是否合法
        return {
            "action": "review",
            "command": None,
            "patch": None,
            "verify": "Manually review whether this newly released package is legitimate before installation."
        }

    # 默认：通用审查建议
    return {
        "action": "review",
        "command": None,
        "patch": None,
        "verify": "Review the dependency evidence before making changes."
    }

def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(
        description="根据 temporal_status_v2 和 install_reachability 生成 THO 最小版 Risk Card"
    )

    parser.add_argument(
        "--input",
        default=str(DEFAULT_INPUT_PATH),
        help="输入 JSONL 文件路径，默认 output/pilot_temporal_enriched.jsonl"
    )

    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT_PATH),
        help="输出 Risk Card JSONL 文件路径，默认 output/temporal_risk_cards_v2.jsonl"
    )

    parser.add_argument(
        "--summary",
        default=str(DEFAULT_SUMMARY_PATH),
        help="输出 Markdown 摘要路径，默认 output/temporal_risk_summary.md"
    )

    return parser.parse_args()

def main():
    """主函数：读取输入、分类风险、生成卡片、输出结果"""
    args = parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)
    summary_path = Path(args.summary)

    # 确保路径为绝对路径
    if not input_path.is_absolute():
        input_path = BASE_DIR / input_path

    if not output_path.is_absolute():
        output_path = BASE_DIR / output_path

    if not summary_path.is_absolute():
        summary_path = BASE_DIR / summary_path

    risk_cards = []
    all_records = list(read_jsonl(input_path))

    # 统计计数器
    temporal_status_counter = Counter()
    severity_counter = Counter()
    risk_type_counter = Counter()

    # 遍历所有记录，生成风险卡片
    for record in all_records:
        temporal_status = record.get("temporal_status_v2") or record.get("status")
        temporal_status_counter[temporal_status] += 1

        decision = classify_risk(record)

        # 跳过不需要生成风险卡的记录
        if decision is None:
            continue

        card = build_risk_card(record, decision)
        risk_cards.append(card)

        severity_counter[card["severity"]] += 1
        risk_type_counter[card["type"]] += 1

    # 创建输出目录并写入风险卡片
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as f:
        for card in risk_cards:
            f.write(json.dumps(card, ensure_ascii=False) + "\n")

    # 生成 Markdown 摘要报告
    lines = []
    lines.append("# temporal risk cards v2 生成结果\n")
    lines.append(f"- 输入文件：`{input_path.relative_to(BASE_DIR)}`")
    lines.append(f"- 输出文件：`{output_path.relative_to(BASE_DIR)}`")
    lines.append(f"- 输入记录数：{len(all_records)}")
    lines.append(f"- 风险卡片数：{len(risk_cards)}\n")

    lines.append("## 1. temporal_status_v2 分布\n")
    lines.append("| temporal_status_v2 | count |")
    lines.append("|---|---:|")
    for status, count in temporal_status_counter.most_common():
        lines.append(f"| {status} | {count} |")

    lines.append("\n## 2. 风险类型分布\n")
    lines.append("| risk_type | count |")
    lines.append("|---|---:|")
    for risk_type, count in risk_type_counter.most_common():
        lines.append(f"| {risk_type} | {count} |")

    lines.append("\n## 3. 严重程度分布\n")
    lines.append("| severity | count |")
    lines.append("|---|---:|")
    for severity, count in severity_counter.most_common():
        lines.append(f"| {severity} | {count} |")

    lines.append("\n## 4. 风险卡片列表\n")
    lines.append("| risk_id | sample_id | package | temporal_status | reachability | severity | status |")
    lines.append("|---|---|---|---|---|---|---|")

    for card in risk_cards:
        temporal_evidence = card["evidence"]["temporal"][0]
        reachability = card["install_reachability"]["level"]
        lines.append(
            f"| {card['risk_id']} | {card.get('sample_id', '')} | "
            f"{card['introduced_by'].get('entity', '')} | "
            f"{temporal_evidence.get('temporal_status', '')} | "
            f"{reachability} | {card.get('severity', '')} | {card.get('status', '')} |"
        )

    lines.append("\n## 5. 说明\n")
    lines.append(
        "本步骤根据 `temporal_status_v2` 和安装可达性字段生成 THO 最小版风险卡片；如果存在 `install_reachability_v2`，则优先使用 v2 字段。"
        "`nonexistent_now` 表示包在审计时 PyPI 当前不存在；"
        "`created_after_tg` 表示包当前存在，但首次发布时间晚于代码生成时间。"
        "当前输出用于 pilot 阶段验证风险链路，不用于估计真实 LLM 风险比例。"
    )

    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text("\n".join(lines), encoding="utf-8")

    print("Risk Card v2 生成完成。")
    print("输出 JSONL：", output_path)
    print("输出摘要：", summary_path)
    print("风险卡片数：", len(risk_cards))


if __name__ == "__main__":
    main()