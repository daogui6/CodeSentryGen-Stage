import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path


# ROOT 表示项目根目录。
# 当前文件在 src/build_sceg_v0.py，
# Path(__file__).resolve().parents[1] 就是回到项目根目录 CodeSentryGen_Pilot。
ROOT = Path(__file__).resolve().parents[1]


# 这些 temporal_status 被认为是“有可能需要生成风险卡”的时态状态。
# nonexistent_now：包现在 PyPI 明确不存在
# created_after_tg：包现在存在，但首次发布时间晚于代码生成时间
# temporal_unknown：时间关系不确定，当前先作为风险候选保留
RISK_TEMPORAL_STATUSES = {
    "nonexistent_now",
    "created_after_tg",
    "temporal_unknown",
}


def norm_name(value):
    """
    用于规范化包名，主要用于 Risk Card 和 dependency record 的匹配。

    例如：
    PyYAML -> pyyaml
    python_dateutil -> python-dateutil
    google.api.client -> google-api-client

    这里做的是很轻量的规范化：
    1. 去掉前后空格
    2. 转小写
    3. 把下划线和点替换成横线
    """
    if value is None:
        return ""
    return str(value).strip().lower().replace("_", "-").replace(".", "-")


def read_jsonl(path: Path):
    """
    读取 JSONL 文件。

    JSONL 是一行一个 JSON 对象。
    例如：
    {"sample_id": "xxx", "package": "requests"}
    {"sample_id": "yyy", "package": "flask"}

    这个函数会返回一个 list，每个元素是一条 JSON 记录。
    """
    if not path.exists():
        raise FileNotFoundError(f"missing file: {path}")

    # 如果文件是空文件，比如 risk cards 数量为 0，就直接返回空列表。
    if path.stat().st_size == 0:
        return []

    rows = []

    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()

            if not line:
                continue

            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise ValueError(f"{path} line {line_no} is invalid json: {e}") from e

    return rows


def write_jsonl(path: Path, rows):
    """
    写出 JSONL 文件。

    rows 是一个列表，每个元素写成一行 JSON。
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def make_short_id(prefix: str, parts):
    """
    根据若干字段生成一个稳定的短 ID。

    为什么需要这个？
    因为 SCEG 里面需要给 dependency entity 和 graph record 一个稳定 ID。
    只要输入字段不变，生成出来的 ID 就不变，方便后续复现和链接。

    例如：
    prefix = "dep"  -> dep_xxxxxxxxxxxxxxxx
    prefix = "sceg" -> sceg_xxxxxxxxxxxxxxxx
    """
    text = "|".join("" if x is None else str(x) for x in parts)
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
    return f"{prefix}_{digest}"


def get_record_reachability(record):
    """
    获取依赖的安装可达性。

    优先使用 install_reachability_v2。
    如果没有 v2 字段，再回退到旧字段 install_reachability。

    这样做的原因是：
    旧流程里已经有 install_reachability；
    后来我们新增了更完整的 install_reachability_v2；
    为了兼容旧输出，所以这里做一个 fallback。
    """
    return record.get("install_reachability_v2") or record.get("install_reachability")


def get_record_temporal_status(record):
    """
    获取依赖的时态状态。

    优先使用 temporal_status_v2。
    如果没有 v2 字段，再回退到旧字段 status。
    """
    return record.get("temporal_status_v2") or record.get("status")

def get_declaration_consistency_evidence(record):
    """
    读取已经写回 dependency record 的 manifest-only 复核证据。

    这部分证据用于说明：
    requirements 中声明的依赖，与代码实际使用之间是什么关系。

    可能的分类包括：
    - direct_import_backed
    - transitive_dependency_backed
    - optional_extra_dependency
    - conditional_dependency_backed
    - no_dependency_evidence

    普通 import 记录没有这类证据时，返回 None。
    """
    raw_evidence = record.get(
        "manifest_only_evidence"
    )

    # 只有经过 manifest-only evidence enrichment 的记录，
    # 才会包含这个字典。
    if not isinstance(raw_evidence, dict):
        return None

    # 优先读取 dependency record 顶层的结果；
    # 如果顶层没有，再从完整证据对象中读取。
    label = (
        record.get(
            "manifest_only_evidence_label"
        )
        or raw_evidence.get("label")
    )

    risk_candidate = record.get(
        "manifest_only_risk_candidate"
    )

    if risk_candidate is None:
        risk_candidate = raw_evidence.get(
            "risk_candidate"
        )

    evidence_level = record.get(
        "manifest_only_evidence_level"
    )

    if evidence_level is None:
        evidence_level = raw_evidence.get(
            "recommended_evidence_level"
        )

    review_priority = record.get(
        "manifest_only_review_priority"
    )

    if review_priority is None:
        review_priority = raw_evidence.get(
            "recommended_review_priority"
        )

    return {
        "label": label,
        "risk_candidate": risk_candidate,
        "evidence_level": evidence_level,
        "review_priority": review_priority,

        "recommended_status": raw_evidence.get(
            "recommended_status"
        ),
        "recommended_severity": raw_evidence.get(
            "recommended_severity"
        ),

        # 第一层：直接 import 复核证据。
        "matched_by": raw_evidence.get(
            "matched_by"
        ),
        "matched_import_paths": raw_evidence.get(
            "matched_import_paths"
        ),
        "matched_wheel_prefixes": raw_evidence.get(
            "matched_wheel_prefixes"
        ),

        # 第二层：软件包依赖关系证据。
        "direct_distributions": raw_evidence.get(
            "direct_distributions"
        ),
        "dependency_evidence": raw_evidence.get(
            "dependency_evidence"
        ),

        "resolver_status": raw_evidence.get(
            "resolver_status"
        ),
        "resolver_error": raw_evidence.get(
            "resolver_error"
        ),

        "reason": raw_evidence.get(
            "reason"
        ),
        "source": raw_evidence.get(
            "source"
        ),
    }

def build_risk_card_index(risk_cards):
    """
    把 Risk Card 列表建立成一个索引，方便后面把 SCEG record 和 Risk Card 关联起来。

    索引 key 是：
    (sample_id, normalized_package_name)

    例如：
    ("controlled_001", "fake-llm-security-helper-xyz") -> [对应的 Risk Card]

    因为 dependency records 和 risk cards 原来是两个文件。
    SCEG 的目标是把证据和风险输出关联起来，所以这里先建立索引。
    """
    index = {}

    for card in risk_cards:
        sample_id = card.get("sample_id")

        introduced_by = card.get("introduced_by") or {}

        # 不同版本 Risk Card 里的包名字段可能不完全一样。
        # Step8 AVCS Risk Card 显式提供 distribution；API 场景下
        # introduced_by.entity 是 API symbol，不能当作包名。
        # 所以 package identity 优先级是：
        # 1. card.distribution
        # 2. card.package
        # 3. introduced_by.package
        # 4. legacy introduced_by.entity
        # 5. legacy temporal title
        package = (
            card.get("distribution")
            or card.get("package")
            or introduced_by.get("package")
            or introduced_by.get("entity")
            or card.get("title", "").replace(
                "Temporal dependency risk:", ""
            ).strip()
        )

        key = (sample_id, norm_name(package))
        index.setdefault(key, []).append(card)

    return index

def build_sceg_edges(
    entity_id,
    risk_card_links,
    declaration_consistency_evidence,
    trigger_evidence,
    avcs_evidence,
):
    """
    构建 SCEG v0 的边关系。

    之前的 SCEG v0 已经有 nodes 和 evidence，
    但是还没有显式说明它们之间是什么关系。

    这个函数就是把这些关系写成 edges。

    当前 v0 先使用轻量字符串节点名：
    - sample
    - dependency_entity
    - package
    - structural_evidence
    - registry_evidence
    - temporal_evidence
    - reachability_evidence

    后续如果要做更完整的图结构，可以再给每类 evidence 单独生成 evidence_id。
    """

    edges = [
        {
            "source": "sample",
            "target": entity_id,
            "type": "contains_dependency",
            "description": "The generated sample contains this dependency entity.",
        },
        {
            "source": entity_id,
            "target": "package",
            "type": "maps_to_package",
            "description": "The dependency entity is normalized or mapped to a package.",
        },
        {
            "source": entity_id,
            "target": "structural_evidence",
            "type": "has_structural_evidence",
            "description": "The dependency entity has structural evidence such as source type and location.",
        },
        {
            "source": entity_id,
            "target": "registry_evidence",
            "type": "has_registry_evidence",
            "description": "The dependency entity has registry evidence from PyPI or reference sources.",
        },
        {
            "source": entity_id,
            "target": "temporal_evidence",
            "type": "has_temporal_evidence",
            "description": "The dependency entity has temporal evidence such as generation time and first release time.",
        },
        {
            "source": entity_id,
            "target": "reachability_evidence",
            "type": "has_reachability_evidence",
            "description": "The dependency entity has install reachability evidence.",
        },
    ]

    # 只有当前 dependency record 确实包含
    # manifest-only 复核证据时，才增加这条关系边。
    if isinstance(
        declaration_consistency_evidence,
        dict,
    ):
        edges.append(
            {
                "source": entity_id,
                "target": (
                    "declaration_consistency_evidence"
                ),
                "type": (
                    "has_declaration_consistency_evidence"
                ),
                "description": (
                    "The dependency entity has declaration "
                    "consistency evidence derived from "
                    "direct-import and dependency-chain checks."
                ),
            }
        )

    # 只有当前 dependency record 确实包含
    # AVCS vulnerability trigger evidence 时，
    # 才增加 dependency entity -> trigger evidence 的关系边。
    if isinstance(
        trigger_evidence,
        dict,
    ):
        edges.append(
            {
                "source": entity_id,
                "target": "trigger_evidence",
                "type": "has_trigger_evidence",
                "description": (
                    "The dependency entity has vulnerability "
                    "trigger evidence from AVCS."
                ),
            }
        )

    # Step8 AVCS Risk Card 自带版本集合、API constraint、
    # advisory provenance 和 unknown boundary。把这些 provenance 作为
    # SCEG evidence 挂到 dependency entity，而不是只保留一条 card link。
    if isinstance(avcs_evidence, list) and avcs_evidence:
        edges.append(
            {
                "source": entity_id,
                "target": "avcs_evidence",
                "type": "has_avcs_evidence",
                "description": (
                    "The dependency entity has Step8 AVCS version, API-history, "
                    "vulnerability, and decision provenance."
                ),
            }
        )

    # 如果这条 SCEG record 对应了 Risk Card，
    # 就增加一条 dependency_entity -> risk_card 的边。
    #
    # positive control 里面应该会有这种边；
    # qwen37_100 和 hard negative 里面一般没有。
    for card in risk_card_links:
        risk_id = card.get("risk_id")

        if not risk_id:
            continue

        edges.append(
            {
                "source": entity_id,
                "target": risk_id,
                "type": "supports_risk_card",
                "description": "The dependency evidence supports a generated Risk Card.",
            }
        )

    return edges

def build_sceg_record(record, risk_index, dataset_label: str):
    """
    把一条原始 dependency record 转换成一条 SCEG v0 record。

    核心函数

    输入 record 来自：
    output/xxx_reachability_v2_enriched.jsonl

    输出 sceg_record 会分成几块：
    1. nodes：节点信息，包括 sample、dependency_entity、package
    2. evidence：证据，包括 structural、registry、temporal、reachability
    3. analysis：当前 THO mini 的判断结果
    4. risk_card_links：和 Risk Card 的链接
    """
    # -------------------------
    # 1. 读取样本级信息
    # -------------------------
    sample_id = record.get("sample_id")
    prompt_id = record.get("prompt_id")
    model = record.get("model")
    generation_time = record.get("generation_time")

    # -------------------------
    # 2. 读取依赖实体信息
    # -------------------------
    raw_name = record.get("raw_name")
    package = record.get("package")
    source_type = record.get("source_type")
    location = record.get("location") or {}

    # -------------------------
    # 3. 读取 PyPI 注册表证据
    # -------------------------
    pypi = record.get("pypi") or {}

    # -------------------------
    # 4. 读取时态状态和安装可达性
    # -------------------------
    temporal_status = get_record_temporal_status(record)
    reachability = get_record_reachability(record)
    reachability_evidence = record.get("reachability_v2_evidence") or {}

    trigger_evidence = record.get(
        "trigger_evidence"
    )

    # 读取 manifest-only 的依赖声明一致性证据。
    declaration_consistency_evidence = (
        get_declaration_consistency_evidence(
            record
        )
    )

    # -------------------------
    # 5. 生成 dependency entity ID
    # -------------------------
    entity_id = make_short_id(
        "dep",
        [
            sample_id,
            raw_name,
            package,
            source_type,
            location.get("file"),
            location.get("line"),
        ],
    )

    # -------------------------
    # 6. 生成整条 SCEG record 的 graph_id
    # -------------------------
    graph_id = make_short_id(
        "sceg",
        [
            dataset_label,
            sample_id,
            entity_id,
            temporal_status,
            reachability,
        ],
    )

    # -------------------------
    # 7. 查找当前 dependency record 是否有关联 Risk Card
    # -------------------------
    linked_cards = risk_index.get((sample_id, norm_name(package)), [])

    risk_card_links = []
    avcs_evidence = []

    for card in linked_cards:
        if (
            card.get("pipeline_origin") == "AVCS"
            or str(card.get("schema_version", "")).startswith(
                "step8_avcs_risk_card_"
            )
        ):
            avcs_evidence.append(
                {
                    "risk_id": card.get("risk_id"),
                    "distribution": card.get("distribution"),
                    "vulnerability_id": card.get("vulnerability_id"),
                    "actionability": card.get("actionability"),
                    "decision": card.get("decision"),
                    "version_evidence": card.get("version_evidence"),
                    "provenance": card.get("evidence"),
                    "unknowns": card.get("unknowns"),
                    "trigger_evidence": card.get("trigger_evidence"),
                    "repair": card.get("repair"),
                }
            )

    for card in linked_cards:
        risk_card_link = {
            "risk_id": card.get("risk_id"),
            "title": card.get("title"),
            "type": card.get("type"),
            "subtype": card.get("subtype"),
            "status": card.get("status"),
            "severity": card.get("severity"),
            "pipeline_origin": card.get("pipeline_origin"),
            "distribution": card.get("distribution"),
            "vulnerability_id": card.get("vulnerability_id"),
            "actionability": card.get("actionability"),
        }

        # THO 时态风险仍保留 numeric confidence。
        if "confidence" in card:
            risk_card_link[
                "confidence"
            ] = card[
                "confidence"
            ]

        # manifest-only 风险使用离散证据等级。
        if "evidence_level" in card:
            risk_card_link[
                "evidence_level"
            ] = card[
                "evidence_level"
            ]

        if "review_priority" in card:
            risk_card_link[
                "review_priority"
            ] = card[
                "review_priority"
            ]

        risk_card_links.append(
            risk_card_link
        )

    # 第一类风险候选：
    # 包当前不存在、生成后才出现，或者时态关系不确定。
    temporal_risk_candidate = (
            temporal_status
            in RISK_TEMPORAL_STATUSES
    )

    # 第二类风险候选：
    # manifest-only 证据复核后，仍然被保留为
    # 依赖声明不一致候选。
    declaration_risk_candidate = bool(
        declaration_consistency_evidence
        and declaration_consistency_evidence.get(
            "risk_candidate"
        )
    )

    # 第三类风险候选：
    # AVCS trigger evidence 已经完成版本暴露和
    # vulnerability-trigger matching 后，
    # 如果其 evaluation 明确保留为 risk candidate，
    # SCEG 顶层分析也需要继承这个判断。
    trigger_risk_candidate = bool(
        isinstance(
            trigger_evidence,
            dict,
        )
        and isinstance(
            trigger_evidence.get(
                "trigger"
            ),
            dict,
        )
        and trigger_evidence[
            "trigger"
        ].get(
            "risk_candidate"
        )
    )

    # 第四类风险候选：
    # 已经由 Step8 AVCS 正式生成 Risk Card 的版本暴露。
    # 这里不要求 Trigger 命中；Trigger 仍只是 secondary evidence。
    avcs_risk_candidate = bool(avcs_evidence)

    # SCEG 顶层 risk_candidate 综合四类风险来源：
    #
    # 1. THO temporal risk
    # 2. declaration consistency risk
    # 3. legacy/frozen Trigger risk evidence
    # 4. Step8 AVCS formal Risk Card
    risk_candidate = (
            temporal_risk_candidate
            or declaration_risk_candidate
            or trigger_risk_candidate
            or avcs_risk_candidate
    )

    # -------------------------
    # 8. 构造最终 SCEG record
    # -------------------------
    sceg_record = {
        "schema_version": "sceg_v0.1",
        "dataset_label": dataset_label,
        "graph_id": graph_id,

        # nodes 表示图里的节点。
        # 当前 v0 最小版只有三类节点：
        # sample、dependency_entity、package。
        "nodes": {
            "sample": {
                "sample_id": sample_id,
                "prompt_id": prompt_id,
                "model": model,
                "generation_time": generation_time,
            },
            "dependency_entity": {
                "entity_id": entity_id,
                "raw_name": raw_name,
                "normalized_package": package,
                "source_type": source_type,
                "location": {
                    "file": location.get("file"),
                    "line": location.get("line"),
                },
            },
            "package": {
                "ecosystem": record.get("ecosystem") or "pypi",
                "name": package,
            },
        },

        # evidence 表示证据。
        # 这里把原来零散的字段分成四类：
        # structural：结构证据，说明依赖从哪里来
        # registry：注册表证据，说明 PyPI 查询结果
        # temporal：时态证据，说明生成时间和发布时间关系
        # reachability：安装可达性证据，说明是否可能被安装
        "evidence": {
            "structural": {
                "raw_name": raw_name,
                "package": package,
                "source_type": source_type,
                "location": {
                    "file": location.get("file"),
                    "line": location.get("line"),
                },
                "code_parse_status": record.get("code_parse_status"),
                "code_parse_error": record.get("code_parse_error"),
                "false_positive_filtered": record.get("false_positive_filtered"),
                "local_module_filtered": record.get("local_module_filtered"),
            },
            "registry": {
                "ecosystem": "pypi",
                "exists_now": pypi.get("exists_now"),
                "query_url": pypi.get("query_url"),
                "audit_time": pypi.get("audit_time"),
                "latest_version": pypi.get("latest_version"),
                "first_release_time": pypi.get("first_release_time"),
                "status_code": pypi.get("status_code"),
                "error": pypi.get("error"),
                "offline_pypi_exists": record.get("offline_pypi_exists"),
                "reference_false_positive": record.get("reference_false_positive"),
            },
            "temporal": {
                "generation_time": generation_time,
                "first_release_time": pypi.get("first_release_time"),
                "audit_time": pypi.get("audit_time"),
                "status": record.get("status"),
                "temporal_status_v2": temporal_status,
                "temporal_status_v2_note": record.get("temporal_status_v2_note"),
            },
            "reachability": {
                "install_reachability": record.get("install_reachability"),
                "install_reachability_v2": record.get("install_reachability_v2"),
                "reachability_v2_evidence": reachability_evidence,
            },
            # declaration_consistency 表示：
            # requirements 中的依赖声明，与代码实际使用
            # 以及软件包依赖关系之间是否一致。
            #
            # 普通 import 记录没有这类证据时为 None。
            "declaration_consistency": (
                declaration_consistency_evidence
            ),
            "trigger": trigger_evidence,
            "avcs": (
                avcs_evidence
                if avcs_evidence
                else None
            ),
        },

        # edges 表示 SCEG 里的边关系。
        # 它显式说明 sample、dependency entity、package、evidence 和 Risk Card 之间的关系。
        # 这一步让 SCEG v0 更接近真正的 evidence graph。
        "edges": build_sceg_edges(
            entity_id,
            risk_card_links,
            declaration_consistency_evidence,
            trigger_evidence,
            avcs_evidence,
        ),

        # analysis 表示当前 THO mini 对这条依赖的判断结果。
        # 注意它不是原始证据，而是分析结果。
        "analysis": {
            "temporal_status_v2": temporal_status,
            "install_reachability_v2": reachability,
            "risk_candidate": risk_candidate,
            "avcs_risk_candidate": avcs_risk_candidate,
            "avcs_evidence_count": len(avcs_evidence),
            "risk_card_count": len(risk_card_links),
        },

        # risk_card_links 用来把 SCEG record 和已经生成的 Risk Card 关联起来。
        # qwen37_100 和 hard negative 里应该是空列表。
        # positive control 里应该能链接到 4 张 Risk Card。
        "risk_card_links": risk_card_links,
    }

    return sceg_record


def write_summary(summary_path: Path, input_path: Path, output_path: Path, records, sceg_records):
    """
    为本次 SCEG 构建生成一个 Markdown 摘要报告。

    它主要统计：
    1. 输入记录数
    2. 输出 SCEG 记录数
    3. risk_candidate 数量
    4. linked risk card 数量
    5. temporal_status_v2 分布
    6. install_reachability_v2 分布
    7. source_type 分布
    """
    temporal_counter = Counter(
        row.get("analysis", {}).get("temporal_status_v2")
        for row in sceg_records
    )

    reachability_counter = Counter(
        row.get("analysis", {}).get("install_reachability_v2")
        for row in sceg_records
    )

    source_type_counter = Counter(
        row.get("nodes", {}).get("dependency_entity", {}).get("source_type")
        for row in sceg_records
    )

    risk_candidate_count = sum(
        1 for row in sceg_records
        if row.get("analysis", {}).get("risk_candidate")
    )

    linked_risk_card_count = sum(
        row.get("analysis", {}).get("risk_card_count", 0)
        for row in sceg_records
    )

    lines = []

    lines.append("# SCEG v0 Build Summary")
    lines.append("")
    lines.append(f"- input: `{input_path}`")
    lines.append(f"- output: `{output_path}`")
    lines.append(f"- input_records: {len(records)}")
    lines.append(f"- sceg_records: {len(sceg_records)}")
    lines.append(f"- risk_candidate_records: {risk_candidate_count}")
    lines.append(f"- linked_risk_cards: {linked_risk_card_count}")
    lines.append("")

    lines.append("## temporal_status_v2")
    lines.append("")
    for key, value in sorted(temporal_counter.items()):
        lines.append(f"- {key}: {value}")

    lines.append("")
    lines.append("## install_reachability_v2")
    lines.append("")
    for key, value in sorted(reachability_counter.items()):
        lines.append(f"- {key}: {value}")

    lines.append("")
    lines.append("## source_type")
    lines.append("")
    for key, value in sorted(source_type_counter.items()):
        lines.append(f"- {key}: {value}")

    lines.append("")
    lines.append("## Notes")
    lines.append("")
    lines.append(
        "SCEG v0 is a lightweight intermediate evidence graph. "
        "It does not change THO detection decisions. "
        "It reorganizes existing dependency records into sample, dependency entity, registry evidence, "
        "temporal evidence, reachability evidence, and risk-card links."
    )

    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text("\n".join(lines), encoding="utf-8")


def parse_args():
    """
    解析命令行参数。

    这个脚本不是写死某个输入文件，而是通过参数指定：
    --input       输入 dependency records
    --risk-cards  可选 Risk Card 文件
    --out         输出 SCEG JSONL
    --summary     输出 summary Markdown
    --dataset-label 数据集标签
    """
    parser = argparse.ArgumentParser(
        description="Build lightweight SCEG v0 records from THO mini dependency records."
    )

    parser.add_argument("--input", required=True, help="Input enriched dependency records JSONL.")
    parser.add_argument("--risk-cards", default="", help="Optional risk cards JSONL.")
    parser.add_argument("--out", required=True, help="Output SCEG JSONL.")
    parser.add_argument("--summary", required=True, help="Output Markdown summary.")
    parser.add_argument("--dataset-label", default="unknown_dataset", help="Dataset label for SCEG records.")

    return parser.parse_args()


def main():
    """
    主函数，整个脚本的执行入口。

    执行流程：
    1. 解析命令行参数
    2. 读取 dependency records
    3. 读取 risk cards
    4. 建立 Risk Card 索引
    5. 逐条构建 SCEG record
    6. 写出 SCEG JSONL
    7. 写出 Markdown summary
    """
    args = parse_args()

    input_path = Path(args.input)
    risk_cards_path = Path(args.risk_cards) if args.risk_cards else None
    output_path = Path(args.out)
    summary_path = Path(args.summary)

    records = read_jsonl(input_path)

    # Risk Card 文件是可选的。
    # qwen37_100 的 Risk Card 文件可能为空，这种情况 risk_cards 就是 []。
    if risk_cards_path and risk_cards_path.exists():
        risk_cards = read_jsonl(risk_cards_path)
    else:
        risk_cards = []

    # 建立 Risk Card 索引，方便后面根据 sample_id + package 找对应 Risk Card。
    risk_index = build_risk_card_index(risk_cards)

    # 把每条 dependency record 转成一条 SCEG record。
    sceg_records = [
        build_sceg_record(record, risk_index, dataset_label=args.dataset_label)
        for record in records
    ]

    write_jsonl(output_path, sceg_records)
    write_summary(summary_path, input_path, output_path, records, sceg_records)

    print("[OK] SCEG v0 built")
    print(f"[OK] input records: {len(records)}")
    print(f"[OK] risk cards: {len(risk_cards)}")
    print(f"[OK] sceg records: {len(sceg_records)}")
    print(f"[OK] output: {output_path}")
    print(f"[OK] summary: {summary_path}")


if __name__ == "__main__":
    main()