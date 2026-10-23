import json
from collections import Counter
from pathlib import Path


# 项目根目录
ROOT = Path(__file__).resolve().parents[1]


# SCEG schema 文件路径。
# 这个文件定义了每条 SCEG record 应该包含哪些字段。
SCHEMA_PATH = ROOT / "schemas" / "sceg_schema_v0.json"


# 要检查的三类 SCEG 输出。
DATASETS = [
    {
        "name": "qwen37_100_manifest_calibrated",
        "path": (
                ROOT
                / "output"
                / "sceg_qwen37_100_calibrated_v0.jsonl"
        ),
        "expected_records": 260,
        "expected_linked_risk_cards": 5,

        # 260条记录中，20条 manifest-only 记录
        # 应该包含 declaration consistency 证据。
        "expected_declaration_consistency_records": 20,

        # 20条证据的细分类分布。
        "expected_declaration_labels": {
            "direct_import_backed": 15,
            "transitive_dependency_backed": 3,
            "optional_extra_dependency": 1,
            "no_dependency_evidence": 1,
        },
        "expected_declaration_evidence_levels": {
            "strong": 18,
            "moderate": 1,
            "none": 1,
        },

        "expected_declaration_review_priorities": {
            "none": 15,
            "low": 3,
            "medium": 1,
            "high": 1,
        },

        "expected_linked_manifest_evidence_levels": {
            "strong": 3,
            "moderate": 1,
            "none": 1,
        },

        "expected_linked_manifest_review_priorities": {
            "low": 3,
            "medium": 1,
            "high": 1,
        },
    },
    {
        "name": "risk_seed_positive_control",
        "path": (
                ROOT
                / "output"
                / "sceg_risk_seed_validation_v0.jsonl"
        ),
        "expected_records": 4,
        "expected_linked_risk_cards": 4,
        "expected_declaration_consistency_records": 0,
        "expected_declaration_labels": {},
    },
    {
        "name": "hard_negative_control",
        "path": (
                ROOT
                / "output"
                / "sceg_hard_negative_validation_v0.jsonl"
        ),
        "expected_records": 15,
        "expected_linked_risk_cards": 3,
        "expected_declaration_consistency_records": 0,
        "expected_declaration_labels": {},
    },
]


OUT_PATH = ROOT / "output" / "sceg_v0_final_summary.md"


# 业务层面要求的基础边。
# 注意：schema 只规定 edge type 允许有哪些；
# 这里额外规定每条 SCEG record 至少应该包含哪些基础边。
REQUIRED_BASE_EDGE_TYPES = {
    "contains_dependency",
    "maps_to_package",
    "has_structural_evidence",
    "has_registry_evidence",
    "has_temporal_evidence",
    "has_reachability_evidence",
}


def read_json(path: Path):
    """
    读取普通 JSON 文件。

    这里主要用于读取 schemas/sceg_schema_v0.json。
    """
    if not path.exists():
        raise FileNotFoundError(f"missing file: {path}")

    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def read_jsonl(path: Path):
    """
    读取 JSONL 文件。

    JSONL 是一行一个 JSON 对象。
    """
    if not path.exists():
        raise FileNotFoundError(f"missing file: {path}")

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


def get_schema_requirements(schema: dict):
    """
    从 schema 文件中提取我们当前检查需要用到的规则。

    当前先提取三类规则：
    1. 顶层 required 字段
    2. edges 里每条 edge 的 required 字段
    3. edges.type 允许的枚举值

    这样以后如果 schema 里改了 required 字段，
    checker 也能跟着 schema 变化，而不是完全写死在 Python 里。
    """
    top_required = set(schema.get("required", []))

    edge_schema = (
        schema.get("properties", {})
        .get("edges", {})
        .get("items", {})
    )

    edge_required = set(edge_schema.get("required", []))

    allowed_edge_types = set(
        edge_schema.get("properties", {})
        .get("type", {})
        .get("enum", [])
    )

    return top_required, edge_required, allowed_edge_types


def validate_with_schema(row: dict, top_required, edge_required, allowed_edge_types):
    """
    使用 schema 中提取出的规则，对一条 SCEG record 做最小 schema validation。

    这里不是完整 JSON Schema 引擎，但已经覆盖当前 SCEG v0 最关键的结构：
    - 顶层 required 字段是否存在
    - edges 是否是数组
    - edge 是否包含 source / target / type
    - edge type 是否在 schema enum 中
    """
    errors = []

    for key in sorted(top_required):
        if key not in row:
            errors.append(f"schema_missing_top_key:{key}")

    edges = row.get("edges")

    if not isinstance(edges, list):
        errors.append("schema_edges_not_array")
        return errors

    for idx, edge in enumerate(edges):
        if not isinstance(edge, dict):
            errors.append(f"schema_edge_not_object:{idx}")
            continue

        for key in sorted(edge_required):
            if key not in edge:
                errors.append(f"schema_edge_missing_{key}:{idx}")

        edge_type = edge.get("type")

        if allowed_edge_types and edge_type not in allowed_edge_types:
            errors.append(f"schema_edge_type_not_allowed:{edge_type}")

    return errors


def check_required_shape(row: dict, schema_rules):
    """
    检查单条 SCEG record 的完整性。

    这里分两类检查：
    1. schema validation：检查是否符合 schema 文件规定的基本格式
    2. project validation：检查本项目额外要求的结构，比如基础边是否齐全
    """
    top_required, edge_required, allowed_edge_types = schema_rules

    schema_errors = validate_with_schema(
        row,
        top_required=top_required,
        edge_required=edge_required,
        allowed_edge_types=allowed_edge_types,
    )

    nodes = row.get("nodes") or {}
    evidence = row.get("evidence") or {}

    required_nodes = ["sample", "dependency_entity", "package"]
    missing_nodes = [key for key in required_nodes if key not in nodes]

    required_evidence = [
        "structural",
        "registry",
        "temporal",
        "reachability",
        "declaration_consistency",
        "trigger",
    ]
    missing_evidence = [key for key in required_evidence if key not in evidence]

    edge_errors = check_edges(row)

    return schema_errors, missing_nodes, missing_evidence, edge_errors


def check_edges(row: dict):
    """
    检查 edges 是否满足本项目当前的业务要求。

    schema 负责回答：
    这条边格式对不对？

    check_edges 负责回答：
    这条 SCEG record 该有的基础边是否都有？
    """
    errors = []

    edges = row.get("edges")

    if not isinstance(edges, list):
        return ["edges_not_list"]

    edge_types = Counter()

    for edge in edges:
        if not isinstance(edge, dict):
            errors.append("edge_not_object")
            continue

        for key in ["source", "target", "type"]:
            if key not in edge:
                errors.append(f"edge_missing_{key}")

        edge_type = edge.get("type")
        if edge_type:
            edge_types[edge_type] += 1

    missing_base_edges = REQUIRED_BASE_EDGE_TYPES - set(edge_types.keys())

    for edge_type in sorted(missing_base_edges):
        errors.append(f"missing_edge_type:{edge_type}")

    # 如果当前记录包含 declaration consistency 证据，
    # 就必须有对应的证据边。
    declaration_consistency = (
        row.get(
            "evidence",
            {},
        ).get(
            "declaration_consistency"
        )
    )

    if isinstance(
        declaration_consistency,
        dict,
    ):
        if edge_types.get(
            "has_declaration_consistency_evidence",
            0,
        ) == 0:
            errors.append(
                "missing_edge_type:"
                "has_declaration_consistency_evidence"
            )

    # 如果当前记录没有 declaration consistency 证据，
    # 则不应该凭空出现对应的证据边。
    else:
        if edge_types.get(
            "has_declaration_consistency_evidence",
            0,
        ) > 0:
            errors.append(
                "unexpected_edge_type:"
                "has_declaration_consistency_evidence"
            )

    # Trigger evidence 和 has_trigger_evidence 边
    # 必须保持双向一致：
    #
    # 有真实 trigger evidence -> 必须有对应边；
    # 没有 trigger evidence -> 不允许凭空出现对应边。
    trigger_evidence = (
        row.get(
            "evidence",
            {},
        ).get(
            "trigger"
        )
    )

    if isinstance(
        trigger_evidence,
        dict,
    ):
        if edge_types.get(
            "has_trigger_evidence",
            0,
        ) == 0:
            errors.append(
                "missing_edge_type:"
                "has_trigger_evidence"
            )

    else:
        if edge_types.get(
            "has_trigger_evidence",
            0,
        ) > 0:
            errors.append(
                "unexpected_edge_type:"
                "has_trigger_evidence"
            )

    risk_card_count = row.get("analysis", {}).get("risk_card_count", 0)

    if risk_card_count > 0 and edge_types.get("supports_risk_card", 0) == 0:
        errors.append("missing_edge_type:supports_risk_card")

    return errors


def main():
    # 读取 schema，并提取检查规则。
    schema = read_json(SCHEMA_PATH)
    schema_rules = get_schema_requirements(schema)

    all_rows = []
    dataset_summaries = []

    all_pass = True

    for dataset in DATASETS:
        rows = read_jsonl(dataset["path"])
        all_rows.extend(rows)

        temporal_counter = Counter(
            row.get("analysis", {}).get("temporal_status_v2")
            for row in rows
        )

        reachability_counter = Counter(
            row.get("analysis", {}).get("install_reachability_v2")
            for row in rows
        )

        source_type_counter = Counter(
            row.get("nodes", {}).get("dependency_entity", {}).get("source_type")
            for row in rows
        )

        edge_type_counter = Counter()
        edge_count = 0

        # declaration consistency 证据统计。
        declaration_consistency_records = 0
        declaration_label_counter = Counter()

        declaration_evidence_level_counter = Counter()
        declaration_review_priority_counter = Counter()

        linked_manifest_evidence_level_counter = Counter()
        linked_manifest_review_priority_counter = Counter()

        declaration_legacy_confidence_count = 0
        linked_manifest_legacy_confidence_count = 0

        linked_risk_cards = sum(
            row.get("analysis", {}).get("risk_card_count", 0)
            for row in rows
        )

        bad_schema_count = 0
        bad_shape_count = 0
        bad_edges_count = 0

        for row in rows:
            declaration_consistency = (
                row.get(
                    "evidence",
                    {},
                ).get(
                    "declaration_consistency"
                )
            )

            # 只有值为字典时，才说明当前记录真正包含
            # manifest-only 声明一致性证据。
            if isinstance(
                declaration_consistency,
                dict,
            ):
                declaration_consistency_records += 1

                label = declaration_consistency.get(
                    "label"
                )

                if label:
                    declaration_label_counter[
                        str(label)
                    ] += 1

                evidence_level = (
                    declaration_consistency.get(
                        "evidence_level"
                    )
                )

                if evidence_level:
                    declaration_evidence_level_counter[
                        str(evidence_level)
                    ] += 1

                review_priority = (
                    declaration_consistency.get(
                        "review_priority"
                    )
                )

                if review_priority:
                    declaration_review_priority_counter[
                        str(review_priority)
                    ] += 1

                if (
                    "confidence"
                    in declaration_consistency
                ):
                    declaration_legacy_confidence_count += 1

            risk_card_links = row.get(
                "risk_card_links",
                [],
            )

            if isinstance(
                    risk_card_links,
                    list,
            ):
                for link in risk_card_links:
                    if not isinstance(
                            link,
                            dict,
                    ):
                        continue

                    if (
                            link.get("type")
                            != "dependency_declaration_mismatch"
                    ):
                        continue

                    evidence_level = link.get(
                        "evidence_level"
                    )

                    if evidence_level:
                        linked_manifest_evidence_level_counter[
                            str(evidence_level)
                        ] += 1

                    review_priority = link.get(
                        "review_priority"
                    )

                    if review_priority:
                        linked_manifest_review_priority_counter[
                            str(review_priority)
                        ] += 1

                    if "confidence" in link:
                        linked_manifest_legacy_confidence_count += 1

            schema_errors, missing_nodes, missing_evidence, edge_errors = check_required_shape(
                row,
                schema_rules=schema_rules,
            )

            if schema_errors:
                bad_schema_count += 1

            if missing_nodes or missing_evidence:
                bad_shape_count += 1

            if edge_errors:
                bad_edges_count += 1

            edges = row.get("edges")

            if isinstance(edges, list):
                edge_count += len(edges)
                edge_type_counter.update(
                    edge.get("type")
                    for edge in edges
                    if isinstance(edge, dict)
                )

        records_ok = len(rows) == dataset["expected_records"]
        linked_cards_ok = linked_risk_cards == dataset["expected_linked_risk_cards"]

        expected_declaration_records = (
            dataset.get(
                "expected_declaration_consistency_records",
                0,
            )
        )

        expected_declaration_labels = (
            dataset.get(
                "expected_declaration_labels",
                {},
            )
        )

        expected_declaration_evidence_levels = (
            dataset.get(
                "expected_declaration_evidence_levels"
            )
        )

        expected_declaration_review_priorities = (
            dataset.get(
                "expected_declaration_review_priorities"
            )
        )

        expected_linked_manifest_evidence_levels = (
            dataset.get(
                "expected_linked_manifest_evidence_levels"
            )
        )

        expected_linked_manifest_review_priorities = (
            dataset.get(
                "expected_linked_manifest_review_priorities"
            )
        )

        declaration_records_ok = (
            declaration_consistency_records
            == expected_declaration_records
        )

        declaration_labels_ok = (
            dict(declaration_label_counter)
            == dict(expected_declaration_labels)
        )

        declaration_evidence_levels_ok = (
            expected_declaration_evidence_levels
            is None
            or dict(
                declaration_evidence_level_counter
            )
            == dict(
                expected_declaration_evidence_levels
            )
        )

        declaration_review_priorities_ok = (
            expected_declaration_review_priorities
            is None
            or dict(
                declaration_review_priority_counter
            )
            == dict(
                expected_declaration_review_priorities
            )
        )

        linked_manifest_evidence_levels_ok = (
            expected_linked_manifest_evidence_levels
            is None
            or dict(
                linked_manifest_evidence_level_counter
            )
            == dict(
                expected_linked_manifest_evidence_levels
            )
        )

        linked_manifest_review_priorities_ok = (
            expected_linked_manifest_review_priorities
            is None
            or dict(
                linked_manifest_review_priority_counter
            )
            == dict(
                expected_linked_manifest_review_priorities
            )
        )

        no_legacy_manifest_confidence = (
            declaration_legacy_confidence_count == 0
            and linked_manifest_legacy_confidence_count == 0
        )

        schema_ok = bad_schema_count == 0
        shape_ok = bad_shape_count == 0
        edges_ok = bad_edges_count == 0

        dataset_pass = (
                records_ok
                and linked_cards_ok
                and declaration_records_ok
                and declaration_labels_ok
                and declaration_evidence_levels_ok
                and declaration_review_priorities_ok
                and linked_manifest_evidence_levels_ok
                and linked_manifest_review_priorities_ok
                and no_legacy_manifest_confidence
                and schema_ok
                and shape_ok
                and edges_ok
        )
        all_pass = all_pass and dataset_pass

        dataset_summaries.append(
            {
                "name": dataset["name"],
                "path": dataset["path"],
                "records": len(rows),
                "expected_records": dataset["expected_records"],
                "linked_risk_cards": linked_risk_cards,
                "expected_linked_risk_cards": dataset["expected_linked_risk_cards"],
                "declaration_consistency_records": (
                    declaration_consistency_records
                ),
                "expected_declaration_consistency_records": (
                    expected_declaration_records
                ),
                "declaration_label_counter": (
                    declaration_label_counter
                ),
                "expected_declaration_labels": (
                    expected_declaration_labels
                ),
                "declaration_records_ok": (
                    declaration_records_ok
                ),
                "declaration_labels_ok": (
                    declaration_labels_ok
                ),
                "bad_schema_count": bad_schema_count,
                "bad_shape_count": bad_shape_count,
                "bad_edges_count": bad_edges_count,
                "edge_count": edge_count,
                "temporal_counter": temporal_counter,
                "reachability_counter": reachability_counter,
                "source_type_counter": source_type_counter,
                "edge_type_counter": edge_type_counter,
                "dataset_pass": dataset_pass,
            }
        )

    total_records = len(all_rows)

    total_linked_risk_cards = sum(
        row.get("analysis", {}).get("risk_card_count", 0)
        for row in all_rows
    )

    total_temporal_counter = Counter(
        row.get("analysis", {}).get("temporal_status_v2")
        for row in all_rows
    )

    total_reachability_counter = Counter(
        row.get("analysis", {}).get("install_reachability_v2")
        for row in all_rows
    )

    total_edge_type_counter = Counter()
    total_edge_count = 0

    # declaration consistency 证据统计。
    declaration_consistency_records = 0
    declaration_label_counter = Counter()

    for row in all_rows:
        edges = row.get("edges")

        if isinstance(edges, list):
            total_edge_count += len(edges)
            total_edge_type_counter.update(
                edge.get("type")
                for edge in edges
                if isinstance(edge, dict)
            )

    lines = []

    lines.append("# SCEG v0 Final Summary")
    lines.append("")
    lines.append(f"ALL_PASS = {all_pass}")
    lines.append("")
    lines.append(
        f"- schema: `{SCHEMA_PATH.relative_to(ROOT)}`"
    )
    lines.append(f"- total_sceg_records: {total_records}")
    lines.append(f"- total_linked_risk_cards: {total_linked_risk_cards}")
    lines.append(f"- total_edges: {total_edge_count}")
    lines.append("")

    lines.append("## 1. Dataset Overview")
    lines.append("")
    lines.append(
        "| dataset | records | expected_records | "
        "linked_risk_cards | expected_linked_risk_cards | "
        "declaration_records | expected_declaration_records | "
        "declaration_records_ok | declaration_labels_ok | "
        "edge_count | bad_schema_count | bad_shape_count | "
        "bad_edges_count | pass |"
    )

    lines.append(
        "|---|---:|---:|---:|---:|---:|---:|"
        "---|---|---:|---:|---:|---:|---|"
    )

    for item in dataset_summaries:
        lines.append(
            f"| {item['name']} | "
            f"{item['records']} | "
            f"{item['expected_records']} | "
            f"{item['linked_risk_cards']} | "
            f"{item['expected_linked_risk_cards']} | "
            f"{item['declaration_consistency_records']} | "
            f"{item['expected_declaration_consistency_records']} | "
            f"{item['declaration_records_ok']} | "
            f"{item['declaration_labels_ok']} | "
            f"{item['edge_count']} | "
            f"{item['bad_schema_count']} | "
            f"{item['bad_shape_count']} | "
            f"{item['bad_edges_count']} | "
            f"{item['dataset_pass']} |"
        )

    lines.append("")
    lines.append("## 2. Total temporal_status_v2")
    lines.append("")
    for key, value in sorted(total_temporal_counter.items()):
        lines.append(f"- {key}: {value}")

    lines.append("")
    lines.append("## 3. Total install_reachability_v2")
    lines.append("")
    for key, value in sorted(total_reachability_counter.items()):
        lines.append(f"- {key}: {value}")

    lines.append("")
    lines.append("## 4. Total edge types")
    lines.append("")
    for key, value in sorted(total_edge_type_counter.items()):
        lines.append(f"- {key}: {value}")

    lines.append("")
    lines.append("## 5. Per-dataset Details")
    lines.append("")

    for item in dataset_summaries:
        lines.append(f"### {item['name']}")
        lines.append("")
        lines.append("temporal_status_v2:")
        for key, value in sorted(item["temporal_counter"].items()):
            lines.append(f"- {key}: {value}")

        lines.append("")
        lines.append("install_reachability_v2:")
        for key, value in sorted(item["reachability_counter"].items()):
            lines.append(f"- {key}: {value}")

        lines.append("")
        lines.append("source_type:")
        for key, value in sorted(item["source_type_counter"].items()):
            lines.append(f"- {key}: {value}")

        lines.append("")
        lines.append(
            "declaration_consistency:"
        )
        lines.append(
            "- actual_records: "
            f"{item['declaration_consistency_records']}"
        )
        lines.append(
            "- expected_records: "
            f"{item['expected_declaration_consistency_records']}"
        )
        lines.append(
            "- records_ok: "
            f"{item['declaration_records_ok']}"
        )
        lines.append(
            "- labels_ok: "
            f"{item['declaration_labels_ok']}"
        )

        lines.append("")
        lines.append(
            "declaration_consistency_labels:"
        )

        actual_labels = (
            item["declaration_label_counter"]
        )

        expected_labels = (
            item["expected_declaration_labels"]
        )

        all_declaration_labels = sorted(
            set(actual_labels.keys())
            | set(expected_labels.keys())
        )

        if all_declaration_labels:
            for label in all_declaration_labels:
                lines.append(
                    f"- {label}: "
                    f"actual={actual_labels.get(label, 0)}, "
                    f"expected={expected_labels.get(label, 0)}"
                )
        else:
            lines.append("- none")

        lines.append("")
        lines.append("edge_type:")
        for key, value in sorted(item["edge_type_counter"].items()):
            lines.append(f"- {key}: {value}")

        lines.append("")

    lines.append("## 6. Notes")
    lines.append("")
    lines.append(
        "SCEG v0 is a lightweight intermediate evidence graph built from existing THO mini outputs. "
        "It does not change detection decisions. It reorganizes dependency records into sample nodes, "
        "dependency entity nodes, package nodes, registry evidence, temporal evidence, reachability evidence, "
        "risk-card links, and explicit evidence edges. This check also validates records against "
        "the SCEG v0 schema definition."
    )

    OUT_PATH.write_text("\n".join(lines), encoding="utf-8")

    print("[OK] saved:", OUT_PATH.relative_to(ROOT))
    print("schema =", SCHEMA_PATH.relative_to(ROOT))
    print("ALL_PASS =", all_pass)
    print("total_sceg_records =", total_records)
    print("total_linked_risk_cards =", total_linked_risk_cards)
    print("total_edges =", total_edge_count)

    for item in dataset_summaries:
        print(
            item["name"],
            "| records =", item["records"],
            "| linked_risk_cards =", item["linked_risk_cards"],
            "| edges =", item["edge_count"],
            "| bad_schema =", item["bad_schema_count"],
            "| bad_edges =", item["bad_edges_count"],
            "| pass =", item["dataset_pass"],
        )

    if not all_pass:
        raise SystemExit(1)

if __name__ == "__main__":
    main()