import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read_jsonl(path: Path):
    if not path.exists():
        raise FileNotFoundError(f"missing file: {path}")

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
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def normalize_package_name(name):
    """
    PEP503 风格的包名规范化：
    - 转小写
    - 把 . _ - 都统一成 -
    - 连续分隔符合并成一个 -
    """
    if not name:
        return None

    name = str(name).strip().lower()
    name = re.sub(r"[-_.]+", "-", name)

    return name or None


def short_id(prefix, parts):
    text = "|".join(str(p) for p in parts if p is not None)
    digest = hashlib.sha1(text.encode("utf-8")).hexdigest()[:12]
    return f"{prefix}_{digest}"


def get_package_name(record):
    """
    尽量从不同字段中取规范包名。

    不同阶段脚本里字段名可能略有差异，
    所以这里做得稍微兼容一点。
    """
    candidates = [
        record.get("package"),
        record.get("normalized_package"),
        record.get("package_name"),
        record.get("dist_name"),
        record.get("raw_name"),
        record.get("name"),
    ]

    for value in candidates:
        normalized = normalize_package_name(value)

        if normalized:
            return normalized

    return None


def get_raw_name(record):
    return (
        record.get("raw_name")
        or record.get("import_name")
        or record.get("name")
        or record.get("package")
        or record.get("normalized_package")
    )


def get_source_type(record):
    return record.get("source_type") or record.get("source") or "unknown"


def get_temporal_status(record):
    return (
        record.get("temporal_status_v2")
        or record.get("temporal_status")
        or record.get("status")
        or "unknown"
    )


def get_reachability(record):
    return (
        record.get("install_reachability_v2")
        or record.get("install_reachability")
        or "unknown"
    )


def get_pypi_evidence(record):
    pypi = record.get("pypi")

    if isinstance(pypi, dict):
        return pypi

    evidence = {}

    for key in [
        "exists_now",
        "query_url",
        "first_release_time",
        "latest_version",
        "registry_status_code",
        "registry_error",
    ]:
        if key in record:
            evidence[key] = record.get(key)

    return evidence


def pick_primary_status(values):
    """
    一个实体可能聚合了多条 record。
    这里给一个简单优先级，方便摘要展示。
    """
    priority = [
        "created_after_tg",
        "nonexistent_now",
        "temporal_unknown",
        "registry_query_error",
        "local_or_private_unknown",
        "existed_at_tg",
        "filtered_false_positive",
        "unknown",
    ]

    value_set = set(values)

    for item in priority:
        if item in value_set:
            return item

    return sorted(value_set)[0] if value_set else "unknown"


def pick_primary_reachability(values):
    priority = [
        "both_docker_and_ci",
        "docker_installable",
        "ci_installable",
        "manifest_declared",
        "import_only",
        "unknown",
    ]

    value_set = set(values)

    for item in priority:
        if item in value_set:
            return item

    return sorted(value_set)[0] if value_set else "unknown"


def build_entities(records, dataset_label):
    grouped = defaultdict(list)

    for index, record in enumerate(records):
        sample_id = record.get("sample_id") or record.get("id") or "unknown_sample"
        package = get_package_name(record)

        if not package:
            continue

        key = (sample_id, package)
        grouped[key].append((index, record))

    entities = []

    for (sample_id, package), items in sorted(grouped.items()):
        records_only = [item[1] for item in items]
        record_indexes = [item[0] for item in items]

        first = records_only[0]

        raw_names = sorted(
            {
                str(get_raw_name(record))
                for record in records_only
                if get_raw_name(record)
            }
        )

        source_types = sorted(
            {
                str(get_source_type(record))
                for record in records_only
                if get_source_type(record)
            }
        )

        temporal_statuses = [
            get_temporal_status(record)
            for record in records_only
        ]

        reachability_statuses = [
            get_reachability(record)
            for record in records_only
        ]

        locations = [
            record.get("location")
            for record in records_only
            if record.get("location") is not None
        ]

        pypi_evidence = get_pypi_evidence(first)

        has_import_evidence = any(
            "import" in source_type
            for source_type in source_types
        )

        has_manifest_evidence = any(
            source_type in {"requirements", "manifest", "manifest_declared"}
            or "requirement" in source_type
            for source_type in source_types
        ) or any(
            status == "manifest_declared"
            for status in reachability_statuses
        )

        has_registry_evidence = bool(pypi_evidence)

        has_temporal_evidence = any(
            status not in {None, "unknown"}
            for status in temporal_statuses
        )

        has_reachability_evidence = any(
            status not in {None, "unknown"}
            for status in reachability_statuses
        )

        entity = {
            "schema_version": "pre_sceg_dependency_entity_v0.1",
            "dataset_label": dataset_label,
            "entity_id": short_id("dep_entity", [dataset_label, sample_id, package]),
            "sample": {
                "sample_id": sample_id,
                "prompt_id": first.get("prompt_id"),
                "model": first.get("model"),
                "generation_time": first.get("generation_time"),
            },
            "package": {
                "ecosystem": first.get("ecosystem") or "pypi",
                "name": package,
            },
            "dependency_entity": {
                "raw_names": raw_names,
                "normalized_package": package,
                "source_types": source_types,
                "record_count": len(records_only),
                "source_record_indexes": record_indexes,
                "locations": locations,
            },
            "evidence_summary": {
                "has_import_evidence": has_import_evidence,
                "has_manifest_evidence": has_manifest_evidence,
                "has_registry_evidence": has_registry_evidence,
                "has_temporal_evidence": has_temporal_evidence,
                "has_reachability_evidence": has_reachability_evidence,
            },
            "registry": {
                "exists_now": pypi_evidence.get("exists_now"),
                "query_url": pypi_evidence.get("query_url"),
                "first_release_time": pypi_evidence.get("first_release_time"),
                "latest_version": pypi_evidence.get("latest_version"),
                "error": pypi_evidence.get("error") or pypi_evidence.get("registry_error"),
            },
            "temporal": {
                "statuses": sorted(set(temporal_statuses)),
                "primary_status": pick_primary_status(temporal_statuses),
            },
            "reachability": {
                "statuses": sorted(set(reachability_statuses)),
                "primary_reachability": pick_primary_reachability(reachability_statuses),
            },
        }

        entities.append(entity)

    return entities


def write_summary(path: Path, input_records, entities, dataset_label):
    temporal_counter = Counter(
        entity["temporal"]["primary_status"]
        for entity in entities
    )

    reachability_counter = Counter(
        entity["reachability"]["primary_reachability"]
        for entity in entities
    )

    source_type_counter = Counter()

    for entity in entities:
        source_type_counter.update(entity["dependency_entity"]["source_types"])

    evidence_counter = Counter()

    for entity in entities:
        summary = entity["evidence_summary"]

        for key, value in summary.items():
            if value:
                evidence_counter[key] += 1

    sample_counter = Counter(
        entity["sample"]["sample_id"]
        for entity in entities
    )

    lines = []

    lines.append("# Pre-SCEG Dependency Entity Summary")
    lines.append("")
    lines.append(f"- dataset_label: `{dataset_label}`")
    lines.append(f"- input_dependency_records: {len(input_records)}")
    lines.append(f"- output_dependency_entities: {len(entities)}")
    lines.append(f"- merged_duplicate_records: {len(input_records) - len(entities)}")
    lines.append(f"- samples_with_entities: {len(sample_counter)}")
    lines.append("")

    lines.append("## 1. temporal primary status")
    lines.append("")
    for key, value in sorted(temporal_counter.items()):
        lines.append(f"- {key}: {value}")

    lines.append("")
    lines.append("## 2. reachability primary status")
    lines.append("")
    for key, value in sorted(reachability_counter.items()):
        lines.append(f"- {key}: {value}")

    lines.append("")
    lines.append("## 3. source types")
    lines.append("")
    for key, value in sorted(source_type_counter.items()):
        lines.append(f"- {key}: {value}")

    lines.append("")
    lines.append("## 4. evidence coverage")
    lines.append("")
    for key, value in sorted(evidence_counter.items()):
        lines.append(f"- {key}: {value}")

    lines.append("")
    lines.append("## 5. Notes")
    lines.append("")
    lines.append(
        "This file is a pre-SCEG dependency entity audit. "
        "It groups THO dependency records by sample and normalized package, "
        "then summarizes raw names, source types, registry evidence, temporal status, "
        "and reachability evidence. It does not change THO decisions. "
        "It prepares a cleaner entity-level input for the later SCEG builder."
    )

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Build pre-SCEG dependency entity records from THO enriched dependency records."
    )

    parser.add_argument(
        "--input",
        default=str(ROOT / "output" / "auto_qwen37_100_reachability_v2_enriched.jsonl"),
    )

    parser.add_argument(
        "--out",
        default=str(ROOT / "output" / "pre_sceg_dependency_entities_qwen37_100.jsonl"),
    )

    parser.add_argument(
        "--summary",
        default=str(ROOT / "output" / "pre_sceg_dependency_entities_qwen37_100_summary.md"),
    )

    parser.add_argument(
        "--dataset-label",
        default="qwen37_100",
    )

    return parser.parse_args()


def main():
    args = parse_args()

    input_path = Path(args.input)
    out_path = Path(args.out)
    summary_path = Path(args.summary)

    records = read_jsonl(input_path)
    entities = build_entities(records, dataset_label=args.dataset_label)

    write_jsonl(out_path, entities)
    write_summary(summary_path, records, entities, dataset_label=args.dataset_label)

    print("[OK] pre-SCEG dependency entities built")
    print("[OK] input dependency records:", len(records))
    print("[OK] output dependency entities:", len(entities))
    print("[OK] merged duplicate records:", len(records) - len(entities))
    print("[OK] output:", out_path.relative_to(ROOT))
    print("[OK] summary:", summary_path.relative_to(ROOT))


if __name__ == "__main__":
    main()