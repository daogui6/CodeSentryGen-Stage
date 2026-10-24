from __future__ import annotations

import argparse
import hashlib
import json
import re
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any

from freeze_hash_v1 import canonical_sha256_file
from step9_protocol_registry import require_active_pre_generation_protocol
from build_step9_method_freeze_v1 import verify_step9_formal_freeze_binding

from prepare_pilot20 import normalize_prompt_records, read_json as read_source_json


ROOT = Path(__file__).resolve().parents[1]
SOURCE_INVENTORY = ROOT / "data/prompts/packagehallucination_python_prompts.jsonl"

SCAN_ROOTS = (
    ROOT / "data/prompts",
    ROOT / "data/samples",
    ROOT / "archive",
    ROOT / "output",
)

EXCLUDED_SCAN_PREFIXES = (
    "data/prompts/step9_fresh_",
    "output/step9_fresh_benchmark_v0/",
    "output/step9_fresh_pilot20_v0/",
    "output/step9_fresh_test100_v0/",
    "output/step9_fresh_benchmark_v1/",
    "output/step9_fresh_pilot20_v1/",
    "output/step9_fresh_test100_v1/",
    "output/step9_fresh_benchmark_v2/",
    "output/step9_fresh_pilot20_v2/",
    "output/step9_fresh_test100_v2/",
    "output/step9_fresh_benchmark_v3/",
    "output/step9_fresh_pilot20_v3/",
    "output/step9_fresh_test100_v3/",
    "output/step9_fresh_benchmark_v4/",
    "output/step9_fresh_pilot20_v4/",
    "output/step9_fresh_test100_v4/",
)

MAX_JSONL_BYTES = 50 * 1024 * 1024


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return value


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8-sig") as handle:
        for line_no, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"Expected object at {path}:{line_no}")
            rows.append(value)
    return rows


def write_json(path: Path, value: Any) -> None:
    if path.exists():
        raise FileExistsError(
            f"Refusing overwrite of Step9 leakage audit: {path}"
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def rel(path: Path) -> str:
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return canonical_sha256_file(path)


def canonical_prompt_text(value: Any) -> str:
    text = str(value or "").strip()
    return re.sub(r"\s+", " ", text)


def prompt_hash(value: Any) -> str:
    return sha256_bytes(canonical_prompt_text(value).encode("utf-8"))


def extract_prompt_text(row: dict[str, Any]) -> str:
    for key in (
        "prompt",
        "prompt_text",
        "instruction",
        "task",
        "query",
    ):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def classify_artifact(path: Path) -> str:
    value = rel(path).lower()

    if value.startswith("data/prompts/selected_prompts_"):
        return "development_prompt_selection"
    if "e2e_real_smoke" in value or "e2e_mock_smoke" in value:
        return "engineering_smoke"
    if "hard_negative" in value:
        return "hard_negative_development"
    if "risk_seed" in value or "controlled_positive" in value:
        return "controlled_injection_development"
    if value.startswith("data/samples/"):
        return "historical_generated_or_control_sample"
    if value.startswith("archive/"):
        return "historical_archive"
    if value.startswith("output/"):
        return "historical_output"
    return "other_historical_prompt_artifact"


def should_scan(path: Path) -> bool:
    if path.suffix.lower() != ".jsonl":
        return False

    relative = rel(path)

    if relative == "data/prompts/packagehallucination_python_prompts.jsonl":
        return False

    if any(relative.startswith(prefix) for prefix in EXCLUDED_SCAN_PREFIXES):
        return False

    return True


def collect_jsonl_candidates() -> list[Path]:
    paths: set[Path] = set()

    for root in SCAN_ROOTS:
        if not root.exists():
            continue
        for path in root.rglob("*.jsonl"):
            if path.is_file() and should_scan(path):
                paths.add(path)

    return sorted(paths, key=lambda path: rel(path))


def download_if_needed(cache: Path, url: str) -> bytes:
    if cache.exists() and cache.stat().st_size > 0:
        return cache.read_bytes()

    cache.parent.mkdir(parents=True, exist_ok=True)

    print("[STEP9-A] downloading pinned upstream prompt source")
    with urllib.request.urlopen(url, timeout=120) as response:
        data = response.read()

    if not data:
        raise RuntimeError("Downloaded upstream prompt source is empty")

    cache.write_bytes(data)
    return data


def normalized_source_rows(
    protocol: dict[str, Any],
) -> tuple[list[dict[str, Any]], bytes]:
    source = protocol["source"]
    cache = ROOT / source["local_cache"]
    raw = download_if_needed(cache, source["raw_url"])
    payload = read_source_json(cache)

    rows = normalize_prompt_records(payload)

    if not rows:
        raise RuntimeError("Pinned upstream source normalized to zero prompts")

    return rows, raw


def source_inventory_alignment(
    source_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    if not SOURCE_INVENTORY.exists():
        return {
            "status": "missing",
            "file": rel(SOURCE_INVENTORY),
            "source_count": len(source_rows),
            "inventory_count": None,
            "mismatch_count": None,
        }

    inventory = read_jsonl(SOURCE_INVENTORY)

    source_pairs = [
        (
            str(row.get("prompt_id", "")).strip(),
            prompt_hash(row.get("prompt_text")),
        )
        for row in source_rows
    ]
    inventory_pairs = [
        (
            str(row.get("prompt_id", "")).strip(),
            prompt_hash(row.get("prompt_text")),
        )
        for row in inventory
    ]

    mismatch_count = 0
    for index in range(max(len(source_pairs), len(inventory_pairs))):
        source_value = source_pairs[index] if index < len(source_pairs) else None
        inventory_value = (
            inventory_pairs[index] if index < len(inventory_pairs) else None
        )
        if source_value != inventory_value:
            mismatch_count += 1

    return {
        "status": "PASS" if mismatch_count == 0 else "MISMATCH",
        "file": rel(SOURCE_INVENTORY),
        "source_count": len(source_rows),
        "inventory_count": len(inventory),
        "mismatch_count": mismatch_count,
        "inventory_sha256": sha256_file(SOURCE_INVENTORY),
    }


def explicit_exclusion_fingerprints(
    protocol: dict[str, Any],
) -> tuple[set[str], set[str], dict[str, Any] | None]:
    prompt_ids: set[str] = set()
    prompt_hashes: set[str] = set()
    predecessor_manifest_metadata: dict[str, Any] | None = None

    explicit = protocol["freshness_rule"].get(
        "exclude_explicit_prompt_id_range"
    )
    if isinstance(explicit, dict):
        prefix = str(explicit.get("prefix") or "")
        start = explicit.get("start")
        end = explicit.get("end")
        if prefix and isinstance(start, int) and isinstance(end, int):
            for number in range(start, end + 1):
                prompt_ids.add(f"{prefix}{number:04d}")

    for relative in protocol["freshness_rule"].get(
        "exclude_prompt_files",
        [],
    ):
        path = ROOT / relative
        if not path.exists():
            continue
        for row in read_jsonl(path):
            value = str(row.get("prompt_id", "")).strip()
            if value:
                prompt_ids.add(value)
            text = extract_prompt_text(row)
            if text:
                prompt_hashes.add(prompt_hash(text))

    predecessor_rel = str(
        protocol["freshness_rule"].get(
            "predecessor_fingerprint_manifest"
        )
        or ""
    ).strip()
    if predecessor_rel:
        predecessor_path = ROOT / predecessor_rel
        if not predecessor_path.is_file():
            raise FileNotFoundError(
                "R5-r7 predecessor fingerprint manifest missing: "
                f"{predecessor_rel}"
            )
        predecessor = read_json(predecessor_path)
        schema_version = str(predecessor.get("schema_version") or "")
        supported_predecessor_schemas = {
            "step9_v4_r5_r7_predecessor_fingerprint_manifest_v1",
            "step9_v4_r5_r8_predecessor_fingerprint_manifest_v1",
            "step9_v4_r5_r9_predecessor_fingerprint_manifest_v1",
            "step9_v4_r5_r10_predecessor_fingerprint_manifest_v1",
            "step9_v4_r5_r11_predecessor_fingerprint_manifest_v1",
            "step9_v4_r5_r12_predecessor_fingerprint_manifest_v1",
            "step9_v4_r5_r13_predecessor_fingerprint_manifest_v1",
        }
        if schema_version not in supported_predecessor_schemas:
            raise ValueError(
                "Unexpected Step9 predecessor fingerprint schema: "
                f"{schema_version!r}"
            )
        if predecessor.get("status") != "FROZEN_PRE_SELECTION":
            raise ValueError(
                "Step9 predecessor fingerprint manifest is not frozen"
            )
        records = predecessor.get("records")
        if not isinstance(records, list):
            raise ValueError(
                "Step9 predecessor fingerprint records missing"
            )
        manifest_ids: set[str] = set()
        manifest_hashes: set[str] = set()
        for row in records:
            if not isinstance(row, dict):
                raise ValueError(
                    "Invalid Step9 predecessor fingerprint row"
                )
            prompt_id = str(row.get("prompt_id") or "").strip()
            digest = str(
                row.get("normalized_prompt_text_sha256") or ""
            ).strip()
            if not prompt_id or not digest:
                raise ValueError(
                    "Incomplete Step9 predecessor fingerprint row"
                )
            manifest_ids.add(prompt_id)
            manifest_hashes.add(digest)

        if schema_version in {
            "step9_v4_r5_r11_predecessor_fingerprint_manifest_v1",
            "step9_v4_r5_r12_predecessor_fingerprint_manifest_v1",
            "step9_v4_r5_r13_predecessor_fingerprint_manifest_v1",
        }:
            expected = (
                predecessor.get("record_contract")
                if isinstance(predecessor.get("record_contract"), dict)
                else {}
            )
            expected_count = int(expected.get("record_count") or 0)
            expected_id_count = int(
                expected.get("distinct_prompt_ids") or 0
            )
            expected_hash_count = int(
                expected.get("distinct_prompt_text_hashes") or 0
            )
        else:
            expected = (
                predecessor.get("exclusion_policy")
                if isinstance(
                    predecessor.get("exclusion_policy"), dict
                )
                else {}
            )
            expected_count = int(
                expected.get("expected_total_records")
                or expected.get("actual_total_records")
                or 0
            )
            expected_id_count = int(
                expected.get("expected_distinct_prompt_ids")
                or expected.get("actual_distinct_prompt_ids")
                or 0
            )
            expected_hash_count = int(
                expected.get("expected_distinct_prompt_hashes")
                or expected.get("actual_distinct_prompt_hashes")
                or 0
            )
        freshness = protocol.get("freshness_rule", {})
        protocol_expected_count = int(
            freshness.get("expected_predecessor_fingerprint_count")
            or 0
        )
        protocol_expected_id_count = int(
            freshness.get("expected_predecessor_distinct_prompt_ids")
            or 0
        )
        protocol_expected_hash_count = int(
            freshness.get(
                "expected_predecessor_distinct_prompt_text_hashes"
            )
            or 0
        )
        if (
            expected_count <= 0
            or expected_id_count <= 0
            or expected_hash_count <= 0
            or len(records) != expected_count
            or len(manifest_ids) != expected_id_count
            or len(manifest_hashes) != expected_hash_count
            or (
                protocol_expected_count > 0
                and expected_count != protocol_expected_count
            )
            or (
                protocol_expected_id_count > 0
                and expected_id_count != protocol_expected_id_count
            )
            or (
                protocol_expected_hash_count > 0
                and expected_hash_count != protocol_expected_hash_count
            )
        ):
            raise ValueError(
                "Step9 predecessor fingerprint manifest count mismatch"
            )
        prompt_ids.update(manifest_ids)
        prompt_hashes.update(manifest_hashes)
        predecessor_manifest_metadata = {
            "file": predecessor_rel,
            "sha256": sha256_file(predecessor_path),
            "record_count": len(records),
            "distinct_prompt_id_count": len(manifest_ids),
            "distinct_prompt_text_hash_count": len(manifest_hashes),
            "outcome_fields_forbidden": True,
        }

    return prompt_ids, prompt_hashes, predecessor_manifest_metadata


def existing_fresh_artifacts(
    protocol: dict[str, Any],
) -> list[str]:
    candidates = [
        ROOT / protocol["splits"]["pilot"]["output"],
        ROOT / protocol["splits"]["test"]["output"],
        ROOT / protocol["planned_outputs"]["selection_manifest"],
        ROOT / protocol["planned_outputs"]["pilot_run"],
        ROOT / protocol["planned_outputs"]["test_run"],
    ]

    return [
        rel(path)
        for path in candidates
        if path.exists()
    ]


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Audit CodeSentry-Gen historical prompt usage before any fresh "
            "Step9 generation. The audit reads historical artifacts only and "
            "does not inspect risk labels or generated-code semantics."
        )
    )
    parser.add_argument(
        "--protocol",
        type=Path,
        required=True,
        help="Explicit frozen active Step9 protocol; no historical default.",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help=(
            "Optional audit output path. Defaults to the explicit protocol's "
            "leakage_audit.file."
        ),
    )
    args = parser.parse_args()

    protocol_path, protocol, _ = (
        require_active_pre_generation_protocol(
            args.protocol,
            operation="Step9 leakage audit",
        )
    )

    method_rel = str(
        protocol.get("planned_outputs", {}).get("method_freeze") or ""
    ).strip()
    if not method_rel:
        raise ValueError(
            "Frozen v4 protocol must declare planned_outputs.method_freeze"
        )
    method_path = ROOT / method_rel
    if not method_path.exists():
        raise FileNotFoundError(
            "Pre-generation method freeze is required before leakage audit: "
            f"{method_rel}"
        )
    method_freeze = verify_step9_formal_freeze_binding(
        method_path,
        protocol_path=protocol_path,
        require_git_identity=True,
        require_environment_versions=True,
    )

    out_path = args.out
    if out_path is None:
        out_path = ROOT / protocol["leakage_audit"]["file"]
    elif not out_path.is_absolute():
        out_path = ROOT / out_path

    source_rows, raw_source = normalized_source_rows(protocol)
    alignment = source_inventory_alignment(source_rows)

    (
        historical_ids,
        historical_hashes,
        predecessor_manifest_metadata,
    ) = explicit_exclusion_fingerprints(protocol)
    artifact_rows: list[dict[str, Any]] = []
    parse_errors: list[dict[str, Any]] = []
    oversized_skips: list[str] = []

    prompt_record_count = 0
    category_counter: Counter[str] = Counter()

    for path in collect_jsonl_candidates():
        relative = rel(path)

        if path.stat().st_size > MAX_JSONL_BYTES:
            oversized_skips.append(relative)
            continue

        file_ids: set[str] = set()
        file_hashes: set[str] = set()
        file_prompt_records = 0
        total_rows = 0

        try:
            with path.open("r", encoding="utf-8-sig") as handle:
                for line_no, line in enumerate(handle, start=1):
                    line = line.strip()
                    if not line:
                        continue

                    total_rows += 1

                    try:
                        row = json.loads(line)
                    except json.JSONDecodeError as exc:
                        parse_errors.append(
                            {
                                "file": relative,
                                "line": line_no,
                                "error": str(exc),
                            }
                        )
                        continue

                    if not isinstance(row, dict):
                        parse_errors.append(
                            {
                                "file": relative,
                                "line": line_no,
                                "error": "JSONL row is not an object",
                            }
                        )
                        continue

                    prompt_id = str(row.get("prompt_id", "")).strip()
                    text = extract_prompt_text(row)

                    if not prompt_id and not text:
                        continue

                    file_prompt_records += 1
                    prompt_record_count += 1

                    if prompt_id:
                        historical_ids.add(prompt_id)
                        file_ids.add(prompt_id)

                    if text:
                        digest = prompt_hash(text)
                        historical_hashes.add(digest)
                        file_hashes.add(digest)

        except OSError as exc:
            parse_errors.append(
                {
                    "file": relative,
                    "line": None,
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )
            continue

        if file_prompt_records:
            category = classify_artifact(path)
            category_counter[category] += file_prompt_records
            artifact_rows.append(
                {
                    "file": relative,
                    "category": category,
                    "file_sha256": sha256_file(path),
                    "row_count": total_rows,
                    "prompt_bearing_record_count": file_prompt_records,
                    "unique_prompt_id_count": len(file_ids),
                    "unique_prompt_hash_count": len(file_hashes),
                }
            )

    source_prompt_ids = {
        str(row.get("prompt_id", "")).strip()
        for row in source_rows
        if str(row.get("prompt_id", "")).strip()
    }

    source_prompt_hashes = {
        prompt_hash(row.get("prompt_text"))
        for row in source_rows
        if canonical_prompt_text(row.get("prompt_text"))
    }

    historical_ids_in_source = historical_ids & source_prompt_ids
    historical_hashes_in_source = historical_hashes & source_prompt_hashes

    fresh_candidates = []
    for row in source_rows:
        prompt_id = str(row.get("prompt_id", "")).strip()
        text = row.get("prompt_text", "")
        digest = prompt_hash(text)

        if prompt_id in historical_ids:
            continue
        if digest in historical_hashes:
            continue

        fresh_candidates.append(
            {
                "prompt_id": prompt_id,
                "prompt_text_sha256": digest,
            }
        )

    required_count = (
        int(protocol["splits"]["pilot"]["size"])
        + int(protocol["splits"]["test"]["size"])
    )

    already_exists = existing_fresh_artifacts(protocol)

    blockers: list[str] = []

    if alignment.get("status") != "PASS":
        blockers.append("normalized_source_inventory_mismatch")

    if parse_errors:
        blockers.append("historical_jsonl_parse_errors")

    if oversized_skips:
        blockers.append("historical_jsonl_oversized_files_skipped")

    if already_exists:
        blockers.append("fresh_step9_artifacts_already_exist")

    if len(fresh_candidates) < required_count:
        blockers.append("insufficient_fresh_prompt_candidates")

    report = {
        "schema_version": "step9_pre_generation_leakage_audit_v0.1",
        "status": "PASS" if not blockers else "BLOCKED",
        "protocol_file": rel(protocol_path),
        "protocol_sha256": sha256_file(protocol_path),
        "method_freeze": {
            "file": rel(method_path),
            "sha256": sha256_file(method_path),
            "method_closure_sha256": method_freeze.get(
                "method_closure_sha256"
            ),
        },
        "source": {
            "repository": protocol["source"]["repository"],
            "upstream_commit": protocol["source"]["upstream_commit"],
            "path": protocol["source"]["path"],
            "cache_file": protocol["source"]["local_cache"],
            "source_sha256": sha256_bytes(raw_source),
            "normalized_prompt_count": len(source_rows),
            "normalization_impl": (
                "src/prepare_pilot20.py::normalize_prompt_records"
            ),
            "inventory_alignment": alignment,
        },
        "historical_scan": {
            "roots": [rel(path) for path in SCAN_ROOTS],
            "artifact_file_count_with_prompt_evidence": len(artifact_rows),
            "prompt_bearing_record_count": prompt_record_count,
            "category_record_counts": dict(sorted(category_counter.items())),
            "unique_historical_prompt_id_count": len(historical_ids),
            "unique_historical_prompt_text_hash_count": len(historical_hashes),
            "historical_prompt_ids_in_source_count": len(
                historical_ids_in_source
            ),
            "historical_prompt_hashes_in_source_count": len(
                historical_hashes_in_source
            ),
            "historical_prompt_ids": sorted(historical_ids),
            "historical_prompt_text_sha256": sorted(historical_hashes),
            "explicit_predecessor_fingerprint_manifest": (
                predecessor_manifest_metadata
            ),
            "artifacts": artifact_rows,
            "parse_errors": parse_errors,
            "oversized_skips": oversized_skips,
        },
        "fresh_candidate_pool": {
            "required_count": required_count,
            "eligible_count": len(fresh_candidates),
            "candidate_inventory_sha256": sha256_bytes(
                json.dumps(
                    fresh_candidates,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ),
            "candidate_ids": [
                row["prompt_id"]
                for row in fresh_candidates
            ],
        },
        "pre_generation_guard": {
            "existing_fresh_artifacts": already_exists,
            "fresh_generation_has_started": bool(already_exists),
        },
        "blockers": blockers,
        "scientific_boundary": {
            "audit_runs_before_fresh_generation": not bool(already_exists),
            "method_freeze_verified_before_leakage_audit": True,
            "selection_may_use_historical_prompt_identity": True,
            "selection_may_use_historical_prompt_text_fingerprint": True,
            "selection_uses_historical_generated_code_semantics": False,
            "selection_uses_risk_labels": False,
            "selection_uses_step8_detection_outputs": False,
            "prompt_id_overlap_is_leakage": True,
            "prompt_text_hash_overlap_is_leakage": True,
        },
    }

    write_json(out_path, report)

    print("STEP9 PRE-GENERATION LEAKAGE AUDIT", report["status"])
    print("normalized_source_prompt_count =", len(source_rows))
    print(
        "historical_prompt_ids_in_source_count =",
        len(historical_ids_in_source),
    )
    print(
        "historical_prompt_hashes_in_source_count =",
        len(historical_hashes_in_source),
    )
    print("fresh_candidate_count =", len(fresh_candidates))
    print("required_count =", required_count)
    print("parse_error_count =", len(parse_errors))
    print("existing_fresh_artifact_count =", len(already_exists))
    print("saved =", rel(out_path))

    if blockers:
        print("blockers =")
        for blocker in blockers:
            print(" -", blocker)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
