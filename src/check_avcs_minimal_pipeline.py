from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

OUTPUT_PATH = (
    ROOT
    / "output"
    / "avcs_minimal_pipeline_validation.csv"
)


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(
        path.read_text(encoding="utf-8")
    )


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    with path.open("r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if line:
                rows.append(json.loads(line))

    return rows


def add_check(
    rows: list[dict[str, str]],
    check_id: str,
    description: str,
    expected: Any,
    actual: Any,
) -> None:
    passed = actual == expected

    rows.append(
        {
            "check_id": check_id,
            "description": description,
            "expected": json.dumps(
                expected,
                ensure_ascii=False,
                sort_keys=True,
            ),
            "actual": json.dumps(
                actual,
                ensure_ascii=False,
                sort_keys=True,
            ),
            "status": "PASS" if passed else "FAIL",
        }
    )


def run_validation() -> list[dict[str, str]]:
    positive_api_calls = read_json(
        ROOT
        / "output"
        / "avcs_control_full_load_api_calls_v0.json"
    )

    positive_api = read_json(
        ROOT
        / "output"
        / "avcs_control_full_load_api_constraints_v0.json"
    )

    positive_evaluation = read_json(
        ROOT
        / "output"
        / "avcs_control_full_load_evaluation_v0.json"
    )

    positive_cards = read_jsonl(
        ROOT
        / "output"
        / "avcs_control_full_load_risk_cards_v0.jsonl"
    )

    positive_vulnerability = read_json(
        ROOT
        / "output"
        / "avcs_control_full_load_vulnerability_constraints_v0.json"
    )

    negative_api = read_json(
        ROOT
        / "output"
        / "auto_pilot50_018_api_constraints_v0.json"
    )

    negative_release_history = read_json(
        ROOT
        / "output"
        / "auto_pilot50_018_pyyaml_release_history_v0.json"
    )

    negative_api_compatible = read_json(
        ROOT
        / "output"
        / "auto_pilot50_018_api_compatible_releases_v0.json"
    )

    negative_manifest_constraints = read_json(
        ROOT
        / "output"
        / "auto_pilot50_018_manifest_constraints_v0.json"
    )

    negative_manifest_compatible = read_json(
        ROOT
        / "output"
        / "auto_pilot50_018_manifest_compatible_releases_v0.json"
    )

    negative_exposed = read_json(
        ROOT
        / "output"
        / "auto_pilot50_018_exposed_releases_v0.json"
    )

    negative_evaluation = read_json(
        ROOT
        / "output"
        / "auto_pilot50_018_avcs_evaluation_v0.json"
    )

    negative_cards = read_jsonl(
        ROOT
        / "output"
        / "auto_pilot50_018_avcs_risk_cards_v0.jsonl"
    )

    negative_source_samples = read_jsonl(
        ROOT
        / "data"
        / "samples"
        / "auto_qwen37_100_generated_codes.jsonl"
    )

    negative_source_sample = next(
        row
        for row in negative_source_samples
        if row.get("sample_id")
        == "auto_pilot50_018"
    )

    unresolved_api = read_json(
        ROOT
        / "output"
        / "avcs_unresolved_yaml_load_api_constraints.json"
    )

    unresolved_evaluation = read_json(
        ROOT
        / "output"
        / "avcs_unresolved_yaml_load_evaluation_v0.json"
    )

    unresolved_cards = read_jsonl(
        ROOT
        / "output"
        / "avcs_unresolved_yaml_load_risk_cards_v0.jsonl"
    )

    rows: list[dict[str, str]] = []

    positive_fixed_version = (
        positive_vulnerability["vulnerabilities"][0][
            "fixed_version_specifier"
        ]
    )

    positive_distribution = (
        positive_evaluation["distribution"]
    )

    expected_repair_command = (
        "python -m pip install "
        f"\"{positive_distribution}{positive_fixed_version}\""
    )

    positive_trigger_call = next(
        call
        for call in positive_api_calls["api_calls"]
        if call.get("api_symbol")
        == "yaml.full_load"
    )

    expected_trigger_location = (
        positive_trigger_call["location"]
    )

    add_check(
        rows,
        "positive_s_api",
        "受控正例的 API 版本约束",
        ">=5.1",
        positive_api["distribution_constraints"][0][
            "s_api"
        ]["simplified_specifier"],
    )

    add_check(
        rows,
        "positive_candidate_count",
        "受控正例产生一个候选风险",
        1,
        positive_evaluation[
            "risk_card_candidate_count"
        ],
    )

    add_check(
        rows,
        "positive_assessment",
        "受控正例需要输入来源复核",
        "candidate_requires_input_review",
        positive_evaluation["evaluations"][0][
            "assessment"
        ],
    )

    add_check(
        rows,
        "positive_intersection",
        "受控正例的版本交集",
        ">=5.1,<5.4",
        positive_evaluation["evaluations"][0][
            "intersection_specifier"
        ],
    )

    add_check(
        rows,
        "positive_risk_card_count",
        "受控正例生成一张 Risk Card",
        1,
        len(positive_cards),
    )

    add_check(
        rows,
        "positive_risk_type",
        "受控正例风险类型正确",
        "api_vulnerability_compatibility",
        (
            positive_cards[0]["type"]
            if positive_cards
            else None
        ),
    )

    add_check(
        rows,
        "positive_fixed_version_evaluation",
        "修复版本约束传入 AVCS evaluation",
        positive_fixed_version,
        positive_evaluation["evaluations"][0][
            "fixed_version_specifier"
        ],
    )

    add_check(
        rows,
        "positive_fixed_version_risk_card",
        "修复版本约束传入 Risk Card",
        positive_fixed_version,
        positive_cards[0]["evidence"][
            "version_constraints"
        ]["fixed_version_specifier"],
    )

    add_check(
        rows,
        "positive_repair_command",
        "Risk Card 修复命令使用漏洞修复版本",
        expected_repair_command,
        positive_cards[0]["repair"]["command"],
    )

    add_check(
        rows,
        "positive_sample_context_status",
        "受控正例成功关联 controlled sample metadata",
        "matched",
        positive_evaluation[
            "sample_context_status"
        ],
    )

    add_check(
        rows,
        "positive_card_model",
        "受控样本 Risk Card 不伪造 LLM model",
        None,
        positive_cards[0]["model"],
    )

    add_check(
        rows,
        "positive_card_prompt_id",
        "受控样本 Risk Card 不伪造 prompt_id",
        None,
        positive_cards[0]["prompt_id"],
    )

    add_check(
        rows,
        "positive_card_source_dataset",
        "Risk Card 保留受控样本数据集来源",
        "avcs_controlled_validation",
        positive_cards[0]["evidence"][
            "sample_context"
        ]["source_dataset"],
    )

    add_check(
        rows,
        "positive_card_source",
        "Risk Card 保留受控样本来源类型",
        "controlled_validation",
        positive_cards[0]["evidence"][
            "sample_context"
        ]["source"],
    )

    add_check(
        rows,
        "positive_card_generation_time",
        "受控样本不伪造 generation_time",
        None,
        positive_cards[0]["evidence"][
            "sample_context"
        ]["generation_time"],
    )

    add_check(
        rows,
        "negative_s_api",
        "真实安全样本的 API 版本约束",
        ">=5.1",
        negative_api["distribution_constraints"][0][
            "s_api"
        ]["simplified_specifier"],
    )

    add_check(
        rows,
        "negative_confirmed_release_count",
        "真实样本生成时间前确认的 PyYAML 历史版本数量",
        31,
        negative_release_history[
            "confirmed_release_count_as_of_time_view"
        ],
    )

    add_check(
        rows,
        "negative_api_compatible_count",
        "真实样本经 API 约束筛选后的兼容版本数量",
        18,
        negative_api_compatible[
            "confirmed_api_compatible_release_count"
        ],
    )

    add_check(
        rows,
        "negative_manifest_constraint_status",
        "真实样本 manifest 版本约束解析成功",
        "resolved",
        negative_manifest_constraints["status"],
    )

    add_check(
        rows,
        "negative_manifest_constraint_kind",
        "真实样本声明 PyYAML 但没有限制具体版本",
        "unconstrained",
        negative_manifest_constraints["constraint_kind"],
    )

    add_check(
        rows,
        "negative_manifest_compatible_count",
        "真实样本经 manifest 约束后的候选版本数量",
        18,
        negative_manifest_compatible[
            "confirmed_manifest_compatible_release_count"
        ],
    )

    add_check(
        rows,
        "negative_exposed_release_evidence_mode",
        "漏洞版本分析使用 manifest-compatible releases",
        "manifest_compatible",
        negative_exposed["release_evidence_mode"],
    )

    add_check(
        rows,
        "negative_manifest_context_status",
        "manifest 版本证据与当前样本和软件包一致",
        "matched",
        negative_exposed["manifest_context_status"],
    )

    add_check(
        rows,
        "negative_release_candidate_count",
        "最终参与漏洞版本匹配的真实候选版本数量",
        18,
        negative_exposed["evaluations"][0][
            "release_candidate_count"
        ],
    )

    add_check(
        rows,
        "negative_exposed_release_count",
        "API 兼容版本中落入漏洞影响范围的版本数量",
        8,
        negative_exposed["evaluations"][0][
            "confirmed_exposed_release_count"
        ],
    )

    add_check(
        rows,
        "negative_version_evidence_mode",
        "真实样本 evaluation 优先使用离散历史版本证据",
        "discrete_confirmed_releases",
        negative_evaluation["evaluations"][0][
            "version_evidence_mode"
        ],
    )

    add_check(
        rows,
        "negative_has_version_exposure",
        "真实样本存在漏洞影响范围内的兼容历史版本",
        True,
        negative_evaluation["evaluations"][0][
            "has_version_exposure"
        ],
    )

    add_check(
        rows,
        "negative_exposed_count_in_evaluation",
        "离散漏洞版本数量正确传入最终 evaluation",
        8,
        negative_evaluation["evaluations"][0][
            "confirmed_exposed_release_count"
        ],
    )

    add_check(
        rows,
        "negative_candidate_count",
        "安全 API 不产生候选风险",
        0,
        negative_evaluation[
            "risk_card_candidate_count"
        ],
    )

    add_check(
        rows,
        "negative_assessment",
        "安全样本未观察到漏洞触发 API",
        "trigger_api_not_observed",
        negative_evaluation["evaluations"][0][
            "assessment"
        ],
    )

    add_check(
        rows,
        "negative_risk_card_count",
        "安全样本不生成 Risk Card",
        0,
        len(negative_cards),
    )

    add_check(
        rows,
        "negative_sample_context_status",
        "真实样本成功关联原始 sample record",
        "matched",
        negative_evaluation[
            "sample_context_status"
        ],
    )

    add_check(
        rows,
        "negative_sample_model",
        "真实样本模型信息传入 AVCS evaluation",
        negative_source_sample["model"],
        negative_evaluation["sample_context"][
            "model"
        ],
    )

    add_check(
        rows,
        "negative_sample_prompt_id",
        "真实样本 prompt_id 传入 AVCS evaluation",
        negative_source_sample["prompt_id"],
        negative_evaluation["sample_context"][
            "prompt_id"
        ],
    )

    add_check(
        rows,
        "negative_sample_generation_time",
        "真实样本生成时间传入 AVCS evaluation",
        negative_source_sample["generation_time"],
        negative_evaluation["sample_context"][
            "generation_time"
        ],
    )

    add_check(
        rows,
        "unresolved_api_status",
        "缺少 API History 时版本约束保持 unresolved",
        "unresolved",
        unresolved_api["distribution_constraints"][0][
            "status"
        ],
    )

    add_check(
        rows,
        "unresolved_s_api",
        "unresolved API 不伪造版本范围",
        "",
        unresolved_api["distribution_constraints"][0][
            "s_api"
        ]["simplified_specifier"]
        or unresolved_api["distribution_constraints"][0][
            "s_api"
        ]["raw_specifier"],
    )

    add_check(
        rows,
        "unresolved_trigger_observed",
        "unresolved case 仍然观察到 yaml.load trigger",
        ["yaml.load"],
        unresolved_evaluation["evaluations"][0][
            "observed_trigger_apis"
        ],
    )

    add_check(
        rows,
        "unresolved_version_overlap",
        "unresolved API 不声称存在或不存在版本交集",
        None,
        unresolved_evaluation["evaluations"][0][
            "version_overlap"
        ],
    )

    add_check(
        rows,
        "unresolved_assessment",
        "unresolved API 保留不确定性状态",
        "api_constraint_unresolved",
        unresolved_evaluation["evaluations"][0][
            "assessment"
        ],
    )

    add_check(
        rows,
        "unresolved_candidate_count",
        "unresolved API 不生成漏洞候选",
        0,
        unresolved_evaluation[
            "risk_card_candidate_count"
        ],
    )

    add_check(
        rows,
        "unresolved_risk_card_count",
        "unresolved API 不生成 AVCS Risk Card",
        0,
        len(unresolved_cards),
    )

    add_check(
        rows,
        "positive_trigger_location_evaluation",
        "触发 API 位置传入 AVCS evaluation",
        expected_trigger_location,
        positive_evaluation["evaluations"][0][
            "observed_trigger_calls"
        ][0]["location"],
    )

    add_check(
        rows,
        "positive_trigger_location_risk_card",
        "触发 API 位置传入 Risk Card evidence",
        expected_trigger_location,
        positive_cards[0]["evidence"]["api"][
            "observed_trigger_calls"
        ][0]["location"],
    )

    add_check(
        rows,
        "positive_introduced_by_file",
        "Risk Card 定位到触发 API 文件",
        expected_trigger_location["file"],
        positive_cards[0]["introduced_by"][
            "file"
        ],
    )

    add_check(
        rows,
        "positive_introduced_by_line",
        "Risk Card 定位到触发 API 行号",
        expected_trigger_location["line"],
        positive_cards[0]["introduced_by"][
            "line"
        ],
    )

    return rows


def write_csv(rows: list[dict[str, str]]) -> None:
    OUTPUT_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fieldnames = [
        "check_id",
        "description",
        "expected",
        "actual",
        "status",
    ]

    with OUTPUT_PATH.open(
        "w",
        encoding="utf-8-sig",
        newline="",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    rows = run_validation()
    write_csv(rows)

    passed = sum(
        row["status"] == "PASS"
        for row in rows
    )

    failed = len(rows) - passed

    print(f"[OK] total checks: {len(rows)}")
    print(f"[OK] passed: {passed}")
    print(f"[OK] failed: {failed}")
    print(f"[OK] result saved to: {OUTPUT_PATH}")

    for row in rows:
        print(
            f"[{row['status']}] "
            f"{row['check_id']}"
        )

    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()