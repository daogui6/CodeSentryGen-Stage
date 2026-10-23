from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]

DEFAULT_CORPUS = ROOT / "output" / "avcs_trigger_candidate_evidence_corpus_v0.json"

DEFAULT_FACTS = ROOT / "output" / "avcs_trigger_candidate_facts_v0.json"

EXPECTED_SCHEMA_VERSION = "avcs_trigger_candidate_facts_v0.1"
EXPECTED_EXTRACTOR_VERSION = "trigger_candidate_fact_extractor_v0.2"

EXPECTED_CORPUS_ENTRY_COUNT = 38
EXPECTED_EVIDENCE_UNIT_COUNT = 86
EXPECTED_UNITS_WITH_CANDIDATES = 57
EXPECTED_SOURCES_WITH_CANDIDATES = 34
EXPECTED_RAW_CANDIDATE_FACT_COUNT = 1887
EXPECTED_CANDIDATE_FACT_COUNT = 833
EXPECTED_RAW_PYTHON_CANDIDATE_COUNT = 1418
EXPECTED_RETAINED_PYTHON_CANDIDATE_COUNT = 364
EXPECTED_REJECTED_PYTHON_CANDIDATE_COUNT = 1054
EXPECTED_EXPRESSION_FACT_COUNT = 205


class CheckState:
    def __init__(self) -> None:
        self.passed = 0
        self.failed = 0
        self.failures: list[str] = []

    def check(self, condition: bool, label: str) -> None:
        if condition:
            self.passed += 1
            return

        self.failed += 1
        self.failures.append(label)


def clean_text(value: Any) -> str:
    return str(value if value is not None else "").strip()


def load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))

    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object: {path}")

    return data


def dict_rows(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []

    return [row for row in value if isinstance(row, dict)]


def normalized_ids(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return tuple()

    return tuple(
        sorted({clean_text(item).lower() for item in value if clean_text(item)})
    )


def evidence_group_key(row: dict[str, Any]) -> tuple[str, tuple[str, ...]]:
    return (
        clean_text(row.get("distribution")).lower(),
        normalized_ids(row.get("vulnerability_ids")),
    )


def is_python_release_source_unit(entry: dict[str, Any], unit: dict[str, Any]) -> bool:
    if clean_text(unit.get("unit_kind")) != "github_source_file_text":
        return False

    if clean_text(entry.get("source_type")) != "upstream_release_source":
        return False

    locator = unit.get("locator", {})

    if not isinstance(locator, dict):
        return False

    source_path = clean_text(locator.get("path"))

    return Path(source_path).suffix.lower() == ".py"


def find_fact(
    facts: list[dict[str, Any]], predicate: Callable[[dict[str, Any]], bool]
) -> bool:
    return any(predicate(fact) for fact in facts)


def nested_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value

    return {}


def build_corpus_indices(
    corpus: dict[str, Any],
) -> tuple[dict[str, dict[str, Any]], dict[str, tuple[dict[str, Any], dict[str, Any]]]]:
    entry_index: dict[str, dict[str, Any]] = {}

    unit_index: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}

    for entry in dict_rows(corpus.get("entries")):
        source_key = clean_text(entry.get("source_key"))

        if source_key:
            entry_index[source_key] = entry

        for unit in dict_rows(entry.get("evidence_units")):
            unit_id = clean_text(unit.get("unit_id"))

            if unit_id:
                unit_index[unit_id] = (entry, unit)

    return (entry_index, unit_index)


def check_top_level(state: CheckState, data: dict[str, Any]) -> None:
    state.check(data.get("schema_version") == EXPECTED_SCHEMA_VERSION, "schema_version")

    state.check(
        data.get("extractor_version") == EXPECTED_EXTRACTOR_VERSION, "extractor_version"
    )

    state.check(data.get("status") == "resolved", "status_resolved")

    state.check(
        data.get("source_mode")
        == ("deterministic_candidate_fact_" "extraction_from_evidence_corpus"),
        "source_mode",
    )

    boundary = nested_dict(data.get("semantic_boundary"))

    expected_boundary = {
        "consumes_candidate_evidence_corpus": True,
        "consumes_trigger_raw_ground_truth": False,
        "uses_llm_semantic_inference": False,
        "creates_candidate_facts": True,
        "creates_resolved_trigger_rules": False,
        "candidate_status_is_ground_truth": False,
        "all_candidates_require_review": True,
        "python_candidates_require_cross_source_identifier_support": True,
        "intended_next_stage": "conservative_candidate_fact_validation",
    }

    for key, expected in expected_boundary.items():
        state.check(boundary.get(key) == expected, f"semantic_boundary::{key}")

    supported = nested_dict(data.get("supported_extraction"))

    state.check(
        supported.get("structured_osv_range_events") is True,
        "supported::structured_osv_range_events",
    )

    state.check(
        supported.get("python_ast_parameter_defaults") is True,
        "supported::python_ast_parameter_defaults",
    )

    state.check(
        supported.get("python_ast_call_shapes") is True,
        "supported::python_ast_call_shapes",
    )

    state.check(
        supported.get("evidence_code_expression_call_arguments") is True,
        "supported::evidence_code_expression_call_arguments",
    )

    state.check(
        supported.get("evidence_code_expression_assignments") is True,
        "supported::evidence_code_expression_assignments",
    )

    state.check(
        supported.get("natural_language_trigger_inference") is False,
        "unsupported::natural_language_trigger_inference",
    )

    state.check(
        supported.get("cross_source_semantic_rule_composition") is False,
        "unsupported::cross_source_semantic_rule_composition",
    )

    input_text = json.dumps(data.get("input", {}), ensure_ascii=False).lower()

    state.check("trigger_raw" not in input_text, "input_does_not_reference_trigger_raw")


def check_summary(
    state: CheckState, data: dict[str, Any], facts: list[dict[str, Any]]
) -> None:
    summary = nested_dict(data.get("summary"))

    state.check(
        summary.get("corpus_entry_count") == EXPECTED_CORPUS_ENTRY_COUNT,
        "summary::corpus_entry_count",
    )

    state.check(
        summary.get("evidence_unit_count") == EXPECTED_EVIDENCE_UNIT_COUNT,
        "summary::evidence_unit_count",
    )

    state.check(
        summary.get("units_with_candidates") == EXPECTED_UNITS_WITH_CANDIDATES,
        "summary::units_with_candidates",
    )

    state.check(
        summary.get("sources_with_candidates") == EXPECTED_SOURCES_WITH_CANDIDATES,
        "summary::sources_with_candidates",
    )

    state.check(
        summary.get("raw_candidate_fact_count") == EXPECTED_RAW_CANDIDATE_FACT_COUNT,
        "summary::raw_candidate_fact_count",
    )

    state.check(
        summary.get("candidate_fact_count") == EXPECTED_CANDIDATE_FACT_COUNT,
        "summary::candidate_fact_count",
    )

    state.check(
        len(facts) == EXPECTED_CANDIDATE_FACT_COUNT, "actual_candidate_fact_count"
    )

    state.check(summary.get("issue_count") == 0, "summary::issue_count_zero")

    issues = data.get("issues", [])

    state.check(isinstance(issues, list) and len(issues) == 0, "issues_empty")

    gate = nested_dict(summary.get("python_relevance_gate"))

    state.check(
        gate.get("method") == "cross_source_identifier_overlap_v0", "gate::method"
    )

    state.check(
        gate.get("raw_python_candidate_count") == EXPECTED_RAW_PYTHON_CANDIDATE_COUNT,
        "gate::raw_python_candidate_count",
    )

    state.check(
        gate.get("retained_python_candidate_count")
        == EXPECTED_RETAINED_PYTHON_CANDIDATE_COUNT,
        "gate::retained_python_candidate_count",
    )

    state.check(
        gate.get("rejected_python_candidate_count")
        == EXPECTED_REJECTED_PYTHON_CANDIDATE_COUNT,
        "gate::rejected_python_candidate_count",
    )

    raw_python = gate.get("raw_python_candidate_count")

    retained_python = gate.get("retained_python_candidate_count")

    rejected_python = gate.get("rejected_python_candidate_count")

    state.check(
        isinstance(raw_python, int)
        and isinstance(retained_python, int)
        and isinstance(rejected_python, int)
        and raw_python == retained_python + rejected_python,
        "gate::raw_equals_retained_plus_rejected",
    )

    state.check(
        summary.get("raw_candidate_fact_count") - rejected_python
        == summary.get("candidate_fact_count"),
        "summary::raw_minus_rejected_equals_final",
    )

    actual_python_count = sum(
        1 for fact in facts if clean_text(fact.get("fact_kind")).startswith("python_")
    )

    state.check(
        actual_python_count == retained_python, "actual_python_count_matches_gate"
    )

    actual_expression_count = sum(
        1
        for fact in facts
        if clean_text(fact.get("fact_kind")).startswith("code_expression_")
    )

    state.check(
        actual_expression_count == EXPECTED_EXPRESSION_FACT_COUNT,
        "expression_fact_count",
    )

    actual_kind_counts = Counter(clean_text(fact.get("fact_kind")) for fact in facts)

    expected_kind_counts = nested_dict(summary.get("fact_kind_counts"))

    state.check(
        dict(sorted(actual_kind_counts.items())) == expected_kind_counts,
        "summary::fact_kind_counts_recomputed",
    )

    actual_confidence_counts = Counter(
        clean_text(fact.get("confidence_level")) for fact in facts
    )

    expected_confidence_counts = nested_dict(summary.get("confidence_counts"))

    state.check(
        dict(sorted(actual_confidence_counts.items())) == expected_confidence_counts,
        "summary::confidence_counts_recomputed",
    )

    distributions = {clean_text(fact.get("distribution")).lower() for fact in facts}

    state.check(
        distributions == {"aiohttp", "numpy", "pyjwt", "pyyaml", "requests", "urllib3"},
        "all_six_distributions_present",
    )


def check_fact_provenance(
    state: CheckState,
    facts: list[dict[str, Any]],
    entry_index: dict[str, dict[str, Any]],
    unit_index: dict[str, tuple[dict[str, Any], dict[str, Any]]],
) -> None:
    seen_fact_ids: set[str] = set()

    for index, fact in enumerate(facts):
        prefix = f"fact[{index}]"

        fact_id = clean_text(fact.get("fact_id"))

        state.check(bool(fact_id), f"{prefix}::fact_id_present")

        state.check(fact_id not in seen_fact_ids, f"{prefix}::fact_id_unique")

        seen_fact_ids.add(fact_id)

        state.check(
            fact.get("candidate_status") == "candidate", f"{prefix}::candidate_status"
        )

        state.check(fact.get("review_required") is True, f"{prefix}::review_required")

        state.check(
            clean_text(fact.get("fact_kind")) != "", f"{prefix}::fact_kind_present"
        )

        state.check(
            fact.get("confidence_level") in {"high", "moderate"},
            f"{prefix}::confidence_level",
        )

        state.check(
            bool(clean_text(fact.get("confidence_basis"))),
            f"{prefix}::confidence_basis_present",
        )

        state.check(
            fact.get("extractor") == EXPECTED_EXTRACTOR_VERSION,
            f"{prefix}::extractor_version",
        )

        source_key = clean_text(fact.get("source_key"))

        state.check(source_key in entry_index, f"{prefix}::source_key_in_corpus")

        entry = entry_index.get(source_key)

        if entry is not None:
            state.check(
                clean_text(fact.get("distribution")).lower()
                == clean_text(entry.get("distribution")).lower(),
                f"{prefix}::distribution_matches_entry",
            )

            state.check(
                normalized_ids(fact.get("vulnerability_ids"))
                == normalized_ids(entry.get("vulnerability_ids")),
                f"{prefix}::vulnerability_ids_match_entry",
            )

        unit_id = clean_text(fact.get("evidence_unit_id"))

        state.check(unit_id in unit_index, f"{prefix}::evidence_unit_in_corpus")

        unit_pair = unit_index.get(unit_id)

        if unit_pair is not None:
            unit_entry, unit = unit_pair

            state.check(
                clean_text(unit_entry.get("source_key")) == source_key,
                f"{prefix}::unit_belongs_to_source",
            )

            state.check(
                fact.get("unit_kind") == unit.get("unit_kind"),
                f"{prefix}::unit_kind_matches",
            )

            state.check(
                fact.get("text_sha256") == unit.get("text_sha256"),
                f"{prefix}::text_sha256_matches",
            )

            state.check(
                fact.get("evidence_locator") == unit.get("locator", {}),
                f"{prefix}::evidence_locator_matches",
            )


def check_python_relevance_gate(
    state: CheckState,
    facts: list[dict[str, Any]],
    unit_index: dict[str, tuple[dict[str, Any], dict[str, Any]]],
) -> None:
    for index, fact in enumerate(facts):
        fact_kind = clean_text(fact.get("fact_kind"))

        if not fact_kind.startswith("python_"):
            continue

        prefix = f"python_fact[{index}]"

        gate = nested_dict(fact.get("relevance_gate"))

        state.check(gate.get("status") == "supported", f"{prefix}::gate_status")

        state.check(
            gate.get("method") == "cross_source_identifier_overlap_v0",
            f"{prefix}::gate_method",
        )

        state.check(
            gate.get("support_is_cross_source") is True, f"{prefix}::cross_source"
        )

        state.check(
            gate.get("support_excludes_python_release_source") is True,
            f"{prefix}::excludes_python_release_source",
        )

        state.check(
            gate.get("support_excludes_commit_patch") is True,
            f"{prefix}::excludes_patch",
        )

        anchors = gate.get("matched_anchors", [])

        state.check(
            isinstance(anchors, list) and len(anchors) > 0,
            f"{prefix}::matched_anchors_present",
        )

        support_ids = gate.get("supporting_evidence_unit_ids", [])

        state.check(
            isinstance(support_ids, list) and len(support_ids) > 0,
            f"{prefix}::support_units_present",
        )

        fact_group = evidence_group_key(fact)

        for support_id in support_ids:
            support_pair = unit_index.get(clean_text(support_id))

            state.check(
                support_pair is not None,
                (f"{prefix}::support_unit_exists::" f"{support_id}"),
            )

            if support_pair is None:
                continue

            support_entry, support_unit = support_pair

            state.check(
                evidence_group_key(support_entry) == fact_group,
                (f"{prefix}::support_same_evidence_group::" f"{support_id}"),
            )

            state.check(
                clean_text(support_unit.get("unit_kind")) != "github_commit_patch",
                (f"{prefix}::support_not_patch::" f"{support_id}"),
            )

            state.check(
                not is_python_release_source_unit(support_entry, support_unit),
                (f"{prefix}::support_not_python_source::" f"{support_id}"),
            )


def check_key_case_facts(state: CheckState, facts: list[dict[str, Any]]) -> None:
    def sv(fact: dict[str, Any]) -> dict[str, Any]:
        return nested_dict(fact.get("structured_value"))

    def arg(fact: dict[str, Any]) -> dict[str, Any]:
        return nested_dict(sv(fact).get("argument_value"))

    def default(fact: dict[str, Any]) -> dict[str, Any]:
        return nested_dict(sv(fact).get("default"))

    state.check(
        find_fact(
            facts,
            lambda fact: (
                clean_text(fact.get("distribution")).lower() == "numpy"
                and fact.get("fact_kind") == "python_parameter_default_candidate"
                and sv(fact).get("function_symbol") == "load"
                and sv(fact).get("parameter_name") == "allow_pickle"
                and default(fact).get("value") is True
                and "1_16_2" in clean_text(fact.get("source_key"))
            ),
        ),
        "key_case::numpy_allow_pickle_true",
    )

    state.check(
        find_fact(
            facts,
            lambda fact: (
                clean_text(fact.get("distribution")).lower() == "numpy"
                and fact.get("fact_kind") == "python_parameter_default_candidate"
                and sv(fact).get("function_symbol") == "load"
                and sv(fact).get("parameter_name") == "allow_pickle"
                and default(fact).get("value") is False
                and "1_16_3" in clean_text(fact.get("source_key"))
            ),
        ),
        "key_case::numpy_allow_pickle_false",
    )

    state.check(
        find_fact(
            facts,
            lambda fact: (
                clean_text(fact.get("distribution")).lower() == "aiohttp"
                and fact.get("fact_kind") == "text_assignment_literal_candidate"
                and sv(fact).get("name") == "follow_symlinks"
                and sv(fact).get("literal") is True
            ),
        ),
        "key_case::aiohttp_follow_symlinks_true",
    )

    state.check(
        find_fact(
            facts,
            lambda fact: (
                clean_text(fact.get("distribution")).lower() == "pyjwt"
                and fact.get("fact_kind") == "code_expression_keyword_call_candidate"
                and sv(fact).get("call_symbol") == "jwt.decode"
                and sv(fact).get("keyword_name") == "algorithms"
                and arg(fact).get("call_symbol")
                == ("jwt.algorithms." "get_default_algorithms")
            ),
        ),
        "key_case::pyjwt_algorithms_default_call",
    )

    state.check(
        find_fact(
            facts,
            lambda fact: (
                clean_text(fact.get("distribution")).lower() == "pyyaml"
                and fact.get("fact_kind")
                == "code_expression_positional_symbol_candidate"
                and sv(fact).get("call_symbol") == "yaml.load"
                and sv(fact).get("position") == 1
                and arg(fact).get("symbol") == "yaml.FullLoader"
            ),
        ),
        "key_case::pyyaml_load_fullloader",
    )

    state.check(
        find_fact(
            facts,
            lambda fact: (
                clean_text(fact.get("distribution")).lower() == "urllib3"
                and fact.get("fact_kind") == "code_expression_keyword_literal_candidate"
                and sv(fact).get("call_symbol") == "urllib3.PoolManager"
                and sv(fact).get("keyword_name") == "retries"
                and arg(fact).get("value") == 0
            ),
        ),
        "key_case::urllib3_poolmanager_retries_zero",
    )

    state.check(
        find_fact(
            facts,
            lambda fact: (
                clean_text(fact.get("distribution")).lower() == "urllib3"
                and fact.get("fact_kind") == "code_expression_keyword_literal_candidate"
                and sv(fact).get("call_symbol") == "urllib3.PoolManager"
                and sv(fact).get("keyword_name") == "retries"
                and arg(fact).get("value") is False
            ),
        ),
        "key_case::urllib3_poolmanager_retries_false",
    )

    state.check(
        find_fact(
            facts,
            lambda fact: (
                clean_text(fact.get("distribution")).lower() == "requests"
                and fact.get("fact_kind") == "python_parameter_default_candidate"
                and sv(fact).get("function_symbol") == "resolve_proxies"
                and sv(fact).get("parameter_name") == "trust_env"
                and default(fact).get("value") is True
            ),
        ),
        "key_case::requests_trust_env_true",
    )

    state.check(
        find_fact(
            facts,
            lambda fact: (
                clean_text(fact.get("distribution")).lower() == "requests"
                and fact.get("fact_kind")
                in {
                    "text_assignment_literal_candidate",
                    "text_code_assignment_literal_candidate",
                }
                and sv(fact).get("name") == "trust_env"
                and sv(fact).get("literal") is False
            ),
        ),
        "key_case::requests_trust_env_false",
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=("Validate AVCS Trigger Evidence " "candidate fact extraction v0.")
    )

    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)

    parser.add_argument("--facts", type=Path, default=DEFAULT_FACTS)

    args = parser.parse_args()

    corpus = load_json(args.corpus)

    data = load_json(args.facts)

    facts = dict_rows(data.get("facts"))

    entry_index, unit_index = build_corpus_indices(corpus)

    state = CheckState()

    check_top_level(state, data)

    check_summary(state, data, facts)

    check_fact_provenance(state, facts, entry_index, unit_index)

    check_python_relevance_gate(state, facts, unit_index)

    check_key_case_facts(state, facts)

    print("=" * 60)

    print("AVCS TRIGGER CANDIDATE FACT CHECK")

    print("=" * 60)

    print("[INFO] corpus entries:", len(entry_index))

    print("[INFO] corpus evidence units:", len(unit_index))

    print("[INFO] candidate facts:", len(facts))

    print("[INFO] checks passed:", state.passed)

    print("[INFO] checks failed:", state.failed)

    if state.failures:
        print("")

        print("[FAIL] failed checks:")

        for failure in state.failures:
            print("  -", failure)

        sys.exit(1)

    print("[OK] ALL CHECKS PASS")


if __name__ == "__main__":
    main()
