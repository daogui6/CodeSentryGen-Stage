"""Pure successor-generation outcome accounting candidate.

This module is intentionally not wired into the formal Step9 runner yet.
It implements only the first half of the successor-method revision:

* exact selected-population accounting,
* durable final-outcome partition validation,
* stage finalization classification, and
* byte-independent canonical content binding.

It does not call a provider, perform retry/recovery actions, acquire snapshots,
run THO/AVCS/SCEG/Risk Card analysis, or authorize a benchmark.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from typing import Any, Iterable


SCHEMA_VERSION = "step9_generation_outcome_manifest_v1"

RECOVERY_PROVEN_NOT_STARTED = "PROVEN_NOT_STARTED"
RECOVERY_PROVEN_ACCEPTED = "PROVEN_ACCEPTED"
RECOVERY_PROVEN_RETRYABLE_PRECOMMIT_FAILURE = (
    "PROVEN_RETRYABLE_PRECOMMIT_FAILURE"
)
RECOVERY_PROVEN_TERMINAL_FAILURE = "PROVEN_TERMINAL_FAILURE"
RECOVERY_AMBIGUOUS_IN_FLIGHT = "AMBIGUOUS_IN_FLIGHT"
RECOVERY_EVIDENCE_CONFLICT = "EVIDENCE_CONFLICT"

OUTCOME_ACCEPTED_COMPLETE = "ACCEPTED_COMPLETE"
OUTCOME_TERMINAL_MODEL_OUTPUT_FAILURE = "TERMINAL_MODEL_OUTPUT_FAILURE"
OUTCOME_TERMINAL_PROVIDER_PROTOCOL_FAILURE = (
    "TERMINAL_PROVIDER_PROTOCOL_FAILURE"
)
OUTCOME_TERMINAL_RETRY_BUDGET_EXHAUSTED = (
    "TERMINAL_RETRY_BUDGET_EXHAUSTED"
)
OUTCOME_TERMINAL_AMBIGUOUS_IN_FLIGHT = "TERMINAL_AMBIGUOUS_IN_FLIGHT"
OUTCOME_TERMINAL_EVIDENCE_CONFLICT = "TERMINAL_EVIDENCE_CONFLICT"

STATUS_FINALIZED_ALL_ACCEPTED = "FINALIZED_ALL_ACCEPTED"
STATUS_FINALIZED_WITH_TERMINALS = "FINALIZED_WITH_TERMINALS"
STATUS_UNRESOLVED_RECOVERY_PENDING = "UNRESOLVED_RECOVERY_PENDING"
STATUS_EVIDENCE_INVALID = "EVIDENCE_INVALID"

FINAL_OUTCOMES = {
    OUTCOME_ACCEPTED_COMPLETE,
    OUTCOME_TERMINAL_MODEL_OUTPUT_FAILURE,
    OUTCOME_TERMINAL_PROVIDER_PROTOCOL_FAILURE,
    OUTCOME_TERMINAL_RETRY_BUDGET_EXHAUSTED,
    OUTCOME_TERMINAL_AMBIGUOUS_IN_FLIGHT,
    OUTCOME_TERMINAL_EVIDENCE_CONFLICT,
}

MODEL_OUTPUT_FAILURE_CLASSES = {
    "output_token_limit_exceeded",
    "final_answer_content_missing",
    "model_output_contract_invalid",
    "model_output_json_decode_error",
}

PROVIDER_PROTOCOL_FAILURE_CLASSES = {
    "provider_model_identity_mismatch",
    "provider_thinking_mode_violation",
    "provider_protocol_violation",
    "sse_event_malformed",
    "sse_event_truncated",
    "sse_completion_interrupted",
}

EVIDENCE_FAILURE_CLASSES = {
    "accepted_response_persistence_failure",
    "attempt_ledger_persistence_failure",
}

RETRYABLE_FAILURE_CLASSES = {
    "connect_timeout",
    "read_timeout",
    "connection_error",
    "request_deadline_exceeded",
    "sse_completion_not_delivered",
    "sse_completion_interrupted",
    "sse_event_truncated",
    "provider_http_408",
    "provider_http_409",
    "provider_http_425",
    "provider_http_429",
}

REQUIRED_SELECTED_FIELDS = {"prompt_id", "sample_id"}

REQUIRED_INPUT_RECORD_FIELDS = {
    "prompt_id",
    "sample_id",
    "recovery_state",
    "recovery_reason",
    "attempt_count",
    "final_failure_class_or_null",
    "retry_budget_exhausted",
    "provider_recall_authorized",
    "accepted_response_journal_ref_or_null",
    "attempt_evidence_ref",
    "generated_sample_ref_or_null",
    "generated_code_ref_or_null",
    "requirements_ref_or_null",
    "generation_time_or_null",
}


def _nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_json_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def _is_provider_http_failure_class(value: str) -> bool:
    if not value.startswith("provider_http_"):
        return False
    suffix = value.removeprefix("provider_http_")
    try:
        status = int(suffix)
    except ValueError:
        return False
    return status > 0


def _is_retryable_failure_class(failure_class: str) -> bool:
    if failure_class in RETRYABLE_FAILURE_CLASSES:
        return True
    if failure_class.startswith("provider_http_"):
        try:
            status = int(failure_class.rsplit("_", 1)[1])
        except ValueError:
            return False
        return 500 <= status <= 599
    return False


def _classify_terminal_failure_class(failure_class: str) -> str | None:
    if _is_retryable_failure_class(failure_class):
        return None
    if failure_class in MODEL_OUTPUT_FAILURE_CLASSES:
        return OUTCOME_TERMINAL_MODEL_OUTPUT_FAILURE
    if (
        failure_class in PROVIDER_PROTOCOL_FAILURE_CLASSES
        or _is_provider_http_failure_class(failure_class)
    ):
        return OUTCOME_TERMINAL_PROVIDER_PROTOCOL_FAILURE
    if failure_class in EVIDENCE_FAILURE_CLASSES:
        return OUTCOME_TERMINAL_EVIDENCE_CONFLICT
    return None


def _copy_ref(value: Any) -> str | None:
    if value is None:
        return None
    if not _nonempty_string(value):
        return None
    return str(value).strip()


def _record_error(
    errors: list[str],
    sample_id: str,
    message: str,
) -> None:
    errors.append(f"{sample_id}: {message}")


def _validate_selected_population(
    selected_records: list[dict[str, Any]],
) -> tuple[list[dict[str, str]], list[str]]:
    errors: list[str] = []
    normalized: list[dict[str, str]] = []
    seen_prompt_ids: set[str] = set()
    seen_sample_ids: set[str] = set()

    for index, raw in enumerate(selected_records):
        label = f"selected[{index}]"
        if not isinstance(raw, dict):
            errors.append(f"{label}: record is not an object")
            continue

        missing = sorted(REQUIRED_SELECTED_FIELDS - set(raw))
        if missing:
            errors.append(
                f"{label}: missing required fields: {', '.join(missing)}"
            )
            continue

        prompt_id = str(raw.get("prompt_id") or "").strip()
        sample_id = str(raw.get("sample_id") or "").strip()
        if not prompt_id:
            errors.append(f"{label}: prompt_id is empty")
        if not sample_id:
            errors.append(f"{label}: sample_id is empty")
        if not prompt_id or not sample_id:
            continue

        if prompt_id in seen_prompt_ids:
            errors.append(f"{label}: duplicate prompt_id {prompt_id!r}")
        if sample_id in seen_sample_ids:
            errors.append(f"{label}: duplicate sample_id {sample_id!r}")
        seen_prompt_ids.add(prompt_id)
        seen_sample_ids.add(sample_id)

        normalized.append(
            {
                "prompt_id": prompt_id,
                "sample_id": sample_id,
            }
        )

    return normalized, errors


def _normalize_input_records(
    input_records: list[dict[str, Any]],
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    by_sample: dict[str, dict[str, Any]] = {}
    errors: list[str] = []

    for index, raw in enumerate(input_records):
        label = f"outcome_input[{index}]"
        if not isinstance(raw, dict):
            errors.append(f"{label}: record is not an object")
            continue

        missing = sorted(REQUIRED_INPUT_RECORD_FIELDS - set(raw))
        if missing:
            errors.append(
                f"{label}: missing required fields: {', '.join(missing)}"
            )
            continue

        sample_id = str(raw.get("sample_id") or "").strip()
        if not sample_id:
            errors.append(f"{label}: sample_id is empty")
            continue

        if sample_id in by_sample:
            errors.append(f"{label}: duplicate sample_id {sample_id!r}")
            continue

        by_sample[sample_id] = dict(raw)

    return by_sample, errors


def _derive_final_outcome(
    *,
    record: dict[str, Any],
    errors: list[str],
) -> str | None:
    sample_id = str(record.get("sample_id") or "").strip()
    state = str(record.get("recovery_state") or "").strip()
    failure_class_value = record.get("final_failure_class_or_null")
    failure_class = (
        str(failure_class_value).strip()
        if failure_class_value is not None
        else ""
    )
    retry_budget_exhausted = record.get("retry_budget_exhausted")

    if not isinstance(retry_budget_exhausted, bool):
        _record_error(
            errors,
            sample_id,
            "retry_budget_exhausted must be boolean",
        )
        return None

    if state == RECOVERY_PROVEN_ACCEPTED:
        if retry_budget_exhausted:
            _record_error(
                errors,
                sample_id,
                "accepted sample cannot exhaust retry budget",
            )
            return None
        if failure_class:
            _record_error(
                errors,
                sample_id,
                "accepted sample cannot have final failure class",
            )
            return None
        return OUTCOME_ACCEPTED_COMPLETE

    if state == RECOVERY_PROVEN_RETRYABLE_PRECOMMIT_FAILURE:
        if retry_budget_exhausted:
            return OUTCOME_TERMINAL_RETRY_BUDGET_EXHAUSTED
        return None

    if state == RECOVERY_PROVEN_NOT_STARTED:
        if retry_budget_exhausted:
            _record_error(
                errors,
                sample_id,
                "not-started sample cannot exhaust retry budget",
            )
        return None

    if state == RECOVERY_PROVEN_TERMINAL_FAILURE:
        if retry_budget_exhausted:
            _record_error(
                errors,
                sample_id,
                "terminal failure cannot also be retry-budget-exhausted",
            )
            return None
        if not failure_class:
            _record_error(
                errors,
                sample_id,
                "terminal failure is missing final failure class",
            )
            return None
        if _is_retryable_failure_class(failure_class):
            _record_error(
                errors,
                sample_id,
                "retryable failure class cannot be PROVEN_TERMINAL_FAILURE",
            )
            return None
        mapped = _classify_terminal_failure_class(failure_class)
        if mapped is None:
            _record_error(
                errors,
                sample_id,
                f"unmapped terminal failure class {failure_class!r}",
            )
            return None
        return mapped

    if state == RECOVERY_AMBIGUOUS_IN_FLIGHT:
        if retry_budget_exhausted:
            _record_error(
                errors,
                sample_id,
                "ambiguous in-flight cannot be retry-budget-exhausted",
            )
        return OUTCOME_TERMINAL_AMBIGUOUS_IN_FLIGHT

    if state == RECOVERY_EVIDENCE_CONFLICT:
        if retry_budget_exhausted:
            _record_error(
                errors,
                sample_id,
                "evidence conflict cannot be retry-budget-exhausted",
            )
        return OUTCOME_TERMINAL_EVIDENCE_CONFLICT

    _record_error(
        errors,
        sample_id,
        f"unknown recovery_state {state!r}",
    )
    return None


def _validate_record_evidence(
    *,
    selected: dict[str, str],
    record: dict[str, Any],
    final_outcome: str | None,
    errors: list[str],
) -> dict[str, Any]:
    sample_id = selected["sample_id"]
    prompt_id = selected["prompt_id"]

    observed_prompt_id = str(record.get("prompt_id") or "").strip()
    if observed_prompt_id != prompt_id:
        _record_error(
            errors,
            sample_id,
            "prompt_id does not match frozen selection",
        )

    attempt_count = record.get("attempt_count")
    if (
        not isinstance(attempt_count, int)
        or isinstance(attempt_count, bool)
        or attempt_count < 0
    ):
        _record_error(
            errors,
            sample_id,
            "attempt_count must be a non-negative integer",
        )
        attempt_count = 0

    provider_recall_authorized = record.get(
        "provider_recall_authorized"
    )
    if not isinstance(provider_recall_authorized, bool):
        _record_error(
            errors,
            sample_id,
            "provider_recall_authorized must be boolean",
        )
        provider_recall_authorized = False

    accepted_ref = _copy_ref(
        record.get("accepted_response_journal_ref_or_null")
    )
    attempt_ref = _copy_ref(record.get("attempt_evidence_ref"))
    generated_ref = _copy_ref(record.get("generated_sample_ref_or_null"))
    code_ref = _copy_ref(record.get("generated_code_ref_or_null"))
    requirements_ref = _copy_ref(record.get("requirements_ref_or_null"))
    generation_time = _copy_ref(record.get("generation_time_or_null"))
    failure_class_value = record.get("final_failure_class_or_null")
    failure_class = (
        str(failure_class_value).strip()
        if failure_class_value is not None
        else None
    )
    recovery_state = str(record.get("recovery_state") or "").strip()
    recovery_reason = str(record.get("recovery_reason") or "").strip()

    if attempt_ref is None:
        _record_error(
            errors,
            sample_id,
            "attempt_evidence_ref is required",
        )

    if final_outcome == OUTCOME_ACCEPTED_COMPLETE:
        if attempt_count <= 0:
            _record_error(
                errors,
                sample_id,
                "accepted sample must have at least one attempt",
            )
        for label, value in (
            ("accepted_response_journal_ref_or_null", accepted_ref),
            ("generated_sample_ref_or_null", generated_ref),
            ("generated_code_ref_or_null", code_ref),
            ("requirements_ref_or_null", requirements_ref),
            ("generation_time_or_null", generation_time),
        ):
            if value is None:
                _record_error(
                    errors,
                    sample_id,
                    f"accepted sample is missing {label}",
                )
        if provider_recall_authorized:
            _record_error(
                errors,
                sample_id,
                "accepted sample cannot authorize provider recall",
            )

    elif final_outcome in FINAL_OUTCOMES:
        if accepted_ref is not None:
            _record_error(
                errors,
                sample_id,
                "terminal sample cannot have accepted journal ref",
            )
        if generated_ref is not None:
            _record_error(
                errors,
                sample_id,
                "terminal sample cannot have generated sample ref",
            )
        if code_ref is not None:
            _record_error(
                errors,
                sample_id,
                "terminal sample cannot have generated code ref",
            )
        if requirements_ref is not None:
            _record_error(
                errors,
                sample_id,
                "terminal sample cannot have requirements ref",
            )
        if generation_time is not None:
            _record_error(
                errors,
                sample_id,
                "terminal sample cannot have generation_time",
            )
        if provider_recall_authorized:
            _record_error(
                errors,
                sample_id,
                "terminal final outcome cannot authorize provider recall",
            )
        if final_outcome in {
            OUTCOME_TERMINAL_MODEL_OUTPUT_FAILURE,
            OUTCOME_TERMINAL_PROVIDER_PROTOCOL_FAILURE,
            OUTCOME_TERMINAL_RETRY_BUDGET_EXHAUSTED,
        }:
            if attempt_count <= 0:
                _record_error(
                    errors,
                    sample_id,
                    "terminal attempt-derived outcome must have an attempt",
                )
            if not failure_class:
                _record_error(
                    errors,
                    sample_id,
                    "terminal attempt-derived outcome must preserve failure class",
                )

    else:
        if accepted_ref is not None or generated_ref is not None:
            _record_error(
                errors,
                sample_id,
                "unresolved sample cannot carry accepted generated-project refs",
            )
        if code_ref is not None or requirements_ref is not None:
            _record_error(
                errors,
                sample_id,
                "unresolved sample cannot carry generated sidecar refs",
            )
        if generation_time is not None:
            _record_error(
                errors,
                sample_id,
                "unresolved sample cannot have generation_time",
            )

    return {
        "prompt_id": prompt_id,
        "sample_id": sample_id,
        "recovery_state": recovery_state,
        "recovery_reason": recovery_reason,
        "final_outcome": final_outcome,
        "attempt_count": attempt_count,
        "final_failure_class_or_null": failure_class,
        "retry_budget_exhausted": bool(
            record.get("retry_budget_exhausted") is True
        ),
        "provider_recall_authorized": provider_recall_authorized,
        "accepted_response_journal_ref_or_null": accepted_ref,
        "attempt_evidence_ref": attempt_ref,
        "generated_sample_ref_or_null": generated_ref,
        "generated_code_ref_or_null": code_ref,
        "requirements_ref_or_null": requirements_ref,
        "generation_time_or_null": generation_time,
    }


def _ordered_unique(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(values))


def build_generation_outcome_manifest(
    *,
    split: str,
    protocol_id: str,
    selection_manifest_hash: str,
    method_closure_sha256: str,
    request_contract_sha256: str,
    selected_records: list[dict[str, Any]],
    outcome_input_records: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build a strict, read-only generation-outcome accounting manifest.

    The function never authorizes provider calls or downstream analysis.
    Structural or evidence defects are represented as EVIDENCE_INVALID rather
    than being silently dropped.
    """

    top_level_errors: list[str] = []
    for label, value in (
        ("split", split),
        ("protocol_id", protocol_id),
        ("selection_manifest_hash", selection_manifest_hash),
        ("method_closure_sha256", method_closure_sha256),
        ("request_contract_sha256", request_contract_sha256),
    ):
        if not _nonempty_string(value):
            top_level_errors.append(f"{label}: must be a non-empty string")

    selected, selected_errors = _validate_selected_population(
        selected_records
    )
    if not selected:
        selected_errors.append("selected population must not be empty")
    input_by_sample, input_errors = _normalize_input_records(
        outcome_input_records
    )

    errors = top_level_errors + selected_errors + input_errors
    selected_sample_ids = [row["sample_id"] for row in selected]
    selected_prompt_ids = [row["prompt_id"] for row in selected]
    selected_sample_set = set(selected_sample_ids)

    extra_sample_ids = sorted(set(input_by_sample) - selected_sample_set)
    if extra_sample_ids:
        errors.append(
            "outcome_input contains non-selected sample_ids: "
            + ", ".join(extra_sample_ids)
        )

    normalized_records: list[dict[str, Any]] = []
    missing_sample_ids: list[str] = []

    for selected_row in selected:
        sample_id = selected_row["sample_id"]
        raw = input_by_sample.get(sample_id)
        if raw is None:
            missing_sample_ids.append(sample_id)
            continue

        final_outcome = _derive_final_outcome(
            record=raw,
            errors=errors,
        )
        normalized_records.append(
            _validate_record_evidence(
                selected=selected_row,
                record=raw,
                final_outcome=final_outcome,
                errors=errors,
            )
        )

    if missing_sample_ids:
        errors.append(
            "selected samples missing outcome input records: "
            + ", ".join(missing_sample_ids)
        )

    accepted_records = [
        row
        for row in normalized_records
        if row["final_outcome"] == OUTCOME_ACCEPTED_COMPLETE
    ]
    terminal_records = [
        row
        for row in normalized_records
        if row["final_outcome"] in FINAL_OUTCOMES
        and row["final_outcome"] != OUTCOME_ACCEPTED_COMPLETE
    ]
    unresolved_records = [
        row
        for row in normalized_records
        if row["final_outcome"] is None
        and row["recovery_state"]
        in {
            RECOVERY_PROVEN_NOT_STARTED,
            RECOVERY_PROVEN_RETRYABLE_PRECOMMIT_FAILURE,
        }
    ]

    accepted_sample_ids = [row["sample_id"] for row in accepted_records]
    terminal_sample_ids = [row["sample_id"] for row in terminal_records]
    unresolved_sample_ids = [row["sample_id"] for row in unresolved_records]

    accepted_prompt_ids = [row["prompt_id"] for row in accepted_records]
    terminal_prompt_ids = [row["prompt_id"] for row in terminal_records]
    unresolved_prompt_ids = [row["prompt_id"] for row in unresolved_records]

    accepted_set = set(accepted_sample_ids)
    terminal_set = set(terminal_sample_ids)
    unresolved_set = set(unresolved_sample_ids)

    accepted_terminal_disjoint = accepted_set.isdisjoint(terminal_set)
    partition_pairwise_disjoint = (
        accepted_set.isdisjoint(terminal_set)
        and accepted_set.isdisjoint(unresolved_set)
        and terminal_set.isdisjoint(unresolved_set)
    )
    if not partition_pairwise_disjoint:
        errors.append("accepted/terminal/unresolved partitions overlap")

    all_selected_accounted = (
        not missing_sample_ids
        and not extra_sample_ids
        and len(input_by_sample) == len(selected_sample_ids)
        and set(input_by_sample) == selected_sample_set
    )

    partition_count = (
        len(accepted_records)
        + len(terminal_records)
        + len(unresolved_records)
    )
    partition_complete = (
        partition_count == len(selected_sample_ids)
        and set(
            accepted_sample_ids
            + terminal_sample_ids
            + unresolved_sample_ids
        )
        == selected_sample_set
        and partition_pairwise_disjoint
    )

    terminal_failure_counter: Counter[str] = Counter()
    terminal_outcome_counter: Counter[str] = Counter()
    for row in terminal_records:
        terminal_outcome_counter[row["final_outcome"]] += 1
        failure_key = (
            row["final_failure_class_or_null"]
            or row["recovery_reason"]
            or row["final_outcome"]
        )
        terminal_failure_counter[str(failure_key)] += 1

    if errors or not all_selected_accounted or not partition_complete:
        stage_status = STATUS_EVIDENCE_INVALID
    elif unresolved_records:
        stage_status = STATUS_UNRESOLVED_RECOVERY_PENDING
    elif terminal_records:
        stage_status = STATUS_FINALIZED_WITH_TERMINALS
    else:
        stage_status = STATUS_FINALIZED_ALL_ACCEPTED

    finalized = stage_status in {
        STATUS_FINALIZED_ALL_ACCEPTED,
        STATUS_FINALIZED_WITH_TERMINALS,
    }
    all_selected_finalized = finalized and len(unresolved_records) == 0
    selected_count = len(selected_sample_ids)
    accepted_count = len(accepted_records)
    completion_rate = (
        accepted_count / selected_count if selected_count else None
    )

    manifest: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "split": str(split),
        "protocol_id": str(protocol_id),
        "selection_manifest_hash": str(selection_manifest_hash),
        "method_closure_sha256": str(method_closure_sha256),
        "request_contract_sha256": str(request_contract_sha256),
        "selected_count": selected_count,
        "selected_prompt_ids": selected_prompt_ids,
        "selected_sample_ids": selected_sample_ids,
        "accepted_complete_count": accepted_count,
        "accepted_prompt_ids": accepted_prompt_ids,
        "accepted_sample_ids": accepted_sample_ids,
        "terminal_count": len(terminal_records),
        "terminal_prompt_ids": terminal_prompt_ids,
        "terminal_sample_ids": terminal_sample_ids,
        "terminal_count_by_failure_class": dict(
            sorted(terminal_failure_counter.items())
        ),
        "terminal_count_by_final_outcome": dict(
            sorted(terminal_outcome_counter.items())
        ),
        "unresolved_count": len(unresolved_records),
        "unresolved_prompt_ids": unresolved_prompt_ids,
        "unresolved_sample_ids": unresolved_sample_ids,
        "generation_completion_rate": completion_rate,
        "analysis_population_count": accepted_count,
        "analysis_population_sample_ids": accepted_sample_ids,
        "stage_evidence_status": stage_status,
        "all_selected_accounted": all_selected_accounted,
        "all_selected_finalized": all_selected_finalized,
        "accepted_terminal_disjoint": accepted_terminal_disjoint,
        "selected_outcome_partition_complete": partition_complete,
        "outcome_records": normalized_records,
        "validation_errors": _ordered_unique(errors),
        "scientific_boundary": {
            "provider_calls_authorized_by_manifest": False,
            "retry_authorized_by_manifest": False,
            "snapshot_authorized_by_manifest": False,
            "downstream_analysis_authorized_by_manifest": False,
            "terminal_generation_is_dependency_risk_negative": False,
            "terminal_generation_is_dependency_risk_unknown": False,
            "analysis_population_is_accepted_complete_only": True,
            "terminal_partial_output_is_generated_project": False,
            "successful_sample_regeneration_authorized": False,
        },
    }

    manifest["manifest_content_sha256"] = canonical_json_sha256(manifest)
    return manifest


def validate_manifest_self_consistency(
    manifest: dict[str, Any],
) -> None:
    """Raise ValueError if a built manifest is internally inconsistent."""

    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("generation outcome manifest schema mismatch")

    copy_without_hash = dict(manifest)
    observed_hash = str(
        copy_without_hash.pop("manifest_content_sha256", "")
    )
    expected_hash = canonical_json_sha256(copy_without_hash)
    if observed_hash != expected_hash:
        raise ValueError("generation outcome manifest content hash mismatch")

    selected_ids = list(manifest.get("selected_sample_ids") or [])
    accepted_ids = list(manifest.get("accepted_sample_ids") or [])
    terminal_ids = list(manifest.get("terminal_sample_ids") or [])
    unresolved_ids = list(manifest.get("unresolved_sample_ids") or [])

    if len(selected_ids) != int(manifest.get("selected_count") or 0):
        raise ValueError("selected_count mismatch")
    if len(accepted_ids) != int(
        manifest.get("accepted_complete_count") or 0
    ):
        raise ValueError("accepted_complete_count mismatch")
    if len(terminal_ids) != int(manifest.get("terminal_count") or 0):
        raise ValueError("terminal_count mismatch")
    if len(unresolved_ids) != int(
        manifest.get("unresolved_count") or 0
    ):
        raise ValueError("unresolved_count mismatch")

    if set(accepted_ids) & set(terminal_ids):
        raise ValueError("accepted and terminal sets overlap")
    if set(accepted_ids) & set(unresolved_ids):
        raise ValueError("accepted and unresolved sets overlap")
    if set(terminal_ids) & set(unresolved_ids):
        raise ValueError("terminal and unresolved sets overlap")

    status = manifest.get("stage_evidence_status")
    errors = list(manifest.get("validation_errors") or [])
    if status == STATUS_EVIDENCE_INVALID:
        if not errors and bool(manifest.get("selected_outcome_partition_complete")):
            raise ValueError("EVIDENCE_INVALID has no recorded defect")
    elif errors:
        raise ValueError("non-invalid manifest contains validation errors")

    if status == STATUS_FINALIZED_ALL_ACCEPTED:
        if terminal_ids or unresolved_ids:
            raise ValueError("all-accepted status contains non-accepted outcomes")
        if set(accepted_ids) != set(selected_ids):
            raise ValueError("all-accepted status does not cover selection")
    elif status == STATUS_FINALIZED_WITH_TERMINALS:
        if not terminal_ids or unresolved_ids:
            raise ValueError("terminal-finalized status partition mismatch")
        if set(accepted_ids) | set(terminal_ids) != set(selected_ids):
            raise ValueError("terminal-finalized status does not cover selection")
    elif status == STATUS_UNRESOLVED_RECOVERY_PENDING:
        if not unresolved_ids:
            raise ValueError("unresolved status has no unresolved samples")
    elif status != STATUS_EVIDENCE_INVALID:
        raise ValueError(f"unknown stage_evidence_status: {status!r}")

    if list(manifest.get("analysis_population_sample_ids") or []) != accepted_ids:
        raise ValueError("analysis population must equal accepted sample IDs")
