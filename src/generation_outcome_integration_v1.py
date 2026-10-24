"""Successor generation-outcome integration helpers.

This module adapts the existing frozen generation/recovery evidence into the
Part1 outcome-accounting core.  It does not call a provider and it does not
change retry, completion-commit, crash-recovery, THO, AVCS, SCEG, Risk Card,
or F10 semantics.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

import generation_outcome_accounting_v1 as goa
from generate_code_from_prompts import validate_selected_prompt_rows


PILOT_SELECTED_COUNT = 20
PILOT_MIN_ACCEPTED_COMPLETE = 17
TEST_SELECTED_COUNT = 100
TEST_MIN_ACCEPTED_COMPLETE = 93

SUCCESSOR_ACCOUNTING_CONTRACT_SCHEMA = (
    "step9_successor_generation_outcome_accounting_contract_v1"
)
SUCCESSOR_STATISTICAL_CONTRACT_SCHEMA = (
    "step9_successor_statistical_eligibility_contract_v1"
)


def require_successor_method_revision_contract(
    protocol: dict[str, Any],
) -> dict[str, Any]:
    """Fail closed unless a future protocol explicitly freezes this revision.

    The current R5-r11 protocol intentionally lacks these fields, so the
    successor accounting implementation cannot retroactively reinterpret its
    historical outcomes.
    """

    accounting = protocol.get("successor_generation_outcome_accounting")
    statistical = protocol.get("successor_statistical_eligibility")
    if not isinstance(accounting, dict) or not isinstance(statistical, dict):
        raise ValueError(
            "Successor method revision is not frozen by this protocol"
        )
    if accounting.get("schema_version") != (
        SUCCESSOR_ACCOUNTING_CONTRACT_SCHEMA
    ):
        raise ValueError("Successor generation-outcome contract schema mismatch")
    if accounting.get("design_source") != (
        "step9_successor_generation_outcome_accounting_proposal_v1"
    ):
        raise ValueError("Successor generation-outcome design source mismatch")
    required_accounting_true = (
        "prospective_only",
        "r5_r11_reinterpretation_forbidden",
        "every_selected_prompt_accounted_exactly_once",
        "terminal_no_resampling",
        "analysis_population_is_accepted_complete_only",
    )
    for key in required_accounting_true:
        if accounting.get(key) is not True:
            raise ValueError(
                f"Successor generation-outcome contract missing {key}=true"
            )
    if accounting.get("analysis_population_source") != "accepted_sample_ids":
        raise ValueError(
            "Successor analysis population must be bound to accepted_sample_ids"
        )

    if statistical.get("schema_version") != (
        SUCCESSOR_STATISTICAL_CONTRACT_SCHEMA
    ):
        raise ValueError("Successor statistical contract schema mismatch")
    if statistical.get("design_source") != (
        "step9_successor_statistical_eligibility_rule_proposal_v1"
    ):
        raise ValueError("Successor statistical design source mismatch")
    expected = {
        "pilot_selected_count": PILOT_SELECTED_COUNT,
        "pilot_min_accepted_complete": PILOT_MIN_ACCEPTED_COMPLETE,
        "test_selected_count": TEST_SELECTED_COUNT,
        "test_min_accepted_complete": TEST_MIN_ACCEPTED_COMPLETE,
    }
    for key, value in expected.items():
        if statistical.get(key) != value:
            raise ValueError(
                f"Successor statistical contract mismatch for {key}"
            )
    if statistical.get("thresholds_frozen_before_selection") is not True:
        raise ValueError(
            "Successor statistical thresholds are not frozen before selection"
        )
    return {
        "generation_outcome_accounting": accounting,
        "statistical_eligibility": statistical,
    }


def derive_selective_recovery_authority(
    *,
    recovery_assessment: dict[str, Any],
    max_resume_rounds: int,
) -> dict[str, Any]:
    """Derive per-sample continuation without changing the frozen classifier.

    The frozen classifier remains authoritative for each sample's recovery
    state. This successor orchestration layer only prevents an unrelated
    terminal sample from suppressing recall for independently safe nonfinal
    samples.
    """

    states = recovery_assessment.get("sample_recovery_state")
    if not isinstance(states, dict):
        raise ValueError("Recovery assessment sample states missing")
    exhausted = {
        str(value).strip()
        for value in (
            recovery_assessment.get("retry_budget_exhausted_ids") or []
        )
        if str(value).strip()
    }
    current_round = int(
        recovery_assessment.get("current_resume_round") or 0
    )
    round_available = current_round < int(max_resume_rounds)
    recall_ids: list[str] = []
    for sample_id, state in states.items():
        sample_id = str(sample_id).strip()
        state = str(state or "").strip()
        if state == goa.RECOVERY_PROVEN_NOT_STARTED:
            if round_available:
                recall_ids.append(sample_id)
        elif (
            state == goa.RECOVERY_PROVEN_RETRYABLE_PRECOMMIT_FAILURE
            and sample_id not in exhausted
            and round_available
        ):
            recall_ids.append(sample_id)

    return {
        "schema_version": "step9_successor_selective_recovery_authority_v1",
        "selective_resume_authorized": bool(recall_ids),
        "provider_recall_sample_ids": recall_ids,
        "current_resume_round": current_round,
        "next_resume_round": (
            current_round + 1 if recall_ids else None
        ),
        "max_resume_rounds": int(max_resume_rounds),
        "frozen_classifier_stage_status": recovery_assessment.get(
            "stage_recovery_status"
        ),
        "frozen_classifier_provider_recall_authorized": bool(
            recovery_assessment.get("provider_recall_authorized")
        ),
        "terminal_or_ambiguous_samples_never_recalled": True,
        "classifier_semantics_changed": False,
    }


def derive_journal_backed_local_reconstruction_ids(
    *,
    recovery_assessment: dict[str, Any],
    generated_rows: list[dict[str, Any]],
    attempt_rows: list[dict[str, Any]],
    code_dir: Path,
    requirements_dir: Path,
) -> list[str]:
    """Find journal-accepted samples whose local materialization is incomplete.

    PROVEN_ACCEPTED means the frozen classifier verified a durable accepted
    journal. It does not by itself prove that the later attempt-ledger,
    generated-row, and sidecar transaction finished before a crash.
    """

    states = recovery_assessment.get("sample_recovery_state")
    if not isinstance(states, dict):
        raise ValueError("Recovery assessment sample states missing")
    generated_by_id = _generated_row_map(generated_rows)
    attempts_by_id = _attempts_by_sample(attempt_rows)

    result: list[str] = []
    for raw_sample_id, raw_state in states.items():
        sample_id = str(raw_sample_id).strip()
        state = str(raw_state or "").strip()
        if state != goa.RECOVERY_PROVEN_ACCEPTED:
            continue

        row = generated_by_id.get(sample_id)
        accepted_attempt_durable = any(
            attempt.get("accepted_response") is True
            for attempt in attempts_by_id.get(sample_id, [])
        )
        code_path = code_dir / f"{sample_id}.py"
        requirements_path = (
            requirements_dir / f"{sample_id}_requirements.txt"
        )
        row_materialized = (
            row is not None
            and _nonempty(row.get("generation_error")) is None
            and _nonempty(row.get("generation_time")) is not None
        )
        if not (
            row_materialized
            and accepted_attempt_durable
            and code_path.is_file()
            and requirements_path.is_file()
        ):
            result.append(sample_id)

    return result


def derive_successor_recovery_action(
    *,
    local_reconstruction_ids: list[str],
    selective_authority: dict[str, Any],
    outcome_projection: dict[str, Any] | None,
) -> str:
    """Choose the successor orchestration action from independent evidence."""

    selective_resume = (
        selective_authority.get("selective_resume_authorized") is True
    )
    if local_reconstruction_ids and selective_resume:
        return "LOCAL_RECONSTRUCT_AND_SELECTIVE_RESUME"
    if local_reconstruction_ids:
        return "LOCAL_RECONSTRUCT"
    if selective_resume:
        return "SELECTIVE_RESUME"
    if isinstance(outcome_projection, dict) and outcome_projection.get(
        "stage_evidence_status"
    ) in {
        goa.STATUS_FINALIZED_ALL_ACCEPTED,
        goa.STATUS_FINALIZED_WITH_TERMINALS,
    }:
        return "LOCAL_FINALIZE"
    return "HARD_STOP_UNRESOLVED"


def _nonempty(value: Any) -> str | None:
    text = str(value or "").strip()
    return text or None


def _attempts_by_sample(
    attempt_rows: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in attempt_rows:
        sample_id = str(row.get("sample_id") or "").strip()
        if not sample_id:
            continue
        grouped.setdefault(sample_id, []).append(row)
    for sample_id, rows in grouped.items():
        rows.sort(key=lambda row: int(row.get("attempt_index") or 0))
        observed = [int(row.get("attempt_index") or 0) for row in rows]
        if observed and observed != list(range(1, observed[-1] + 1)):
            raise ValueError(
                f"Attempt indices are not contiguous for {sample_id}"
            )
    return grouped


def _last_failure_class(
    attempts: list[dict[str, Any]],
) -> str | None:
    if not attempts:
        return None
    value = attempts[-1].get("failure_class")
    return _nonempty(value)


def _prompt_id(row: dict[str, Any]) -> str:
    return str(row.get("prompt_id") or "").strip()


def _sample_id(row: dict[str, Any]) -> str:
    return str(row.get("sample_id") or "").strip()


def normalize_selected_records_for_outcome(
    selected_records: list[dict[str, Any]],
) -> list[dict[str, str]]:
    """Normalize raw selection rows to generated-sample identities.

    Real Step9 selection JSONL stores prompt/source identity and prompt text,
    not the generated auto_* sample identity. Reuse the exact frozen
    generator identity function here so outcome accounting cannot drift from
    the sample IDs emitted by formal generation.

    Controlled fixtures may already supply normalized prompt_id/sample_id
    pairs and intentionally omit prompt text; those remain supported.
    """

    if not selected_records:
        raise ValueError("Selected population is empty")

    has_generation_input = [
        (
            isinstance(row.get("prompt"), str)
            and bool(str(row.get("prompt") or "").strip())
        )
        or (
            isinstance(row.get("prompt_text"), str)
            and bool(str(row.get("prompt_text") or "").strip())
        )
        for row in selected_records
    ]
    if any(has_generation_input) and not all(has_generation_input):
        raise ValueError(
            "Selected population mixes raw generation rows and normalized "
            "identity-only rows"
        )

    normalized: list[dict[str, str]] = []
    if all(has_generation_input):
        identities = validate_selected_prompt_rows(
            selected_records,
            start=1,
        )
        for position, (row, identity) in enumerate(
            zip(selected_records, identities, strict=True),
            1,
        ):
            prompt_id = _prompt_id(row)
            if not prompt_id:
                raise ValueError(
                    f"Selected prompt_id missing at position {position}"
                )
            normalized.append(
                {
                    "prompt_id": prompt_id,
                    "sample_id": identity["sample_id"],
                }
            )
    else:
        for position, row in enumerate(selected_records, 1):
            prompt_id = _prompt_id(row)
            sample_id = _sample_id(row)
            if not prompt_id or not sample_id:
                raise ValueError(
                    f"Selected identity missing at position {position}"
                )
            normalized.append(
                {
                    "prompt_id": prompt_id,
                    "sample_id": sample_id,
                }
            )

    seen_sample_ids: set[str] = set()
    seen_prompt_ids: set[str] = set()
    for row in normalized:
        sample_id = row["sample_id"]
        prompt_id = row["prompt_id"]
        if sample_id in seen_sample_ids:
            raise ValueError(
                f"Duplicate selected sample_id: {sample_id}"
            )
        if prompt_id in seen_prompt_ids:
            raise ValueError(
                f"Duplicate selected prompt_id: {prompt_id}"
            )
        seen_sample_ids.add(sample_id)
        seen_prompt_ids.add(prompt_id)
    return normalized


def _selected_identity_map(
    selected_records: list[dict[str, Any]],
) -> tuple[list[str], dict[str, str]]:
    normalized = normalize_selected_records_for_outcome(
        selected_records
    )
    sample_order = [row["sample_id"] for row in normalized]
    prompt_by_sample = {
        row["sample_id"]: row["prompt_id"] for row in normalized
    }
    return sample_order, prompt_by_sample


def _generated_row_map(
    generated_rows: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    for position, row in enumerate(generated_rows, 1):
        sample_id = _sample_id(row)
        if not sample_id:
            raise ValueError(
                f"Generated row {position} has no sample_id"
            )
        if sample_id in by_id:
            raise ValueError(
                f"Duplicate generated sample_id: {sample_id}"
            )
        by_id[sample_id] = row
    return by_id


def build_outcome_input_records_from_generation(
    *,
    selected_records: list[dict[str, Any]],
    generated_rows: list[dict[str, Any]],
    attempt_rows: list[dict[str, Any]],
    retry_budget_exhausted_ids: set[str] | list[str] | tuple[str, ...],
    attempts_ref: str,
    accepted_journal_dir_ref: str,
    generated_samples_ref: str,
    code_dir_ref: str,
    requirements_dir_ref: str,
) -> list[dict[str, Any]]:
    """Adapt a normal generation-stage transaction into Part1 input records."""

    sample_order, prompt_by_sample = _selected_identity_map(selected_records)
    generated_by_id = _generated_row_map(generated_rows)
    attempts_by_id = _attempts_by_sample(attempt_rows)
    exhausted = {str(value).strip() for value in retry_budget_exhausted_ids}

    if set(generated_by_id) != set(sample_order):
        missing = sorted(set(sample_order) - set(generated_by_id))
        extra = sorted(set(generated_by_id) - set(sample_order))
        raise ValueError(
            "Generated-row identity does not equal frozen selection: "
            f"missing={missing}, extra={extra}"
        )

    records: list[dict[str, Any]] = []
    for sample_id in sample_order:
        row = generated_by_id[sample_id]
        prompt_id = prompt_by_sample[sample_id]
        if _prompt_id(row) != prompt_id:
            raise ValueError(
                f"Generated prompt identity mismatch for {sample_id}"
            )
        attempts = attempts_by_id.get(sample_id, [])
        generation_error = _nonempty(row.get("generation_error"))
        recovery_class = str(
            row.get("generation_failure_recovery_class") or ""
        ).strip()

        if generation_error is None:
            recovery_state = goa.RECOVERY_PROVEN_ACCEPTED
            recovery_reason = "durable_accepted_response_journal"
            failure_class = None
            retry_budget_exhausted = False
            provider_recall_authorized = False
            accepted_ref = (
                f"{accepted_journal_dir_ref.rstrip('/')}/"
                f"{sample_id}.accepted.json"
            )
            generated_ref = (
                f"{generated_samples_ref}#sample_id={sample_id}"
            )
            code_ref = (
                f"{code_dir_ref.rstrip('/')}/{sample_id}.py"
            )
            requirements_ref = (
                f"{requirements_dir_ref.rstrip('/')}/"
                f"{sample_id}_requirements.txt"
            )
            generation_time = _nonempty(row.get("generation_time"))
        else:
            failure_class = _last_failure_class(attempts)
            accepted_ref = None
            generated_ref = None
            code_ref = None
            requirements_ref = None
            generation_time = None

            if recovery_class == "transport_pending":
                recovery_state = (
                    goa.RECOVERY_PROVEN_RETRYABLE_PRECOMMIT_FAILURE
                )
                retry_budget_exhausted = sample_id in exhausted
                recovery_reason = (
                    "retry_budget_exhausted"
                    if retry_budget_exhausted
                    else "durable_retryable_precommit_failure"
                )
                provider_recall_authorized = not retry_budget_exhausted
            elif recovery_class == "terminal_failure":
                recovery_state = goa.RECOVERY_PROVEN_TERMINAL_FAILURE
                retry_budget_exhausted = False
                recovery_reason = "durable_terminal_failure"
                provider_recall_authorized = False
            else:
                raise ValueError(
                    f"Unknown generation_failure_recovery_class for "
                    f"{sample_id}: {recovery_class!r}"
                )

        records.append(
            {
                "prompt_id": prompt_id,
                "sample_id": sample_id,
                "recovery_state": recovery_state,
                "recovery_reason": recovery_reason,
                "attempt_count": len(attempts),
                "final_failure_class_or_null": failure_class,
                "retry_budget_exhausted": retry_budget_exhausted,
                "provider_recall_authorized": provider_recall_authorized,
                "accepted_response_journal_ref_or_null": accepted_ref,
                "attempt_evidence_ref": (
                    f"{attempts_ref}#sample_id={sample_id}"
                ),
                "generated_sample_ref_or_null": generated_ref,
                "generated_code_ref_or_null": code_ref,
                "requirements_ref_or_null": requirements_ref,
                "generation_time_or_null": generation_time,
            }
        )
    return records


def build_outcome_input_records_from_recovery(
    *,
    selected_records: list[dict[str, Any]],
    generated_rows: list[dict[str, Any]],
    attempt_rows: list[dict[str, Any]],
    recovery_assessment: dict[str, Any],
    attempts_ref: str,
    accepted_journal_dir_ref: str,
    generated_samples_ref: str,
    code_dir_ref: str,
    requirements_dir_ref: str,
) -> list[dict[str, Any]]:
    """Adapt read-only crash-recovery classification into Part1 records."""

    sample_order, prompt_by_sample = _selected_identity_map(selected_records)
    generated_by_id = _generated_row_map(generated_rows)
    attempts_by_id = _attempts_by_sample(attempt_rows)

    states = recovery_assessment.get("sample_recovery_state")
    reasons = recovery_assessment.get("sample_recovery_reason")
    if not isinstance(states, dict) or not isinstance(reasons, dict):
        raise ValueError("Recovery assessment sample maps are missing")
    if set(states) != set(sample_order):
        raise ValueError(
            "Recovery state identities do not equal frozen selection"
        )

    exhausted = {
        str(value).strip()
        for value in (
            recovery_assessment.get("retry_budget_exhausted_ids") or []
        )
    }
    if recovery_assessment.get("stage_recovery_status") == (
        "TERMINAL_RESUME_ROUND_EXHAUSTED"
    ):
        exhausted.update(
            sample_id
            for sample_id in sample_order
            if str(states.get(sample_id) or "").strip()
            == goa.RECOVERY_PROVEN_RETRYABLE_PRECOMMIT_FAILURE
        )
    recall_ids = {
        str(value).strip()
        for value in (
            recovery_assessment.get("provider_recall_ids") or []
        )
    }

    records: list[dict[str, Any]] = []
    for sample_id in sample_order:
        prompt_id = prompt_by_sample[sample_id]
        row = generated_by_id.get(sample_id)
        attempts = attempts_by_id.get(sample_id, [])
        state = str(states.get(sample_id) or "").strip()
        reason = str(reasons.get(sample_id) or "").strip()
        if (
            sample_id in exhausted
            and recovery_assessment.get("stage_recovery_status")
            == "TERMINAL_RESUME_ROUND_EXHAUSTED"
        ):
            reason = "resume_round_budget_exhausted"
        failure_class = _last_failure_class(attempts)

        accepted = state == goa.RECOVERY_PROVEN_ACCEPTED
        if accepted:
            if row is None:
                raise ValueError(
                    f"Accepted recovery sample has no generated row: {sample_id}"
                )
            if _prompt_id(row) != prompt_id:
                raise ValueError(
                    f"Recovered prompt identity mismatch for {sample_id}"
                )
            accepted_ref = (
                f"{accepted_journal_dir_ref.rstrip('/')}/"
                f"{sample_id}.accepted.json"
            )
            generated_ref = (
                f"{generated_samples_ref}#sample_id={sample_id}"
            )
            code_ref = f"{code_dir_ref.rstrip('/')}/{sample_id}.py"
            requirements_ref = (
                f"{requirements_dir_ref.rstrip('/')}/"
                f"{sample_id}_requirements.txt"
            )
            generation_time = _nonempty(row.get("generation_time"))
        else:
            accepted_ref = None
            generated_ref = None
            code_ref = None
            requirements_ref = None
            generation_time = None

        records.append(
            {
                "prompt_id": prompt_id,
                "sample_id": sample_id,
                "recovery_state": state,
                "recovery_reason": reason,
                "attempt_count": len(attempts),
                "final_failure_class_or_null": failure_class,
                "retry_budget_exhausted": sample_id in exhausted,
                "provider_recall_authorized": sample_id in recall_ids,
                "accepted_response_journal_ref_or_null": accepted_ref,
                "attempt_evidence_ref": (
                    f"{attempts_ref}#sample_id={sample_id}"
                ),
                "generated_sample_ref_or_null": generated_ref,
                "generated_code_ref_or_null": code_ref,
                "requirements_ref_or_null": requirements_ref,
                "generation_time_or_null": generation_time,
            }
        )
    return records


def build_manifest_from_generation(
    *,
    split: str,
    protocol_id: str,
    selection_manifest_hash: str,
    method_closure_sha256: str,
    request_contract_sha256: str,
    selected_records: list[dict[str, Any]],
    generated_rows: list[dict[str, Any]],
    attempt_rows: list[dict[str, Any]],
    retry_budget_exhausted_ids: set[str] | list[str] | tuple[str, ...],
    attempts_ref: str,
    accepted_journal_dir_ref: str,
    generated_samples_ref: str,
    code_dir_ref: str,
    requirements_dir_ref: str,
) -> dict[str, Any]:
    normalized_selected_records = normalize_selected_records_for_outcome(
        selected_records
    )
    records = build_outcome_input_records_from_generation(
        selected_records=normalized_selected_records,
        generated_rows=generated_rows,
        attempt_rows=attempt_rows,
        retry_budget_exhausted_ids=retry_budget_exhausted_ids,
        attempts_ref=attempts_ref,
        accepted_journal_dir_ref=accepted_journal_dir_ref,
        generated_samples_ref=generated_samples_ref,
        code_dir_ref=code_dir_ref,
        requirements_dir_ref=requirements_dir_ref,
    )
    manifest = goa.build_generation_outcome_manifest(
        split=split,
        protocol_id=protocol_id,
        selection_manifest_hash=selection_manifest_hash,
        method_closure_sha256=method_closure_sha256,
        request_contract_sha256=request_contract_sha256,
        selected_records=normalized_selected_records,
        outcome_input_records=records,
    )
    goa.validate_manifest_self_consistency(manifest)
    return manifest


def build_manifest_from_recovery(
    *,
    split: str,
    protocol_id: str,
    selection_manifest_hash: str,
    method_closure_sha256: str,
    request_contract_sha256: str,
    selected_records: list[dict[str, Any]],
    generated_rows: list[dict[str, Any]],
    attempt_rows: list[dict[str, Any]],
    recovery_assessment: dict[str, Any],
    attempts_ref: str,
    accepted_journal_dir_ref: str,
    generated_samples_ref: str,
    code_dir_ref: str,
    requirements_dir_ref: str,
) -> dict[str, Any]:
    normalized_selected_records = normalize_selected_records_for_outcome(
        selected_records
    )
    records = build_outcome_input_records_from_recovery(
        selected_records=normalized_selected_records,
        generated_rows=generated_rows,
        attempt_rows=attempt_rows,
        recovery_assessment=recovery_assessment,
        attempts_ref=attempts_ref,
        accepted_journal_dir_ref=accepted_journal_dir_ref,
        generated_samples_ref=generated_samples_ref,
        code_dir_ref=code_dir_ref,
        requirements_dir_ref=requirements_dir_ref,
    )
    manifest = goa.build_generation_outcome_manifest(
        split=split,
        protocol_id=protocol_id,
        selection_manifest_hash=selection_manifest_hash,
        method_closure_sha256=method_closure_sha256,
        request_contract_sha256=request_contract_sha256,
        selected_records=normalized_selected_records,
        outcome_input_records=records,
    )
    goa.validate_manifest_self_consistency(manifest)
    return manifest


def evaluate_split_statistical_eligibility(
    manifest: dict[str, Any],
) -> dict[str, Any]:
    """Apply the already-frozen prospective Pilot20/Test100 thresholds."""

    goa.validate_manifest_self_consistency(manifest)
    split = str(manifest.get("split") or "").strip()
    status = str(manifest.get("stage_evidence_status") or "").strip()
    selected_count = int(manifest.get("selected_count") or 0)
    accepted_count = int(manifest.get("accepted_complete_count") or 0)
    terminal_count = int(manifest.get("terminal_count") or 0)
    unresolved_count = int(manifest.get("unresolved_count") or 0)

    finalized = status in {
        goa.STATUS_FINALIZED_ALL_ACCEPTED,
        goa.STATUS_FINALIZED_WITH_TERMINALS,
    }
    if split == "pilot":
        expected_selected = PILOT_SELECTED_COUNT
        minimum_accepted = PILOT_MIN_ACCEPTED_COMPLETE
        decision_name = "test100_generation_authorized"
    elif split == "test":
        expected_selected = TEST_SELECTED_COUNT
        minimum_accepted = TEST_MIN_ACCEPTED_COMPLETE
        decision_name = "prototype_dependency_claim_eligible"
    else:
        raise ValueError(f"Unsupported split for eligibility: {split!r}")

    selected_size_valid = selected_count == expected_selected
    eligible = (
        finalized
        and unresolved_count == 0
        and selected_size_valid
        and accepted_count >= minimum_accepted
    )
    return {
        "schema_version": "step9_statistical_eligibility_decision_v1",
        "split": split,
        "status": "PASS" if eligible else "NO_GO",
        "decision_name": decision_name,
        "eligible": eligible,
        "selected_count": selected_count,
        "expected_selected_count": expected_selected,
        "accepted_complete_count": accepted_count,
        "minimum_accepted_complete_count": minimum_accepted,
        "terminal_count": terminal_count,
        "unresolved_count": unresolved_count,
        "stage_evidence_status": status,
        "all_selected_finalized": bool(
            manifest.get("all_selected_finalized")
        ),
        "threshold_source": (
            "step9_successor_statistical_eligibility_rule_proposal_v1"
        ),
        "derived_from_r5_r11_99_of_100": False,
        "resampling_or_backfill_authorized": False,
    }


def accepted_rows_from_manifest(
    *,
    generated_rows: list[dict[str, Any]],
    manifest: dict[str, Any],
) -> list[dict[str, Any]]:
    """Return exactly the accepted-complete rows in frozen accepted order."""

    goa.validate_manifest_self_consistency(manifest)
    by_id = _generated_row_map(generated_rows)
    selected_ids = list(manifest.get("selected_sample_ids") or [])
    selected_set = set(selected_ids)
    if not set(by_id).issubset(selected_set):
        raise ValueError(
            "Generated rows contain identities outside outcome manifest "
            "selected population"
        )

    observed_selected_order = [
        sample_id for sample_id in selected_ids if sample_id in by_id
    ]
    if list(by_id) != observed_selected_order:
        raise ValueError(
            "Generated rows violate frozen selected relative order"
        )

    accepted_ids = list(manifest.get("accepted_sample_ids") or [])
    accepted_rows: list[dict[str, Any]] = []
    for sample_id in accepted_ids:
        row = by_id.get(str(sample_id))
        if row is None:
            raise ValueError(
                f"Accepted outcome has no generated row: {sample_id}"
            )
        if _nonempty(row.get("generation_error")) is not None:
            raise ValueError(
                f"Accepted outcome row contains generation_error: {sample_id}"
            )
        accepted_rows.append(row)

    if len(accepted_rows) != int(
        manifest.get("accepted_complete_count") or 0
    ):
        raise ValueError("Accepted analysis population count mismatch")
    return accepted_rows


def atomic_write_json(
    path: Path,
    value: dict[str, Any],
    *,
    refuse_overwrite: bool = True,
) -> None:
    if refuse_overwrite and path.exists():
        raise FileExistsError(f"Refusing overwrite: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
        text=True,
    )
    temp_path = Path(temp_name)
    try:
        with os.fdopen(
            descriptor,
            "w",
            encoding="utf-8",
            newline="\n",
        ) as handle:
            handle.write(
                json.dumps(value, ensure_ascii=False, indent=2) + "\n"
            )
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        try:
            parent_fd = os.open(str(path.parent), flags)
        except OSError:
            parent_fd = None
        if parent_fd is not None:
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
    except Exception:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass
        raise


def atomic_write_jsonl(
    path: Path,
    rows: list[dict[str, Any]],
    *,
    refuse_overwrite: bool = True,
) -> None:
    if refuse_overwrite and path.exists():
        raise FileExistsError(f"Refusing overwrite: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
        text=True,
    )
    temp_path = Path(temp_name)
    try:
        with os.fdopen(
            descriptor,
            "w",
            encoding="utf-8",
            newline="\n",
        ) as handle:
            for row in rows:
                handle.write(
                    json.dumps(
                        row,
                        ensure_ascii=False,
                        sort_keys=True,
                    )
                    + "\n"
                )
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        try:
            parent_fd = os.open(str(path.parent), flags)
        except OSError:
            parent_fd = None
        if parent_fd is not None:
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
    except Exception:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass
        raise
