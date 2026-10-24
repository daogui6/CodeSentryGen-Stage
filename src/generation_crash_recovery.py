"""Read-only crash-recovery classification for formal generation stages.

This module does not call a provider and does not repair artifacts.  It
classifies the durable evidence that already exists after an interrupted
generation stage so a later authority layer can decide whether local sealing,
bounded resume, or fail-closed termination is permitted.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import generate_code_from_prompts as gen


PROVEN_NOT_STARTED = "PROVEN_NOT_STARTED"
PROVEN_ACCEPTED = "PROVEN_ACCEPTED"
PROVEN_RETRYABLE_PRECOMMIT_FAILURE = "PROVEN_RETRYABLE_PRECOMMIT_FAILURE"
PROVEN_TERMINAL_FAILURE = "PROVEN_TERMINAL_FAILURE"
AMBIGUOUS_IN_FLIGHT = "AMBIGUOUS_IN_FLIGHT"
EVIDENCE_CONFLICT = "EVIDENCE_CONFLICT"


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _sample_id(row: dict[str, Any]) -> str:
    return str(row.get("sample_id") or "").strip()


def _group_rows(
    rows: list[dict[str, Any]],
    *,
    expected_ids: set[str],
    label: str,
) -> dict[str, list[dict[str, Any]]]:
    grouped = {sample_id: [] for sample_id in expected_ids}
    for position, row in enumerate(rows, 1):
        _require(isinstance(row, dict), f"{label} row {position} is not an object")
        sample_id = _sample_id(row)
        _require(
            sample_id in expected_ids,
            f"{label} row {position} has unknown sample_id: {sample_id!r}",
        )
        grouped[sample_id].append(row)
    return grouped


def _existing_success_row_consistent(
    row: dict[str, Any],
    generated: dict[str, Any],
) -> bool:
    if str(row.get("generation_error") or "").strip():
        return False
    for field in ("raw_response", "generated_code", "requirements_text", "notes"):
        if row.get(field) != generated.get(field):
            return False
    return True


def _sidecars_consistent_if_present(
    *,
    sample_id: str,
    generated: dict[str, Any],
    code_dir: Path | None,
    requirements_dir: Path | None,
) -> bool:
    if code_dir is not None:
        code_path = code_dir / f"{sample_id}.py"
        if code_path.exists():
            observed = code_path.read_text(encoding="utf-8-sig")
            if observed != gen.canonical_sidecar_text(generated.get("generated_code")):
                return False
    if requirements_dir is not None:
        req_path = requirements_dir / f"{sample_id}_requirements.txt"
        if req_path.exists():
            observed = req_path.read_text(encoding="utf-8-sig")
            if observed != gen.canonical_sidecar_text(
                generated.get("requirements_text")
            ):
                return False
    return True


def assess_partial_generation_artifacts(
    *,
    prompt_rows: list[dict[str, Any]],
    attempt_intent_rows: list[dict[str, Any]],
    attempt_rows: list[dict[str, Any]],
    generated_rows: list[dict[str, Any]],
    accepted_journal_dir: Path,
    expected_request_contract: dict[str, Any],
    expected_max_total_attempts: int,
    expected_max_resume_rounds: int,
    code_dir: Path | None = None,
    requirements_dir: Path | None = None,
) -> dict[str, Any]:
    """Classify interrupted-stage evidence without mutating any artifact.

    A durable ATTEMPT_ARMED record is the local point after which the system
    can no longer prove that the provider was not called.  If such an intent
    lacks either an accepted-response journal or a durable final attempt
    outcome, the sample is AMBIGUOUS_IN_FLIGHT and provider recall is forbidden.
    """

    _require(expected_max_total_attempts > 0, "max total attempts must be positive")
    _require(expected_max_resume_rounds >= 0, "max resume rounds must be non-negative")

    identities = gen.validate_selected_prompt_rows(prompt_rows, start=1)
    expected_by_id = {identity["sample_id"]: identity for identity in identities}
    expected_ids = set(expected_by_id)
    contract_hash = gen.canonical_json_sha256(expected_request_contract)

    intent_by_id = _group_rows(
        attempt_intent_rows,
        expected_ids=expected_ids,
        label="attempt-intent",
    )
    attempts_by_id = _group_rows(
        attempt_rows,
        expected_ids=expected_ids,
        label="attempt",
    )

    rows_by_id: dict[str, dict[str, Any]] = {}
    for position, row in enumerate(generated_rows, 1):
        _require(isinstance(row, dict), f"generated row {position} is not an object")
        sample_id = _sample_id(row)
        _require(
            sample_id in expected_ids,
            f"generated row {position} has unknown sample_id: {sample_id!r}",
        )
        _require(
            sample_id not in rows_by_id,
            f"generated rows contain duplicate sample_id: {sample_id}",
        )
        rows_by_id[sample_id] = row

    states: dict[str, str] = {}
    reasons: dict[str, str] = {}
    retry_budget_exhausted_ids: list[str] = []
    observed_resume_rounds: list[int] = []

    for sample_id in [identity["sample_id"] for identity in identities]:
        identity = expected_by_id[sample_id]
        intents = intent_by_id[sample_id]
        attempts = attempts_by_id[sample_id]
        row = rows_by_id.get(sample_id)
        conflict_reason: str | None = None

        intent_by_index: dict[int, dict[str, Any]] = {}
        for intent in intents:
            if intent.get("schema_version") != "codesentry_generation_attempt_intent_v1":
                conflict_reason = "attempt_intent_schema_mismatch"
                break
            if intent.get("state") != "ATTEMPT_ARMED":
                conflict_reason = "attempt_intent_state_mismatch"
                break
            if intent.get("source_sample_id") != identity["source_sample_id"]:
                conflict_reason = "attempt_intent_source_identity_mismatch"
                break
            if intent.get("prompt_sha256") != identity["prompt_sha256"]:
                conflict_reason = "attempt_intent_prompt_hash_mismatch"
                break
            if intent.get("request_contract_sha256") != contract_hash:
                conflict_reason = "attempt_intent_request_contract_mismatch"
                break
            attempt_index = intent.get("attempt_index")
            invocation_index = intent.get("invocation_attempt_index")
            resume_round = intent.get("resume_round")
            if (
                not isinstance(attempt_index, int)
                or isinstance(attempt_index, bool)
                or attempt_index <= 0
                or not isinstance(invocation_index, int)
                or isinstance(invocation_index, bool)
                or invocation_index <= 0
                or not isinstance(resume_round, int)
                or isinstance(resume_round, bool)
                or resume_round < 0
            ):
                conflict_reason = "attempt_intent_index_or_round_invalid"
                break
            if attempt_index in intent_by_index:
                conflict_reason = "duplicate_attempt_intent_index"
                break
            intent_by_index[attempt_index] = intent
            observed_resume_rounds.append(resume_round)

        if conflict_reason is None and intent_by_index:
            observed_indices = sorted(intent_by_index)
            if observed_indices != list(range(1, observed_indices[-1] + 1)):
                conflict_reason = "attempt_intent_indices_not_contiguous"

        attempt_by_index: dict[int, dict[str, Any]] = {}
        if conflict_reason is None:
            for attempt in attempts:
                if attempt.get("source_sample_id") != identity["source_sample_id"]:
                    conflict_reason = "attempt_source_identity_mismatch"
                    break
                if attempt.get("prompt_sha256") != identity["prompt_sha256"]:
                    conflict_reason = "attempt_prompt_hash_mismatch"
                    break
                if attempt.get("request_contract_sha256") != contract_hash:
                    conflict_reason = "attempt_request_contract_mismatch"
                    break
                attempt_index = attempt.get("attempt_index")
                if (
                    not isinstance(attempt_index, int)
                    or isinstance(attempt_index, bool)
                    or attempt_index <= 0
                    or attempt_index in attempt_by_index
                ):
                    conflict_reason = "attempt_index_invalid_or_duplicate"
                    break
                intent = intent_by_index.get(attempt_index)
                if intent is None:
                    conflict_reason = "attempt_outcome_without_armed_intent"
                    break
                if (
                    attempt.get("invocation_attempt_index")
                    != intent.get("invocation_attempt_index")
                    or attempt.get("resume_round") != intent.get("resume_round")
                ):
                    conflict_reason = "attempt_outcome_intent_binding_mismatch"
                    break
                attempt_by_index[attempt_index] = attempt
                resume_round = attempt.get("resume_round")
                if isinstance(resume_round, int) and not isinstance(resume_round, bool):
                    observed_resume_rounds.append(resume_round)

        journal_path = gen.accepted_response_journal_path(
            accepted_journal_dir,
            sample_id,
        )
        journal_generated: dict[str, Any] | None = None
        journal_attempt: dict[str, Any] | None = None
        if conflict_reason is None and journal_path.exists():
            try:
                journal_generated, journal_attempt = gen.load_accepted_response_journal(
                    journal_path,
                    expected_binding={
                        "sample_id": sample_id,
                        "source_sample_id": identity["source_sample_id"],
                        "prompt_sha256": identity["prompt_sha256"],
                        "request_contract_sha256": contract_hash,
                    },
                )
            except Exception:
                conflict_reason = "accepted_journal_invalid"

        if conflict_reason is None and journal_attempt is not None:
            journal_index = journal_attempt.get("attempt_index")
            intent = intent_by_index.get(journal_index)
            if intent is None:
                conflict_reason = "accepted_journal_without_armed_intent"
            elif (
                journal_attempt.get("invocation_attempt_index")
                != intent.get("invocation_attempt_index")
                or journal_attempt.get("resume_round") != intent.get("resume_round")
            ):
                conflict_reason = "accepted_journal_intent_binding_mismatch"
            elif any(index > int(journal_index) for index in intent_by_index):
                conflict_reason = "attempt_intent_exists_after_accepted_response"
            elif journal_index in attempt_by_index and attempt_by_index[journal_index] != journal_attempt:
                conflict_reason = "accepted_journal_attempt_ledger_mismatch"
            elif row is not None and not _existing_success_row_consistent(
                row,
                journal_generated or {},
            ):
                conflict_reason = "accepted_journal_generated_row_conflict"
            elif not _sidecars_consistent_if_present(
                sample_id=sample_id,
                generated=journal_generated or {},
                code_dir=code_dir,
                requirements_dir=requirements_dir,
            ):
                conflict_reason = "accepted_journal_sidecar_conflict"

        if conflict_reason is not None:
            states[sample_id] = EVIDENCE_CONFLICT
            reasons[sample_id] = conflict_reason
            continue

        if journal_attempt is not None:
            states[sample_id] = PROVEN_ACCEPTED
            reasons[sample_id] = "durable_accepted_response_journal"
            continue

        if any(attempt.get("accepted_response") is True for attempt in attempts):
            states[sample_id] = EVIDENCE_CONFLICT
            reasons[sample_id] = "accepted_attempt_missing_accepted_journal"
            continue

        if row is not None and not str(row.get("generation_error") or "").strip():
            states[sample_id] = EVIDENCE_CONFLICT
            reasons[sample_id] = "success_row_missing_accepted_journal"
            continue

        if not intents:
            if attempts or row is not None:
                states[sample_id] = EVIDENCE_CONFLICT
                reasons[sample_id] = "local_outcome_exists_without_armed_intent"
            else:
                states[sample_id] = PROVEN_NOT_STARTED
                reasons[sample_id] = "no_durable_attempt_intent_or_outcome"
            continue

        unresolved_intent_indices = sorted(
            index for index in intent_by_index if index not in attempt_by_index
        )
        if unresolved_intent_indices:
            if (
                len(unresolved_intent_indices) != 1
                or unresolved_intent_indices[0] != max(intent_by_index)
            ):
                states[sample_id] = EVIDENCE_CONFLICT
                reasons[sample_id] = "non_tail_attempt_intent_has_no_durable_outcome"
            else:
                states[sample_id] = AMBIGUOUS_IN_FLIGHT
                reasons[sample_id] = "armed_attempt_has_no_durable_final_outcome"
            continue

        latest_index = max(attempt_by_index)
        latest = attempt_by_index[latest_index]
        if latest.get("retryable_failure") is True:
            states[sample_id] = PROVEN_RETRYABLE_PRECOMMIT_FAILURE
            reasons[sample_id] = "durable_retryable_precommit_failure"
            if latest_index >= expected_max_total_attempts:
                retry_budget_exhausted_ids.append(sample_id)
        else:
            states[sample_id] = PROVEN_TERMINAL_FAILURE
            reasons[sample_id] = "durable_terminal_failure"

    ids_by_state = {
        state: [
            sample_id
            for sample_id in [identity["sample_id"] for identity in identities]
            if states.get(sample_id) == state
        ]
        for state in (
            PROVEN_NOT_STARTED,
            PROVEN_ACCEPTED,
            PROVEN_RETRYABLE_PRECOMMIT_FAILURE,
            PROVEN_TERMINAL_FAILURE,
            AMBIGUOUS_IN_FLIGHT,
            EVIDENCE_CONFLICT,
        )
    }

    if ids_by_state[EVIDENCE_CONFLICT]:
        stage_status = "TERMINAL_EVIDENCE_CONFLICT"
    elif ids_by_state[AMBIGUOUS_IN_FLIGHT]:
        stage_status = "TERMINAL_AMBIGUOUS_IN_FLIGHT"
    elif ids_by_state[PROVEN_TERMINAL_FAILURE]:
        stage_status = "TERMINAL_FAILURE"
    elif retry_budget_exhausted_ids:
        stage_status = "TERMINAL_RETRY_BUDGET_EXHAUSTED"
    elif len(ids_by_state[PROVEN_ACCEPTED]) == len(identities):
        stage_status = "COMPLETE_SEALABLE"
    else:
        stage_status = "RESUME_ELIGIBLE"

    current_resume_round = max(observed_resume_rounds) if observed_resume_rounds else 0
    next_resume_round = current_resume_round + 1
    if (
        stage_status == "RESUME_ELIGIBLE"
        and next_resume_round > expected_max_resume_rounds
    ):
        stage_status = "TERMINAL_RESUME_ROUND_EXHAUSTED"

    provider_recall_ids = (
        ids_by_state[PROVEN_NOT_STARTED]
        + ids_by_state[PROVEN_RETRYABLE_PRECOMMIT_FAILURE]
    )
    provider_recall_authorized = stage_status == "RESUME_ELIGIBLE"

    return {
        "schema_version": "codesentry_generation_recovery_assessment_v1",
        "stage_recovery_status": stage_status,
        "sample_recovery_state": states,
        "sample_recovery_reason": reasons,
        "ids_by_state": ids_by_state,
        "retry_budget_exhausted_ids": sorted(retry_budget_exhausted_ids),
        "provider_recall_ids": provider_recall_ids if provider_recall_authorized else [],
        "provider_recall_authorized": provider_recall_authorized,
        "local_sealing_authorized": stage_status == "COMPLETE_SEALABLE",
        "release_snapshot_authorized": False,
        "downstream_analysis_authorized": False,
        "current_resume_round": current_resume_round,
        "next_resume_round": (
            next_resume_round if provider_recall_authorized else None
        ),
        "request_contract_sha256": contract_hash,
        "scientific_boundary": {
            "ambiguous_in_flight_is_terminal": True,
            "ambiguous_in_flight_provider_recall_forbidden": True,
            "accepted_response_recovery_is_local_only": True,
            "successful_samples_must_not_be_regenerated": True,
            "assessment_is_read_only_except_its_own_output_manifest": True,
            "assessment_does_not_authorize_release_snapshot": True,
        },
    }
