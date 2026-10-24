"""Cross-file invariants for a formal generation-stage transaction.

This module intentionally validates evidence consistency only.  It does not
decide scientific detection semantics and it never repairs an artifact.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from generate_code_from_prompts import (
    accepted_response_journal_path,
    canonical_json_sha256,
    canonical_sidecar_text,
    load_accepted_response_journal,
    validate_selected_prompt_rows,
)


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


def _is_retryable_failure_class(value: str) -> bool:
    if value in RETRYABLE_FAILURE_CLASSES:
        return True
    if value.startswith("provider_http_"):
        try:
            status = int(value.rsplit("_", 1)[1])
        except ValueError:
            return False
        return 500 <= status <= 599
    return False


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _aware_datetime(value: Any, *, label: str) -> datetime:
    text = str(value or "").strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"{label} is not ISO-8601: {value!r}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} is not timezone-aware")
    return parsed


def _require_nonnegative_int(value: Any, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")
    return value


def _validate_stream_summary(
    value: Any,
    *,
    label: str,
    required: bool,
) -> None:
    _require(isinstance(value, dict), f"{label} must be an object")
    if not required and not value:
        return
    _require(
        value.get("schema_version") == "codesentry_sse_event_summary_v1",
        f"{label} schema mismatch",
    )
    for field in (
        "raw_line_count",
        "sse_event_count",
        "json_event_count",
        "completion_choice_event_count",
        "content_delta_count",
        "reasoning_delta_count",
        "done_marker_count",
        "malformed_json_event_count",
        "truncated_json_event_count",
    ):
        _require_nonnegative_int(value.get(field), label=f"{label}.{field}")
    _require(
        isinstance(value.get("event_digest_head"), list)
        and len(value["event_digest_head"]) <= 8,
        f"{label}.event_digest_head must be bounded",
    )
    _require(
        isinstance(value.get("event_digest_tail"), list)
        and len(value["event_digest_tail"]) <= 8,
        f"{label}.event_digest_tail must be bounded",
    )
    _require(
        isinstance(value.get("finish_reason_distribution"), dict),
        f"{label}.finish_reason_distribution must be an object",
    )
    _require(
        isinstance(value.get("choice_index_distribution"), dict),
        f"{label}.choice_index_distribution must be an object",
    )
    _require(
        str(value.get("termination") or "") in {
            "done_marker",
            "finish_reason_commit",
            "eof_after_finish",
            "eof_before_finish",
            "transport_error_after_finish",
            "transport_error_before_finish",
            "parser_error",
        },
        f"{label}.termination is unknown",
    )


def validate_generation_artifacts(
    *,
    prompt_rows: list[dict[str, Any]],
    generated_rows: list[dict[str, Any]],
    attempt_rows: list[dict[str, Any]],
    attempt_intent_rows: list[dict[str, Any]] | None = None,
    code_dir: Path,
    requirements_dir: Path,
    accepted_journal_dir: Path,
    expected_request_contract: dict[str, Any],
    expected_retries_per_invocation: int,
    expected_max_resume_rounds: int,
    expected_max_total_attempts: int,
) -> dict[str, Any]:
    """Validate prompt -> attempts -> journal -> row -> sidecar closure."""
    identities = validate_selected_prompt_rows(prompt_rows, start=1)
    _require(
        len(generated_rows) == len(identities),
        "Generated row count does not match selected prompt count",
    )
    expected_by_id = {
        identity["sample_id"]: (identity, prompt_rows[index])
        for index, identity in enumerate(identities)
    }
    expected_ids = [identity["sample_id"] for identity in identities]
    observed_ids = [
        str(row.get("sample_id") or "").strip()
        for row in generated_rows
    ]
    _require(observed_ids == expected_ids, "Generated sample order/identity mismatch")
    _require(
        len(set(observed_ids)) == len(observed_ids),
        "Generated rows contain duplicate sample_id",
    )

    contract_hash = canonical_json_sha256(expected_request_contract)
    attempts_by_id: dict[str, list[dict[str, Any]]] = {
        sample_id: [] for sample_id in expected_ids
    }
    intents_by_id: dict[str, list[dict[str, Any]]] | None = (
        {sample_id: [] for sample_id in expected_ids}
        if attempt_intent_rows is not None
        else None
    )
    if attempt_intent_rows is not None and intents_by_id is not None:
        for position, intent in enumerate(attempt_intent_rows, 1):
            _require(
                isinstance(intent, dict),
                f"Attempt-intent {position} is not an object",
            )
            sample_id = str(intent.get("sample_id") or "").strip()
            _require(
                sample_id in expected_by_id,
                f"Attempt-intent has unknown sample_id: {sample_id!r}",
            )
            identity, _ = expected_by_id[sample_id]
            _require(
                intent.get("schema_version")
                == "codesentry_generation_attempt_intent_v1"
                and intent.get("state") == "ATTEMPT_ARMED",
                f"Attempt-intent lifecycle mismatch for {sample_id}",
            )
            _require(
                intent.get("source_sample_id")
                == identity["source_sample_id"]
                and intent.get("prompt_sha256")
                == identity["prompt_sha256"]
                and intent.get("request_contract_sha256")
                == contract_hash,
                f"Attempt-intent binding mismatch for {sample_id}",
            )
            intents_by_id[sample_id].append(intent)
        for sample_id, intents in intents_by_id.items():
            indices = [intent.get("attempt_index") for intent in intents]
            _require(
                indices == list(range(1, len(intents) + 1)),
                f"Attempt-intent indices are not contiguous for {sample_id}",
            )

    for position, attempt in enumerate(attempt_rows, 1):
        _require(isinstance(attempt, dict), f"Attempt {position} is not an object")
        sample_id = str(attempt.get("sample_id") or "").strip()
        _require(sample_id in expected_by_id, f"Attempt has unknown sample_id: {sample_id!r}")
        identity, _ = expected_by_id[sample_id]
        _require(
            attempt.get("source_sample_id") == identity["source_sample_id"],
            f"Attempt source identity mismatch for {sample_id}",
        )
        _require(
            attempt.get("prompt_sha256") == identity["prompt_sha256"],
            f"Attempt prompt hash mismatch for {sample_id}",
        )
        _require(
            attempt.get("request_contract") == expected_request_contract
            and attempt.get("request_contract_sha256") == contract_hash,
            f"Attempt request contract mismatch for {sample_id}",
        )
        attempts_by_id[sample_id].append(attempt)

    success_count = 0
    pending_count = 0
    terminal_count = 0
    accepted_journal_ids: set[str] = set()

    for row in generated_rows:
        sample_id = str(row.get("sample_id") or "").strip()
        identity, prompt_row = expected_by_id[sample_id]
        expected_prompt = prompt_row.get("prompt")
        if expected_prompt is None:
            expected_prompt = prompt_row.get("prompt_text")
        _require(row.get("prompt") == expected_prompt, f"Prompt bytes mismatch for {sample_id}")
        _require(
            row.get("source_sample_id") == identity["source_sample_id"],
            f"Output source identity mismatch for {sample_id}",
        )
        _require(
            row.get("generation_prompt_sha256") == identity["prompt_sha256"],
            f"Output prompt hash mismatch for {sample_id}",
        )
        _require(
            row.get("generation_request_contract") == expected_request_contract
            and row.get("generation_request_contract_sha256") == contract_hash,
            f"Output request contract mismatch for {sample_id}",
        )

        sample_attempts = attempts_by_id[sample_id]
        _require(sample_attempts, f"No attempt evidence for {sample_id}")
        if intents_by_id is not None:
            sample_intents = intents_by_id[sample_id]
            _require(
                len(sample_intents) == len(sample_attempts),
                f"Attempt-intent/outcome count mismatch for {sample_id}",
            )
            for intent, attempt in zip(sample_intents, sample_attempts):
                _require(
                    intent.get("attempt_index") == attempt.get("attempt_index")
                    and intent.get("invocation_attempt_index")
                    == attempt.get("invocation_attempt_index")
                    and intent.get("resume_round") == attempt.get("resume_round"),
                    f"Attempt-intent/outcome identity mismatch for {sample_id}",
                )
        _require(
            len(sample_attempts) <= expected_max_total_attempts,
            f"Total attempt budget exceeded for {sample_id}",
        )
        observed_indices = [a.get("attempt_index") for a in sample_attempts]
        _require(
            observed_indices == list(range(1, len(sample_attempts) + 1)),
            f"Attempt indices are not contiguous for {sample_id}",
        )

        accepted = []
        previous_round = -1
        expected_invocation_index = 0
        for index, attempt in enumerate(sample_attempts, 1):
            label = f"attempt[{sample_id}:{index}]"
            resume_round = attempt.get("resume_round")
            _require(
                isinstance(resume_round, int)
                and not isinstance(resume_round, bool)
                and 0 <= resume_round <= expected_max_resume_rounds,
                f"{label}.resume_round invalid",
            )
            if resume_round != previous_round:
                _require(
                    resume_round == previous_round + 1,
                    f"{label}.resume_round is not contiguous",
                )
                previous_round = resume_round
                expected_invocation_index = 1
            else:
                expected_invocation_index += 1
            _require(
                attempt.get("invocation_attempt_index")
                == expected_invocation_index,
                f"{label}.invocation_attempt_index mismatch",
            )
            _require(
                expected_invocation_index <= expected_retries_per_invocation + 1,
                f"{label} exceeds per-invocation retry budget",
            )
            _require(
                attempt.get("resume_invocation") is (resume_round > 0),
                f"{label}.resume_invocation mismatch",
            )

            started = _aware_datetime(
                attempt.get("request_started_at"),
                label=f"{label}.request_started_at",
            )
            completed = _aware_datetime(
                attempt.get("response_completed_at"),
                label=f"{label}.response_completed_at",
            )
            _require(started <= completed, f"{label} time interval inverted")
            observed_seconds = attempt.get("observed_seconds")
            _require(
                isinstance(observed_seconds, (int, float))
                and not isinstance(observed_seconds, bool)
                and observed_seconds >= 0,
                f"{label}.observed_seconds invalid",
            )
            _require(
                abs(float(observed_seconds) - (completed - started).total_seconds())
                <= 0.02,
                f"{label}.observed_seconds inconsistent",
            )
            for telemetry_field in (
                "partial_stream_chunk_count",
                "completion_choice_chunk_count",
                "reasoning_char_count",
                "content_char_count",
            ):
                _require_nonnegative_int(
                    attempt.get(telemetry_field),
                    label=f"{label}.{telemetry_field}",
                )
            _require(
                isinstance(attempt.get("saw_done_marker"), bool),
                f"{label}.saw_done_marker must be boolean",
            )
            _require(
                isinstance(attempt.get("api_usage"), dict),
                f"{label}.api_usage must be an object",
            )
            _require(
                isinstance(attempt.get("provider_request_id"), str),
                f"{label}.provider_request_id must be a string",
            )
            _require(
                isinstance(attempt.get("provider_error_summary"), dict),
                f"{label}.provider_error_summary must be an object",
            )
            _validate_stream_summary(
                attempt.get("stream_event_summary"),
                label=f"{label}.stream_event_summary",
                required=(
                    expected_request_contract["transport_mode"]
                    == "streaming_sse"
                    and (
                        int(attempt.get("partial_stream_chunk_count") or 0) > 0
                        or str(attempt.get("failure_class") or "").startswith("sse_")
                        or attempt.get("accepted_response") is True
                    )
                ),
            )

            accepted_response = attempt.get("accepted_response")
            retryable = attempt.get("retryable_failure")
            _require(isinstance(accepted_response, bool), f"{label}.accepted_response invalid")
            _require(isinstance(retryable, bool), f"{label}.retryable_failure invalid")
            if accepted_response:
                accepted.append(attempt)
                _require(not retryable, f"{label} accepted response marked retryable")
                _require(attempt.get("failure_class") is None, f"{label} accepted response has failure class")
                _require(attempt.get("error") is None, f"{label} accepted response has error")
                _require(
                    str(attempt.get("finish_reason") or "").lower() == "stop",
                    f"{label} accepted response finish_reason is not stop",
                )
                _require(
                    int(attempt.get("content_char_count") or 0) > 0,
                    f"{label} accepted response has no content",
                )
                if expected_request_contract["thinking_mode"] == "disabled":
                    _require(
                        int(attempt.get("reasoning_char_count") or 0) == 0,
                        f"{label} violates disabled-thinking contract",
                    )
            else:
                failure_class = str(attempt.get("failure_class") or "")
                _require(failure_class, f"{label} failed attempt has no failure class")
                _require(
                    isinstance(attempt.get("error"), str)
                    and bool(attempt["error"].strip()),
                    f"{label} failed attempt has no error",
                )
                _require(
                    retryable == _is_retryable_failure_class(failure_class),
                    f"{label} retry decision contradicts frozen taxonomy",
                )
                if index < len(sample_attempts):
                    _require(retryable, f"{label} terminal failure has a later attempt")

        _require(len(accepted) <= 1, f"Multiple accepted responses for {sample_id}")
        if accepted:
            _require(
                sample_attempts[-1] is accepted[0],
                f"Accepted response is not the final attempt for {sample_id}",
            )

        generation_error = str(row.get("generation_error") or "").strip()
        attempt_count = row.get("generation_attempt_count")
        _require(
            attempt_count == len(sample_attempts),
            f"Output attempt count mismatch for {sample_id}",
        )
        _require(
            row.get("generation_retry_count") == max(0, len(sample_attempts) - 1),
            f"Output retry count mismatch for {sample_id}",
        )
        last_attempt = sample_attempts[-1]
        telemetry_pairs = {
            "generation_stream_chunk_count": "partial_stream_chunk_count",
            "generation_completion_choice_chunk_count": "completion_choice_chunk_count",
            "generation_saw_done_marker": "saw_done_marker",
            "generation_finish_reason": "finish_reason",
            "generation_reasoning_char_count": "reasoning_char_count",
            "generation_content_char_count": "content_char_count",
            "api_usage": "api_usage",
            "generation_stream_event_summary": "stream_event_summary",
            "generation_provider_request_id": "provider_request_id",
            "generation_provider_error_summary": "provider_error_summary",
        }
        for output_field, attempt_field in telemetry_pairs.items():
            _require(
                row.get(output_field) == last_attempt.get(attempt_field),
                f"Output/attempt telemetry mismatch for {sample_id}: {output_field}",
            )

        if not generation_error:
            success_count += 1
            _require(len(accepted) == 1, f"Success row has no accepted attempt: {sample_id}")
            _require(
                row.get("generation_failure_recovery_class") == "",
                f"Success row has a failure recovery class: {sample_id}",
            )
            _require(
                row.get("generation_recovered_after_retry")
                is (len(sample_attempts) > 1),
                f"Recovered-after-retry mismatch for {sample_id}",
            )
            _require(
                row.get("generation_response_completed_at")
                == accepted[0].get("response_completed_at")
                and row.get("generation_request_started_at")
                == accepted[0].get("request_started_at"),
                f"Success timing does not bind accepted attempt: {sample_id}",
            )
            _require(
                row.get("generation_time")
                == accepted[0].get("response_completed_at"),
                f"generation_time does not bind accepted completion: {sample_id}",
            )
            raw_response = row.get("raw_response")
            _require(isinstance(raw_response, str), f"raw_response invalid for {sample_id}")
            if expected_request_contract["response_format"] == "json_object":
                try:
                    parsed = json.loads(raw_response)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"Strict raw JSON invalid for {sample_id}") from exc
                _require(isinstance(parsed, dict), f"Raw JSON is not an object for {sample_id}")
                for field in ("generated_code", "requirements_text", "notes"):
                    _require(
                        parsed.get(field) == row.get(field),
                        f"Raw/output {field} mismatch for {sample_id}",
                    )

            code_path = code_dir / f"{sample_id}.py"
            requirements_path = requirements_dir / f"{sample_id}_requirements.txt"
            _require(code_path.is_file(), f"Code sidecar missing for {sample_id}")
            _require(requirements_path.is_file(), f"Requirements sidecar missing for {sample_id}")
            _require(
                code_path.read_text(encoding="utf-8-sig")
                == canonical_sidecar_text(row.get("generated_code")),
                f"Code sidecar content mismatch for {sample_id}",
            )
            _require(
                requirements_path.read_text(encoding="utf-8-sig")
                == canonical_sidecar_text(row.get("requirements_text")),
                f"Requirements sidecar content mismatch for {sample_id}",
            )

            journal_path = accepted_response_journal_path(
                accepted_journal_dir,
                sample_id,
            )
            _require(journal_path.is_file(), f"Accepted-response journal missing for {sample_id}")
            generated, journal_attempt = load_accepted_response_journal(
                journal_path,
                expected_binding={
                    "sample_id": sample_id,
                    "source_sample_id": identity["source_sample_id"],
                    "prompt_sha256": identity["prompt_sha256"],
                    "request_contract_sha256": contract_hash,
                },
            )
            accepted_journal_ids.add(sample_id)
            _require(journal_attempt == accepted[0], f"Journal/attempt mismatch for {sample_id}")
            for field in (
                "raw_response",
                "generated_code",
                "requirements_text",
                "notes",
            ):
                _require(
                    generated.get(field) == row.get(field),
                    f"Journal/output {field} mismatch for {sample_id}",
                )
        else:
            _require(not accepted, f"Failure row has an accepted attempt: {sample_id}")
            _require(
                not str(row.get("generated_code") or "").strip(),
                f"Failure row contains generated code: {sample_id}",
            )
            if last_attempt.get("retryable_failure") is True:
                pending_count += 1
                _require(
                    row.get("generation_failure_recovery_class")
                    == "transport_pending",
                    f"Retryable failure row classification mismatch: {sample_id}",
                )
            else:
                terminal_count += 1
                _require(
                    row.get("generation_failure_recovery_class")
                    == "terminal_failure",
                    f"Terminal failure row classification mismatch: {sample_id}",
                )

    observed_code_names = {path.name for path in code_dir.glob("*.py") if path.is_file()}
    observed_requirement_names = {
        path.name
        for path in requirements_dir.glob("*_requirements.txt")
        if path.is_file()
    }
    successful_ids = {
        str(row.get("sample_id") or "")
        for row in generated_rows
        if not str(row.get("generation_error") or "").strip()
    }
    _require(
        observed_code_names == {f"{sample_id}.py" for sample_id in successful_ids},
        "Code sidecar file set does not exactly match successful rows",
    )
    _require(
        observed_requirement_names
        == {f"{sample_id}_requirements.txt" for sample_id in successful_ids},
        "Requirements sidecar file set does not exactly match successful rows",
    )
    observed_journal_ids = {
        path.name.removesuffix(".accepted.json")
        for path in accepted_journal_dir.glob("*.accepted.json")
        if path.is_file()
    }
    _require(
        observed_journal_ids == accepted_journal_ids == successful_ids,
        "Accepted-response journal file set does not match successful rows",
    )

    return {
        "successful_sample_count": success_count,
        "transport_pending_sample_count": pending_count,
        "terminal_failure_sample_count": terminal_count,
        "attempt_count_by_sample": {
            sample_id: len(attempts_by_id[sample_id])
            for sample_id in expected_ids
        },
        "armed_attempt_count_by_sample": (
            {
                sample_id: len(intents_by_id[sample_id])
                for sample_id in expected_ids
            }
            if intents_by_id is not None
            else None
        ),
        "request_contract_sha256": contract_hash,
    }
