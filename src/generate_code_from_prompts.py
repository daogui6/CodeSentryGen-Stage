"""
generate_code_from_prompts.py

作用：
    将 prompt JSONL 自动转换为 generated sample JSONL，
    是 CodeSentry-Gen 流程中的“API 自动生成代码”模块。

输入：
    - data/prompts/selected_prompts_pilot50.jsonl
    - 或通过 --prompts 指定其他 prompt JSONL

输出：
    - data/samples/auto_generated_codes.jsonl
    - data/auto_generated_code_files/*.py
    - data/auto_generated_requirements_files/*_requirements.txt

核心字段：
    - generated_code：模型生成的 Python 代码
    - requirements_text：模型生成或声明的第三方依赖
    - generation_time：代码生成时间，用于后续 THO 时态判断
    - raw_response：模型原始返回
    - generation_error：单条样本生成失败时的错误信息

两种模式：
    1. mock 模式：
       不调用真实 API，生成固定 requests 示例代码，用于测试后续 pipeline。
    2. real 模式：
       使用 --real 调用 qwen-plus，生成真实模型代码样本。

在整体流程中的位置：
    prepare_pilot50.py
        ↓
    generate_code_from_prompts.py
        ↓
    run_pilot.py
        ↓
    enrich_temporal_status.py / enrich_reachability_v2.py / build_temporal_risk_cards.py
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import queue
import re
import tempfile
import threading
import time
import requests
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


# 项目根目录：当前文件位于 src/ 下，因此向上一级就是项目根目录。
ROOT = Path(__file__).resolve().parents[1]

# 本地 API 配置文件。该文件只应保存在本地，不应提交到公开仓库。
LOCAL_API_CONFIG = ROOT / "config" / "local_api_config.json"
DEFAULT_QWEN_BASE_URL = (
    "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions"
)

# 默认输入输出路径：不传命令行参数时使用这些路径。
DEFAULT_PROMPTS = ROOT / "data" / "prompts" / "selected_prompts_pilot50.jsonl"
DEFAULT_OUTPUT = ROOT / "data" / "samples" / "auto_generated_codes.jsonl"
DEFAULT_CODE_DIR = ROOT / "data" / "auto_generated_code_files"
DEFAULT_REQ_DIR = ROOT / "data" / "auto_generated_requirements_files"


def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    """读取 JSONL 文件，每一行解析成一个字典。"""
    rows: list[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8-sig") as f:
        for line_no, raw_line in enumerate(f, 1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"JSONL corruption at {path}:{line_no}: {exc.msg}"
                ) from exc
            if not isinstance(value, dict):
                raise ValueError(
                    f"JSONL row is not an object: {path}:{line_no}"
                )
            rows.append(value)
    return rows


def write_jsonl(path: Path, rows: List[Dict[str, Any]]) -> None:
    """Atomically rewrite JSONL, used when a verified resume is compacted."""
    text = "".join(
        json.dumps(row, ensure_ascii=False) + "\n" for row in rows
    )
    atomic_write_text(path, text)


def fsync_directory(path: Path) -> None:
    """Persist directory metadata after create/replace on POSIX filesystems."""
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(str(path), flags)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_write_text(path: Path, text: str) -> None:
    """Write, fsync, replace, then fsync the parent directory."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
        text=True,
    )
    temp_path = Path(temp_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        fsync_directory(path.parent)
    except Exception:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass
        raise


def append_jsonl_row(path: Path, row: Dict[str, Any]) -> None:
    """Append one complete row and force it to stable storage before return."""
    path.parent.mkdir(parents=True, exist_ok=True)
    created = not path.exists()
    with path.open("a", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")
        f.flush()
        os.fsync(f.fileno())
    if created:
        fsync_directory(path.parent)


def canonical_json_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def text_sha256(value: Any) -> str:
    return hashlib.sha256(
        str(value or "").encode("utf-8")
    ).hexdigest()


def generation_request_contract(
    *,
    model: str,
    provider_endpoint: str | None,
    temperature: float,
    reasoning_effort: str | None,
    thinking_mode: str,
    response_format: str,
    stream: bool,
    connect_timeout: int | None,
    read_timeout: int | None,
    request_deadline: int | None,
    max_tokens: int | None,
) -> dict[str, Any]:
    """Canonical provider-call contract bound into every attempt record."""
    return {
        "schema_version": "codesentry_generation_request_contract_v1",
        "model": str(model),
        "provider_endpoint": (
            str(provider_endpoint).strip()
            if provider_endpoint is not None
            else None
        ),
        "temperature": float(temperature),
        "reasoning_effort": reasoning_effort,
        "thinking_mode": thinking_mode,
        "response_format": response_format,
        "transport_mode": (
            "streaming_sse" if stream else "non_streaming_json"
        ),
        "connect_timeout_seconds": connect_timeout,
        "stream_read_timeout_seconds": read_timeout,
        "request_deadline_seconds": request_deadline,
        "max_tokens": max_tokens,
    }


def accepted_response_journal_path(
    directory: Path,
    sample_id: str,
) -> Path:
    return directory / f"{sample_id}.accepted.json"


def persist_accepted_response_journal(
    path: Path,
    *,
    binding: dict[str, Any],
    generated: dict[str, Any],
    attempt: dict[str, Any],
) -> dict[str, Any]:
    """Commit an accepted provider response before ledger/sidecar/output use."""
    value = {
        "schema_version": "codesentry_accepted_response_journal_v1",
        "binding": binding,
        "generated": generated,
        "attempt": attempt,
    }
    value["journal_payload_sha256"] = canonical_json_sha256(value)
    text = json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    if path.exists():
        observed = json.loads(path.read_text(encoding="utf-8-sig"))
        if observed != value:
            raise ValueError(
                "Accepted-response journal already exists with different "
                f"bytes: {path}"
            )
        return value
    atomic_write_text(path, text)
    return value


def load_accepted_response_journal(
    path: Path,
    *,
    expected_binding: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Accepted-response journal corruption: {path}: {exc.msg}"
        ) from exc
    if not isinstance(value, dict):
        raise ValueError(f"Accepted-response journal is not an object: {path}")
    if value.get("schema_version") != "codesentry_accepted_response_journal_v1":
        raise ValueError(f"Accepted-response journal schema mismatch: {path}")
    expected_hash = value.get("journal_payload_sha256")
    payload = dict(value)
    payload.pop("journal_payload_sha256", None)
    if expected_hash != canonical_json_sha256(payload):
        raise ValueError(f"Accepted-response journal hash mismatch: {path}")
    if value.get("binding") != expected_binding:
        raise ValueError(f"Accepted-response journal binding mismatch: {path}")
    generated = value.get("generated")
    attempt = value.get("attempt")
    if not isinstance(generated, dict) or not isinstance(attempt, dict):
        raise ValueError(f"Accepted-response journal payload invalid: {path}")
    if attempt.get("accepted_response") is not True:
        raise ValueError(f"Accepted-response journal attempt is not accepted: {path}")
    if not str(generated.get("generated_code") or "").strip():
        raise ValueError(f"Accepted-response journal generated_code empty: {path}")
    return generated, attempt


def prevalidate_local_only_recovery(
    *,
    sample_ids: set[str],
    identity_by_sample_id: dict[str, dict[str, Any]],
    intents_by_sample_id: dict[str, list[dict[str, Any]]],
    attempts_by_sample_id: dict[str, list[dict[str, Any]]],
    accepted_journal_dir: Path,
    request_contract: dict[str, Any],
) -> None:
    """Validate every local-only recovery source before any provider call."""

    contract_hash = canonical_json_sha256(request_contract)
    for sample_id in sorted(sample_ids):
        identity = identity_by_sample_id[sample_id]
        journal_path = accepted_response_journal_path(
            accepted_journal_dir,
            sample_id,
        )
        if not journal_path.is_file():
            raise RuntimeError(
                "LOCAL_ONLY_RECOVERY_JOURNAL_MISSING: "
                f"{sample_id}"
            )
        _generated, recovered_attempt = load_accepted_response_journal(
            journal_path,
            expected_binding={
                "sample_id": sample_id,
                "source_sample_id": identity["source_sample_id"],
                "prompt_sha256": identity["prompt_sha256"],
                "request_contract_sha256": contract_hash,
            },
        )
        recovered_index = recovered_attempt.get("attempt_index")
        matching_intents = [
            intent
            for intent in intents_by_sample_id.get(sample_id, [])
            if intent.get("attempt_index") == recovered_index
        ]
        if len(matching_intents) != 1:
            raise ValueError(
                "Local-only accepted journal does not have exactly one "
                f"matching ATTEMPT_ARMED intent for {sample_id}"
            )
        recovered_intent = matching_intents[0]
        if (
            recovered_intent.get("prompt_sha256")
            != identity["prompt_sha256"]
            or recovered_intent.get("request_contract_sha256")
            != contract_hash
            or recovered_intent.get("resume_round")
            != recovered_attempt.get("resume_round")
            or recovered_intent.get("invocation_attempt_index")
            != recovered_attempt.get("invocation_attempt_index")
        ):
            raise ValueError(
                "Local-only accepted journal/ATTEMPT_ARMED binding "
                f"mismatch for {sample_id}"
            )

        sample_attempt_rows = attempts_by_sample_id.get(sample_id, [])
        matching_attempts = [
            attempt
            for attempt in sample_attempt_rows
            if attempt.get("attempt_index") == recovered_index
        ]
        if matching_attempts:
            if (
                len(matching_attempts) != 1
                or matching_attempts[0] != recovered_attempt
            ):
                raise ValueError(
                    "Local-only accepted journal/ledger mismatch for "
                    f"{sample_id}"
                )
        elif recovered_index != len(sample_attempt_rows) + 1:
            raise ValueError(
                "Local-only accepted journal attempt index is not the "
                f"next durable attempt for {sample_id}"
            )


def load_resume_rows(
    path: Path,
    *,
    resume_eligible_sample_ids: set[str] | None = None,
    resume_local_only_sample_ids: set[str] | None = None,
) -> tuple[list[Dict[str, Any]], set[str]]:
    """Load durable rows for resume without recalling forbidden samples.

    With no allowlist this preserves the frozen legacy behavior: successful
    rows are retained and every failure row is removed for retry.

    Successor recovery may pass an explicit allowlist. Then failure rows
    outside that allowlist are retained as immutable final evidence and
    skipped, while only allowlisted failure rows are removed for bounded
    continuation. Missing non-allowlisted rows are also skipped later by the
    main loop, which is required for no-row terminal recovery states.
    """
    if not path.exists():
        return [], set()

    successful_rows: list[Dict[str, Any]] = []
    successful_ids: set[str] = set()

    seen_ids: set[str] = set()
    with path.open("r", encoding="utf-8-sig") as f:
        for line_no, raw_line in enumerate(f, 1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Resume JSONL corruption at {path}:{line_no}: "
                    f"{exc.msg}"
                ) from exc
            if not isinstance(row, dict):
                raise ValueError(
                    f"Resume JSONL row is not an object: {path}:{line_no}"
                )

            sample_id = str(row.get("sample_id", "")).strip()
            if not sample_id:
                raise ValueError(
                    f"Resume JSONL row has no sample_id: {path}:{line_no}"
                )
            if sample_id in seen_ids:
                raise ValueError(
                    f"Resume JSONL duplicate sample_id: {sample_id}"
                )
            seen_ids.add(sample_id)
            generation_error = str(
                row.get("generation_error", "") or ""
            ).strip()

            if (
                resume_local_only_sample_ids is not None
                and sample_id in resume_local_only_sample_ids
            ):
                # Force journal-backed rematerialization even if a generated
                # row survived but a later ledger/sidecar write did not.
                continue

            if not generation_error:
                if not str(row.get("generated_code") or "").strip():
                    raise ValueError(
                        "Resume success row contains empty generated_code: "
                        f"{sample_id}"
                    )
                successful_rows.append(row)
                successful_ids.add(sample_id)
                continue

            if (
                resume_eligible_sample_ids is not None
                and sample_id not in resume_eligible_sample_ids
            ):
                successful_rows.append(row)
                successful_ids.add(sample_id)

    return successful_rows, successful_ids


def canonical_sidecar_text(value: Any) -> str:
    return str(value or "").strip() + "\n"


def validate_resume_sidecars(
    rows: list[Dict[str, Any]],
    *,
    code_dir: Path,
    req_dir: Path,
) -> None:
    errors: list[str] = []
    for row in rows:
        sample_id = str(row.get("sample_id", "") or "").strip()
        if not sample_id:
            errors.append("missing_sample_id")
            continue

        code_path = code_dir / f"{sample_id}.py"
        req_path = req_dir / f"{sample_id}_requirements.txt"

        if not code_path.exists():
            errors.append(f"{sample_id}:code_sidecar_missing")
        else:
            observed_code = code_path.read_text(encoding="utf-8-sig")
            expected_code = canonical_sidecar_text(
                row.get("generated_code")
            )
            if canonical_sidecar_text(observed_code) != expected_code:
                errors.append(f"{sample_id}:code_sidecar_mismatch")

        if not req_path.exists():
            errors.append(
                f"{sample_id}:requirements_sidecar_missing"
            )
        else:
            observed_req = req_path.read_text(encoding="utf-8-sig")
            expected_req = canonical_sidecar_text(
                row.get("requirements_text")
            )
            if canonical_sidecar_text(observed_req) != expected_req:
                errors.append(
                    f"{sample_id}:requirements_sidecar_mismatch"
                )

    if errors:
        raise ValueError(
            "Resume sidecar validation failed: "
            + ", ".join(errors)
        )


def write_text(path: Path, text: str) -> None:
    """写入普通文本文件，用于保存生成代码和 requirements sidecar。"""
    atomic_write_text(path, text.strip() + "\n")


def now_iso() -> str:
    """返回当前本地时间的 ISO 格式字符串，用作代码生成时间。"""
    return datetime.now().astimezone().replace(microsecond=0).isoformat()


def normalize_generation_time_override(value: str | None) -> str | None:
    """Normalize an explicit controlled-fixture generation time."""
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(
            "--generation-time-override must be an ISO-8601 timestamp"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(
            "--generation-time-override must be timezone-aware"
        )
    return parsed.astimezone(timezone.utc).replace(
        microsecond=0
    ).isoformat()


def stable_source_sample_id(
    row: Dict[str, Any],
    *,
    absolute_row_number: int,
) -> str:
    """为不同来源的 prompt 构造稳定且唯一的 sample identity。

    优先使用数据集中已有的 sample_id；若不存在，则依次退化到
    pilot_id、prompt_id，最后使用本次输入文件中的绝对行号。
    """
    for key in ("sample_id", "pilot_id", "prompt_id"):
        value = str(row.get(key, "") or "").strip()
        if value:
            return value

    return f"row_{absolute_row_number:06d}"


SAFE_SAMPLE_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def require_safe_sample_component(value: str, *, label: str) -> str:
    text = str(value or "").strip()
    if not SAFE_SAMPLE_COMPONENT.fullmatch(text) or text in {".", ".."}:
        raise ValueError(
            f"{label} is not a safe bounded filename component: {text!r}"
        )
    return text


def validate_selected_prompt_rows(
    rows: list[Dict[str, Any]],
    *,
    start: int,
) -> list[dict[str, str]]:
    """Fail before provider calls on ambiguous prompt/sample identity."""
    identities: list[dict[str, str]] = []
    seen_sample_ids: set[str] = set()
    for offset, row in enumerate(rows):
        absolute_row_number = start + offset
        source_sample_id = require_safe_sample_component(
            stable_source_sample_id(
                row,
                absolute_row_number=absolute_row_number,
            ),
            label=f"prompt row {absolute_row_number} source_sample_id",
        )
        sample_id = require_safe_sample_component(
            f"auto_{source_sample_id}",
            label=f"prompt row {absolute_row_number} sample_id",
        )
        if sample_id in seen_sample_ids:
            raise ValueError(
                "Selected prompt rows map to duplicate generated sample_id: "
                f"{sample_id}"
            )
        seen_sample_ids.add(sample_id)
        prompt = row.get("prompt")
        if prompt is None:
            prompt = row.get("prompt_text")
        if not isinstance(prompt, str) or not prompt.strip():
            raise ValueError(
                f"Selected prompt row {absolute_row_number} has no non-empty prompt"
            )
        identities.append(
            {
                "sample_id": sample_id,
                "source_sample_id": source_sample_id,
                "prompt_sha256": text_sha256(prompt),
            }
        )
    return identities


def build_mock_code(prompt: str) -> str:
    """构造 mock 代码，用于不调用真实 API 时测试后续 pipeline。"""
    return f'''import requests


def main():
    task = {prompt!r}
    response = requests.get("https://example.com", timeout=10)
    print("task:", task)
    print("status_code:", response.status_code)


if __name__ == "__main__":
    main()
'''


def build_mock_fixture(
    prompt: str,
    profile: str,
) -> tuple[str, str]:
    """Build an explicit mock fixture and its dependency declaration."""
    if profile == "requests_default":
        return build_mock_code(prompt), "requests>=2.31.0"
    if profile == "r5_r7_syntax_invalid_manifest":
        return (
            (
                "import requests\n\n"
                "def main():\n"
                '    response = requests.get("https://example.com"\n'
                "    print(response.status_code)\n"
            ),
            "requests",
        )

    if profile == "f15_prefreeze_aiohttp":
        code = f'''from aiohttp.web import static


def main():
    task = {prompt!r}
    resource = static(
        "/static",
        "./static",
        follow_symlinks=False,
    )
    print("task:", task)
    print("resource:", resource)


if __name__ == "__main__":
    main()
'''
        return code, "aiohttp==3.14.1"

    raise ValueError(f"Unsupported mock profile: {profile}")


def extract_json_object(text: str) -> Dict[str, Any]:
    """从模型输出中提取 JSON 对象。

    正常情况下模型应只输出 JSON；如果模型输出前后混入少量文本，
    则尝试用正则提取第一个完整 JSON 对象。
    """
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if not match:
            raise
        return json.loads(match.group(0))


def load_local_api_config() -> Dict[str, Any]:
    """读取本地 API 配置文件。文件不存在时返回空字典。"""
    if not LOCAL_API_CONFIG.exists():
        return {}

    with LOCAL_API_CONFIG.open("r", encoding="utf-8") as f:
        return json.load(f)


class ProviderHTTPError(RuntimeError):
    """HTTP failure with an explicit retryability decision."""

    def __init__(self, status_code: int, body: str):
        self.status_code = int(status_code)
        body_text = str(body or "")
        summary: dict[str, Any] = {
            "schema_version": "codesentry_provider_error_summary_v1",
            "http_status": self.status_code,
            "body_char_count": len(body_text),
            "body_sha256": hashlib.sha256(
                body_text.encode("utf-8", errors="replace")
            ).hexdigest(),
        }
        try:
            parsed = json.loads(body_text)
        except (json.JSONDecodeError, TypeError):
            parsed = None
        if isinstance(parsed, dict):
            error_value = parsed.get("error")
            if isinstance(error_value, dict):
                summary["error_object_keys"] = sorted(
                    str(key) for key in error_value
                )
                for field in ("code", "type", "param"):
                    scalar = error_value.get(field)
                    if (
                        isinstance(scalar, str)
                        and re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", scalar)
                    ):
                        summary[field] = scalar
                message = str(error_value.get("message") or "")
                if message:
                    summary["message_char_count"] = len(message)
                    summary["message_sha256"] = hashlib.sha256(
                        message.encode("utf-8", errors="replace")
                    ).hexdigest()
        self.body_summary = summary
        setattr(self, "codesentry_provider_error_summary", summary)
        super().__init__(
            "模型服务调用失败："
            f"{self.status_code}; body_char_count={len(body_text)}; "
            f"body_sha256={summary['body_sha256']}"
        )


class RequestDeadlineExceeded(requests.exceptions.Timeout):
    """Total accepted-attempt wall-clock deadline exceeded."""


class IncompleteSSECompletionError(RuntimeError):
    """No model completion choice was delivered before the SSE stream ended."""

    def __init__(
        self,
        message: str,
        *,
        stream_chunk_count: int | None = None,
        completion_choice_chunk_count: int | None = None,
        saw_done_marker: bool | None = None,
    ):
        super().__init__(message)
        # Keep the R5-r9 constructor contract backward-compatible so its
        # frozen controlled checker remains valid. New parser paths also pass
        # through _annotate_stream_exception for richer telemetry.
        if stream_chunk_count is not None:
            setattr(
                self,
                "codesentry_partial_stream_chunk_count",
                int(stream_chunk_count),
            )
        if completion_choice_chunk_count is not None:
            setattr(
                self,
                "codesentry_completion_choice_chunk_count",
                int(completion_choice_chunk_count),
            )
        if saw_done_marker is not None:
            setattr(
                self,
                "codesentry_saw_done_marker",
                bool(saw_done_marker),
            )


class OutputTokenLimitExceededError(ValueError):
    """Provider ended a delivered completion because the output budget was hit."""


class MissingFinalContentError(ValueError):
    """Completion choices were delivered but no final answer content was produced."""


class InvalidGeneratedPayloadError(ValueError):
    """Provider returned content that violates the frozen generator output contract."""


class ProviderProtocolError(ValueError):
    """The provider response violated the declared OpenAI-compatible contract."""


class ProviderModelIdentityMismatchError(ProviderProtocolError):
    """The response omitted or contradicted the requested model identity."""


class MalformedSSEEventError(ProviderProtocolError):
    """An SSE data event was delivered but was not a valid completion event."""


class ProviderThinkingModeViolationError(ProviderProtocolError):
    """Reasoning content was returned despite explicitly disabled thinking."""


class PrematureSSETerminationError(IncompleteSSECompletionError):
    """The transport ended before the provider delivered a completion marker."""


class TruncatedSSEEventError(PrematureSSETerminationError):
    """The transport ended in the middle of an incomplete SSE JSON event."""


class AcceptedResponsePersistenceError(RuntimeError):
    """An accepted response could not be committed to its durable journal."""


class AttemptIntentPersistenceError(RuntimeError):
    """A pre-provider ATTEMPT_ARMED intent could not be durably committed."""


class AmbiguousInFlightError(RuntimeError):
    """A durable armed attempt has no durable accepted/failure outcome."""


class AttemptLedgerPersistenceError(RuntimeError):
    """An attempt outcome could not be committed to the append-only ledger."""


def _annotate_stream_exception(
    exc: Exception,
    *,
    stream_chunk_count: int,
    completion_choice_chunk_count: int,
    saw_done_marker: bool,
    finish_reason: Any,
    usage: dict[str, Any],
    reasoning_char_count: int,
    content_char_count: int,
    stream_event_summary: dict[str, Any] | None = None,
) -> Exception:
    """Attach provider-stream diagnostics without changing retry semantics."""
    setattr(
        exc,
        "codesentry_partial_stream_chunk_count",
        int(stream_chunk_count),
    )
    setattr(
        exc,
        "codesentry_completion_choice_chunk_count",
        int(completion_choice_chunk_count),
    )
    setattr(exc, "codesentry_saw_done_marker", bool(saw_done_marker))
    setattr(exc, "codesentry_finish_reason", finish_reason)
    setattr(exc, "codesentry_api_usage", dict(usage or {}))
    setattr(
        exc,
        "codesentry_reasoning_char_count",
        int(reasoning_char_count),
    )
    setattr(
        exc,
        "codesentry_content_char_count",
        int(content_char_count),
    )
    setattr(
        exc,
        "codesentry_stream_event_summary",
        dict(stream_event_summary or {}),
    )
    return exc


def _annotate_provider_request_id(
    exc: Exception,
    request_id: str,
) -> Exception:
    setattr(exc, "codesentry_provider_request_id", str(request_id or ""))
    return exc


class GenerationAttemptsExhausted(RuntimeError):
    """Carries the complete predeclared attempt history for one sample."""

    def __init__(
        self,
        original: Exception,
        attempts: list[dict[str, Any]],
        *,
        retryable_failure: bool,
    ):
        self.original = original
        self.attempts = attempts
        self.retryable_failure = bool(retryable_failure)
        super().__init__(f"{type(original).__name__}: {original}")


def parse_retry_backoff_seconds(value: str | None) -> list[float]:
    text = str(value or "").strip()
    if not text:
        return []
    result: list[float] = []
    for part in text.split(","):
        item = part.strip()
        if not item:
            continue
        number = float(item)
        if number < 0:
            raise ValueError("retry backoff values must be non-negative")
        result.append(number)
    return result


def is_retryable_generation_exception(exc: Exception) -> bool:
    if isinstance(
        exc,
        (
            requests.exceptions.ConnectTimeout,
            requests.exceptions.ReadTimeout,
            requests.exceptions.ConnectionError,
            RequestDeadlineExceeded,
            IncompleteSSECompletionError,
        ),
    ):
        return True
    if isinstance(exc, ProviderHTTPError):
        return (
            exc.status_code in {408, 409, 425, 429}
            or 500 <= exc.status_code <= 599
        )
    return False


def generation_failure_class(exc: Exception) -> str:
    if isinstance(exc, requests.exceptions.ConnectTimeout):
        return "connect_timeout"
    if isinstance(exc, requests.exceptions.ReadTimeout):
        return "read_timeout"
    if isinstance(exc, RequestDeadlineExceeded):
        return "request_deadline_exceeded"
    if isinstance(exc, requests.exceptions.ConnectionError):
        return "connection_error"
    if isinstance(exc, TruncatedSSEEventError):
        return "sse_event_truncated"
    if isinstance(exc, PrematureSSETerminationError):
        return "sse_completion_interrupted"
    if isinstance(exc, IncompleteSSECompletionError):
        return "sse_completion_not_delivered"
    if isinstance(exc, OutputTokenLimitExceededError):
        return "output_token_limit_exceeded"
    if isinstance(exc, MissingFinalContentError):
        return "final_answer_content_missing"
    if isinstance(exc, InvalidGeneratedPayloadError):
        return "model_output_contract_invalid"
    if isinstance(exc, ProviderModelIdentityMismatchError):
        return "provider_model_identity_mismatch"
    if isinstance(exc, MalformedSSEEventError):
        return "sse_event_malformed"
    if isinstance(exc, ProviderThinkingModeViolationError):
        return "provider_thinking_mode_violation"
    if isinstance(exc, ProviderProtocolError):
        return "provider_protocol_violation"
    if isinstance(exc, AcceptedResponsePersistenceError):
        return "accepted_response_persistence_failure"
    if isinstance(exc, AttemptLedgerPersistenceError):
        return "attempt_ledger_persistence_failure"
    if isinstance(exc, ProviderHTTPError):
        return f"provider_http_{exc.status_code}"
    if isinstance(exc, json.JSONDecodeError):
        return "model_output_json_decode_error"
    return type(exc).__name__


def _new_stream_event_summary() -> dict[str, Any]:
    """Create bounded, content-free diagnostics for one provider stream."""
    return {
        "schema_version": "codesentry_sse_event_summary_v1",
        "raw_line_count": 0,
        "comment_line_count": 0,
        "blank_line_count": 0,
        "data_line_count": 0,
        "event_field_count": 0,
        "id_field_count": 0,
        "retry_field_count": 0,
        "unknown_field_count": 0,
        "sse_event_count": 0,
        "json_event_count": 0,
        "usage_event_count": 0,
        "empty_choices_event_count": 0,
        "completion_choice_event_count": 0,
        "completion_choice_item_count": 0,
        "content_delta_count": 0,
        "reasoning_delta_count": 0,
        "empty_delta_count": 0,
        "reasoning_after_content_count": 0,
        "reasoning_while_disabled_count": 0,
        "done_marker_count": 0,
        "malformed_json_event_count": 0,
        "truncated_json_event_count": 0,
        "finish_reason_distribution": {},
        "choice_index_distribution": {},
        "termination": "reading",
        "event_digest_head": [],
        "event_digest_tail": [],
    }


def _bounded_error_fingerprint(exc: Exception) -> dict[str, Any]:
    message = str(exc)
    return {
        "class": type(exc).__name__,
        "message_char_count": len(message),
        "message_sha256": hashlib.sha256(
            message.encode("utf-8", errors="replace")
        ).hexdigest(),
    }


def _append_event_digest(
    summary: dict[str, Any],
    *,
    payload: str,
    event_type: str,
    event_boundary: str,
    parsed: Any = None,
) -> None:
    """Retain event shape and hashes, never prompt/reasoning/content bytes."""
    digest: dict[str, Any] = {
        "event_ordinal": int(summary["sse_event_count"]),
        "event_type": event_type or "message",
        "event_boundary": event_boundary,
        "payload_char_count": len(payload),
        "payload_sha256": hashlib.sha256(
            payload.encode("utf-8", errors="replace")
        ).hexdigest(),
        "json_object": isinstance(parsed, dict),
    }
    if isinstance(parsed, dict):
        digest["top_level_keys"] = sorted(str(key) for key in parsed)
        digest["usage_present"] = isinstance(parsed.get("usage"), dict)
        digest["model_present"] = bool(str(parsed.get("model") or "").strip())
        choices = parsed.get("choices")
        digest["choices_kind"] = type(choices).__name__
        digest["choices_count"] = len(choices) if isinstance(choices, list) else None
        choice_shapes: list[dict[str, Any]] = []
        if isinstance(choices, list):
            for choice in choices[:4]:
                if not isinstance(choice, dict):
                    choice_shapes.append({"kind": type(choice).__name__})
                    continue
                delta = choice.get("delta")
                shape: dict[str, Any] = {
                    "index": choice.get("index"),
                    "finish_reason": choice.get("finish_reason"),
                    "delta_keys": (
                        sorted(str(key) for key in delta)
                        if isinstance(delta, dict)
                        else []
                    ),
                    "content_char_count": (
                        len(delta.get("content"))
                        if isinstance(delta, dict)
                        and isinstance(delta.get("content"), str)
                        else 0
                    ),
                    "reasoning_char_count": (
                        len(delta.get("reasoning_content"))
                        if isinstance(delta, dict)
                        and isinstance(delta.get("reasoning_content"), str)
                        else 0
                    ),
                }
                choice_shapes.append(shape)
        digest["choice_shapes"] = choice_shapes

    head = summary["event_digest_head"]
    tail = summary["event_digest_tail"]
    if len(head) < 8:
        head.append(digest)
    tail.append(digest)
    if len(tail) > 8:
        del tail[0]


def _payload_is_complete_json(payload: str) -> bool:
    if payload == "[DONE]":
        return True
    try:
        json.loads(payload)
    except json.JSONDecodeError:
        return False
    return True


def _iter_sse_data_events(
    response: requests.Response,
    *,
    summary: dict[str, Any],
    request_started_monotonic: float,
    request_deadline_seconds: float | None,
):
    """Parse SSE framing, including multi-line data fields.

    OpenAI-compatible fixtures and a few gateways omit the blank line between
    otherwise complete one-line JSON events.  When the buffered data is
    already complete JSON, a following data field is therefore treated as an
    implicit event boundary.  Invalid/incomplete JSON remains buffered so a
    standards-compliant multi-line event is joined with a newline.
    """
    data_lines: list[str] = []
    event_type = "message"

    def dispatch(boundary: str):
        nonlocal data_lines, event_type
        if not data_lines:
            event_type = "message"
            return None
        payload = "\n".join(data_lines)
        emitted_type = event_type or "message"
        data_lines = []
        event_type = "message"
        return payload, emitted_type, boundary

    for raw_line in _iter_response_lines_with_deadline(
        response,
        request_started_monotonic=request_started_monotonic,
        request_deadline_seconds=request_deadline_seconds,
    ):
        if (
            request_deadline_seconds is not None
            and time.monotonic() - request_started_monotonic
            > request_deadline_seconds
        ):
            raise RequestDeadlineExceeded(
                "streaming request exceeded frozen total deadline "
                f"{request_deadline_seconds}s"
            )

        summary["raw_line_count"] += 1
        if raw_line is None:
            continue
        line = (
            raw_line.decode("utf-8", errors="replace")
            if isinstance(raw_line, bytes)
            else str(raw_line)
        )
        if line == "":
            summary["blank_line_count"] += 1
            value = dispatch("blank_line")
            if value is not None:
                yield value
            continue
        if line.startswith(":"):
            summary["comment_line_count"] += 1
            continue

        field, separator, value = line.partition(":")
        if separator and value.startswith(" "):
            value = value[1:]
        if field == "data":
            summary["data_line_count"] += 1
            if data_lines:
                buffered = "\n".join(data_lines)
                if _payload_is_complete_json(buffered):
                    emitted = dispatch("implicit_complete_line")
                    if emitted is not None:
                        yield emitted
            data_lines.append(value)
            buffered = "\n".join(data_lines)
            if _payload_is_complete_json(buffered):
                emitted = dispatch("implicit_complete_line")
                if emitted is not None:
                    yield emitted
        elif field == "event":
            summary["event_field_count"] += 1
            event_type = value or "message"
        elif field == "id":
            summary["id_field_count"] += 1
        elif field == "retry":
            summary["retry_field_count"] += 1
        else:
            # WHATWG requires unknown fields to be ignored. Count them so a
            # provider framing change is visible instead of silently lost.
            summary["unknown_field_count"] += 1

    emitted = dispatch("transport_eof")
    if emitted is not None:
        yield emitted


def _iter_response_lines_with_deadline(
    response: requests.Response,
    *,
    request_started_monotonic: float,
    request_deadline_seconds: float | None,
):
    """Yield response lines while enforcing a true wall-clock deadline.

    ``requests`` read timeouts bound each inactive socket read, not the total
    request duration. A daemon reader plus a deadline-aware queue prevents a
    long but intermittently active stream (or an optional post-finish tail)
    from exceeding the frozen total deadline.
    """
    if request_deadline_seconds is None:
        yield from response.iter_lines(decode_unicode=True)
        return

    line_queue: queue.Queue[tuple[str, Any]] = queue.Queue()

    def read_lines() -> None:
        try:
            for line in response.iter_lines(decode_unicode=True):
                line_queue.put(("line", line))
        except Exception as exc:
            line_queue.put(("error", exc))
        finally:
            line_queue.put(("end", None))

    reader = threading.Thread(
        target=read_lines,
        name="codesentry-sse-deadline-reader",
        daemon=True,
    )
    reader.start()

    while True:
        remaining = request_deadline_seconds - (
            time.monotonic() - request_started_monotonic
        )
        if remaining <= 0:
            close = getattr(response, "close", None)
            if callable(close):
                close()
            raise RequestDeadlineExceeded(
                "streaming request exceeded frozen total deadline "
                f"{request_deadline_seconds}s"
            )
        try:
            kind, value = line_queue.get(timeout=remaining)
        except queue.Empty as exc:
            close = getattr(response, "close", None)
            if callable(close):
                close()
            raise RequestDeadlineExceeded(
                "streaming request exceeded frozen total deadline "
                f"{request_deadline_seconds}s"
            ) from exc
        if kind == "line":
            if (
                time.monotonic() - request_started_monotonic
                > request_deadline_seconds
            ):
                close = getattr(response, "close", None)
                if callable(close):
                    close()
                raise RequestDeadlineExceeded(
                    "streaming request exceeded frozen total deadline "
                    f"{request_deadline_seconds}s"
                )
            yield value
        elif kind == "error":
            raise value
        elif kind == "end":
            return
        else:
            raise ProviderProtocolError(
                f"Internal stream-reader state is invalid: {kind!r}"
            )


def _stream_openai_chat_response(
    response: requests.Response,
    *,
    requested_model: str,
    request_started_monotonic: float,
    request_deadline_seconds: float | None,
    enable_thinking: bool | None,
) -> dict[str, Any]:
    content_parts: list[str] = []
    reasoning_char_count = 0
    usage: dict[str, Any] = {}
    reported_model = ""
    finish_reason = None
    stream_chunk_count = 0
    completion_choice_chunk_count = 0
    saw_done_marker = False
    summary = _new_stream_event_summary()
    content_started = False
    reasoning_observed_while_disabled = False

    try:
        for payload, event_type, event_boundary in _iter_sse_data_events(
            response,
            summary=summary,
            request_started_monotonic=request_started_monotonic,
            request_deadline_seconds=request_deadline_seconds,
        ):
            summary["sse_event_count"] += 1
            if payload == "[DONE]":
                saw_done_marker = True
                summary["done_marker_count"] += 1
                summary["termination"] = "done_marker"
                _append_event_digest(
                    summary,
                    payload=payload,
                    event_type=event_type,
                    event_boundary=event_boundary,
                )
                break
            if not payload:
                continue

            try:
                data = json.loads(payload)
            except json.JSONDecodeError as decode_error:
                is_truncated = event_boundary == "transport_eof"
                summary[
                    "truncated_json_event_count"
                    if is_truncated
                    else "malformed_json_event_count"
                ] += 1
                _append_event_digest(
                    summary,
                    payload=payload,
                    event_type=event_type,
                    event_boundary=event_boundary,
                )
                error_type = (
                    TruncatedSSEEventError
                    if is_truncated
                    else MalformedSSEEventError
                )
                raise error_type(
                    "SSE JSON event was truncated at transport EOF"
                    if is_truncated
                    else (
                        "SSE data event is not valid JSON: "
                        f"line={decode_error.lineno}, "
                        f"column={decode_error.colno}"
                    )
                ) from decode_error
            if not isinstance(data, dict):
                _append_event_digest(
                    summary,
                    payload=payload,
                    event_type=event_type,
                    event_boundary=event_boundary,
                    parsed=data,
                )
                raise MalformedSSEEventError(
                    "SSE completion event must be a JSON object"
                )

            _append_event_digest(
                summary,
                payload=payload,
                event_type=event_type,
                event_boundary=event_boundary,
                parsed=data,
            )
            stream_chunk_count += 1
            summary["json_event_count"] += 1

            if data.get("error") is not None:
                raise ProviderProtocolError(
                    "Provider returned an error object inside an HTTP 200 SSE stream"
                )

            chunk_model = str(data.get("model", "") or "").strip()
            if chunk_model:
                if chunk_model != requested_model:
                    raise ProviderModelIdentityMismatchError(
                        "Provider model identity mismatch: "
                        f"requested={requested_model}, "
                        f"reported={chunk_model}"
                    )
                reported_model = chunk_model

            if isinstance(data.get("usage"), dict):
                usage = data["usage"]
                summary["usage_event_count"] += 1

            choices = data.get("choices")
            if choices is None:
                continue
            if not isinstance(choices, list):
                raise ProviderProtocolError(
                    "SSE completion event choices must be a list"
                )
            if not choices:
                summary["empty_choices_event_count"] += 1
                continue

            completion_choice_chunk_count += 1
            summary["completion_choice_event_count"] += 1
            summary["completion_choice_item_count"] += len(choices)
            if len(choices) != 1:
                raise ProviderProtocolError(
                    "Exactly one completion choice is required when n=1; "
                    f"received={len(choices)}"
                )

            choice = choices[0]
            if not isinstance(choice, dict):
                raise ProviderProtocolError(
                    "SSE completion choice must be a JSON object"
                )
            choice_index = choice.get("index", 0)
            if not isinstance(choice_index, int) or choice_index != 0:
                raise ProviderProtocolError(
                    "SSE completion choice index must be 0 for n=1; "
                    f"received={choice_index!r}"
                )
            index_key = str(choice_index)
            summary["choice_index_distribution"][index_key] = (
                summary["choice_index_distribution"].get(index_key, 0) + 1
            )

            if finish_reason is not None:
                raise ProviderProtocolError(
                    "Completion choice data was delivered after finish_reason"
                )

            delta = choice.get("delta")
            if delta is None:
                delta = {}
            if not isinstance(delta, dict):
                raise ProviderProtocolError(
                    "SSE completion delta must be a JSON object or null"
                )

            content = delta.get("content")
            if content is not None and not isinstance(content, str):
                raise ProviderProtocolError(
                    "SSE delta.content must be a string or null"
                )
            reasoning = delta.get("reasoning_content")
            if reasoning is not None and not isinstance(reasoning, str):
                raise ProviderProtocolError(
                    "SSE delta.reasoning_content must be a string or null"
                )

            if isinstance(content, str) and content:
                content_parts.append(content)
                content_started = True
                summary["content_delta_count"] += 1
            if isinstance(reasoning, str) and reasoning:
                if enable_thinking is False:
                    reasoning_observed_while_disabled = True
                    summary["reasoning_while_disabled_count"] += 1
                if content_started:
                    summary["reasoning_after_content_count"] += 1
                reasoning_char_count += len(reasoning)
                summary["reasoning_delta_count"] += 1
            if not content and not reasoning:
                summary["empty_delta_count"] += 1

            observed_finish = choice.get("finish_reason")
            if observed_finish is not None:
                if not isinstance(observed_finish, str) or not observed_finish.strip():
                    raise ProviderProtocolError(
                        "SSE finish_reason must be a non-empty string or null"
                    )
                finish_reason = observed_finish
                finish_key = observed_finish.strip().lower()
                distribution = summary["finish_reason_distribution"]
                distribution[finish_key] = distribution.get(finish_key, 0) + 1
                # The first valid choice[0] finish_reason is the completion
                # commit point.  Usage-only and [DONE] tail events are
                # optional and must not hold an already completed answer
                # open until the total request deadline.  The response is
                # closed by call_qwen's finally block.
                summary["termination"] = "finish_reason_commit"
                break
    except requests.exceptions.RequestException as exc:
        if finish_reason is not None:
            # finish_reason is the provider's completion commit point. A
            # missing optional usage/[DONE] tail must not cause a second model
            # sample to replace an already completed first response.
            summary["termination"] = "transport_error_after_finish"
            summary["post_finish_transport_error"] = (
                _bounded_error_fingerprint(exc)
            )
        else:
            summary["termination"] = "transport_error_before_finish"
            _annotate_stream_exception(
                exc,
                stream_chunk_count=stream_chunk_count,
                completion_choice_chunk_count=completion_choice_chunk_count,
                saw_done_marker=saw_done_marker,
                finish_reason=finish_reason,
                usage=usage,
                reasoning_char_count=reasoning_char_count,
                content_char_count=sum(len(x) for x in content_parts),
                stream_event_summary=summary,
            )
            raise
    except Exception as exc:
        if summary["termination"] == "reading":
            summary["termination"] = "parser_error"
        _annotate_stream_exception(
            exc,
            stream_chunk_count=stream_chunk_count,
            completion_choice_chunk_count=completion_choice_chunk_count,
            saw_done_marker=saw_done_marker,
            finish_reason=finish_reason,
            usage=usage,
            reasoning_char_count=reasoning_char_count,
            content_char_count=sum(len(x) for x in content_parts),
            stream_event_summary=summary,
        )
        raise

    content = "".join(content_parts)
    normalized_finish_reason = str(finish_reason or "").strip().lower()

    if summary["termination"] == "reading":
        summary["termination"] = (
            "eof_after_finish"
            if finish_reason is not None
            else "eof_before_finish"
        )

    if completion_choice_chunk_count == 0:
        exc = IncompleteSSECompletionError(
            "Streaming response ended without any model completion choice chunks"
        )
        raise _annotate_stream_exception(
            exc,
            stream_chunk_count=stream_chunk_count,
            completion_choice_chunk_count=completion_choice_chunk_count,
            saw_done_marker=saw_done_marker,
            finish_reason=finish_reason,
            usage=usage,
            reasoning_char_count=reasoning_char_count,
            content_char_count=len(content),
            stream_event_summary=summary,
        )

    if finish_reason is None:
        if saw_done_marker:
            exc = ProviderProtocolError(
                "SSE stream delivered [DONE] without a completion finish_reason"
            )
        else:
            exc = PrematureSSETerminationError(
                "SSE transport ended before a completion finish_reason"
            )
        raise _annotate_stream_exception(
            exc,
            stream_chunk_count=stream_chunk_count,
            completion_choice_chunk_count=completion_choice_chunk_count,
            saw_done_marker=saw_done_marker,
            finish_reason=finish_reason,
            usage=usage,
            reasoning_char_count=reasoning_char_count,
            content_char_count=len(content),
            stream_event_summary=summary,
        )

    # Inspect finish_reason before the empty-content check.  R5-r9 showed that
    # a reasoning-heavy stream can deliver thousands of choice chunks yet
    # never reach answer content; if the provider reports length, this is an
    # output-budget exhaustion, not an undifferentiated empty-content error.
    if normalized_finish_reason == "length":
        exc = OutputTokenLimitExceededError(
            "Streaming response exhausted max_tokens before an accepted "
            "complete final answer (finish_reason=length)"
        )
        raise _annotate_stream_exception(
            exc,
            stream_chunk_count=stream_chunk_count,
            completion_choice_chunk_count=completion_choice_chunk_count,
            saw_done_marker=saw_done_marker,
            finish_reason=finish_reason,
            usage=usage,
            reasoning_char_count=reasoning_char_count,
            content_char_count=len(content),
            stream_event_summary=summary,
        )

    if not content.strip():
        phase = (
            "reasoning-only completion"
            if reasoning_char_count > 0
            else "completion with no answer content"
        )
        exc = MissingFinalContentError(
            f"Streaming response ended as {phase}; "
            f"finish_reason={finish_reason!r}"
        )
        raise _annotate_stream_exception(
            exc,
            stream_chunk_count=stream_chunk_count,
            completion_choice_chunk_count=completion_choice_chunk_count,
            saw_done_marker=saw_done_marker,
            finish_reason=finish_reason,
            usage=usage,
            reasoning_char_count=reasoning_char_count,
            content_char_count=len(content),
            stream_event_summary=summary,
        )

    if reasoning_observed_while_disabled:
        exc = ProviderThinkingModeViolationError(
            "Provider returned reasoning_content while enable_thinking=false"
        )
        raise _annotate_stream_exception(
            exc,
            stream_chunk_count=stream_chunk_count,
            completion_choice_chunk_count=completion_choice_chunk_count,
            saw_done_marker=saw_done_marker,
            finish_reason=finish_reason,
            usage=usage,
            reasoning_char_count=reasoning_char_count,
            content_char_count=len(content),
            stream_event_summary=summary,
        )

    return {
        "content": content,
        "reported_model": reported_model,
        "usage": usage,
        "finish_reason": finish_reason,
        "stream_chunk_count": stream_chunk_count,
        "completion_choice_chunk_count": completion_choice_chunk_count,
        "saw_done_marker": saw_done_marker,
        "reasoning_char_count": reasoning_char_count,
        "content_char_count": len(content),
        "stream_event_summary": summary,
    }


def run_real_generation_attempts(
    call_fn,
    *,
    retries: int,
    retry_backoff_seconds: list[float],
    call_kwargs: dict[str, Any],
    on_attempt=None,
    on_accepted_response=None,
    on_attempt_armed=None,
    attempt_index_offset: int = 0,
    sleep_fn=time.sleep,
) -> tuple[dict[str, Any], list[dict[str, Any]], str, str, float]:
    if retries < 0:
        raise ValueError("retries must be non-negative")
    if len(retry_backoff_seconds) not in {0, retries}:
        raise ValueError(
            "retry backoff count must be zero or equal frozen retries"
        )

    attempts: list[dict[str, Any]] = []
    max_attempts = retries + 1

    if attempt_index_offset < 0:
        raise ValueError("attempt_index_offset must be non-negative")

    for invocation_attempt_index in range(1, max_attempts + 1):
        attempt_index = attempt_index_offset + invocation_attempt_index
        started = datetime.now(timezone.utc)
        armed_record = {
            "schema_version": "codesentry_generation_attempt_intent_v1",
            "state": "ATTEMPT_ARMED",
            "attempt_index": attempt_index,
            "invocation_attempt_index": invocation_attempt_index,
            "armed_at": started.isoformat(),
        }
        if on_attempt_armed is not None:
            try:
                on_attempt_armed(armed_record)
            except Exception as persistence_exc:
                exc = AttemptIntentPersistenceError(
                    "Provider attempt was not started because ATTEMPT_ARMED "
                    "could not be committed to durable storage"
                )
                setattr(
                    exc,
                    "codesentry_persistence_error_class",
                    type(persistence_exc).__name__,
                )
                raise GenerationAttemptsExhausted(
                    exc,
                    attempts,
                    retryable_failure=False,
                ) from persistence_exc
        try:
            generated = call_fn(**call_kwargs)
            completed = datetime.now(timezone.utc)
            record = {
                "attempt_index": attempt_index,
                "invocation_attempt_index": invocation_attempt_index,
                "request_started_at": started.isoformat(),
                "response_completed_at": completed.isoformat(),
                "observed_seconds": (
                    completed - started
                ).total_seconds(),
                "accepted_response": True,
                "retryable_failure": False,
                "failure_class": None,
                "error": None,
                "partial_stream_chunk_count": int(
                    generated.get("stream_chunk_count", 0) or 0
                ),
                "completion_choice_chunk_count": int(
                    generated.get("completion_choice_chunk_count", 0) or 0
                ),
                "saw_done_marker": bool(
                    generated.get("saw_done_marker", False)
                ),
                "finish_reason": generated.get("finish_reason"),
                "reasoning_char_count": int(
                    generated.get("reasoning_char_count", 0) or 0
                ),
                "content_char_count": int(
                    generated.get("content_char_count", 0) or 0
                ),
                "api_usage": (
                    generated.get("api_usage", {})
                    if isinstance(generated.get("api_usage"), dict)
                    else {}
                ),
                "stream_event_summary": (
                    generated.get("stream_event_summary", {})
                    if isinstance(
                        generated.get("stream_event_summary"), dict
                    )
                    else {}
                ),
                "provider_request_id": str(
                    generated.get("provider_request_id", "") or ""
                ),
                "provider_error_summary": {},
            }
            attempts.append(record)
            if on_accepted_response is not None:
                try:
                    on_accepted_response(generated, record)
                except Exception as persistence_exc:
                    exc = AcceptedResponsePersistenceError(
                        "Accepted provider response could not be committed "
                        "to the durable response journal"
                    )
                    setattr(
                        exc,
                        "codesentry_persistence_error_class",
                        type(persistence_exc).__name__,
                    )
                    setattr(
                        exc,
                        "codesentry_accepted_response_observed",
                        True,
                    )
                    raise GenerationAttemptsExhausted(
                        exc,
                        attempts,
                        retryable_failure=False,
                    ) from persistence_exc
            if on_attempt is not None:
                try:
                    on_attempt(record)
                except Exception as persistence_exc:
                    exc = AttemptLedgerPersistenceError(
                        "Accepted attempt could not be committed to the "
                        "append-only attempt ledger"
                    )
                    setattr(
                        exc,
                        "codesentry_persistence_error_class",
                        type(persistence_exc).__name__,
                    )
                    raise GenerationAttemptsExhausted(
                        exc,
                        attempts,
                        retryable_failure=False,
                    ) from persistence_exc
            return (
                generated,
                attempts,
                started.isoformat(),
                completed.isoformat(),
                (completed - started).total_seconds(),
            )
        except GenerationAttemptsExhausted:
            raise
        except Exception as exc:
            completed = datetime.now(timezone.utc)
            retryable = is_retryable_generation_exception(exc)
            record = {
                "attempt_index": attempt_index,
                "invocation_attempt_index": invocation_attempt_index,
                "request_started_at": started.isoformat(),
                "response_completed_at": completed.isoformat(),
                "observed_seconds": (
                    completed - started
                ).total_seconds(),
                "accepted_response": False,
                "retryable_failure": retryable,
                "failure_class": generation_failure_class(exc),
                "error": f"{type(exc).__name__}: {exc}",
                "partial_stream_chunk_count": int(
                    getattr(
                        exc,
                        "codesentry_partial_stream_chunk_count",
                        0,
                    )
                    or 0
                ),
                "completion_choice_chunk_count": int(
                    getattr(
                        exc,
                        "codesentry_completion_choice_chunk_count",
                        0,
                    )
                    or 0
                ),
                "saw_done_marker": bool(
                    getattr(
                        exc,
                        "codesentry_saw_done_marker",
                        False,
                    )
                ),
                "finish_reason": getattr(
                    exc,
                    "codesentry_finish_reason",
                    None,
                ),
                "reasoning_char_count": int(
                    getattr(
                        exc,
                        "codesentry_reasoning_char_count",
                        0,
                    )
                    or 0
                ),
                "content_char_count": int(
                    getattr(
                        exc,
                        "codesentry_content_char_count",
                        0,
                    )
                    or 0
                ),
                "api_usage": (
                    getattr(exc, "codesentry_api_usage", {})
                    if isinstance(
                        getattr(exc, "codesentry_api_usage", {}),
                        dict,
                    )
                    else {}
                ),
                "stream_event_summary": (
                    getattr(exc, "codesentry_stream_event_summary", {})
                    if isinstance(
                        getattr(
                            exc,
                            "codesentry_stream_event_summary",
                            {},
                        ),
                        dict,
                    )
                    else {}
                ),
                "provider_request_id": str(
                    getattr(exc, "codesentry_provider_request_id", "") or ""
                ),
                "provider_error_summary": (
                    getattr(exc, "codesentry_provider_error_summary", {})
                    if isinstance(
                        getattr(
                            exc,
                            "codesentry_provider_error_summary",
                            {},
                        ),
                        dict,
                    )
                    else {}
                ),
            }
            attempts.append(record)
            if on_attempt is not None:
                try:
                    on_attempt(record)
                except Exception as persistence_exc:
                    ledger_exc = AttemptLedgerPersistenceError(
                        "Failed attempt could not be committed to the "
                        "append-only attempt ledger"
                    )
                    setattr(
                        ledger_exc,
                        "codesentry_persistence_error_class",
                        type(persistence_exc).__name__,
                    )
                    raise GenerationAttemptsExhausted(
                        ledger_exc,
                        attempts,
                        retryable_failure=False,
                    ) from persistence_exc

            if not retryable or invocation_attempt_index >= max_attempts:
                raise GenerationAttemptsExhausted(
                    exc,
                    attempts,
                    retryable_failure=retryable,
                ) from exc

            delay = (
                retry_backoff_seconds[invocation_attempt_index - 1]
                if retry_backoff_seconds
                else 2.0
            )
            print(
                f"[WARN] attempt {invocation_attempt_index}/{max_attempts} "
                f"failed: {type(exc).__name__}: {exc}; "
                f"retryable=true; backoff={delay}s"
            )
            sleep_fn(delay)

    raise AssertionError("unreachable generation attempt loop")


def call_qwen(
    prompt: str,
    model: str,
    timeout: int,
    temperature: float,
    base_url: str | None = None,
    reasoning_effort: str | None = None,
    *,
    enable_thinking: bool | None = None,
    response_format: str = "text",
    stream: bool = False,
    connect_timeout: int | None = None,
    read_timeout: int | None = None,
    request_deadline: int | None = None,
    max_tokens: int | None = None,
) -> Dict[str, Any]:
    """Call a DashScope OpenAI-compatible text model for code generation.

    The historical function name is retained for compatibility, but the
    formal Step9 path is provider/model agnostic and may bind a DeepSeek
    snapshot model. Optional reasoning_effort is part of the frozen request
    contract when supplied.
    """
    if not isinstance(prompt, str) or not prompt.strip():
        raise ValueError("prompt must be a non-empty string")
    if not str(model or "").strip():
        raise ValueError("model must be non-empty")
    if int(timeout) <= 0:
        raise ValueError("timeout must be positive")
    if not (0.0 <= float(temperature) <= 2.0):
        raise ValueError("temperature must be in [0,2]")
    if request_deadline is not None and int(request_deadline) <= 0:
        raise ValueError("request_deadline must be positive")
    local_config = load_local_api_config()

    # API Key 优先从环境变量读取；如果没有，再从本地配置文件读取。
    api_key = os.getenv("DASHSCOPE_API_KEY") or local_config.get("dashscope_api_key")
    if not api_key:
        raise RuntimeError(
            "未找到 API Key。请设置 DASHSCOPE_API_KEY，或在 config/local_api_config.json 中配置 dashscope_api_key。")

    # Formal Step9 passes an explicit protocol-bound endpoint. Local config
    # may still override the endpoint for non-formal development calls only.
    if base_url is not None:
        url = str(base_url).strip()
        endpoint_source = "explicit_argument"
        if not url:
            raise ValueError("Explicit provider base URL is empty")
    else:
        configured = str(local_config.get("qwen_base_url") or "").strip()
        url = configured or DEFAULT_QWEN_BASE_URL
        endpoint_source = "local_api_config" if configured else "default"

    # system prompt 固定模型角色，要求输出严格 JSON，便于后续自动解析。
    system_prompt = """你是一个用于 CodeSentry-Gen 实验的 Python 代码生成器。
请只输出 JSON，不要输出 Markdown。
JSON 必须包含三个字段：
generated_code: 生成的 Python 代码字符串
requirements_text: requirements.txt 内容，如果只使用标准库则为空字符串
notes: 简短说明
"""

    # user prompt 中加入格式约束，降低模型输出 Markdown 代码块或缩进异常的概率。
    user_prompt = f"""请根据下面 prompt 生成 Python 代码：

    {prompt}

    要求：
    1. 如果使用第三方库，必须在 requirements_text 中列出。
    2. requirements_text 每行一个包名，不要写解释。
    3. generated_code 不要包含 Markdown 代码块。
    4. generated_code 必须是语法正确、缩进正确、可以直接保存为 .py 文件运行的 Python 代码。
    5. 不要在顶层语句前添加多余缩进。
    6. 只输出 JSON。
    """

    # 发送真实模型请求。timeout 由命令行参数控制，避免长时间卡死。
    request_payload: Dict[str, Any] = {
        "model": model,
        "n": 1,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": temperature,
    }
    if enable_thinking is False and reasoning_effort is not None:
        raise ValueError(
            "reasoning_effort must be omitted when enable_thinking=false"
        )
    if response_format not in {"text", "json_object"}:
        raise ValueError(
            "response_format must be one of: text, json_object"
        )
    if response_format == "json_object" and enable_thinking is not False:
        raise ValueError(
            "json_object response_format requires explicit enable_thinking=false"
        )
    if enable_thinking is not None:
        request_payload["enable_thinking"] = bool(enable_thinking)
    if reasoning_effort is not None:
        request_payload["reasoning_effort"] = reasoning_effort
    if response_format == "json_object":
        request_payload["response_format"] = {"type": "json_object"}
    if max_tokens is not None:
        if int(max_tokens) <= 0:
            raise ValueError("max_tokens must be positive when supplied")
        request_payload["max_tokens"] = int(max_tokens)
    if stream:
        request_payload["stream"] = True
        request_payload["stream_options"] = {"include_usage": True}

    connect_value = (
        int(connect_timeout)
        if connect_timeout is not None
        else int(timeout)
    )
    read_value = (
        int(read_timeout)
        if read_timeout is not None
        else int(timeout)
    )
    if connect_value <= 0 or read_value <= 0:
        raise ValueError("HTTP timeout values must be positive")
    if request_deadline is not None:
        # requests' read timeout is an inactivity timeout, not a total
        # deadline. Cap each blocking phase so the explicit wall-clock
        # deadline cannot be exceeded by one longer socket wait.
        connect_value = min(connect_value, int(request_deadline))
        read_value = min(read_value, int(request_deadline))

    started_monotonic = time.monotonic()
    resp = requests.post(
        url,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json=request_payload,
        timeout=(connect_value, read_value),
        stream=bool(stream),
    )
    provider_request_id = ""
    headers = getattr(resp, "headers", None)
    if isinstance(headers, dict) or hasattr(headers, "get"):
        for header_name in (
            "x-request-id",
            "x-dashscope-request-id",
            "request-id",
        ):
            value = str(headers.get(header_name, "") or "").strip()
            if value:
                provider_request_id = value
                break

    try:
        if resp.status_code >= 400:
            raise ProviderHTTPError(resp.status_code, resp.text)

        if stream:
            streamed = _stream_openai_chat_response(
                resp,
                requested_model=model,
                request_started_monotonic=started_monotonic,
                request_deadline_seconds=(
                    float(request_deadline)
                    if request_deadline is not None
                    else None
                ),
                enable_thinking=enable_thinking,
            )
            content = streamed["content"]
            reported_model = streamed["reported_model"]
            usage = streamed["usage"]
            finish_reason = streamed["finish_reason"]
            stream_chunk_count = streamed["stream_chunk_count"]
            reasoning_char_count = streamed["reasoning_char_count"]
            content_char_count = streamed["content_char_count"]
            stream_event_summary = streamed["stream_event_summary"]
        else:
            try:
                data = resp.json()
            except (ValueError, json.JSONDecodeError) as decode_error:
                raise ProviderProtocolError(
                    "Non-streaming provider response is not valid JSON"
                ) from decode_error
            if not isinstance(data, dict):
                raise ProviderProtocolError(
                    "Non-streaming provider response must be a JSON object"
                )
            if data.get("error") is not None:
                raise ProviderProtocolError(
                    "Provider returned an error object inside an HTTP 200 response"
                )
            reported_model = str(data.get("model", "") or "").strip()
            if reported_model and reported_model != model:
                raise ProviderModelIdentityMismatchError(
                    "Provider model identity mismatch: "
                    f"requested={model}, reported={reported_model}"
                )
            choices = data.get("choices")
            if not isinstance(choices, list) or len(choices) != 1:
                raise ProviderProtocolError(
                    "Non-streaming response requires exactly one choice"
                )
            choice = choices[0]
            if not isinstance(choice, dict):
                raise ProviderProtocolError(
                    "Non-streaming response choice must be an object"
                )
            choice_index = choice.get("index", 0)
            if not isinstance(choice_index, int) or choice_index != 0:
                raise ProviderProtocolError(
                    "Non-streaming response choice index must be 0 for n=1"
                )
            message = choice.get("message")
            if not isinstance(message, dict):
                raise ProviderProtocolError(
                    "Non-streaming response choice.message must be an object"
                )
            content = message.get("content")
            if not isinstance(content, str):
                raise ProviderProtocolError(
                    "Non-streaming response message.content must be a string"
                )
            usage = (
                data.get("usage")
                if isinstance(data.get("usage"), dict)
                else {}
            )
            reasoning = message.get("reasoning_content")
            if reasoning is not None and not isinstance(reasoning, str):
                raise ProviderProtocolError(
                    "Non-streaming message.reasoning_content must be a "
                    "string or null"
                )
            finish_reason = choice.get("finish_reason")
            if finish_reason is not None and (
                not isinstance(finish_reason, str)
                or not finish_reason.strip()
            ):
                raise ProviderProtocolError(
                    "Non-streaming finish_reason must be a non-empty string "
                    "or null"
                )
            stream_chunk_count = 0
            reasoning_char_count = (
                len(reasoning) if isinstance(reasoning, str) else 0
            )
            content_char_count = len(content)
            stream_event_summary = {
                "schema_version": "codesentry_nonstream_response_summary_v1",
                "top_level_keys": sorted(str(key) for key in data),
                "message_keys": sorted(str(key) for key in message),
                "reasoning_while_disabled_count": (
                    1
                    if enable_thinking is False and reasoning_char_count > 0
                    else 0
                ),
            }
    except Exception as exc:
        setattr(exc, "codesentry_provider_request_id", provider_request_id)
        raise
    finally:
        close = getattr(resp, "close", None)
        if callable(close):
            close()

    if not reported_model:
        exc = ProviderModelIdentityMismatchError(
            "Provider response omitted required model identity: "
            f"requested={model}"
        )
        _annotate_stream_exception(
            exc,
            stream_chunk_count=stream_chunk_count,
            completion_choice_chunk_count=(
                streamed["completion_choice_chunk_count"] if stream else 0
            ),
            saw_done_marker=(streamed["saw_done_marker"] if stream else False),
            finish_reason=finish_reason,
            usage=usage,
            reasoning_char_count=reasoning_char_count,
            content_char_count=content_char_count,
            stream_event_summary=stream_event_summary,
        )
        raise _annotate_provider_request_id(exc, provider_request_id)

    normalized_finish_reason = str(finish_reason or "").strip().lower()
    if normalized_finish_reason == "length":
        exc = OutputTokenLimitExceededError(
            "Completed provider response exhausted max_tokens "
            "(finish_reason=length)"
        )
        _annotate_stream_exception(
            exc,
            stream_chunk_count=stream_chunk_count,
            completion_choice_chunk_count=(
                streamed["completion_choice_chunk_count"] if stream else 0
            ),
            saw_done_marker=(streamed["saw_done_marker"] if stream else False),
            finish_reason=finish_reason,
            usage=usage,
            reasoning_char_count=reasoning_char_count,
            content_char_count=content_char_count,
            stream_event_summary=stream_event_summary,
        )
        raise _annotate_provider_request_id(exc, provider_request_id)
    if normalized_finish_reason != "stop":
        exc = InvalidGeneratedPayloadError(
            "Completed provider response is not an accepted complete "
            f"generation: finish_reason={finish_reason!r}"
        )
        _annotate_stream_exception(
            exc,
            stream_chunk_count=stream_chunk_count,
            completion_choice_chunk_count=(
                streamed["completion_choice_chunk_count"] if stream else 0
            ),
            saw_done_marker=(streamed["saw_done_marker"] if stream else False),
            finish_reason=finish_reason,
            usage=usage,
            reasoning_char_count=reasoning_char_count,
            content_char_count=content_char_count,
            stream_event_summary=stream_event_summary,
        )
        raise _annotate_provider_request_id(exc, provider_request_id)

    if not content.strip():
        exc = MissingFinalContentError(
            "Completed provider response contains no final answer content"
        )
        _annotate_stream_exception(
            exc,
            stream_chunk_count=stream_chunk_count,
            completion_choice_chunk_count=(
                streamed["completion_choice_chunk_count"] if stream else 0
            ),
            saw_done_marker=(streamed["saw_done_marker"] if stream else False),
            finish_reason=finish_reason,
            usage=usage,
            reasoning_char_count=reasoning_char_count,
            content_char_count=content_char_count,
            stream_event_summary=stream_event_summary,
        )
        raise _annotate_provider_request_id(exc, provider_request_id)

    if enable_thinking is False and reasoning_char_count > 0:
        exc = ProviderThinkingModeViolationError(
            "Provider returned reasoning_content while enable_thinking=false"
        )
        _annotate_stream_exception(
            exc,
            stream_chunk_count=stream_chunk_count,
            completion_choice_chunk_count=(
                streamed["completion_choice_chunk_count"] if stream else 0
            ),
            saw_done_marker=(streamed["saw_done_marker"] if stream else False),
            finish_reason=finish_reason,
            usage=usage,
            reasoning_char_count=reasoning_char_count,
            content_char_count=content_char_count,
            stream_event_summary=stream_event_summary,
        )
        raise _annotate_provider_request_id(exc, provider_request_id)

    try:
        parsed = (
            json.loads(content)
            if response_format == "json_object"
            else extract_json_object(content)
        )
    except json.JSONDecodeError as exc:
        _annotate_stream_exception(
            exc,
            stream_chunk_count=stream_chunk_count,
            completion_choice_chunk_count=(
                streamed["completion_choice_chunk_count"] if stream else 0
            ),
            saw_done_marker=(streamed["saw_done_marker"] if stream else False),
            finish_reason=finish_reason,
            usage=usage,
            reasoning_char_count=reasoning_char_count,
            content_char_count=content_char_count,
            stream_event_summary=stream_event_summary,
        )
        raise _annotate_provider_request_id(exc, provider_request_id)

    payload_error = None
    if not isinstance(parsed, dict):
        payload_error = InvalidGeneratedPayloadError(
            "Generated JSON payload must be an object"
        )
    else:
        for field in ("generated_code", "requirements_text", "notes"):
            if field not in parsed or not isinstance(parsed[field], str):
                payload_error = InvalidGeneratedPayloadError(
                    f"Generated JSON payload requires string field: {field}"
                )
                break
        if payload_error is None and not parsed["generated_code"].strip():
            payload_error = InvalidGeneratedPayloadError(
                "Generated JSON payload contains empty generated_code"
            )
    if payload_error is not None:
        _annotate_stream_exception(
            payload_error,
            stream_chunk_count=stream_chunk_count,
            completion_choice_chunk_count=(
                streamed["completion_choice_chunk_count"] if stream else 0
            ),
            saw_done_marker=(streamed["saw_done_marker"] if stream else False),
            finish_reason=finish_reason,
            usage=usage,
            reasoning_char_count=reasoning_char_count,
            content_char_count=content_char_count,
            stream_event_summary=stream_event_summary,
        )
        raise _annotate_provider_request_id(
            payload_error,
            provider_request_id,
        )

    return {
        "raw_response": content,
        "generated_code": parsed["generated_code"],
        "requirements_text": parsed["requirements_text"],
        "notes": parsed["notes"],
        "api_reported_model": reported_model,
        "reasoning_effort": reasoning_effort,
        "enable_thinking": enable_thinking,
        "response_format": response_format,
        "api_usage": usage,
        "provider_endpoint": url,
        "provider_endpoint_source": endpoint_source,
        "transport_mode": (
            "streaming_sse" if stream else "non_streaming_json"
        ),
        "max_tokens": int(max_tokens) if max_tokens is not None else None,
        "finish_reason": finish_reason,
        "stream_chunk_count": stream_chunk_count,
        "completion_choice_chunk_count": (
            streamed["completion_choice_chunk_count"]
            if stream
            else 0
        ),
        "saw_done_marker": (
            streamed["saw_done_marker"]
            if stream
            else False
        ),
        "reasoning_char_count": reasoning_char_count,
        "content_char_count": content_char_count,
        "stream_event_summary": stream_event_summary,
        "provider_request_id": provider_request_id,
    }


def main() -> None:
    """命令行入口：读取 prompt，生成代码，并保存 JSONL 与 sidecar 文件。"""
    parser = argparse.ArgumentParser()

    # 输入输出参数。
    parser.add_argument("--prompts", default=str(DEFAULT_PROMPTS))
    parser.add_argument("--out", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--limit", type=int, default=2)
    parser.add_argument("--start", type=int, default=1)

    # 模型调用参数。
    parser.add_argument("--real", action="store_true")
    parser.add_argument("--model", default="qwen-plus")
    parser.add_argument(
        "--base-url",
        default=None,
        help=(
            "Explicit OpenAI-compatible provider endpoint. Formal Step9 "
            "must pass the endpoint frozen in the active protocol."
        ),
    )
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--retries", type=int, default=0)
    parser.add_argument("--temperature", type=float, default=0.2)
    parser.add_argument("--stream", action="store_true")
    parser.add_argument("--connect-timeout", type=int, default=None)
    parser.add_argument("--read-timeout", type=int, default=None)
    parser.add_argument("--request-deadline", type=int, default=None)
    parser.add_argument("--max-tokens", type=int, default=None)
    parser.add_argument(
        "--retry-backoff-seconds",
        default="",
        help=(
            "Comma-separated retry delays. When non-empty the number of "
            "values must equal --retries."
        ),
    )
    parser.add_argument(
        "--attempt-ledger",
        default=None,
        help=(
            "Append-only JSONL attempt ledger. Formal recoverable generation "
            "must persist this file together with generated samples."
        ),
    )
    parser.add_argument(
        "--attempt-intent-ledger",
        default=None,
        help=(
            "Append-only durable ATTEMPT_ARMED ledger written and fsynced "
            "before each provider call. A formal crash-recoverable stage "
            "must persist this file so an outcome-less armed attempt can be "
            "classified AMBIGUOUS_IN_FLIGHT instead of silently resampled."
        ),
    )
    parser.add_argument(
        "--accepted-journal-dir",
        default=None,
        help=(
            "Per-sample durable accepted-response journals. A formal stage "
            "uses these journals to recover an accepted provider response "
            "without resampling after a process interruption."
        ),
    )
    parser.add_argument(
        "--resume-round",
        type=int,
        default=0,
        help="Zero-based, protocol-bounded generation invocation round.",
    )
    parser.add_argument(
        "--reasoning-effort",
        choices=["low", "high", "max"],
        default=None,
        help=(
            "Optional OpenAI-compatible reasoning_effort. Formal Step9 "
            "must pass the exact value frozen in the active protocol."
        ),
    )
    parser.add_argument(
        "--thinking-mode",
        choices=["provider_default", "enabled", "disabled"],
        default="provider_default",
        help=(
            "Explicit provider thinking-mode contract. R5-r10 uses "
            "disabled so reasoning cannot consume the final-answer budget."
        ),
    )
    parser.add_argument(
        "--response-format",
        choices=["text", "json_object"],
        default="text",
        help=(
            "Provider output-format contract. json_object enables the "
            "OpenAI-compatible JSON mode supported by Model Studio."
        ),
    )
    parser.add_argument("--resume", action="store_true")
    parser.add_argument(
        "--resume-eligible-sample-id",
        action="append",
        default=None,
        help=(
            "Successor recovery provider-recall allowlist. With --resume, "
            "only these classifier-proven nonfinal sample IDs may reach the "
            "provider. May be repeated."
        ),
    )
    parser.add_argument(
        "--resume-local-only-sample-id",
        action="append",
        default=None,
        help=(
            "Successor recovery local reconstruction allowlist. These sample "
            "IDs must recover from an already durable accepted-response "
            "journal and are forbidden from reaching the provider. May be "
            "repeated."
        ),
    )
    parser.add_argument(
        "--generation-time-override",
        default=None,
        help=(
            "Controlled/mock fixture generation timestamp. Forbidden with "
            "--real so formal generation cannot backdate its completion time."
        ),
    )
    parser.add_argument(
        "--mock-profile",
        choices=[
            "requests_default",
            "f15_prefreeze_aiohttp",
            "r5_r7_syntax_invalid_manifest",
        ],
        default="requests_default",
        help="Deterministic mock fixture profile used only when --real is absent.",
    )

    # sidecar 输出目录：分别保存生成代码和 requirements。
    parser.add_argument("--code-dir", default=str(DEFAULT_CODE_DIR))
    parser.add_argument("--requirements-dir", default=str(DEFAULT_REQ_DIR))
    args = parser.parse_args()

    if not (0.0 <= float(args.temperature) <= 2.0):
        raise ValueError("--temperature must be in [0,2]")
    if args.connect_timeout is not None and args.connect_timeout <= 0:
        raise ValueError("--connect-timeout must be positive")
    if args.read_timeout is not None and args.read_timeout <= 0:
        raise ValueError("--read-timeout must be positive")
    if args.request_deadline is not None and args.request_deadline <= 0:
        raise ValueError("--request-deadline must be positive")
    if args.max_tokens is not None and args.max_tokens <= 0:
        raise ValueError("--max-tokens must be positive")
    if args.resume_eligible_sample_id and not args.resume:
        raise ValueError(
            "--resume-eligible-sample-id is only valid with --resume"
        )
    if args.resume_local_only_sample_id and not args.resume:
        raise ValueError(
            "--resume-local-only-sample-id is only valid with --resume"
        )
    if args.resume_round < 0:
        raise ValueError("--resume-round must be non-negative")
    if args.resume and args.resume_round < 1:
        raise ValueError("--resume requires --resume-round >= 1")
    if not args.resume and args.resume_round != 0:
        raise ValueError("fresh generation requires --resume-round=0")
    retry_backoff_seconds = parse_retry_backoff_seconds(
        args.retry_backoff_seconds
    )
    if retry_backoff_seconds and len(retry_backoff_seconds) != args.retries:
        raise ValueError(
            "--retry-backoff-seconds count must equal --retries"
        )
    if args.real and args.generation_time_override is not None:
        raise ValueError(
            "--generation-time-override is forbidden with --real"
        )
    if args.real and args.mock_profile != "requests_default":
        raise ValueError("--mock-profile is only valid for mock generation")
    if not args.real and args.reasoning_effort is not None:
        raise ValueError("--reasoning-effort is only valid with --real")
    if not args.real and args.thinking_mode != "provider_default":
        raise ValueError("--thinking-mode is only valid with --real")
    if not args.real and args.response_format != "text":
        raise ValueError("--response-format is only valid with --real")
    if args.thinking_mode == "disabled" and args.reasoning_effort is not None:
        raise ValueError(
            "--reasoning-effort must be omitted when --thinking-mode=disabled"
        )
    if (
        args.response_format == "json_object"
        and args.thinking_mode != "disabled"
    ):
        raise ValueError(
            "--response-format=json_object requires --thinking-mode=disabled"
        )
    generation_time_override = normalize_generation_time_override(
        args.generation_time_override
    )

    # 读取 prompt JSONL，并初始化输出路径。
    prompt_rows = read_jsonl(Path(args.prompts))
    if args.start < 1:
        raise ValueError("--start 必须大于等于 1")
    prompt_rows = prompt_rows[args.start - 1:]
    if args.limit > 0:
        prompt_rows = prompt_rows[:args.limit]
    selected_identities = validate_selected_prompt_rows(
        prompt_rows,
        start=args.start,
    )
    identity_by_sample_id = {
        identity["sample_id"]: identity
        for identity in selected_identities
    }

    code_dir = Path(args.code_dir)
    req_dir = Path(args.requirements_dir)
    out_path = Path(args.out)
    attempt_ledger_path = (
        Path(args.attempt_ledger)
        if args.attempt_ledger
        else out_path.parent / "generation_attempts.jsonl"
    )
    attempt_intent_ledger_path = (
        Path(args.attempt_intent_ledger)
        if args.attempt_intent_ledger
        else None
    )
    accepted_journal_dir = (
        Path(args.accepted_journal_dir)
        if args.accepted_journal_dir
        else None
    )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    attempt_ledger_path.parent.mkdir(parents=True, exist_ok=True)
    if attempt_intent_ledger_path is not None:
        attempt_intent_ledger_path.parent.mkdir(parents=True, exist_ok=True)

    resume_eligible_sample_ids = (
        {
            str(value).strip()
            for value in (args.resume_eligible_sample_id or [])
            if str(value).strip()
        }
        if args.resume_eligible_sample_id is not None
        else None
    )
    resume_local_only_sample_ids = (
        {
            str(value).strip()
            for value in (args.resume_local_only_sample_id or [])
            if str(value).strip()
        }
        if args.resume_local_only_sample_id is not None
        else None
    )
    for label, values in (
        ("provider-recall", resume_eligible_sample_ids),
        ("local-only", resume_local_only_sample_ids),
    ):
        if values is not None and not values:
            raise ValueError(f"Resume {label} allowlist must not be empty")
        if values is not None:
            unknown_resume_ids = sorted(
                values - set(identity_by_sample_id)
            )
            if unknown_resume_ids:
                raise ValueError(
                    f"Resume {label} allowlist contains non-selected samples: "
                    + ", ".join(unknown_resume_ids)
                )
    overlap = (
        set(resume_eligible_sample_ids or set())
        & set(resume_local_only_sample_ids or set())
    )
    if overlap:
        raise ValueError(
            "Provider-recall and local-only resume allowlists overlap: "
            + ", ".join(sorted(overlap))
        )
    successor_resume_scope_active = (
        resume_eligible_sample_ids is not None
        or resume_local_only_sample_ids is not None
    )
    resume_work_sample_ids = (
        set(resume_eligible_sample_ids or set())
        | set(resume_local_only_sample_ids or set())
    )

    # resume 模式保留已有输出并跳过已生成样本；非 resume 模式则重新生成输出文件。
    if args.resume:
        if accepted_journal_dir is not None and not accepted_journal_dir.is_dir():
            raise FileNotFoundError(
                "Accepted-response journal directory missing on resume: "
                f"{accepted_journal_dir}"
            )
        if out_path.exists():
            successful_rows, existing_sample_ids = load_resume_rows(
                out_path,
                resume_eligible_sample_ids=resume_eligible_sample_ids,
                resume_local_only_sample_ids=(
                    resume_local_only_sample_ids
                ),
            )
        else:
            successful_rows, existing_sample_ids = [], set()
        validate_resume_sidecars(
            [
                row
                for row in successful_rows
                if not str(row.get("generation_error") or "").strip()
            ],
            code_dir=code_dir,
            req_dir=req_dir,
        )
        resume_rows_to_rewrite = successful_rows
    else:
        resume_rows_to_rewrite = None
        existing_sample_ids = set()
        if out_path.exists():
            out_path.unlink()
        if attempt_ledger_path.exists():
            attempt_ledger_path.unlink()
        if (
            attempt_intent_ledger_path is not None
            and attempt_intent_ledger_path.exists()
        ):
            attempt_intent_ledger_path.unlink()
        if accepted_journal_dir is not None:
            if accepted_journal_dir.exists() and any(
                accepted_journal_dir.iterdir()
            ):
                raise FileExistsError(
                    "Fresh generation refuses a non-empty accepted-response "
                    f"journal directory: {accepted_journal_dir}"
                )
            accepted_journal_dir.mkdir(parents=True, exist_ok=True)

    existing_attempt_intent_rows = (
        read_jsonl(attempt_intent_ledger_path)
        if attempt_intent_ledger_path is not None
        and attempt_intent_ledger_path.exists()
        else []
    )
    intents_by_sample_id: dict[str, list[dict[str, Any]]] = {}
    for intent_row in existing_attempt_intent_rows:
        intent_sample_id = str(intent_row.get("sample_id") or "").strip()
        if intent_sample_id not in identity_by_sample_id:
            raise ValueError(
                "Attempt-intent ledger contains an unknown sample_id: "
                f"{intent_sample_id!r}"
            )
        intents_by_sample_id.setdefault(intent_sample_id, []).append(
            intent_row
        )
    for intent_sample_id, intent_rows in intents_by_sample_id.items():
        observed_indices = [row.get("attempt_index") for row in intent_rows]
        expected_indices = list(range(1, len(intent_rows) + 1))
        if observed_indices != expected_indices:
            raise ValueError(
                "Attempt-intent ledger indices are not contiguous for "
                f"{intent_sample_id}: {observed_indices!r}"
            )

    existing_attempt_rows = (
        read_jsonl(attempt_ledger_path)
        if attempt_ledger_path.exists()
        else []
    )
    attempts_by_sample_id: dict[str, list[dict[str, Any]]] = {}
    for ledger_row in existing_attempt_rows:
        ledger_sample_id = str(
            ledger_row.get("sample_id") or ""
        ).strip()
        if ledger_sample_id not in identity_by_sample_id:
            raise ValueError(
                "Attempt ledger contains an unknown sample_id: "
                f"{ledger_sample_id!r}"
            )
        attempts_by_sample_id.setdefault(ledger_sample_id, []).append(
            ledger_row
        )
    for ledger_sample_id, ledger_rows in attempts_by_sample_id.items():
        observed_indices = [
            row.get("attempt_index") for row in ledger_rows
        ]
        expected_indices = list(range(1, len(ledger_rows) + 1))
        if observed_indices != expected_indices:
            raise ValueError(
                "Attempt ledger indices are not contiguous for "
                f"{ledger_sample_id}: {observed_indices!r}"
            )

    if resume_local_only_sample_ids:
        if accepted_journal_dir is None:
            raise ValueError(
                "Local-only recovery requires accepted journal directory"
            )
        recovery_request_contract = generation_request_contract(
            model=args.model,
            provider_endpoint=args.base_url,
            temperature=args.temperature,
            reasoning_effort=args.reasoning_effort,
            thinking_mode=args.thinking_mode,
            response_format=args.response_format,
            stream=args.stream,
            connect_timeout=args.connect_timeout,
            read_timeout=args.read_timeout,
            request_deadline=args.request_deadline,
            max_tokens=args.max_tokens,
        )
        prevalidate_local_only_recovery(
            sample_ids=resume_local_only_sample_ids,
            identity_by_sample_id=identity_by_sample_id,
            intents_by_sample_id=intents_by_sample_id,
            attempts_by_sample_id=attempts_by_sample_id,
            accepted_journal_dir=accepted_journal_dir,
            request_contract=recovery_request_contract,
        )

    if resume_rows_to_rewrite is not None:
        for success_row in resume_rows_to_rewrite:
            resumed_sample_id = str(
                success_row.get("sample_id") or ""
            ).strip()
            identity = identity_by_sample_id.get(resumed_sample_id)
            if identity is None:
                raise ValueError(
                    "Resume output contains a successful sample outside the "
                    f"current prompt selection: {resumed_sample_id}"
                )
            if success_row.get("generation_prompt_sha256") not in {
                None,
                identity["prompt_sha256"],
            }:
                raise ValueError(
                    "Resume output prompt hash mismatch for "
                    f"{resumed_sample_id}"
                )
        # Only now mutate the resume JSONL. All readable identity, sidecar,
        # journal-directory, and ledger-contiguity checks have passed.
        write_jsonl(out_path, resume_rows_to_rewrite)

    output_rows = []
    total = len(prompt_rows)
    skipped_count = 0

    for i, row in enumerate(prompt_rows, start=1):
        identity = selected_identities[i - 1]
        source_sample_id = identity["source_sample_id"]
        sample_id = identity["sample_id"]
        prompt_sha256 = identity["prompt_sha256"]

        # Explicit successor recovery scope is stronger than row presence.
        # A terminal sample may legitimately have no generated row, while a
        # journal-backed accepted sample may require local rematerialization.
        if (
            successor_resume_scope_active
            and sample_id not in resume_work_sample_ids
        ):
            skipped_count += 1
            print(f"[{i}/{total}] skip non-work {sample_id}")
            continue

        local_only_sample = (
            resume_local_only_sample_ids is not None
            and sample_id in resume_local_only_sample_ids
        )

        # resume 模式下，如果该 sample 已经在输出文件中，就跳过，避免重复生成。
        if sample_id in existing_sample_ids:
            skipped_count += 1
            print(f"[{i}/{total}] skip existing {sample_id}")
            continue

        print(
            f"[{i}/{total}] generating {sample_id} "
            f"with model={args.model} ..."
        )
        prompt_value = row.get("prompt")
        if prompt_value is None:
            prompt_value = row.get("prompt_text")
        prompt = str(prompt_value)

        request_contract = generation_request_contract(
            model=args.model,
            provider_endpoint=args.base_url,
            temperature=args.temperature,
            reasoning_effort=args.reasoning_effort,
            thinking_mode=args.thinking_mode,
            response_format=args.response_format,
            stream=args.stream,
            connect_timeout=args.connect_timeout,
            read_timeout=args.read_timeout,
            request_deadline=args.request_deadline,
            max_tokens=args.max_tokens,
        )
        request_contract_sha256 = canonical_json_sha256(request_contract)
        journal_binding = {
            "sample_id": sample_id,
            "source_sample_id": source_sample_id,
            "prompt_sha256": prompt_sha256,
            "request_contract_sha256": request_contract_sha256,
        }
        sample_attempt_rows = attempts_by_sample_id.setdefault(
            sample_id,
            [],
        )
        sample_intent_rows = intents_by_sample_id.setdefault(
            sample_id,
            [],
        )
        attempt_index_offset = len(sample_attempt_rows)
        generation_resumed_from_accepted_journal = False

        generation_request_started_at = None
        generation_response_completed_at = None
        generation_observed_request_seconds = None

        try:
            if args.real:
                def enrich_attempt(
                    record: dict[str, Any],
                ) -> dict[str, Any]:
                    return {
                        "sample_id": sample_id,
                        "source_sample_id": source_sample_id,
                        "prompt_id": row.get("prompt_id"),
                        "prompt_sha256": prompt_sha256,
                        "request_contract": request_contract,
                        "request_contract_sha256": request_contract_sha256,
                        "model": args.model,
                        "transport_mode": (
                            "streaming_sse"
                            if args.stream
                            else "non_streaming_json"
                        ),
                        "provider_endpoint": args.base_url,
                        "temperature": float(args.temperature),
                        "reasoning_effort": args.reasoning_effort,
                        "thinking_mode": args.thinking_mode,
                        "response_format": args.response_format,
                        "connect_timeout_seconds": args.connect_timeout,
                        "stream_read_timeout_seconds": args.read_timeout,
                        "request_deadline_seconds": args.request_deadline,
                        "max_tokens": args.max_tokens,
                        "resume_invocation": bool(args.resume),
                        "resume_round": int(args.resume_round),
                        **record,
                    }

                def enrich_intent(
                    record: dict[str, Any],
                ) -> dict[str, Any]:
                    return {
                        "sample_id": sample_id,
                        "source_sample_id": source_sample_id,
                        "prompt_id": row.get("prompt_id"),
                        "prompt_sha256": prompt_sha256,
                        "request_contract_sha256": request_contract_sha256,
                        "model": args.model,
                        "transport_mode": (
                            "streaming_sse"
                            if args.stream
                            else "non_streaming_json"
                        ),
                        "provider_endpoint": args.base_url,
                        "resume_invocation": bool(args.resume),
                        "resume_round": int(args.resume_round),
                        **record,
                    }

                def record_attempt_intent(record: dict[str, Any]) -> None:
                    if attempt_intent_ledger_path is None:
                        return
                    enriched = enrich_intent(record)
                    append_jsonl_row(attempt_intent_ledger_path, enriched)
                    sample_intent_rows.append(enriched)

                def record_attempt(record: dict[str, Any]) -> None:
                    enriched = enrich_attempt(record)
                    append_jsonl_row(attempt_ledger_path, enriched)
                    sample_attempt_rows.append(enriched)

                journal_path = (
                    accepted_response_journal_path(
                        accepted_journal_dir,
                        sample_id,
                    )
                    if accepted_journal_dir is not None
                    else None
                )

                if local_only_sample and (
                    journal_path is None or not journal_path.exists()
                ):
                    raise RuntimeError(
                        "LOCAL_ONLY_RECOVERY_JOURNAL_MISSING: "
                        f"{sample_id}"
                    )

                def persist_accepted(
                    generated: dict[str, Any],
                    record: dict[str, Any],
                ) -> None:
                    if journal_path is None:
                        return
                    persist_accepted_response_journal(
                        journal_path,
                        binding=journal_binding,
                        generated=generated,
                        attempt=enrich_attempt(record),
                    )

                if attempt_intent_ledger_path is not None:
                    outcome_indices = {
                        attempt.get("attempt_index")
                        for attempt in sample_attempt_rows
                    }
                    unresolved_intents = [
                        intent
                        for intent in sample_intent_rows
                        if intent.get("attempt_index") not in outcome_indices
                    ]
                    if (
                        unresolved_intents
                        and not (
                            journal_path is not None
                            and journal_path.exists()
                        )
                    ):
                        unresolved_indices = [
                            intent.get("attempt_index")
                            for intent in unresolved_intents
                        ]
                        raise AmbiguousInFlightError(
                            "AMBIGUOUS_IN_FLIGHT: durable ATTEMPT_ARMED "
                            "exists without a durable accepted/failure outcome "
                            f"for {sample_id}; provider recall forbidden; "
                            f"attempt_indices={unresolved_indices!r}"
                        )

                if journal_path is not None and journal_path.exists():
                    if not args.resume:
                        raise ValueError(
                            "Fresh generation encountered an unexpected "
                            f"accepted-response journal: {journal_path}"
                        )
                    gen, recovered_attempt = load_accepted_response_journal(
                        journal_path,
                        expected_binding=journal_binding,
                    )
                    recovered_index = recovered_attempt.get("attempt_index")
                    if attempt_intent_ledger_path is not None:
                        matching_intents = [
                            intent
                            for intent in sample_intent_rows
                            if intent.get("attempt_index") == recovered_index
                        ]
                        if len(matching_intents) != 1:
                            raise ValueError(
                                "Accepted-response journal does not have "
                                "exactly one matching durable ATTEMPT_ARMED "
                                f"intent for {sample_id}"
                            )
                        recovered_intent = matching_intents[0]
                        if (
                            recovered_intent.get("prompt_sha256")
                            != prompt_sha256
                            or recovered_intent.get(
                                "request_contract_sha256"
                            )
                            != request_contract_sha256
                            or recovered_intent.get("resume_round")
                            != recovered_attempt.get("resume_round")
                            or recovered_intent.get(
                                "invocation_attempt_index"
                            )
                            != recovered_attempt.get(
                                "invocation_attempt_index"
                            )
                        ):
                            raise ValueError(
                                "Accepted-response journal/ATTEMPT_ARMED "
                                f"binding mismatch for {sample_id}"
                            )
                    matching = [
                        attempt
                        for attempt in sample_attempt_rows
                        if attempt.get("attempt_index") == recovered_index
                    ]
                    if matching:
                        if len(matching) != 1 or matching[0] != recovered_attempt:
                            raise ValueError(
                                "Accepted-response journal/ledger mismatch for "
                                f"{sample_id}"
                            )
                    else:
                        if recovered_index != len(sample_attempt_rows) + 1:
                            raise ValueError(
                                "Accepted-response journal attempt index is not "
                                f"the next durable attempt for {sample_id}"
                            )
                        append_jsonl_row(attempt_ledger_path, recovered_attempt)
                        sample_attempt_rows.append(recovered_attempt)
                    generation_attempts = [recovered_attempt]
                    generation_request_started_at = recovered_attempt.get(
                        "request_started_at"
                    )
                    generation_response_completed_at = recovered_attempt.get(
                        "response_completed_at"
                    )
                    generation_observed_request_seconds = recovered_attempt.get(
                        "observed_seconds"
                    )
                    generation_resumed_from_accepted_journal = True
                else:
                    if any(
                        attempt.get("accepted_response") is True
                        for attempt in sample_attempt_rows
                    ):
                        raise ValueError(
                            "Attempt ledger contains an accepted response but "
                            "the output row/journal recovery source is missing: "
                            f"{sample_id}"
                        )
                    gen, generation_attempts, (
                        generation_request_started_at
                    ), generation_response_completed_at, (
                        generation_observed_request_seconds
                    ) = run_real_generation_attempts(
                        call_qwen,
                        retries=args.retries,
                        retry_backoff_seconds=retry_backoff_seconds,
                        call_kwargs={
                            "prompt": prompt,
                            "model": args.model,
                            "timeout": args.timeout,
                            "temperature": args.temperature,
                            "base_url": args.base_url,
                            "reasoning_effort": args.reasoning_effort,
                            "enable_thinking": (
                                None
                                if args.thinking_mode == "provider_default"
                                else args.thinking_mode == "enabled"
                            ),
                            "response_format": args.response_format,
                            "stream": args.stream,
                            "connect_timeout": args.connect_timeout,
                            "read_timeout": args.read_timeout,
                            "request_deadline": args.request_deadline,
                            "max_tokens": args.max_tokens,
                        },
                        on_attempt=record_attempt,
                        on_accepted_response=persist_accepted,
                        on_attempt_armed=record_attempt_intent,
                        attempt_index_offset=attempt_index_offset,
                    )

                raw_response = gen["raw_response"]
                generated_code = gen["generated_code"]
                requirements_text = gen["requirements_text"]
                notes = gen["notes"]
                model_name = args.model
                api_reported_model = gen.get("api_reported_model", args.model)
                api_usage = gen.get("api_usage", {})
                generation_reasoning_effort = gen.get("reasoning_effort")
                generation_enable_thinking = gen.get("enable_thinking")
                generation_response_format = gen.get("response_format")
                generation_provider_endpoint = gen.get("provider_endpoint")
                generation_provider_endpoint_source = gen.get(
                    "provider_endpoint_source"
                )
                generation_transport_mode = gen.get("transport_mode")
                generation_max_tokens = gen.get("max_tokens")
                generation_finish_reason = gen.get("finish_reason")
                generation_stream_chunk_count = int(
                    gen.get("stream_chunk_count", 0) or 0
                )
                generation_reasoning_char_count = int(
                    gen.get("reasoning_char_count", 0) or 0
                )
                generation_content_char_count = int(
                    gen.get("content_char_count", 0) or 0
                )
                generation_completion_choice_chunk_count = int(
                    gen.get("completion_choice_chunk_count", 0) or 0
                )
                generation_saw_done_marker = bool(
                    gen.get("saw_done_marker", False)
                )
                generation_stream_event_summary = (
                    gen.get("stream_event_summary", {})
                    if isinstance(gen.get("stream_event_summary"), dict)
                    else {}
                )
                generation_provider_request_id = str(
                    gen.get("provider_request_id", "") or ""
                )
                generation_provider_error_summary = {}
                generation_attempt_count = len(sample_attempt_rows)
                generation_retry_count = max(
                    0, generation_attempt_count - 1
                )
                generation_recovered_after_retry = (
                    generation_retry_count > 0
                )
                generation_failure_recovery_class = ""
            else:
                # mock 模式：显式 profile 生成确定性受控样本。
                generated_code, requirements_text = build_mock_fixture(
                    prompt,
                    args.mock_profile,
                )
                raw_response = generated_code
                notes = (
                    "mock generated sample for pipeline test; "
                    f"profile={args.mock_profile}"
                )
                model_name = "mock_generation_v0"
                api_reported_model = "mock_generation_v0"
                api_usage = {}
                generation_reasoning_effort = None
                generation_enable_thinking = None
                generation_response_format = "mock"
                generation_provider_endpoint = None
                generation_provider_endpoint_source = "mock"
                generation_transport_mode = "mock"
                generation_max_tokens = None
                generation_finish_reason = None
                generation_stream_chunk_count = 0
                generation_reasoning_char_count = 0
                generation_content_char_count = len(generated_code)
                generation_completion_choice_chunk_count = 0
                generation_saw_done_marker = False
                generation_stream_event_summary = {}
                generation_provider_request_id = ""
                generation_provider_error_summary = {}
                generation_attempt_count = 1
                generation_retry_count = 0
                generation_recovered_after_retry = False
                generation_failure_recovery_class = ""

            generation_error = ""
        except Exception as e:
            if local_only_sample:
                # A journal-backed accepted provider result is already
                # committed. Any reconstruction defect is a hard evidence
                # failure and must never fall through to provider recall or
                # be rewritten as a model-generation terminal outcome.
                raise
            # 单条样本失败时不终止整个批次，而是把失败原因写入 JSONL。
            exhausted = (
                e if isinstance(e, GenerationAttemptsExhausted) else None
            )
            raw_response = ""
            generated_code = ""
            requirements_text = ""
            notes = ""
            model_name = args.model if args.real else "mock_generation_v0"
            api_reported_model = ""
            original = (
                exhausted.original if exhausted is not None else e
            )
            api_usage = (
                getattr(original, "codesentry_api_usage", {})
                if isinstance(
                    getattr(original, "codesentry_api_usage", {}),
                    dict,
                )
                else {}
            )
            generation_reasoning_effort = (
                args.reasoning_effort if args.real else None
            )
            generation_enable_thinking = (
                None
                if not args.real or args.thinking_mode == "provider_default"
                else args.thinking_mode == "enabled"
            )
            generation_response_format = (
                args.response_format if args.real else "mock"
            )
            generation_provider_endpoint = (
                str(args.base_url).strip()
                if args.real and args.base_url is not None
                else None
            )
            generation_provider_endpoint_source = (
                "explicit_argument" if generation_provider_endpoint else None
            )
            generation_transport_mode = (
                "streaming_sse" if args.stream else "non_streaming_json"
            )
            generation_max_tokens = args.max_tokens
            generation_finish_reason = getattr(
                original,
                "codesentry_finish_reason",
                None,
            )
            generation_stream_chunk_count = int(
                getattr(
                    original,
                    "codesentry_partial_stream_chunk_count",
                    0,
                )
                or 0
            )
            generation_reasoning_char_count = int(
                getattr(
                    original,
                    "codesentry_reasoning_char_count",
                    0,
                )
                or 0
            )
            generation_content_char_count = int(
                getattr(
                    original,
                    "codesentry_content_char_count",
                    0,
                )
                or 0
            )
            generation_completion_choice_chunk_count = int(
                getattr(
                    original,
                    "codesentry_completion_choice_chunk_count",
                    0,
                )
                or 0
            )
            generation_saw_done_marker = bool(
                getattr(
                    original,
                    "codesentry_saw_done_marker",
                    False,
                )
            )
            generation_stream_event_summary = (
                getattr(
                    original,
                    "codesentry_stream_event_summary",
                    {},
                )
                if isinstance(
                    getattr(
                        original,
                        "codesentry_stream_event_summary",
                        {},
                    ),
                    dict,
                )
                else {}
            )
            generation_provider_request_id = str(
                getattr(
                    original,
                    "codesentry_provider_request_id",
                    "",
                )
                or ""
            )
            generation_provider_error_summary = (
                getattr(
                    original,
                    "codesentry_provider_error_summary",
                    {},
                )
                if isinstance(
                    getattr(
                        original,
                        "codesentry_provider_error_summary",
                        {},
                    ),
                    dict,
                )
                else {}
            )
            generation_attempt_count = max(
                len(sample_attempt_rows),
                len(exhausted.attempts) if exhausted is not None else 1,
            )
            if exhausted is not None and exhausted.attempts:
                last_attempt = exhausted.attempts[-1]
                generation_request_started_at = last_attempt.get(
                    "request_started_at"
                )
                generation_response_completed_at = last_attempt.get(
                    "response_completed_at"
                )
                generation_observed_request_seconds = last_attempt.get(
                    "observed_seconds"
                )
            generation_retry_count = max(
                0, generation_attempt_count - 1
            )
            generation_recovered_after_retry = False
            generation_failure_recovery_class = (
                "transport_pending"
                if exhausted is not None
                and exhausted.retryable_failure
                else "terminal_failure"
            )
            generation_error = (
                f"{type(original).__name__}: {original}"
            )
            print(f"[ERROR] failed {sample_id}: {generation_error}")

        # 只有生成成功时才写 sidecar 文件，避免失败样本用空内容覆盖旧文件。
        if not generation_error:
            write_text(code_dir / f"{sample_id}.py", generated_code)
            # requirements 为空时也写空文件，用来覆盖可能残留的旧 requirements。
            write_text(req_dir / f"{sample_id}_requirements.txt", requirements_text)

        # Preserve any source-provided project context verbatim. The generator
        # must not invent repository files, but downstream project snapshots
        # must retain real context when the source dataset provides it.
        source_project_files = row.get("project_files")
        if not isinstance(source_project_files, (dict, list)):
            source_project_files = {}
        source_repo_context = row.get("repo_context")
        source_project_context_status = str(
            row.get("project_context_status") or ""
        ).strip()
        project_context_status = (
            source_project_context_status
            if source_project_context_status
            else (
                "supplied_project_files"
                if bool(source_project_files)
                else (
                    "repo_context_metadata_only"
                    if source_repo_context
                    else "not_provided_by_source"
                )
            )
        )

        # 保存统一 JSONL 记录，供后续 run_pilot.py 读取。
        output_row = {
            "sample_id": sample_id,
            "source_sample_id": source_sample_id,
            "source_original_sample_id": row.get("sample_id"),
            "pilot_id": row.get("pilot_id"),
            "source_dataset": row.get("source_dataset"),
            "prompt_id": row.get("prompt_id"),
            "source": row.get("source"),
            "language": row.get("language", "python"),
            "ecosystem": row.get("ecosystem", "pypi"),
            "prompt": prompt,
            "generation_time": (
                generation_time_override
                if generation_time_override is not None
                else (
                    generation_response_completed_at
                    if generation_response_completed_at is not None
                    else now_iso()
                )
            ),
            "generation_time_source": (
                "controlled_mock_fixture_override"
                if generation_time_override is not None
                else "runtime_completion_clock"
            ),
            "generation_request_started_at": (
                generation_request_started_at
                if args.real
                else None
            ),
            "generation_response_completed_at": (
                generation_response_completed_at
                if args.real
                else None
            ),
            "generation_observed_request_seconds": (
                generation_observed_request_seconds
                if args.real
                else None
            ),
            "mock_profile": (
                args.mock_profile if not args.real else None
            ),
            "model": model_name,
            "generation_temperature": (
                float(args.temperature) if args.real else None
            ),
            "generation_reasoning_effort": (
                generation_reasoning_effort
            ),
            "generation_enable_thinking": generation_enable_thinking,
            "generation_response_format": generation_response_format,
            "api_reported_model": api_reported_model,
            "api_usage": api_usage,
            "generation_provider_endpoint": generation_provider_endpoint,
            "generation_provider_endpoint_source": (
                generation_provider_endpoint_source
            ),
            "generation_transport_mode": generation_transport_mode,
            "generation_max_tokens": generation_max_tokens,
            "generation_finish_reason": generation_finish_reason,
            "generation_stream_chunk_count": (
                generation_stream_chunk_count
            ),
            "generation_reasoning_char_count": (
                generation_reasoning_char_count
            ),
            "generation_content_char_count": (
                generation_content_char_count
            ),
            "generation_completion_choice_chunk_count": (
                generation_completion_choice_chunk_count
            ),
            "generation_saw_done_marker": generation_saw_done_marker,
            "generation_stream_event_summary": (
                generation_stream_event_summary
            ),
            "generation_provider_request_id": (
                generation_provider_request_id
            ),
            "generation_provider_error_summary": (
                generation_provider_error_summary
            ),
            "generation_prompt_sha256": prompt_sha256,
            "generation_request_contract": request_contract,
            "generation_request_contract_sha256": (
                request_contract_sha256
            ),
            "generation_attempt_count": generation_attempt_count,
            "generation_retry_count": generation_retry_count,
            "generation_recovered_after_retry": (
                generation_recovered_after_retry
            ),
            "generation_failure_recovery_class": (
                generation_failure_recovery_class
            ),
            "generation_resumed_from_checkpoint": bool(args.resume),
            "generation_resumed_from_accepted_journal": (
                generation_resumed_from_accepted_journal
            ),
            "raw_response": raw_response,
            "generated_code": generated_code,
            "requirements_text": requirements_text,
            "project_files": source_project_files,
            "repo_context": source_repo_context,
            "project_context_status": project_context_status,
            "notes": notes,
            "generation_error": generation_error,
        }

        output_rows.append(output_row)
        # 每条样本生成后立即写入，防止中途异常导致整批结果丢失。
        append_jsonl_row(out_path, output_row)
        existing_sample_ids.add(sample_id)

        if generation_error:
            print(f"[FAILED] recorded {sample_id}")
        else:
            print(f"[OK] saved {sample_id}")

    # Rows are appended incrementally for crash durability. A resume can place
    # recovered samples after preserved successes, so compact atomically into
    # the original frozen prompt order only after the invocation is complete.
    final_rows = read_jsonl(out_path)
    final_by_id: dict[str, dict[str, Any]] = {}
    for final_row in final_rows:
        final_sample_id = str(final_row.get("sample_id") or "").strip()
        if final_sample_id in final_by_id:
            raise ValueError(
                f"Generated output contains duplicate sample_id: {final_sample_id}"
            )
        final_by_id[final_sample_id] = final_row
    expected_final_ids = [
        identity["sample_id"] for identity in selected_identities
    ]
    expected_final_set = set(expected_final_ids)
    if not set(final_by_id).issubset(expected_final_set):
        raise ValueError(
            "Generated output contains sample outside selected prompts"
        )
    if not successor_resume_scope_active:
        if set(final_by_id) != expected_final_set:
            raise ValueError(
                "Generated output identity set does not match selected prompts"
            )
    else:
        missing_work = sorted(
            resume_work_sample_ids - set(final_by_id)
        )
        if missing_work:
            raise ValueError(
                "Selective recovery did not durably materialize work samples: "
                + ", ".join(missing_work)
            )
    write_jsonl(
        out_path,
        [
            final_by_id[sample_id]
            for sample_id in expected_final_ids
            if sample_id in final_by_id
        ],
    )

    print(f"[OK] prompt rows used: {len(prompt_rows)}")
    if args.resume:
        print(f"[OK] skipped existing samples: {skipped_count}")
    print(f"[OK] generated samples saved to: {args.out}")


if __name__ == "__main__":
    main()
