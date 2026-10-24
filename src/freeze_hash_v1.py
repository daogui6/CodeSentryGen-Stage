from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


HASH_SCHEMA_VERSION = "codesentry_gen_canonical_hash_v1"
ALGORITHM = "sha256"

JSON_SUFFIXES = {".json"}
JSONL_SUFFIXES = {".jsonl", ".ndjson"}
TEXT_SUFFIXES = {
    ".py",
    ".md",
    ".txt",
    ".csv",
    ".tsv",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".cfg",
    ".sh",
    ".ps1",
    ".java",
    ".js",
    ".ts",
    ".html",
    ".css",
    ".xml",
    ".lock",
}


def normalize_sha256_digest(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text.startswith("sha256:"):
        text = text.split(":", 1)[1].strip()
    if len(text) != 64 or any(
        char not in "0123456789abcdef"
        for char in text
    ):
        raise ValueError(f"Invalid SHA-256 digest: {value!r}")
    return text


def raw_sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def raw_sha256_file(path: Path) -> str:
    return raw_sha256_bytes(path.read_bytes())


def canonical_text_bytes(data: bytes) -> bytes:
    text = data.decode("utf-8-sig")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text.encode("utf-8")


def canonical_json_bytes(data: bytes) -> bytes:
    value = json.loads(data.decode("utf-8-sig"))
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_jsonl_bytes(data: bytes) -> bytes:
    text = data.decode("utf-8-sig")
    rows: list[bytes] = []
    for line_no, raw in enumerate(
        text.replace("\r\n", "\n").replace("\r", "\n").split("\n"),
        start=1,
    ):
        stripped = raw.strip()
        if not stripped:
            continue
        try:
            value = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Invalid JSONL at canonicalization line {line_no}"
            ) from exc
        rows.append(
            json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        )
    return b"\n".join(rows) + (b"\n" if rows else b"")


def infer_hash_mode(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in JSON_SUFFIXES:
        return "canonical_json_v1"
    if suffix in JSONL_SUFFIXES:
        return "canonical_jsonl_v1"
    if suffix in TEXT_SUFFIXES or path.name in {
        "Dockerfile",
        "Makefile",
        "requirements.txt",
    }:
        return "canonical_text_lf_v1"
    return "raw_bytes_v1"


def canonical_bytes(
    path: Path,
    *,
    mode: str | None = None,
) -> bytes:
    selected = mode or infer_hash_mode(path)
    data = path.read_bytes()

    if selected == "canonical_json_v1":
        return canonical_json_bytes(data)
    if selected == "canonical_jsonl_v1":
        return canonical_jsonl_bytes(data)
    if selected == "canonical_text_lf_v1":
        return canonical_text_bytes(data)
    if selected == "raw_bytes_v1":
        return data

    raise ValueError(f"Unsupported canonical hash mode: {selected}")


def canonical_sha256_file(
    path: Path,
    *,
    mode: str | None = None,
) -> str:
    return raw_sha256_bytes(canonical_bytes(path, mode=mode))


def hash_record(
    path: Path,
    *,
    mode: str | None = None,
) -> dict[str, Any]:
    selected = mode or infer_hash_mode(path)
    data = path.read_bytes()
    canonical = canonical_bytes(path, mode=selected)
    return {
        "schema_version": HASH_SCHEMA_VERSION,
        "algorithm": ALGORITHM,
        "mode": selected,
        "sha256": raw_sha256_bytes(canonical),
        "raw_sha256": raw_sha256_bytes(data),
        "size_bytes": len(data),
        "canonical_size_bytes": len(canonical),
    }


def legacy_text_hash_variants(path: Path) -> set[str]:
    data = path.read_bytes()
    variants = {raw_sha256_bytes(data)}

    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return variants

    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    variants.add(raw_sha256_bytes(normalized.encode("utf-8")))
    variants.add(
        raw_sha256_bytes(
            normalized.replace("\n", "\r\n").encode("utf-8")
        )
    )
    return variants


def hash_matches(
    path: Path,
    expected: str | dict[str, Any],
    *,
    legacy_eol_compatible: bool = False,
) -> bool:
    if isinstance(expected, dict):
        digest_raw = expected.get("sha256", "")
        mode = str(expected.get("mode", "") or "").strip()
        if not digest_raw or not mode:
            return False
        try:
            digest = normalize_sha256_digest(digest_raw)
        except ValueError:
            return False
        return canonical_sha256_file(path, mode=mode) == digest

    if not str(expected or "").strip():
        return False
    try:
        digest = normalize_sha256_digest(expected)
    except ValueError:
        return False

    if raw_sha256_file(path) == digest:
        return True

    if (
        legacy_eol_compatible
        and digest in legacy_text_hash_variants(path)
    ):
        return True

    return canonical_sha256_file(path) == digest


def verify_hash(
    path: Path,
    expected: str | dict[str, Any],
    *,
    label: str,
    legacy_eol_compatible: bool = False,
) -> None:
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"{label} missing: {path}")

    if hash_matches(
        path,
        expected,
        legacy_eol_compatible=legacy_eol_compatible,
    ):
        return

    if isinstance(expected, dict):
        expected_text = (
            f"{expected.get('sha256')} mode={expected.get('mode')}"
        )
    else:
        expected_text = str(expected)

    actual = hash_record(path)
    raise ValueError(
        f"{label} hash drift: expected={expected_text} "
        f"canonical={actual['sha256']} raw={actual['raw_sha256']} "
        f"mode={actual['mode']}"
    )


def canonical_manifest_sha256(
    entries: dict[str, dict[str, Any]],
) -> str:
    normalized = {
        str(path).replace("\\", "/"): {
            "mode": row.get("mode"),
            "sha256": row.get("sha256"),
        }
        for path, row in sorted(entries.items())
    }
    payload = json.dumps(
        normalized,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return raw_sha256_bytes(payload)
