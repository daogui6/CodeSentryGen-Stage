from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import tarfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from packaging.version import (
    InvalidVersion,
    Version,
)


SCHEMA_VERSION = (
    "pyyaml_api_history_raw_evidence_v0.5"
)

PYPI_PROJECT_JSON_URL = (
    "https://pypi.org/pypi/PyYAML/json"
)

GITHUB_RAW_BASE_URL = (
    "https://raw.githubusercontent.com/"
    "yaml/pyyaml"
)

USER_AGENT = (
    "CodeSentryGen-Pilot/"
    "api-history-evidence-v0.1"
)


def fetch_bytes(
    url: str,
    timeout: int = 30,
    max_attempts: int = 3,
) -> bytes:
    """
    从真实上游地址获取原始字节。

    当前主要用于：
    1. PyPI project JSON
    2. PyPI source distribution

    对偶发网络、SSL、连接中断等传输错误
    进行有限次数重试。

    三次都失败后仍抛出真实异常，
    由上层记录为 download_error，
    不会把缺失证据伪装成成功。
    """
    if max_attempts < 1:
        raise ValueError(
            "max_attempts must be >= 1"
        )

    last_error: Exception | None = None

    for attempt in range(
        1,
        max_attempts + 1,
    ):
        request = urllib.request.Request(
            url,
            headers={
                "User-Agent":
                    USER_AGENT,
            },
        )

        try:
            with urllib.request.urlopen(
                request,
                timeout=timeout,
            ) as response:
                return response.read()

        except urllib.error.HTTPError as exc:
            # 永久性 4xx 一般重试没有意义。
            #
            # 408 / 429 属于可能恢复的情况；
            # 5xx 属于上游临时服务器错误，
            # 因此允许有限重试。
            retryable_http_codes = {
                408,
                429,
                500,
                502,
                503,
                504,
            }

            if (
                exc.code
                not in retryable_http_codes
            ):
                raise

            last_error = exc

        except (
            urllib.error.URLError,
            TimeoutError,
            ConnectionError,
            OSError,
        ) as exc:
            last_error = exc

        if attempt >= max_attempts:
            break

        delay_seconds = float(
            attempt
        )

        print(
            "[WARN] transient download "
            f"failure: attempt "
            f"{attempt}/{max_attempts} | "
            f"retry in "
            f"{delay_seconds:.0f}s | "
            f"{last_error}"
        )

        time.sleep(
            delay_seconds
        )

    if last_error is not None:
        raise last_error

    raise RuntimeError(
        "download failed without "
        "captured exception"
    )

def sha256_bytes(
    content: bytes,
) -> str:
    return hashlib.sha256(
        content
    ).hexdigest()


def normalize_signature_text(
    value: str,
) -> str:
    """
    把多行函数参数整理成便于保存和比较的单行形式。
    """
    return " ".join(
        value.split()
    )


def find_function_signature(
    source_text: str,
    function_name: str,
) -> str | None:
    """
    从源码文本中提取顶层函数签名。

    不直接使用 ast.parse，
    因为我们分析的是非常老的历史 Python 源码，
    不希望被当前 Python 版本的语法兼容性影响。
    """
    pattern = re.compile(
        rf"^def\s+"
        rf"{re.escape(function_name)}"
        rf"\s*\((.*?)\)\s*:",
        flags=(
            re.MULTILINE
            | re.DOTALL
        ),
    )

    match = pattern.search(
        source_text
    )

    if match is None:
        return None

    arguments = normalize_signature_text(
        match.group(1)
    )

    return (
        f"{function_name}"
        f"({arguments})"
    )

def inspect_named_parameter(
    signature: str | None,
    parameter_name: str,
) -> dict[str, Any]:
    """
    从已经提取出的函数签名中检查一个参数。

    当前主要用于分析 PyYAML:

        load(stream, Loader=Loader)
        load(stream, Loader=None)
        load(stream, Loader)

    我们关心：

    1. 参数是否存在
    2. 是否有默认值
    3. 是否属于必填参数
    4. 是否允许作为位置参数传入

    当前 PyYAML 历史签名没有复杂的
    positional-only '/' 场景，因此这里保持
    一个面向当前案例的保守实现。
    """
    if not signature:
        return {
            "present": False,
            "has_default": None,
            "default_text": None,
            "required": None,
            "supports_positional": None,
        }

    left = signature.find("(")
    right = signature.rfind(")")

    if (
        left < 0
        or right <= left
    ):
        return {
            "present": False,
            "has_default": None,
            "default_text": None,
            "required": None,
            "supports_positional": None,
        }

    parameters_text = signature[
        left + 1:right
    ]

    pattern = re.compile(
        rf"(?:^|,\s*)"
        rf"{re.escape(parameter_name)}"
        rf"\s*"
        rf"(?:=\s*([^,]+))?"
        rf"(?=,|$)"
    )

    match = pattern.search(
        parameters_text
    )

    if match is None:
        return {
            "present": False,
            "has_default": None,
            "default_text": None,
            "required": None,
            "supports_positional": None,
        }

    default_text = (
        match.group(1).strip()
        if match.group(1)
        else None
    )

    has_default = (
        default_text is not None
    )

    prefix = parameters_text[
        :match.start()
    ]

    # 若参数前已经出现裸 *，
    # 则它属于 keyword-only。
    #
    # 当前 PyYAML 的 Loader 历史签名
    # 实际都属于普通 positional-or-keyword。
    supports_positional = (
        "*" not in prefix
    )

    return {
        "present": True,
        "has_default": has_default,
        "default_text": default_text,
        "required": not has_default,
        "supports_positional":
            supports_positional,
    }

def find_class_init_signature(
    source_text: str,
    class_name: str,
) -> str | None:
    """
    从源码中提取指定 class 的 __init__ 签名。

    当前主要用于继续跟踪：
        dump_all(..., **kwds)
            ↓
        PythonDumper(...)
    """
    class_pattern = re.compile(
        rf"^class\s+"
        rf"{re.escape(class_name)}"
        rf"\b.*?:",
        flags=re.MULTILINE,
    )

    class_match = class_pattern.search(
        source_text
    )

    if class_match is None:
        return None

    next_class_pattern = re.compile(
        r"^class\s+"
        r"[A-Za-z_]"
        r"[A-Za-z0-9_]*"
        r"\b.*?:",
        flags=re.MULTILINE,
    )

    next_class_match = (
        next_class_pattern.search(
            source_text,
            class_match.end(),
        )
    )

    if next_class_match is None:
        class_block = source_text[
            class_match.start():
        ]
    else:
        class_block = source_text[
            class_match.start():
            next_class_match.start()
        ]

    init_pattern = re.compile(
        r"^\s+def\s+__init__"
        r"\s*\((.*?)\)\s*:",
        flags=(
            re.MULTILINE
            | re.DOTALL
        ),
    )

    init_match = init_pattern.search(
        class_block
    )

    if init_match is None:
        return None

    arguments = normalize_signature_text(
        init_match.group(1)
    )

    return (
        f"{class_name}.__init__"
        f"({arguments})"
    )

def find_function_block(
    source_text: str,
    function_name: str,
) -> str:
    """
    获取某个顶层函数从 def 开始到下一个顶层 def 之前的源码。

    主要用于判断 safe_dump 是否把 **kwds
    继续传给 dump_all。
    """
    start_pattern = re.compile(
        rf"^def\s+"
        rf"{re.escape(function_name)}"
        rf"\s*\(",
        flags=re.MULTILINE,
    )

    start_match = start_pattern.search(
        source_text
    )

    if start_match is None:
        return ""

    block_start = start_match.start()

    next_function_pattern = re.compile(
        r"^def\s+[A-Za-z_]"
        r"[A-Za-z0-9_]*\s*\(",
        flags=re.MULTILINE,
    )

    next_match = (
        next_function_pattern.search(
            source_text,
            start_match.end(),
        )
    )

    if next_match is None:
        return source_text[
            block_start:
        ]

    return source_text[
        block_start:
        next_match.start()
    ]


def inspect_yaml_init_source(
    source_text: str,
    dumper_source_text: str = "",
) -> dict[str, Any]:
    """
    针对当前 PyYAML v0 案例提取我们真正关心的 API 历史事实。

    当前检查：
    - yaml.safe_load
    - yaml.full_load
    - yaml.safe_dump
    - dump_all 是否支持 sort_keys
    - safe_dump 是否能把 **kwds 传给 dump_all
    """
    load_signature = (
        find_function_signature(
            source_text,
            "load",
        )
    )

    load_loader_parameter = (
        inspect_named_parameter(
            signature=load_signature,
            parameter_name="Loader",
        )
    )

    safe_load_signature = (
        find_function_signature(
            source_text,
            "safe_load",
        )
    )

    full_load_signature = (
        find_function_signature(
            source_text,
            "full_load",
        )
    )

    safe_dump_signature = (
        find_function_signature(
            source_text,
            "safe_dump",
        )
    )

    dump_all_signature = (
        find_function_signature(
            source_text,
            "dump_all",
        )
    )

    safe_dump_block = (
        find_function_block(
            source_text,
            "safe_dump",
        )
    )

    effective_dumper_name = ""
    effective_dumper_source = ""

    # 优先看 safe_dump 调用 dump_all 时
    # 是否显式指定了 Dumper。
    safe_dump_dumper_match = re.search(
        r"\bDumper\s*=\s*"
        r"([A-Za-z_]"
        r"[A-Za-z0-9_]*)",
        safe_dump_block,
    )

    if safe_dump_dumper_match:
        effective_dumper_name = (
            safe_dump_dumper_match.group(1)
        )
        effective_dumper_source = (
            "safe_dump_explicit_argument"
        )

    # 如果 safe_dump 没有显式指定，
    # 才退回 dump_all 自己的默认 Dumper。
    elif dump_all_signature:
        dump_all_dumper_match = re.search(
            r"\bDumper\s*=\s*"
            r"([A-Za-z_]"
            r"[A-Za-z0-9_]*)",
            dump_all_signature,
        )

        if dump_all_dumper_match:
            effective_dumper_name = (
                dump_all_dumper_match.group(1)
            )
            effective_dumper_source = (
                "dump_all_default_argument"
            )

    effective_dumper_init_signature = None

    if (
        effective_dumper_name
        and dumper_source_text
    ):
        effective_dumper_init_signature = (
            find_class_init_signature(
                dumper_source_text,
                effective_dumper_name,
            )
        )

    safe_dump_accepts_kwargs = bool(
        safe_dump_signature
        and "**kwds"
        in safe_dump_signature
    )

    safe_dump_forwards_kwargs = (
        bool(
            safe_dump_block
        )
        and "dump_all"
        in safe_dump_block
        and "**kwds"
        in safe_dump_block
    )

    dump_all_supports_sort_keys = bool(
        dump_all_signature
        and re.search(
            r"\bsort_keys\b",
            dump_all_signature,
        )
    )

    dump_all_accepts_kwargs = bool(
        dump_all_signature
        and "**kwds"
        in dump_all_signature
    )

    effective_dumper_supports_sort_keys = bool(
        effective_dumper_init_signature
        and re.search(
            r"\bsort_keys\b",
            effective_dumper_init_signature,
        )
    )

    effective_dumper_accepts_kwargs = bool(
        effective_dumper_init_signature
        and (
                "**kwargs"
                in effective_dumper_init_signature
                or "**kwds"
                in effective_dumper_init_signature
        )
    )

    if safe_dump_signature is None:
        safe_dump_sort_keys_status = (
            "unsupported"
        )

    elif "sort_keys" in safe_dump_signature:
        safe_dump_sort_keys_status = (
            "supported"
        )

    elif (
            not safe_dump_accepts_kwargs
            or not safe_dump_forwards_kwargs
    ):
        safe_dump_sort_keys_status = (
            "unsupported"
        )

    elif dump_all_supports_sort_keys:
        safe_dump_sort_keys_status = (
            "supported"
        )




    elif dump_all_accepts_kwargs:
        if effective_dumper_supports_sort_keys:
            safe_dump_sort_keys_status = (
                "supported"
            )
        elif (
                effective_dumper_init_signature
                and not
                effective_dumper_accepts_kwargs
        ):
            safe_dump_sort_keys_status = (
                "unsupported"
            )
        else:
            safe_dump_sort_keys_status = (
                "unknown"
            )
    else:
        safe_dump_sort_keys_status = (
            "unsupported"
        )
    return {
                "yaml.load": {
            "defined":
                load_signature
                is not None,

            "signature":
                load_signature,

            "supports_loader_keyword": (
                load_loader_parameter[
                    "present"
                ]
            ),

            "supports_loader_positional": (
                load_loader_parameter[
                    "supports_positional"
                ]
            ),

            "loader_has_default": (
                load_loader_parameter[
                    "has_default"
                ]
            ),

            "loader_default_text": (
                load_loader_parameter[
                    "default_text"
                ]
            ),

            "loader_parameter_required": (
                load_loader_parameter[
                    "required"
                ]
            ),

            "loader_can_be_omitted": (
                (
                    load_loader_parameter[
                        "has_default"
                    ]
                )
                if (
                    load_loader_parameter[
                        "present"
                    ]
                )
                else None
            ),
        },
        "yaml.safe_load": {
            "defined":
                safe_load_signature
                is not None,

            "signature":
                safe_load_signature,
        },

        "yaml.full_load": {
            "defined":
                full_load_signature
                is not None,

            "signature":
                full_load_signature,
        },

        "yaml.safe_dump": {
            "defined":
                safe_dump_signature
                is not None,

            "signature":
                safe_dump_signature,

            "accepts_kwargs":
                safe_dump_accepts_kwargs,

            "forwards_kwargs_to_dump_all":
                safe_dump_forwards_kwargs,
        },

        "dump_all": {
            "defined":
                dump_all_signature
                is not None,

            "signature":
                dump_all_signature,

            "supports_sort_keys":
                dump_all_supports_sort_keys,

            "accepts_kwargs":
                dump_all_accepts_kwargs,

                        "effective_dumper": {
                "class_name":
                    effective_dumper_name,

                "selection_source":
                    effective_dumper_source,

                "init_signature":
                    effective_dumper_init_signature,

                "supports_sort_keys":
                    effective_dumper_supports_sort_keys,

                "accepts_kwargs":
                    effective_dumper_accepts_kwargs,
            },
        },

        "yaml.safe_dump(sort_keys=...)": {
            "status":
                safe_dump_sort_keys_status,

            "supported": (
                True
                if safe_dump_sort_keys_status
                == "supported"
                else (
                    False
                    if safe_dump_sort_keys_status
                    == "unsupported"
                    else None
                )
            ),

            "evidence_logic": (
                "safe_dump must accept and "
                "forward the keyword; then "
                "dump_all must explicitly "
                "support sort_keys. If "
                "dump_all only exposes "
                "**kwds, support remains "
                "unknown until the downstream "
                "Dumper signature is checked."
            ),
        },
    }

def fetch_github_tag_source(
    version_text: str,
) -> dict[str, Any]:
    """
    当 PyPI 当前没有可用 sdist 时，
    尝试从 PyYAML 官方 GitHub release tag
    获取对应历史源码。

    优先 lib3，随后 lib。
    """
    candidate_paths = [
        "lib3/yaml/__init__.py",
        "lib/yaml/__init__.py",
    ]

    errors: list[str] = []

    for source_path in candidate_paths:
        source_url = (
            f"{GITHUB_RAW_BASE_URL}/"
            f"{version_text}/"
            f"{source_path}"
        )

        try:
            source_bytes = fetch_bytes(
                source_url
            )
        except Exception as exc:
            errors.append(
                f"{source_path}: {exc}"
            )
            continue

        source_text = (
            source_bytes.decode(
                "utf-8",
                errors="replace",
            )
        )

        # yaml/__init__.py 和 dumper.py
        # 位于同一个 yaml 目录下。
        dumper_source_path = str(
            Path(source_path).parent
            / "dumper.py"
        ).replace(
            "\\",
            "/",
        )

        dumper_source_url = (
            f"{GITHUB_RAW_BASE_URL}/"
            f"{version_text}/"
            f"{dumper_source_path}"
        )

        try:
            dumper_source_bytes = (
                fetch_bytes(
                    dumper_source_url
                )
            )
        except Exception:
            dumper_source_bytes = b""

        dumper_source_text = (
            dumper_source_bytes.decode(
                "utf-8",
                errors="replace",
            )
            if dumper_source_bytes
            else ""
        )

        return {
            "status":
                "resolved",

            "source_mode":
                "official_github_tag",

            "source_url":
                source_url,

            "source_path":
                source_path,

            "source_sha256":
                sha256_bytes(
                    source_bytes
                ),

            "dumper_source_url": (
                dumper_source_url
                if dumper_source_bytes
                else None
            ),

            "dumper_source_path": (
                dumper_source_path
                if dumper_source_bytes
                else None
            ),

            "dumper_source_sha256": (
                sha256_bytes(
                    dumper_source_bytes
                )
                if dumper_source_bytes
                else None
            ),

            "observations":
                inspect_yaml_init_source(
                    source_text,
                    dumper_source_text,
                ),
        }

    return {
        "status":
            "source_unavailable",

        "source_mode":
            "official_github_tag",

        "errors":
            errors,
    }

def choose_source_member(
    archive: tarfile.TarFile,
) -> tarfile.TarInfo | None:
    """
    从 PyYAML sdist 中选择 yaml/__init__.py。

    某些老版本可能同时存在 lib 和 lib3。
    对当前 Python/PyPI 研究场景：
    优先选择 Python 3 分支 lib3，
    否则使用通用 lib。
    """
    members = [
        member
        for member in archive.getmembers()
        if member.isfile()
    ]

    lib3_candidates = [
        member
        for member in members
        if member.name.endswith(
            "/lib3/yaml/__init__.py"
        )
    ]

    if lib3_candidates:
        return sorted(
            lib3_candidates,
            key=lambda item: item.name,
        )[0]

    lib_candidates = [
        member
        for member in members
        if member.name.endswith(
            "/lib/yaml/__init__.py"
        )
    ]

    if lib_candidates:
        return sorted(
            lib_candidates,
            key=lambda item: item.name,
        )[0]

    return None


def inspect_sdist(
    content: bytes,
) -> dict[str, Any]:
    """
    直接在内存中读取 sdist。

    不安装旧 PyYAML，
    也不把 tar.gz 解压到项目目录。
    """
    try:
        with tarfile.open(
            fileobj=io.BytesIO(content),
            mode="r:gz",
        ) as archive:
            source_member = (
                choose_source_member(
                    archive
                )
            )

            if source_member is None:
                return {
                    "status":
                        "source_file_not_found",
                }

            dumper_member_name = (
                str(
                    Path(
                        source_member.name
                    ).parent
                    / "dumper.py"
                ).replace(
                    "\\",
                    "/",
                )
            )

            dumper_members = [
                member
                for member
                in archive.getmembers()
                if (
                    member.isfile()
                    and member.name
                    == dumper_member_name
                )
            ]

            dumper_source_bytes = b""

            if dumper_members:
                dumper_extracted = (
                    archive.extractfile(
                        dumper_members[0]
                    )
                )

                if dumper_extracted:
                    dumper_source_bytes = (
                        dumper_extracted.read()
                    )

            extracted = (
                archive.extractfile(
                    source_member
                )
            )

            if extracted is None:
                return {
                    "status":
                        "source_file_unreadable",
                    "source_path":
                        source_member.name,
                }

            source_bytes = (
                extracted.read()
            )

    except tarfile.TarError as exc:
        return {
            "status":
                "invalid_sdist_archive",
            "error":
                str(exc),
        }

    source_text = source_bytes.decode(
        "utf-8",
        errors="replace",
    )

    dumper_source_text = (
        dumper_source_bytes.decode(
            "utf-8",
            errors="replace",
        )
        if dumper_source_bytes
        else ""
    )

    return {
        "status": "resolved",

        "source_path":
            source_member.name,

        "source_sha256":
            sha256_bytes(
                source_bytes
            ),

        "dumper_source_path": (
            dumper_member_name
            if dumper_source_bytes
            else None
        ),

        "dumper_source_sha256": (
            sha256_bytes(
                dumper_source_bytes
            )
            if dumper_source_bytes
            else None
        ),

        "observations":
            inspect_yaml_init_source(
                source_text,
                dumper_source_text,
            ),
    }


def choose_sdist(
    release_files: list[
        dict[str, Any]
    ],
) -> dict[str, Any] | None:
    sdists = [
        file_info
        for file_info in release_files
        if file_info.get(
            "packagetype"
        ) == "sdist"
    ]

    if not sdists:
        return None

    return sorted(
        sdists,
        key=lambda item: str(
            item.get(
                "filename",
                "",
            )
        ),
    )[0]


def collect_release(
    version_text: str,
    release_files: list[
        dict[str, Any]
    ],
) -> dict[str, Any]:
    sdist = choose_sdist(
        release_files
    )

    if sdist is None:
        github_result = (
            fetch_github_tag_source(
                version_text
            )
        )

        if (
                github_result.get(
                    "status"
                )
                == "resolved"
        ):
            return {
                "version":
                    version_text,

                "pypi_sdist_status":
                    "no_sdist",

                **github_result,
            }

        return {
            "version":
                version_text,

            "status":
                "source_unavailable",

            "pypi_sdist_status":
                "no_sdist",

            "github_fallback":
                github_result,
        }

    filename = str(
        sdist.get(
            "filename",
            "",
        )
    )

    download_url = str(
        sdist.get(
            "url",
            "",
        )
    )

    expected_sha256 = str(
        sdist.get(
            "digests",
            {},
        ).get(
            "sha256",
            "",
        )
    )

    base_result: dict[str, Any] = {
        "version":
            version_text,

        "status":
            "pending",

        "pypi_release_url": (
            "https://pypi.org/project/"
            f"PyYAML/{version_text}/"
        ),

        "sdist_filename":
            filename,

        "sdist_url":
            download_url,

        "sdist_upload_time":
            sdist.get(
                "upload_time_iso_8601"
            ),

        "sdist_size":
            sdist.get(
                "size"
            ),

        "sdist_yanked":
            bool(
                sdist.get(
                    "yanked",
                    False,
                )
            ),

        "sdist_sha256_expected":
            expected_sha256,
    }

    try:
        content = fetch_bytes(
            download_url
        )
    except Exception as exc:
        base_result[
            "status"
        ] = "download_error"

        base_result[
            "error"
        ] = str(exc)

        return base_result

    observed_sha256 = (
        sha256_bytes(
            content
        )
    )

    base_result[
        "sdist_sha256_observed"
    ] = observed_sha256

    hash_verified = bool(
        expected_sha256
        and expected_sha256
        == observed_sha256
    )

    base_result[
        "sdist_hash_verified"
    ] = hash_verified

    if (
        expected_sha256
        and not hash_verified
    ):
        base_result[
            "status"
        ] = "hash_mismatch"

        return base_result

    inspection = inspect_sdist(
        content
    )

    base_result[
        "source_mode"
    ] = "official_pypi_sdist"

    base_result.update(
        inspection
    )

    return base_result


def collect_history(
    min_version_text: str,
    max_version_text: str,
) -> dict[str, Any]:
    queried_at = (
        datetime.now(
            timezone.utc
        ).isoformat()
    )

    project_json_bytes = fetch_bytes(
        PYPI_PROJECT_JSON_URL
    )

    project_json_sha256 = (
        sha256_bytes(
            project_json_bytes
        )
    )

    project_data = json.loads(
        project_json_bytes.decode(
            "utf-8"
        )
    )

    min_version = Version(
        min_version_text
    )

    max_version = Version(
        max_version_text
    )

    candidate_versions: list[
        tuple[Version, str]
    ] = []

    for version_text in (
        project_data.get(
            "releases",
            {}
        )
    ):
        try:
            parsed_version = Version(
                version_text
            )
        except InvalidVersion:
            continue

        if (
            min_version
            <= parsed_version
            <= max_version
        ):
            candidate_versions.append(
                (
                    parsed_version,
                    version_text,
                )
            )

    candidate_versions.sort(
        key=lambda item: item[0]
    )

    release_results: list[
        dict[str, Any]
    ] = []

    releases = project_data.get(
        "releases",
        {}
    )

    for _, version_text in (
        candidate_versions
    ):
        print(
            f"[INFO] inspect "
            f"PyYAML {version_text}"
        )

        result = collect_release(
            version_text=version_text,
            release_files=(
                releases.get(
                    version_text,
                    [],
                )
            ),
        )

        release_results.append(
            result
        )

        print(
            f"       status = "
            f"{result['status']}"
        )

    resolved_count = sum(
        row.get("status")
        == "resolved"
        for row in release_results
    )

    unresolved_count = (
        len(release_results)
        - resolved_count
    )

    overall_status = (
        "resolved"
        if (
            release_results
            and unresolved_count == 0
        )
        else "partial"
    )

    return {
        "schema_version":
            SCHEMA_VERSION,

        "evidence_type":
            "official_pypi_sdist_"
            "static_source_probe",

        "distribution":
            "PyYAML",

        "ecosystem":
            "pypi",

        "queried_at":
            queried_at,

        "pypi_project_json_url":
            PYPI_PROJECT_JSON_URL,

        "pypi_project_json_sha256":
            project_json_sha256,

        "min_version":
            min_version_text,

        "max_version":
            max_version_text,

        "status":
            overall_status,

        "release_count":
            len(
                release_results
            ),

        "resolved_release_count":
            resolved_count,

        "unresolved_release_count":
            unresolved_count,

        "releases":
            release_results,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Collect real PyYAML API "
            "history evidence from "
            "official PyPI source "
            "distributions."
        )
    )

    parser.add_argument(
        "--min-version",
        default="3.01",
    )

    parser.add_argument(
        "--max-version",
        default="5.1",
    )

    parser.add_argument(
        "--out",
        type=Path,
        default=Path(
            "output/"
            "pyyaml_api_history_"
            "raw_evidence_v0.json"
        ),
    )

    args = parser.parse_args()

    result = collect_history(
        min_version_text=(
            args.min_version
        ),
        max_version_text=(
            args.max_version
        ),
    )

    args.out.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    args.out.write_text(
        json.dumps(
            result,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    print("")
    print(
        f"[OK] status: "
        f"{result['status']}"
    )
    print(
        f"[OK] releases: "
        f"{result['release_count']}"
    )
    print(
        f"[OK] resolved: "
        f"{result['resolved_release_count']}"
    )
    print(
        f"[OK] unresolved: "
        f"{result['unresolved_release_count']}"
    )
    print(
        f"[OK] result saved to: "
        f"{args.out}"
    )


if __name__ == "__main__":
    main()