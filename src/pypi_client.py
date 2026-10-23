"""
pypi_client.py

作用：
    CodeSentry-Gen 的 PyPI 查询模块。
    根据规范化后的 PyPI 包名，访问 PyPI JSON API，
    获取包当前是否存在、最新版本、最早 release file upload time 等证据。

输入：
    - package：规范化后的 PyPI 包名
      例如 requests、pyyaml、beautifulsoup4、google-api-python-client

输出：
    - PyPIEvidence
      包含 exists_now、query_url、audit_time、latest_version、
      first_release_time、status_code、error 等字段。

在整体流程中的位置：
    normalizer.py
        ↓
    pypi_client.py
        ↓
    risk_card.py / enrich_temporal_status.py

注意：
    本文件只负责查询 PyPI 和保存证据。
    具体判断 temporal_status_v2 的逻辑在 enrich_temporal_status.py 中。

重要说明：
    first_release_time 当前取的是 PyPI releases 中最早的文件上传时间，
    用来近似表示该包最早可安装的时间。
    它不是严格意义上的包注册时间。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import requests


@dataclass
class PyPIEvidence:
    """
    PyPI 查询证据对象。

    每查询一个包，就返回一个 PyPIEvidence。
    后续 run_pilot.py / enrich_temporal_status.py 会基于这些证据判断状态。
    """
    package: str
    exists_now: bool
    query_url: str
    audit_time: str
    latest_version: Optional[str] = None
    first_release_time: Optional[str] = None
    status_code: Optional[int] = None
    error: Optional[str] = None

    def to_dict(self):
        """转成 dict，方便写入 JSONL。"""
        return asdict(self)


def _now_iso() -> str:
    """
    返回当前 UTC 时间。

    用途：
        记录 audit_time，表示这次 PyPI 查询发生在什么时候。
    """
    return datetime.now(timezone.utc).isoformat()


def _parse_time(value: str) -> Optional[datetime]:
    """
    解析 PyPI 返回的时间字符串。

    PyPI 有些时间以 Z 结尾，例如：
        2020-01-01T00:00:00Z

    Python datetime.fromisoformat 不能直接解析 Z，
    所以这里先把 Z 替换成 +00:00。
    """
    if not value:
        return None

    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _earliest_release_time(data: Dict[str, Any]) -> Optional[str]:
    """
    从 PyPI JSON 的 releases 字段中寻找最早的文件上传时间。

    PyPI JSON 大致结构：
        {
            "releases": {
                "1.0.0": [
                    {"upload_time_iso_8601": "..."}
                ],
                "1.1.0": [
                    {"upload_time_iso_8601": "..."}
                ]
            }
        }

    当前实现：
        遍历所有版本、所有文件，取最早的 upload_time。

    作用：
        用 earliest upload_time 近似表示 first_release_time。

    注意：
        这不是严格包注册时间，只是 PyPI 上可获得的最早 release 文件上传时间。
    """
    earliest: Optional[datetime] = None

    for files in data.get("releases", {}).values():
        for file_info in files:
            upload_time = (
                file_info.get("upload_time_iso_8601")
                or file_info.get("upload_time")
            )

            dt = _parse_time(upload_time)

            if dt is not None and (earliest is None or dt < earliest):
                earliest = dt

    return earliest.isoformat() if earliest else None


def query_pypi(
    package: str,
    cache_dir: Optional[Path] = None,
    timeout: int = 12,
) -> PyPIEvidence:
    """
    查询 PyPI，返回该包的生态证据。

    输入：
        package：
            规范化后的 PyPI 包名。
        cache_dir：
            可选缓存目录。启用后同一个包不重复请求 PyPI。
        timeout：
            网络请求超时时间，默认 12 秒。

    返回：
        PyPIEvidence

    状态区分：
        1. HTTP 404：
           PyPI 明确表示包不存在。
           exists_now=False，error=None。

        2. HTTP 200：
           包存在。
           exists_now=True，并提取 latest_version 和 first_release_time。

        3. 其他 HTTP 错误：
           例如 500、503。
           这是查询错误，不应直接当成包不存在。
           exists_now=False，error="HTTP xxx"。

        4. 网络异常：
           例如 timeout、连接失败。
           这是 registry_query_error，不应直接当成包不存在。
    """
    query_url = f"https://pypi.org/pypi/{package}/json"
    audit_time = _now_iso()

    # =========================
    # 1. 尝试读取缓存
    # =========================

    cache_path = None

    if cache_dir:
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_path = cache_dir / f"{package}.json"

        if cache_path.exists():
            try:
                cached = json.loads(cache_path.read_text(encoding="utf-8"))
                return PyPIEvidence(**cached)
            except Exception:
                # 缓存损坏时忽略缓存，重新请求 PyPI
                pass

    # =========================
    # 2. 请求 PyPI JSON API
    # =========================

    try:
        resp = requests.get(query_url, timeout=timeout)

        # 情况 1：404 表示 PyPI 明确没有这个包
        if resp.status_code == 404:
            evidence = PyPIEvidence(
                package=package,
                exists_now=False,
                query_url=query_url,
                audit_time=audit_time,
                status_code=404,
            )

        # 情况 2：请求成功，包存在
        elif resp.ok:
            data = resp.json()

            evidence = PyPIEvidence(
                package=package,
                exists_now=True,
                query_url=query_url,
                audit_time=audit_time,
                latest_version=data.get("info", {}).get("version"),
                first_release_time=_earliest_release_time(data),
                status_code=resp.status_code,
            )

        # 情况 3：非 404 的 HTTP 错误，例如 500 / 503
        # 这种情况是查询失败，不应该直接当成包不存在。
        else:
            evidence = PyPIEvidence(
                package=package,
                exists_now=False,
                query_url=query_url,
                audit_time=audit_time,
                status_code=resp.status_code,
                error=f"HTTP {resp.status_code}",
            )

    # 情况 4：网络异常，例如 timeout、DNS 失败等
    # 这类情况后续应被视为 registry_query_error。
    except Exception as exc:
        evidence = PyPIEvidence(
            package=package,
            exists_now=False,
            query_url=query_url,
            audit_time=audit_time,
            error=str(exc),
        )

    # =========================
    # 3. 写入缓存
    # =========================

    if cache_path:
        cache_path.write_text(
            json.dumps(evidence.to_dict(), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    return evidence