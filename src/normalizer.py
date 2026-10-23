"""
normalizer.py

作用：
    CodeSentry-Gen 的包名规范化模块。
    主要解决 Python import 名和 PyPI distribution 名不完全一致的问题。

输入：
    - extractor.py 抽取出来的 raw_name
      例如：yaml、bs4、PIL、googleapiclient、requests

输出：
    - 映射和规范化后的 PyPI 包名
      例如：pyyaml、beautifulsoup4、pillow、google-api-python-client、requests

在整体流程中的位置：
    extractor.py
        ↓
    normalizer.py
        ↓
    pypi_client.py

本文件只负责：
    - PEP503 包名规范化
    - import-to-distribution 映射
    - false positive 包列表加载

本文件不负责：
    - 抽取 import
    - 查询 PyPI
    - 生成 Risk Card
"""

import csv
import json
import re
from pathlib import Path
from typing import Dict, Set


def pep503_normalize(name: str) -> str:
    """
    按 PEP 503 风格规范化 Python distribution 名称。

    规则：
        1. 转小写
        2. 把连续的 '-'、'_'、'.' 统一替换成单个 '-'

    示例：
        google_api_python_client -> google-api-python-client
        Google.API-Client -> google-api-client
        scikit_learn -> scikit-learn

    作用：
        避免同一个包因为大小写、下划线、点号差异被当成不同包。
    """
    return re.sub(r"[-_.]+", "-", name).lower()


def load_import_mapping(path: Path) -> Dict[str, str]:
    """
    读取 import 名到 PyPI distribution 名的映射表。

    输入文件：
        config/import_mapping.json

    示例：
        {
            "yaml": "pyyaml",
            "bs4": "beautifulsoup4",
            "PIL": "Pillow",
            "googleapiclient": "google-api-python-client"
        }

    如果文件不存在，返回空字典，表示不做额外映射。
    """
    if not path.exists():
        return {}

    return json.loads(path.read_text(encoding="utf-8"))


def load_false_positive_packages(path: Path) -> Set[str]:
    """
    读取 false positive 包列表。

    输入文件：
        config/false_positive_packages.csv

    作用：
        有些名称不应该进入 PyPI 风险判断，
        可以通过这个列表提前过滤掉。

    处理逻辑：
        - 跳过空行
        - 跳过以 # 开头的注释行
        - 只读取每行第一列
        - 读取后统一做 PEP503 规范化
    """
    packages: Set[str] = set()

    if not path.exists():
        return packages

    with path.open("r", encoding="utf-8") as f:
        for row in csv.reader(f):
            if not row or row[0].strip().startswith("#"):
                continue

            packages.add(pep503_normalize(row[0].strip()))

    return packages


def map_import_to_distribution(raw_name: str, mapping: Dict[str, str]) -> str:
    """
    将 Python import 名映射为 PyPI distribution 名。

    示例：
        yaml -> pyyaml
        bs4 -> beautifulsoup4
        PIL -> Pillow
        googleapiclient -> google-api-python-client

    如果 mapping 中没有对应关系，则返回原始名称。
    例如：
        requests -> requests
        pandas -> pandas
    """
    return mapping.get(raw_name, raw_name)

def map_import_path_to_distribution(
    raw_name: str,
    import_path: str,
    mapping: Dict[str, str],
) -> str:
    """
    根据完整 Python import 路径映射到 PyPI distribution。

    匹配顺序采用最长前缀优先。

    示例：
        google.auth.transport.requests
            -> google.auth
            -> google-auth

        azure.storage.blob
            -> azure-storage-blob

    如果完整路径和各级前缀都没有映射，
    最后退回原有的 raw_name 映射规则。
    """
    if import_path:
        parts = import_path.split(".")

        # 从最长路径开始逐级缩短。
        # google.auth.transport.requests
        # -> google.auth.transport.requests
        # -> google.auth.transport
        # -> google.auth
        # -> google
        for end in range(len(parts), 0, -1):
            candidate = ".".join(parts[:end])

            if candidate in mapping:
                return mapping[candidate]

    return map_import_to_distribution(raw_name, mapping)