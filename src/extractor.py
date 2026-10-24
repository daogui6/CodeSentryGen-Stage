"""
extractor.py

作用：
    CodeSentry-Gen 的依赖抽取模块。
    负责从 Python generated_code 和 requirements 中抽取依赖实体，
    并统一封装为 DependencyEntity。

输入来源：
    1. generated_code：
       通过 AST 抽取 import / from import 语句。
    2. requirements.txt 或 requirements_text：
       按行解析 requirements 依赖声明。

输出：
    List[DependencyEntity]

在整体流程中的位置：
    generate_code_from_prompts.py
        ↓
    run_pilot.py
        ↓
    extractor.py
        ↓
    normalizer.py / pypi_client.py / risk_card.py

注意：
    本文件只负责抽取依赖，不负责：
    - 标准库过滤
    - import-to-distribution 映射
    - PyPI 查询
    - 风险判断

这些后续由 run_pilot.py 调用 normalizer.py、pypi_client.py 和 risk_card.py 完成。
"""

import ast
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable, List, Optional

from python_binding_context_v1 import BindingContexts


@dataclass
class DependencyEntity:
    """
    统一表示一个依赖实体。

    无论依赖来自代码 import，还是来自 requirements，
    最后都会转成 DependencyEntity，方便后续统一处理。

    字段说明：
    - raw_name：原始名称，例如 yaml、bs4、requests
    - source_type：来源类型，import 或 manifest
    - file：依赖出现在哪个文件
    - line：依赖出现在哪一行
    - original_text：原始文本，例如 import requests 或 requirements 原始行
    - normalized_name：后续保存规范化后的包名
    - mapped_name：后续保存 import 映射后的包名
    - is_local_module：后续标记是否为本地模块
    - is_false_positive：后续标记是否为 false positive
    """
    raw_name: str
    source_type: str
    file: str
    line: int

    # 完整 Python import 路径。
    #
    # 示例：
    # raw_name = "google"
    # import_path = "google.protobuf"
    #
    # requirements 来源没有 import 路径，因此保持为空字符串。
    import_path: str = ""

    original_text: str = ""
    normalized_name: str = ""
    mapped_name: str = ""
    is_local_module: bool = False
    is_false_positive: bool = False

    def to_dict(self):
        """将 DependencyEntity 转成普通 dict，方便写入 JSONL。"""
        return asdict(self)


def extract_imports_from_code(code: str, file_name: str = "generated.py") -> List[DependencyEntity]:
    """
    使用 AST 从 Python 代码中抽取 import 依赖。

    支持：
        import requests
        import numpy as np
        from bs4 import BeautifulSoup
        from googleapiclient.discovery import build
        importlib.import_module("requests")
        __import__("requests")

    抽取规则：
        只抽 top-level 名称。
        例如：
            from bs4 import BeautifulSoup -> bs4
            from googleapiclient.discovery import build -> googleapiclient

    如果代码语法错误：
        ast.parse 会失败，本函数直接返回空列表。
        语法错误信息由 run_pilot.py 另外记录在 code_parse_status/code_parse_error 中。
    """
    entities: List[DependencyEntity] = []

    try:
        tree = ast.parse(code)
    except SyntaxError:
        return entities

    # 遍历 AST 中所有节点，找到 import 和 from import
    for node in ast.walk(tree):

        # 处理普通 import：
        #   import requests
        #   import pandas as pd
        #   import googleapiclient.discovery
        if isinstance(node, ast.Import):
            for alias in node.names:
                # 只保留 top-level module。
                # googleapiclient.discovery -> googleapiclient
                top_name = alias.name.split(".")[0]

                entities.append(
                    DependencyEntity(
                        raw_name=top_name,
                        source_type="import",
                        file=file_name,
                        line=getattr(node, "lineno", 0),
                        import_path=alias.name,
                        original_text=f"import {alias.name}",
                    )
                )

        # 处理 from import：
        #   from bs4 import BeautifulSoup
        #   from pathlib import Path
        #   from googleapiclient.discovery import build
        elif isinstance(node, ast.ImportFrom):
            # Relative imports identify project-local modules; their spelling
            # must never be mapped into a public registry distribution.
            if node.level or not node.module:
                continue

            top_name = node.module.split(".")[0]

            alias_names = [
                alias.name
                for alias in node.names
                if alias.name != "*"
            ]

            # 当语句只导入一个名称时，把它也加入完整路径。
            #
            # 例如：
            # from google.cloud import storage
            #
            # node.module = "google.cloud"
            # alias_names = ["storage"]
            # import_path = "google.cloud.storage"
            #
            # 如果一次导入多个名称，暂时保守地只保留 node.module，
            # 避免把普通类名或函数名误认为 Python 子模块。
            import_path = node.module

            if len(alias_names) == 1:
                import_path = f"{node.module}.{alias_names[0]}"

            entities.append(
                DependencyEntity(
                    raw_name=top_name,
                    source_type="import",
                    file=file_name,
                    line=getattr(node, "lineno", 0),
                    import_path=import_path,
                    original_text=f"from {node.module} import "
                                  + ", ".join(alias_names),
                )
            )

    # The API producer uses this same lexical resolver. Only a proved loader
    # and literal module identity become dependency facts; dynamic names stay
    # explicit uncertainty in the API/SCEG extraction metadata.
    contexts = BindingContexts(tree, source_code=code)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        dynamic = contexts.dynamic_import(node)
        if dynamic and dynamic["status"] == "resolved":
            entities.append(DependencyEntity(
                raw_name=dynamic["import_path"].split(".")[0],
                source_type="import", file=file_name, line=node.lineno,
                import_path=dynamic["import_path"],
                original_text=ast.get_source_segment(code, node) or "",
            ))

    return entities


# 简单 requirements 行解析正则。
# 主要匹配：
#   requests
#   requests>=2.31.0
#   pandas==2.2.0
#   google-api-python-client
#
# 当前不完整支持复杂写法：
#   package[extra]
#   package @ URL
#   -r other.txt
_REQ_LINE_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*([<>=!~].*)?$")


def extract_requirements(requirements_path: Path) -> List[DependencyEntity]:
    """
    从 requirements.txt 文件中抽取依赖包名。

    处理逻辑：
    1. 文件不存在时返回空列表
    2. 跳过空行、注释行、以 - 开头的 pip 参数行
    3. 去掉行内注释和环境标记
    4. 用正则抽取包名
    5. 每个包名封装成 DependencyEntity(source_type="manifest")
    """
    entities: List[DependencyEntity] = []

    if not requirements_path.exists():
        return entities

    for idx, raw_line in enumerate(
        requirements_path.read_text(encoding="utf-8", errors="ignore").splitlines(),
        start=1,
    ):
        line = raw_line.strip()

        # 跳过空行、注释行，以及 -r / --index-url 这类 pip 参数行
        if not line or line.startswith("#") or line.startswith("-"):
            continue

        # 去掉行内注释和环境标记。
        # 例如：
        #   requests>=2.31.0  # comment
        #   importlib-metadata; python_version < "3.10"
        line = line.split("#", 1)[0].split(";", 1)[0].strip()

        match = _REQ_LINE_RE.match(line)

        if match:
            entities.append(
                DependencyEntity(
                    raw_name=match.group(1),
                    source_type="manifest",
                    file=str(requirements_path),
                    line=idx,
                    original_text=raw_line,
                )
            )

    return entities


def find_local_modules(repo_path: Optional[Path]) -> set[str]:
    """
    扫描项目根目录下的本地 Python 模块。

    用途：
        避免把本地模块误当成 PyPI 包。

    当前识别两类：
    1. 顶层 .py 文件：
       utils.py -> utils
    2. 顶层 Python 包目录：
       mypkg/__init__.py -> mypkg

    注意：
        当前只扫描顶层，不递归扫描深层子目录。
    """
    if repo_path is None or not repo_path.exists():
        return set()

    modules: set[str] = set()

    for item in repo_path.iterdir():
        # 跳过隐藏文件或隐藏目录
        if item.name.startswith("."):
            continue

        # 顶层 .py 文件，例如 utils.py
        if item.is_file() and item.suffix == ".py":
            modules.add(item.stem)

        # 顶层包目录，例如 mypkg/__init__.py
        elif item.is_dir() and (item / "__init__.py").exists():
            modules.add(item.name)

    return modules


def deduplicate_entities(entities: Iterable[DependencyEntity]) -> List[DependencyEntity]:
    """
    对依赖实体去重。

    去重键：
        raw_name + source_type + file + line

    这样可以避免同一行同一来源的依赖重复进入后续 PyPI 查询。
    """
    seen = set()
    result: List[DependencyEntity] = []

    for e in entities:
        key = (
            e.raw_name,
            e.import_path,
            e.source_type,
            e.file,
            e.line,
        )

        if key not in seen:
            result.append(e)
            seen.add(key)

    return result


def extract_requirements_from_text(
    requirements_text: str,
    file_name: str = "requirements.txt",
) -> List[DependencyEntity]:
    """
    从 sample 中的 requirements_text 字段抽取依赖包名。

    这个函数和 extract_requirements 的区别：
    - extract_requirements：读取真实 requirements.txt 文件
    - extract_requirements_from_text：读取 JSONL 样本中的 requirements_text 字符串

    在当前自动生成流程中，generate_code_from_prompts.py 会保存：
        requirements_text

    run_pilot.py 会调用本函数从 requirements_text 中抽取 manifest 依赖。
    """
    entities: List[DependencyEntity] = []

    if not requirements_text:
        return entities

    for idx, raw_line in enumerate(requirements_text.splitlines(), start=1):
        # lstrip("\ufeff") 用于去掉 UTF-8 BOM，避免第一行包名前出现隐藏字符
        line = raw_line.strip().lstrip("\ufeff")

        # 跳过空行、注释行和 pip 参数行
        if not line or line.startswith("#") or line.startswith("-"):
            continue

        # 去掉行内注释和环境标记
        line = line.split("#", 1)[0].split(";", 1)[0].strip()

        match = _REQ_LINE_RE.match(line)

        if match:
            entities.append(
                DependencyEntity(
                    raw_name=match.group(1),
                    source_type="manifest",
                    file=file_name,
                    line=idx,
                    original_text=raw_line,
                )
            )

    return entities
