"""
enrich_reachability_v2.py

作用：
    CodeSentry-Gen 的安装可达性 v2 增强模块。
    在已有依赖检测记录基础上，根据 requirements、Dockerfile 和 CI 配置，
    判断某个依赖是否真的可能被安装进入环境。

输入：
    - temporal enriched JSONL
      例如 output/pilot50_temporal_enriched.jsonl
    - requirements 文件目录
      例如 data/generated_requirements_files
    - build evidence 目录
      例如 data/build_evidence/{sample_id}/Dockerfile 或 ci.yml

输出：
    - reachability enriched JSONL
      新增 install_reachability_v2 和 reachability_v2_evidence
    - reachability summary Markdown

核心字段：
    - install_reachability：run_pilot.py 生成的原始可达性字段
    - install_reachability_v2：v2 增强后的可达性字段
    - reachability_v2_evidence：requirements / Docker / CI 证据链

主要可达性级别：
    - import_only：只在代码 import 中出现
    - manifest_declared：在 requirements 中声明
    - docker_installable：requirements 会被 Dockerfile 安装
    - ci_installable：requirements 会被 CI 安装

在整体流程中的位置：
    enrich_temporal_status.py
        ↓
    enrich_reachability_v2.py
        ↓
    build_temporal_risk_cards.py

注意：
    Docker/CI 升级必须建立在 package 已经写入 requirements 的基础上。
    本脚本不会覆盖原始 install_reachability，而是新增 install_reachability_v2。
"""

import argparse
import json
import re
from collections import Counter
from pathlib import Path


def norm_pkg(name: str) -> str:
    """PEP 503 风格归一化：大小写统一，- _ . 都视为同一种分隔符。"""
    if not name:
        return ""
    return re.sub(r"[-_.]+", "-", str(name).strip().lower())


def read_jsonl(path: Path):
    """读取 JSONL 文件，返回解析后的记录列表。"""
    records = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def write_jsonl(path: Path, records):
    """将记录列表写入 JSONL 文件。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def parse_requirement_name(line: str):
    """
    从 requirements.txt 的一行中解析出包名。
    
    处理以下情况：
    - 忽略注释行和空行
    - 去掉行内注释和环境标记（如 ; python_version >= "3.6"）
    - 忽略 pip 参数（如 -r、--index-url）
    - 去除 extras 标记（如 Flask[async]）
    - 处理 Package @ URL 格式
    - 提取版本符号前的包名
    
    返回归一化后的包名，如果无法解析则返回 None。
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    # 去掉行内注释和环境标记
    line = line.split("#", 1)[0].split(";", 1)[0].strip()
    if not line:
        return None

    # 忽略 -r、--index-url 之类 pip 参数
    if line.startswith("-") or line.startswith("--"):
        return None

    # 处理 Flask[async]==3.0.0
    line = re.sub(r"\[.*?\]", "", line)

    # 处理 Package @ URL
    if " @ " in line:
        line = line.split(" @ ", 1)[0].strip()

    # 按版本符号切开
    name = re.split(r"\s*(===|==|~=|!=|<=|>=|<|>)\s*", line, maxsplit=1)[0].strip()

    if not name:
        return None

    return norm_pkg(name)


def load_requirements(sample_id: str, requirements_dir: Path):
    """
    加载指定 sample 的 requirements 文件。
    
    返回：
    - requirements 中声明过的包集合（归一化后）
    - 命中的 requirements 文件路径列表
    - 每个包对应的原始行证据（包含文件、行号、原始内容、包名）
    """
    packages = set()
    files = []
    lines = []

    if not requirements_dir.exists():
        return packages, files, lines

    # 遍历所有包含 sample_id 的文件
    for path in requirements_dir.glob(f"*{sample_id}*"):
        if not path.is_file():
            continue

        files.append(path)

        # 逐行解析 requirements 文件
        for line_no, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1):
            pkg = parse_requirement_name(line)
            if pkg:
                packages.add(pkg)
                lines.append(
                    {
                        "file": str(path).replace("\\", "/"),
                        "line": line_no,
                        "raw": line.strip(),
                        "package": pkg,
                    }
                )

    return packages, files, lines


def find_install_commands(path: Path):
    """
    在 Dockerfile 或 CI 配置文件里查找 pip install -r requirements.txt 命令。
    
    使用保守的正则匹配规则，识别以下格式的 pip install 命令：
    - python -m pip install -r requirements.txt
    - pip install -r requirements.txt
    - pip3 install --requirement requirements.txt
    
    返回匹配到的命令列表，包含文件路径、行号和完整命令。
    """
    hits = []

    if not path.exists() or not path.is_file():
        return hits

    # 匹配 pip install -r/--requirement requirements*.txt 的命令
    pattern = re.compile(
        r"(?i)(python\s+-m\s+pip|pip|pip3)\s+install\b.*(-r|--requirement)\s+\S*requirements\S*"
    )

    for line_no, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1):
        if pattern.search(line):
            hits.append(
                {
                    "file": str(path).replace("\\", "/"),
                    "line": line_no,
                    "command": line.strip(),
                }
            )

    return hits


def collect_build_evidence(sample_id: str, evidence_dir: Path):
    """
    收集指定 sample 的构建证据（Dockerfile 和 CI 配置文件）。
    
    扫描 build_evidence/{sample_id}/ 目录下的文件：
    - Dockerfile* 文件：查找 pip install 命令
    - *.yml/*.yaml 文件：查找 pip install 命令
    
    返回两个列表：docker_hits 和 ci_hits。
    """
    sample_dir = evidence_dir / sample_id

    docker_hits = []
    ci_hits = []

    if not sample_dir.exists():
        return docker_hits, ci_hits

    # Dockerfile 证据
    for path in sample_dir.iterdir():
        if path.is_file() and path.name.lower().startswith("dockerfile"):
            docker_hits.extend(find_install_commands(path))

    # CI 证据：先覆盖最小 controlled evidence
    for path in sample_dir.iterdir():
        if path.is_file() and path.suffix.lower() in [".yml", ".yaml"]:
            ci_hits.extend(find_install_commands(path))

    return docker_hits, ci_hits


def decide_reachability_v2(original_level: str, requirements_declared: bool, docker_hits, ci_hits):
    """
    根据 v2 规则决定安装可达性级别。
    
    最小版规则：
    1. 没有 requirements 声明，则不因为 Docker/CI 升级。
    2. 有 requirements 声明，至少 manifest_declared。
    3. Docker 有 pip install -r requirements.txt，则 docker_installable。
    4. CI 有 pip install -r requirements.txt，则 ci_installable。
    5. Docker 和 CI 都有时，最终标 ci_installable，但 evidence 里保留两类证据。
    
    优先级：ci_installable > docker_installable > manifest_declared > original_level
    """
    level = original_level or "import_only"

    # 如果没有 requirements 声明，保持原级别不变
    if not requirements_declared:
        return level

    # 有 requirements 声明，至少提升到 manifest_declared
    if level in ["", "none", "mention_only", "import_only"]:
        level = "manifest_declared"

    # Docker 有安装命令，提升到 docker_installable
    if docker_hits:
        level = "docker_installable"

    # CI 有安装命令，提升到 ci_installable（最高优先级）
    if ci_hits:
        level = "ci_installable"

    return level


def enrich(input_path: Path, output_path: Path, summary_path: Path, requirements_dir: Path, evidence_dir: Path):
    """
    主处理函数：为每条记录添加 v2 版本的安装可达性信息。
    
    处理流程：
    1. 读取输入 JSONL 文件
    2. 对每条记录，加载其 requirements 文件和构建证据
    3. 判断包是否在 requirements 中声明
    4. 根据 v2 规则计算新的可达性级别
    5. 添加详细的证据信息到 reachability_v2_evidence 字段
    6. 写入输出文件和摘要报告
    
    使用 cache 避免重复加载同一个 sample_id 的文件。
    """
    records = read_jsonl(input_path)
    enriched = []

    cache = {}

    for rec in records:
        new_rec = dict(rec)

        sample_id = rec.get("sample_id", "")
        package = rec.get("package", "")
        package_norm = norm_pkg(package)
        original_level = rec.get("install_reachability", "import_only")

        # 缓存机制：避免重复加载同一个 sample 的文件
        if sample_id not in cache:
            req_pkgs, req_files, req_lines = load_requirements(sample_id, requirements_dir)
            docker_hits, ci_hits = collect_build_evidence(sample_id, evidence_dir)
            cache[sample_id] = {
                "req_pkgs": req_pkgs,
                "req_files": req_files,
                "req_lines": req_lines,
                "docker_hits": docker_hits,
                "ci_hits": ci_hits,
            }

        info = cache[sample_id]

        # 判断当前包是否在 requirements 中声明
        requirements_declared = package_norm in info["req_pkgs"]
        matched_req_lines = [
            x for x in info["req_lines"]
            if x.get("package") == package_norm
        ]

        # 判断是否可通过 Docker/CI 安装
        docker_installable = requirements_declared and len(info["docker_hits"]) > 0
        ci_installable = requirements_declared and len(info["ci_hits"]) > 0

        # 根据 v2 规则计算新的可达性级别
        v2_level = decide_reachability_v2(
            original_level=original_level,
            requirements_declared=requirements_declared,
            docker_hits=info["docker_hits"],
            ci_hits=info["ci_hits"],
        )

        # 添加 v2 级别的可达性字段
        new_rec["install_reachability_v2"] = v2_level
        
        # 添加详细的证据信息
        new_rec["reachability_v2_evidence"] = {
            "sample_id": sample_id,
            "package": package,
            "package_normalized": package_norm,
            "original_install_reachability": original_level,
            "install_reachability_v2": v2_level,
            "requirements_declared": requirements_declared,
            "requirements_files": [str(p).replace("\\", "/") for p in info["req_files"]],
            "matched_requirement_lines": matched_req_lines,
            "docker_installable": docker_installable,
            "docker_install_commands": info["docker_hits"] if docker_installable else [],
            "ci_installable": ci_installable,
            "ci_install_commands": info["ci_hits"] if ci_installable else [],
            "note": "v2 does not overwrite install_reachability; CI has priority over Docker when both evidence types exist.",
        }

        enriched.append(new_rec)

    write_jsonl(output_path, enriched)
    write_summary(summary_path, input_path, output_path, records, enriched)


def write_summary(summary_path: Path, input_path: Path, output_path: Path, old_records, new_records):
    """
    生成 v2 增强的摘要报告。
    
    报告内容包括：
    - 基本统计信息（输入输出路径、总记录数、变更记录数等）
    - 原始 install_reachability 分布
    - 新的 install_reachability_v2 分布
    - 发生变更的记录详情表格
    - pilot50_047 受控样本的证据检查
    - 说明注释
    
    以 Markdown 格式写入摘要文件。
    """
    # 统计原始和新版本的可达性级别分布
    old_counter = Counter(r.get("install_reachability", "import_only") for r in old_records)
    v2_counter = Counter(r.get("install_reachability_v2", "import_only") for r in new_records)

    # 收集变更记录和统计数据
    changed = []
    docker_count = 0
    ci_count = 0
    both_count = 0
    controlled_047 = []

    for old, new in zip(old_records, new_records):
        old_level = old.get("install_reachability", "import_only")
        new_level = new.get("install_reachability_v2", "import_only")
        ev = new.get("reachability_v2_evidence", {})

        # 记录发生变化的条目
        if old_level != new_level:
            changed.append(new)

        # 统计各类证据数量
        if ev.get("docker_installable"):
            docker_count += 1
        if ev.get("ci_installable"):
            ci_count += 1
        if ev.get("docker_installable") and ev.get("ci_installable"):
            both_count += 1

        # 收集受控样本 pilot50_047 的记录
        if ev.get("sample_id") == "pilot50_047":
            controlled_047.append(new)

    # 生成 Markdown 格式的摘要报告
    lines = []
    lines.append("# Install Reachability v2 Summary")
    lines.append("")
    lines.append(f"- input: `{input_path}`")
    lines.append(f"- output: `{output_path}`")
    lines.append(f"- total_records: {len(new_records)}")
    lines.append(f"- changed_records: {len(changed)}")
    lines.append(f"- docker_installable_records: {docker_count}")
    lines.append(f"- ci_installable_records: {ci_count}")
    lines.append(f"- both_docker_and_ci_evidence_records: {both_count}")
    lines.append("")
    lines.append("## Original install_reachability")
    lines.append("")
    for k, v in sorted(old_counter.items()):
        lines.append(f"- {k}: {v}")

    lines.append("")
    lines.append("## install_reachability_v2")
    lines.append("")
    for k, v in sorted(v2_counter.items()):
        lines.append(f"- {k}: {v}")

    lines.append("")
    lines.append("## Changed Records")
    lines.append("")
    if not changed:
        lines.append("No records changed.")
    else:
        lines.append("| sample_id | package | original | v2 | requirements | docker | ci |")
        lines.append("|---|---|---|---|---|---|---|")
        for rec in changed:
            ev = rec.get("reachability_v2_evidence", {})
            lines.append(
                f"| {ev.get('sample_id')} | {ev.get('package')} | "
                f"{ev.get('original_install_reachability')} | {ev.get('install_reachability_v2')} | "
                f"{ev.get('requirements_declared')} | {ev.get('docker_installable')} | {ev.get('ci_installable')} |"
            )

    lines.append("")
    lines.append("## Controlled Evidence Check: pilot50_047")
    lines.append("")
    if not controlled_047:
        lines.append("No records found for pilot50_047.")
    else:
        lines.append("| package | original | v2 | requirements | docker | ci |")
        lines.append("|---|---|---|---|---|---|")
        for rec in controlled_047:
            ev = rec.get("reachability_v2_evidence", {})
            lines.append(
                f"| {ev.get('package')} | {ev.get('original_install_reachability')} | "
                f"{ev.get('install_reachability_v2')} | {ev.get('requirements_declared')} | "
                f"{ev.get('docker_installable')} | {ev.get('ci_installable')} |"
            )

    lines.append("")
    lines.append("## Notes")
    lines.append("")
    lines.append("- The original `install_reachability` field is preserved.")
    lines.append("- v2 adds `install_reachability_v2` and `reachability_v2_evidence`.")
    lines.append("- Docker/CI upgrade requires the package to be declared in requirements.")
    lines.append("- If both Docker and CI evidence exist, the final level is `ci_installable`, while both evidence types are recorded.")

    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text("\n".join(lines), encoding="utf-8")


def main():
    """命令行入口：解析参数并执行 enrich 流程。"""
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, help="输入的 JSONL 文件路径")
    parser.add_argument("--output", required=True, help="输出的 JSONL 文件路径")
    parser.add_argument("--summary", required=True, help="输出的摘要报告路径")
    parser.add_argument("--requirements-dir", default="data/generated_requirements_files", 
                        help="requirements 文件所在目录")
    parser.add_argument("--evidence-dir", default="data/build_evidence", 
                        help="构建证据文件所在目录（Dockerfile 和 CI 配置）")
    args = parser.parse_args()

    enrich(
        input_path=Path(args.input),
        output_path=Path(args.output),
        summary_path=Path(args.summary),
        requirements_dir=Path(args.requirements_dir),
        evidence_dir=Path(args.evidence_dir),
    )

    print("[OK] reachability v2 enriched")
    print(f"[OK] output: {args.output}")
    print(f"[OK] summary: {args.summary}")


if __name__ == "__main__":
    main()