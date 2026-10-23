import ast
import csv
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]

RISK_CARD_PATH = (
    ROOT
    / "output"
    / "auto_qwen37_100_temporal_risk_cards_v2.jsonl"
)

OUTPUT_PATH = (
    ROOT
    / "output"
    / "auto_qwen37_100_manifest_only_review.csv"
)


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    """读取 JSONL 文件。"""
    records: list[dict[str, Any]] = []

    with path.open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            line = line.strip()

            if not line:
                continue

            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON at {path}, line {line_number}: {exc}"
                ) from exc

    return records


def find_code_file(sample_id: str) -> Path | None:
    """
    根据 sample_id 在 data 目录中查找对应的 Python 文件。

    qwen37_100 的前50条和后50条代码目前位于不同目录，
    因此这里直接递归查找，不把目录写死。
    """
    matches = sorted((ROOT / "data").rglob(f"{sample_id}.py"))

    if not matches:
        return None

    return matches[0]


def extract_import_statements(code_path: Path | None) -> list[str]:
    """使用 AST 提取代码中的完整 import 语句。"""
    if code_path is None or not code_path.exists():
        return []

    code = code_path.read_text(encoding="utf-8")

    try:
        tree = ast.parse(code)
    except SyntaxError:
        return ["<syntax_error: unable to parse imports>"]

    imports: list[tuple[int, str]] = []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.Import, ast.ImportFrom)):
            continue

        statement = ast.get_source_segment(code, node)

        if statement is None:
            if isinstance(node, ast.Import):
                names = ", ".join(alias.name for alias in node.names)
                statement = f"import {names}"
            else:
                module = node.module or ""
                names = ", ".join(alias.name for alias in node.names)
                statement = f"from {module} import {names}"

        imports.append((getattr(node, "lineno", 0), statement))

    imports.sort(key=lambda item: item[0])

    return [statement for _, statement in imports]


def get_requirement_files(card: dict[str, Any]) -> list[str]:
    """从 Risk Card 中取得 requirements 证据文件。"""
    install_reachability = card.get("install_reachability", {})
    reachability_evidence = install_reachability.get("evidence", {})

    files = reachability_evidence.get("requirements_files", [])

    if not isinstance(files, list):
        return []

    return [str(item) for item in files]


def build_review_rows(
    cards: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """只导出 manifest-only mismatch Risk Card。"""
    rows: list[dict[str, Any]] = []

    mismatch_cards = [
        card
        for card in cards
        if card.get("type") == "dependency_declaration_mismatch"
        and card.get("subtype") == "manifest_only_without_import"
    ]

    for index, card in enumerate(mismatch_cards, start=1):
        sample_id = str(card.get("sample_id", ""))
        introduced_by = card.get("introduced_by", {})

        code_path = find_code_file(sample_id)
        import_statements = extract_import_statements(code_path)
        requirement_files = get_requirement_files(card)

        rows.append(
            {
                "index": index,
                "sample_id": sample_id,
                "prompt_id": card.get("prompt_id", ""),
                "package": introduced_by.get("entity", ""),
                "raw_requirement_name": introduced_by.get(
                    "raw_name",
                    "",
                ),
                "code_file": (
                    str(code_path.relative_to(ROOT))
                    if code_path is not None
                    else ""
                ),
                "requirements_files": " | ".join(requirement_files),
                "import_statements": " | ".join(import_statements),
                "current_risk_type": card.get("type", ""),
                "current_subtype": card.get("subtype", ""),
                "current_confidence": card.get("confidence", ""),
                "review_label": "",
                "review_reason": "",
                "suggested_mapping": "",
            }
        )

    return rows


def write_csv(rows: list[dict[str, Any]], path: Path) -> None:
    """以 UTF-8 BOM 编码写出，方便 Excel 正确显示。"""
    path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "index",
        "sample_id",
        "prompt_id",
        "package",
        "raw_requirement_name",
        "code_file",
        "requirements_files",
        "import_statements",
        "current_risk_type",
        "current_subtype",
        "current_confidence",
        "review_label",
        "review_reason",
        "suggested_mapping",
    ]

    with path.open(
        "w",
        encoding="utf-8-sig",
        newline="",
    ) as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    if not RISK_CARD_PATH.exists():
        raise FileNotFoundError(
            f"Risk Card file not found: {RISK_CARD_PATH}"
        )

    cards = load_jsonl(RISK_CARD_PATH)
    rows = build_review_rows(cards)
    write_csv(rows, OUTPUT_PATH)

    print("[OK] manifest-only review exported")
    print(f"[OK] input risk cards: {len(cards)}")
    print(f"[OK] mismatch review rows: {len(rows)}")
    print(f"[OK] output: {OUTPUT_PATH.relative_to(ROOT)}")


if __name__ == "__main__":
    main()