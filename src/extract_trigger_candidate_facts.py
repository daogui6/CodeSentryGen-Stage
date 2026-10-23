from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

SCHEMA_VERSION = "avcs_trigger_candidate_facts_v0.1"

EXTRACTOR_VERSION = "trigger_candidate_fact_extractor_v0.2"

DEFAULT_CORPUS = ROOT / "output" / "avcs_trigger_candidate_evidence_corpus_v0.json"

DEFAULT_OUTPUT = ROOT / "output" / "avcs_trigger_candidate_facts_v0.json"


STRUCTURED_RECORD_KIND = "structured_json_record"

PYTHON_SOURCE_KIND = "github_source_file_text"

PATCH_KIND = "github_commit_patch"


COMMON_BUILTIN_CALLS = {
    "bool",
    "bytes",
    "dict",
    "enumerate",
    "float",
    "int",
    "len",
    "list",
    "max",
    "min",
    "open",
    "print",
    "range",
    "repr",
    "set",
    "str",
    "sum",
    "super",
    "tuple",
    "type",
    "zip",
}


ASSIGNMENT_LITERAL_RE = re.compile(
    r"""
    (?<![A-Za-z0-9_])
    (?P<name>[A-Za-z_][A-Za-z0-9_]*)
    \s*=\s*
    (?P<literal>
        True
        |
        False
        |
        None
        |
        -?\d+(?:\.\d+)?
        |
        "(?:\\.|[^"\\])*"
        |
        '(?:\\.|[^'\\])*'
    )
    """,
    re.VERBOSE,
)


CALL_SYMBOL_RE = re.compile(
    r"""
    (?<![A-Za-z0-9_])
    (?P<symbol>
        [A-Za-z_][A-Za-z0-9_]*
        (?:
            \.
            [A-Za-z_][A-Za-z0-9_]*
        )*
    )
    \s*
    \(
    """,
    re.VERBOSE,
)


VERSION_RELATION_RE = re.compile(
    r"""
    (?P<operator>
        >=
        |
        <=
        |
        ==
        |
        !=
        |
        <
        |
        >
    )
    \s*
    v?
    (?P<version>
        \d+
        (?:\.\d+){1,3}
        (?:
            [A-Za-z]
            [A-Za-z0-9.\-_]*
        )?
    )
    """,
    re.VERBOSE,
)


FIXED_VERSION_PHRASE_RE = re.compile(
    r"""
    \b
    (?:
        fixed
        |
        patched
        |
        resolved
    )
    (?:
        \s+
        (?:
            in
            |
            by
            |
            with
        )
    )?
    \s+
    (?:
        version
        |
        release
    )?
    \s*
    v?
    (?P<version>
        \d+
        (?:\.\d+){1,3}
        (?:
            [A-Za-z]
            [A-Za-z0-9.\-_]*
        )?
    )
    \b
    """,
    re.VERBOSE | re.IGNORECASE,
)


DOTTED_SYMBOL_RE = re.compile(
    r"""
    ^
    [A-Za-z_][A-Za-z0-9_]*
    (?:
        \.
        [A-Za-z_][A-Za-z0-9_]*
    )+
    $
    """,
    re.VERBOSE,
)


CODE_SPAN_RE = re.compile(r"`(?P<code>[^`\r\n]+)`")


IDENTIFIER_MENTION_RE = re.compile(
    r"""
    (?<![A-Za-z0-9_])
    (?P<token>
        [A-Za-z_][A-Za-z0-9_]{2,}
        (?:
            \.
            [A-Za-z_][A-Za-z0-9_]*
        )*
    )
    (?![A-Za-z0-9_])
    """,
    re.VERBOSE,
)


RELEVANCE_STOPWORDS = {
    "args",
    "class",
    "close",
    "config",
    "data",
    "decode",
    "dump",
    "dumps",
    "encode",
    "error",
    "file",
    "get",
    "item",
    "items",
    "key",
    "keys",
    "load",
    "loads",
    "main",
    "method",
    "name",
    "object",
    "open",
    "options",
    "params",
    "path",
    "read",
    "release",
    "request",
    "response",
    "result",
    "self",
    "set",
    "status",
    "type",
    "url",
    "value",
    "version",
    "write",
}


PYTHON_RELEVANCE_METHOD = "cross_source_identifier_overlap_v0"


def clean_text(value: Any) -> str:
    return str(value if value is not None else "").strip()


def load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))

    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object: {path}")

    return data


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def sha256_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def stable_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def make_fact_id(
    source_key: str,
    evidence_unit_id: str,
    fact_kind: str,
    structured_value: Any,
    extraction_method: str,
) -> str:
    payload = stable_json(
        {
            "source_key": source_key,
            "evidence_unit_id": evidence_unit_id,
            "fact_kind": fact_kind,
            "structured_value": structured_value,
            "extraction_method": extraction_method,
        }
    )

    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]

    return "triggerfact_" + digest


def make_excerpt(
    text: str, start: int | None = None, end: int | None = None, max_chars: int = 240
) -> str:
    if start is not None and end is not None:
        left = max(0, start - 80)

        right = min(len(text), end + 120)

        excerpt = text[left:right]

    else:
        excerpt = text[:max_chars]

    excerpt = " ".join(excerpt.split())

    if len(excerpt) > max_chars:
        excerpt = excerpt[: max_chars - 3] + "..."

    return excerpt


def parse_literal_text(raw: str) -> Any:
    text = raw.strip()

    if text == "True":
        return True

    if text == "False":
        return False

    if text == "None":
        return None

    try:
        return ast.literal_eval(text)

    except (ValueError, SyntaxError):
        return text


def expr_symbol(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id

    if isinstance(node, ast.Attribute):
        parent = expr_symbol(node.value)

        if parent:
            return parent + "." + node.attr

        return node.attr

    return ""


def simple_ast_value(node: ast.AST) -> dict[str, Any] | None:
    if isinstance(node, ast.Constant):
        value = node.value

        if isinstance(value, (str, int, float, bool, type(None))):
            return {"value_kind": "literal", "value": value}

        return None

    if isinstance(node, (ast.Name, ast.Attribute)):
        symbol = expr_symbol(node)

        if symbol:
            return {"value_kind": "symbol", "symbol": symbol}

        return None

    if isinstance(node, ast.Call):
        symbol = expr_symbol(node.func)

        if symbol:
            return {"value_kind": "call", "call_symbol": symbol}

        return None

    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
        operand = simple_ast_value(node.operand)

        if (
            operand
            and operand.get("value_kind") == "literal"
            and isinstance(operand.get("value"), (int, float))
        ):
            value = operand["value"]

            if isinstance(node.op, ast.USub):
                value = -value

            return {"value_kind": "literal", "value": value}

    return None


class FactCollector:
    def __init__(self) -> None:
        self.facts: list[dict[str, Any]] = []

        self.fact_ids: set[str] = set()

    def add(
        self,
        *,
        entry: dict[str, Any],
        unit: dict[str, Any],
        fact_kind: str,
        structured_value: Any,
        extraction_method: str,
        confidence_level: str,
        confidence_basis: str,
        evidence_excerpt: str,
        line_number: int | None = None,
    ) -> None:
        source_key = clean_text(entry.get("source_key"))

        evidence_unit_id = clean_text(unit.get("unit_id"))

        fact_id = make_fact_id(
            source_key=source_key,
            evidence_unit_id=(evidence_unit_id),
            fact_kind=fact_kind,
            structured_value=(structured_value),
            extraction_method=(extraction_method),
        )

        if fact_id in self.fact_ids:
            return

        self.fact_ids.add(fact_id)

        fact: dict[str, Any] = {
            "fact_id": fact_id,
            "fact_kind": fact_kind,
            "candidate_status": "candidate",
            "review_required": True,
            "distribution": entry.get("distribution"),
            "vulnerability_ids": entry.get("vulnerability_ids", []),
            "structured_value": structured_value,
            "source_key": source_key,
            "source_id": entry.get("source_id"),
            "source_type": entry.get("source_type"),
            "evidence_unit_id": evidence_unit_id,
            "unit_kind": unit.get("unit_kind"),
            "text_sha256": unit.get("text_sha256"),
            "extractor": EXTRACTOR_VERSION,
            "extraction_method": extraction_method,
            "confidence_level": confidence_level,
            "confidence_basis": confidence_basis,
            "evidence_excerpt": evidence_excerpt,
            "evidence_locator": unit.get("locator", {}),
        }

        if line_number is not None:
            fact["line_number"] = line_number

        self.facts.append(fact)


def extract_osv_range_facts(
    *,
    entry: dict[str, Any],
    unit: dict[str, Any],
    collector: FactCollector,
    issues: list[dict[str, Any]],
) -> int:
    text = unit.get("text")

    if not isinstance(text, str):
        return 0

    try:
        record = json.loads(text)

    except json.JSONDecodeError as exc:
        issues.append(
            {
                "source_key": entry.get("source_key"),
                "evidence_unit_id": unit.get("unit_id"),
                "issue": "structured_record_json_parse_error",
                "detail": str(exc),
            }
        )

        return 0

    if not isinstance(record, dict):
        return 0

    affected_rows = record.get("affected", [])

    if not isinstance(affected_rows, list):
        return 0

    before = len(collector.facts)

    event_fact_map = {
        "introduced": "osv_introduced_version_candidate",
        "fixed": "osv_fixed_version_candidate",
        "last_affected": "osv_last_affected_version_candidate",
        "limit": "osv_limit_version_candidate",
    }

    for affected_index, affected in enumerate(affected_rows):
        if not isinstance(affected, dict):
            continue

        package = affected.get("package", {})

        if not isinstance(package, dict):
            package = {}

        package_name = clean_text(package.get("name"))

        ecosystem = clean_text(package.get("ecosystem"))

        ranges = affected.get("ranges", [])

        if not isinstance(ranges, list):
            continue

        for range_index, range_row in enumerate(ranges):
            if not isinstance(range_row, dict):
                continue

            range_type = clean_text(range_row.get("type"))

            events = range_row.get("events", [])

            if not isinstance(events, list):
                continue

            for event_index, event in enumerate(events):
                if not isinstance(event, dict):
                    continue

                for event_key, fact_kind in event_fact_map.items():
                    if event_key not in event:
                        continue

                    version = clean_text(event.get(event_key))

                    if not version:
                        continue

                    structured_value = {
                        "event": event_key,
                        "version": version,
                        "range_type": range_type,
                        "package_name": package_name,
                        "ecosystem": ecosystem,
                        "affected_index": affected_index,
                        "range_index": range_index,
                        "event_index": event_index,
                    }

                    collector.add(
                        entry=entry,
                        unit=unit,
                        fact_kind=(fact_kind),
                        structured_value=(structured_value),
                        extraction_method=("structured_osv_range_event"),
                        confidence_level=("high"),
                        confidence_basis=(
                            "Exact machine-readable OSV "
                            "range event; semantic role "
                            "is preserved from the "
                            "structured source."
                        ),
                        evidence_excerpt=(stable_json(event)),
                    )

    return len(collector.facts) - before


class PythonSourceVisitor(ast.NodeVisitor):
    def __init__(
        self,
        *,
        entry: dict[str, Any],
        unit: dict[str, Any],
        text: str,
        collector: FactCollector,
    ) -> None:
        self.entry = entry
        self.unit = unit
        self.text = text
        self.collector = collector

        self.scope: list[str] = []

        self.lines = text.splitlines()

    def current_function_symbol(self, name: str) -> str:
        if self.scope:
            return ".".join(self.scope + [name])

        return name

    def line_excerpt(self, lineno: int) -> str:
        if lineno < 1 or lineno > len(self.lines):
            return ""

        return self.lines[lineno - 1].strip()

    def add_parameter_default(
        self,
        *,
        function_symbol: str,
        parameter_name: str,
        default_node: ast.AST,
        lineno: int,
        parameter_kind: str,
    ) -> None:
        default = simple_ast_value(default_node)

        if default is None:
            return

        structured_value = {
            "function_symbol": function_symbol,
            "parameter_name": parameter_name,
            "parameter_kind": parameter_kind,
            "default": default,
        }

        self.collector.add(
            entry=self.entry,
            unit=self.unit,
            fact_kind=("python_parameter_default_candidate"),
            structured_value=(structured_value),
            extraction_method=("python_ast_function_signature"),
            confidence_level=("high"),
            confidence_basis=(
                "Python AST directly resolves "
                "a function parameter default; "
                "public API significance is not "
                "yet asserted."
            ),
            evidence_excerpt=(self.line_excerpt(lineno)),
            line_number=lineno,
        )

    def process_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        function_symbol = self.current_function_symbol(node.name)

        positional_args = list(node.args.posonlyargs) + list(node.args.args)

        defaults = list(node.args.defaults)

        if defaults:
            mapped_args = positional_args[-len(defaults) :]

            for arg, default in zip(mapped_args, defaults):
                self.add_parameter_default(
                    function_symbol=(function_symbol),
                    parameter_name=(arg.arg),
                    default_node=(default),
                    lineno=(node.lineno),
                    parameter_kind=("positional_or_keyword"),
                )

        for arg, default in zip(node.args.kwonlyargs, node.args.kw_defaults):
            if default is None:
                continue

            self.add_parameter_default(
                function_symbol=(function_symbol),
                parameter_name=(arg.arg),
                default_node=(default),
                lineno=(node.lineno),
                parameter_kind=("keyword_only"),
            )

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        self.scope.append(node.name)

        self.generic_visit(node)

        self.scope.pop()

        return None

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        if not node.name.startswith("_"):
            self.process_function(node)

        self.scope.append(node.name)

        self.generic_visit(node)

        self.scope.pop()

        return None

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        if not node.name.startswith("_"):
            self.process_function(node)

        self.scope.append(node.name)

        self.generic_visit(node)

        self.scope.pop()

        return None

    def visit_Call(self, node: ast.Call) -> Any:
        call_symbol = expr_symbol(node.func)

        if (
            call_symbol
            and call_symbol not in COMMON_BUILTIN_CALLS
            and not call_symbol.split(".")[-1].startswith("_")
        ):
            self.collector.add(
                entry=self.entry,
                unit=self.unit,
                fact_kind=("python_call_symbol_candidate"),
                structured_value={"call_symbol": call_symbol},
                extraction_method=("python_ast_call"),
                confidence_level=("high"),
                confidence_basis=(
                    "Python AST directly resolves "
                    "the syntactic call target; "
                    "runtime binding and security "
                    "meaning are not asserted."
                ),
                evidence_excerpt=(self.line_excerpt(node.lineno)),
                line_number=(node.lineno),
            )

            for keyword in node.keywords:
                keyword_name = keyword.arg

                if keyword_name is None:
                    continue

                value = simple_ast_value(keyword.value)

                if value is None:
                    continue

                value_kind = value.get("value_kind")

                if value_kind == "literal":
                    fact_kind = "python_keyword_literal_call_candidate"

                elif value_kind == "symbol":
                    fact_kind = "python_keyword_symbol_call_candidate"

                elif value_kind == "call":
                    fact_kind = "python_keyword_call_candidate"

                else:
                    continue

                self.collector.add(
                    entry=self.entry,
                    unit=self.unit,
                    fact_kind=(fact_kind),
                    structured_value={
                        "call_symbol": call_symbol,
                        "keyword_name": keyword_name,
                        "argument_value": value,
                    },
                    extraction_method=("python_ast_call_keyword"),
                    confidence_level=("high"),
                    confidence_basis=(
                        "Python AST directly resolves "
                        "the keyword argument syntax; "
                        "trigger semantics are not "
                        "asserted."
                    ),
                    evidence_excerpt=(self.line_excerpt(node.lineno)),
                    line_number=(node.lineno),
                )

        self.generic_visit(node)

        return None


def extract_python_source_facts(
    *,
    entry: dict[str, Any],
    unit: dict[str, Any],
    collector: FactCollector,
    issues: list[dict[str, Any]],
) -> int:
    text = unit.get("text")

    if not isinstance(text, str):
        return 0

    try:
        tree = ast.parse(text)

    except SyntaxError as exc:
        issues.append(
            {
                "source_key": entry.get("source_key"),
                "evidence_unit_id": unit.get("unit_id"),
                "issue": "python_source_ast_parse_error",
                "line": exc.lineno,
                "detail": str(exc),
            }
        )

        return 0

    before = len(collector.facts)

    visitor = PythonSourceVisitor(
        entry=entry, unit=unit, text=text, collector=collector
    )

    visitor.visit(tree)

    return len(collector.facts) - before


def extract_assignment_literals(
    *,
    entry: dict[str, Any],
    unit: dict[str, Any],
    collector: FactCollector,
    text: str,
    fact_kind: str,
    extraction_method: str,
    confidence_level: str,
    confidence_basis: str,
    patch_side: str | None = None,
    line_number: int | None = None,
) -> int:
    before = len(collector.facts)

    for match in ASSIGNMENT_LITERAL_RE.finditer(text):
        structured_value: dict[str, Any] = {
            "name": match.group("name"),
            "literal": parse_literal_text(match.group("literal")),
        }

        if patch_side is not None:
            structured_value["patch_side"] = patch_side

        collector.add(
            entry=entry,
            unit=unit,
            fact_kind=fact_kind,
            structured_value=(structured_value),
            extraction_method=(extraction_method),
            confidence_level=(confidence_level),
            confidence_basis=(confidence_basis),
            evidence_excerpt=(make_excerpt(text, match.start(), match.end())),
            line_number=(line_number),
        )

    return len(collector.facts) - before


def extract_call_symbols_from_text(
    *,
    entry: dict[str, Any],
    unit: dict[str, Any],
    collector: FactCollector,
    text: str,
    fact_kind: str,
    extraction_method: str,
    confidence_level: str,
    confidence_basis: str,
    patch_side: str | None = None,
    line_number: int | None = None,
) -> int:
    before = len(collector.facts)

    for match in CALL_SYMBOL_RE.finditer(text):
        symbol = match.group("symbol")

        if symbol in COMMON_BUILTIN_CALLS or symbol.split(".")[-1].startswith("_"):
            continue

        structured_value: dict[str, Any] = {"call_symbol": symbol}

        if patch_side is not None:
            structured_value["patch_side"] = patch_side

        collector.add(
            entry=entry,
            unit=unit,
            fact_kind=fact_kind,
            structured_value=(structured_value),
            extraction_method=(extraction_method),
            confidence_level=(confidence_level),
            confidence_basis=(confidence_basis),
            evidence_excerpt=(make_excerpt(text, match.start(), match.end())),
            line_number=(line_number),
        )

    return len(collector.facts) - before


def code_expression_fact_kind(relation: str, value_kind: str) -> str:
    return "code_expression_" + relation + "_" + value_kind + "_candidate"


def extract_code_expression_facts_from_snippet(
    *,
    entry: dict[str, Any],
    unit: dict[str, Any],
    collector: FactCollector,
    snippet: str,
    evidence_excerpt: str,
    line_number: int | None,
    expression_origin: str,
) -> int:
    code = snippet.strip()

    if not code:
        return 0

    if "(" not in code and "=" not in code:
        return 0

    try:
        tree = ast.parse(code)

    except SyntaxError:
        return 0

    before = len(collector.facts)

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            call_symbol = expr_symbol(node.func)

            if not call_symbol:
                continue

            for position, argument in enumerate(node.args):
                value = simple_ast_value(argument)

                if value is None:
                    continue

                value_kind = clean_text(value.get("value_kind"))

                if value_kind not in {"literal", "symbol", "call"}:
                    continue

                collector.add(
                    entry=entry,
                    unit=unit,
                    fact_kind=code_expression_fact_kind("positional", value_kind),
                    structured_value={
                        "call_symbol": call_symbol,
                        "position": position,
                        "argument_value": value,
                        "expression_origin": expression_origin,
                    },
                    extraction_method=("python_expression_ast"),
                    confidence_level="high",
                    confidence_basis=(
                        "Python AST directly resolves "
                        "a positional argument relation "
                        "from an explicit code expression "
                        "present in acquired evidence; "
                        "security meaning is not asserted."
                    ),
                    evidence_excerpt=evidence_excerpt,
                    line_number=line_number,
                )

            for keyword in node.keywords:
                if keyword.arg is None:
                    continue

                value = simple_ast_value(keyword.value)

                if value is None:
                    continue

                value_kind = clean_text(value.get("value_kind"))

                if value_kind not in {"literal", "symbol", "call"}:
                    continue

                collector.add(
                    entry=entry,
                    unit=unit,
                    fact_kind=code_expression_fact_kind("keyword", value_kind),
                    structured_value={
                        "call_symbol": call_symbol,
                        "keyword_name": keyword.arg,
                        "argument_value": value,
                        "expression_origin": expression_origin,
                    },
                    extraction_method=("python_expression_ast"),
                    confidence_level="high",
                    confidence_basis=(
                        "Python AST directly resolves "
                        "a keyword argument relation "
                        "from an explicit code expression "
                        "present in acquired evidence; "
                        "security meaning is not asserted."
                    ),
                    evidence_excerpt=evidence_excerpt,
                    line_number=line_number,
                )

        elif isinstance(node, ast.Assign):
            value = simple_ast_value(node.value)

            if value is None:
                continue

            value_kind = clean_text(value.get("value_kind"))

            if value_kind not in {"symbol", "call"}:
                continue

            for target in node.targets:
                target_symbol = expr_symbol(target)

                if not target_symbol:
                    continue

                collector.add(
                    entry=entry,
                    unit=unit,
                    fact_kind=code_expression_fact_kind("assignment", value_kind),
                    structured_value={
                        "target_symbol": target_symbol,
                        "assigned_value": value,
                        "expression_origin": expression_origin,
                    },
                    extraction_method=("python_expression_ast"),
                    confidence_level="high",
                    confidence_basis=(
                        "Python AST directly resolves "
                        "an assignment relation from "
                        "an explicit code expression "
                        "present in acquired evidence; "
                        "security meaning is not asserted."
                    ),
                    evidence_excerpt=evidence_excerpt,
                    line_number=line_number,
                )

    return len(collector.facts) - before


def extract_code_expression_facts_from_text(
    *,
    entry: dict[str, Any],
    unit: dict[str, Any],
    collector: FactCollector,
    text: str,
    expression_origin: str,
) -> int:
    before = len(collector.facts)

    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        cleaned = raw_line.strip()

        while cleaned.startswith(">"):
            cleaned = cleaned[1:].lstrip()

        if not cleaned:
            continue

        extract_code_expression_facts_from_snippet(
            entry=entry,
            unit=unit,
            collector=collector,
            snippet=cleaned,
            evidence_excerpt=raw_line.strip(),
            line_number=line_number,
            expression_origin=expression_origin,
        )

        for code_match in CODE_SPAN_RE.finditer(raw_line):
            code = code_match.group("code").strip()

            extract_code_expression_facts_from_snippet(
                entry=entry,
                unit=unit,
                collector=collector,
                snippet=code,
                evidence_excerpt=raw_line.strip(),
                line_number=line_number,
                expression_origin=expression_origin,
            )

    return len(collector.facts) - before


def extract_patch_facts(
    *, entry: dict[str, Any], unit: dict[str, Any], collector: FactCollector
) -> int:
    text = unit.get("text")

    if not isinstance(text, str):
        return 0

    before = len(collector.facts)

    for line_number, line in enumerate(text.splitlines(), start=1):
        if line.startswith("+++") or line.startswith("---"):
            continue

        if line.startswith("+"):
            patch_side = "added"

        elif line.startswith("-"):
            patch_side = "removed"

        else:
            continue

        content = line[1:]

        if not content.strip():
            continue

        extract_code_expression_facts_from_snippet(
            entry=entry,
            unit=unit,
            collector=collector,
            snippet=content,
            evidence_excerpt=content.strip(),
            line_number=line_number,
            expression_origin=("git_patch_" + patch_side),
        )

        extract_assignment_literals(
            entry=entry,
            unit=unit,
            collector=collector,
            text=content,
            fact_kind=("patch_assignment_literal_candidate"),
            extraction_method=("git_patch_assignment_regex"),
            confidence_level=("moderate"),
            confidence_basis=(
                "The value is explicitly present "
                "on an added or removed patch line; "
                "the semantic role of the change "
                "still requires review."
            ),
            patch_side=(patch_side),
            line_number=(line_number),
        )

        extract_call_symbols_from_text(
            entry=entry,
            unit=unit,
            collector=collector,
            text=content,
            fact_kind=("patch_call_symbol_candidate"),
            extraction_method=("git_patch_call_regex"),
            confidence_level=("moderate"),
            confidence_basis=(
                "The call-like symbol is explicitly "
                "present on an added or removed patch "
                "line; runtime binding and security "
                "meaning are not asserted."
            ),
            patch_side=(patch_side),
            line_number=(line_number),
        )

    return len(collector.facts) - before


def extract_text_version_facts(
    *, entry: dict[str, Any], unit: dict[str, Any], collector: FactCollector, text: str
) -> int:
    before = len(collector.facts)

    for match in VERSION_RELATION_RE.finditer(text):
        collector.add(
            entry=entry,
            unit=unit,
            fact_kind=("text_version_relation_candidate"),
            structured_value={
                "operator": match.group("operator"),
                "version": match.group("version"),
            },
            extraction_method=("text_version_relation_regex"),
            confidence_level=("moderate"),
            confidence_basis=(
                "An explicit version comparison "
                "appears in evidence text; whether "
                "it denotes package, API, trigger, "
                "or another scope remains unvalidated."
            ),
            evidence_excerpt=(make_excerpt(text, match.start(), match.end())),
        )

    for match in FIXED_VERSION_PHRASE_RE.finditer(text):
        collector.add(
            entry=entry,
            unit=unit,
            fact_kind=("text_fixed_version_phrase_candidate"),
            structured_value={"version": match.group("version")},
            extraction_method=("text_fixed_version_phrase_regex"),
            confidence_level=("moderate"),
            confidence_basis=(
                "Evidence text explicitly uses a "
                "fixed/patched/resolved phrase near "
                "a version; package scope and exact "
                "vulnerability linkage still require "
                "validation."
            ),
            evidence_excerpt=(make_excerpt(text, match.start(), match.end())),
        )

    return len(collector.facts) - before


def extract_code_span_facts(
    *, entry: dict[str, Any], unit: dict[str, Any], collector: FactCollector, text: str
) -> int:
    before = len(collector.facts)

    for code_match in CODE_SPAN_RE.finditer(text):
        code = code_match.group("code").strip()

        if not code:
            continue

        assignment_match = ASSIGNMENT_LITERAL_RE.fullmatch(code)

        if assignment_match is not None:
            collector.add(
                entry=entry,
                unit=unit,
                fact_kind=("text_code_assignment_literal_candidate"),
                structured_value={
                    "name": assignment_match.group("name"),
                    "literal": parse_literal_text(assignment_match.group("literal")),
                },
                extraction_method=("markdown_code_span_assignment"),
                confidence_level=("moderate"),
                confidence_basis=(
                    "The assignment-like expression "
                    "is explicitly isolated as a "
                    "Markdown code span; its trigger "
                    "role is not yet asserted."
                ),
                evidence_excerpt=(
                    make_excerpt(text, code_match.start(), code_match.end())
                ),
            )

        call_match = CALL_SYMBOL_RE.match(code)

        if call_match is not None:
            symbol = call_match.group("symbol")

            if symbol not in COMMON_BUILTIN_CALLS:
                collector.add(
                    entry=entry,
                    unit=unit,
                    fact_kind=("text_code_call_symbol_candidate"),
                    structured_value={"call_symbol": symbol},
                    extraction_method=("markdown_code_span_call"),
                    confidence_level=("moderate"),
                    confidence_basis=(
                        "A call-like symbol is "
                        "explicitly isolated as a "
                        "Markdown code span; API "
                        "binding and vulnerability "
                        "meaning remain unvalidated."
                    ),
                    evidence_excerpt=(
                        make_excerpt(text, code_match.start(), code_match.end())
                    ),
                )

        if DOTTED_SYMBOL_RE.fullmatch(code):
            collector.add(
                entry=entry,
                unit=unit,
                fact_kind=("text_code_dotted_symbol_candidate"),
                structured_value={"symbol": code},
                extraction_method=("markdown_code_span_dotted_symbol"),
                confidence_level=("moderate"),
                confidence_basis=(
                    "A dotted identifier is "
                    "explicitly isolated as a "
                    "Markdown code span; public API "
                    "status and trigger meaning are "
                    "not asserted."
                ),
                evidence_excerpt=(
                    make_excerpt(text, code_match.start(), code_match.end())
                ),
            )

    return len(collector.facts) - before


def extract_generic_text_facts(
    *, entry: dict[str, Any], unit: dict[str, Any], collector: FactCollector
) -> int:
    text = unit.get("text")

    if not isinstance(text, str):
        return 0

    before = len(collector.facts)

    extract_code_expression_facts_from_text(
        entry=entry,
        unit=unit,
        collector=collector,
        text=text,
        expression_origin="evidence_text",
    )

    extract_assignment_literals(
        entry=entry,
        unit=unit,
        collector=collector,
        text=text,
        fact_kind=("text_assignment_literal_candidate"),
        extraction_method=("text_assignment_regex"),
        confidence_level=("moderate"),
        confidence_basis=(
            "An explicit assignment-like token "
            "appears in evidence text; syntactic "
            "presence is confirmed but trigger "
            "semantics are unvalidated."
        ),
    )

    fact_policy = unit.get(
        "fact_policy",
        {},
    )

    if not isinstance(
            fact_policy,
            dict,
    ):
        fact_policy = {}

    allow_semantic_text_facts = (
            fact_policy.get(
                "allow_semantic_text_facts"
            )
            is not False
    )

    allow_version_facts = (
            fact_policy.get(
                "allow_version_facts"
            )
            is not False
    )

    if allow_version_facts:
        extract_text_version_facts(
            entry=entry,
            unit=unit,
            collector=collector,
            text=text,
        )

    if allow_semantic_text_facts:
        extract_code_span_facts(
            entry=entry,
            unit=unit,
            collector=collector,
            text=text,
        )

    return len(collector.facts) - before


def dict_rows(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []

    return [row for row in value if isinstance(row, dict)]


def is_python_release_source_unit(entry: dict[str, Any], unit: dict[str, Any]) -> bool:
    if clean_text(unit.get("unit_kind")) != PYTHON_SOURCE_KIND:
        return False

    if clean_text(entry.get("source_type")) != "upstream_release_source":
        return False

    locator = unit.get("locator", {})

    if not isinstance(locator, dict):
        return False

    source_path = clean_text(locator.get("path"))

    return Path(source_path).suffix.lower() == ".py"


def evidence_group_key(row: dict[str, Any]) -> str:
    distribution = clean_text(row.get("distribution")).lower()

    vulnerability_ids = row.get("vulnerability_ids", [])

    if not isinstance(vulnerability_ids, list):
        vulnerability_ids = []

    normalized_ids = sorted(
        {clean_text(value).lower() for value in vulnerability_ids if clean_text(value)}
    )

    return distribution + "::" + "|".join(normalized_ids)


def identifier_forms(value: Any) -> set[str]:
    text = clean_text(value)

    if not text:
        return set()

    forms = {text.lower()}

    parts = text.split(".")

    for part in parts:
        normalized = part.lower()

        if len(normalized) >= 4:
            forms.add(normalized)

    return {
        value for value in forms if len(value) >= 4 and value not in RELEVANCE_STOPWORDS
    }


def build_cross_source_support_index(
    entries: list[dict[str, Any]],
) -> dict[str, dict[str, set[str]]]:
    support_index: dict[str, dict[str, set[str]]] = {}

    for entry in entries:
        group_key = evidence_group_key(entry)

        group_index = support_index.setdefault(group_key, {})

        units = dict_rows(entry.get("evidence_units"))

        for unit in units:
            if is_python_release_source_unit(entry, unit):
                continue

            if clean_text(unit.get("unit_kind")) == PATCH_KIND:
                continue

            text = unit.get("text")

            if not isinstance(text, str):
                continue

            unit_id = clean_text(unit.get("unit_id"))

            if not unit_id:
                continue

            for match in IDENTIFIER_MENTION_RE.finditer(text):
                token = match.group("token")

                for form in identifier_forms(token):
                    group_index.setdefault(form, set()).add(unit_id)

    return support_index


def python_fact_anchor_tokens(fact: dict[str, Any]) -> set[str]:
    structured_value = fact.get("structured_value", {})

    if not isinstance(structured_value, dict):
        return set()

    fact_kind = clean_text(fact.get("fact_kind"))

    anchors: set[str] = set()

    def add_identifier(value: Any) -> None:
        anchors.update(identifier_forms(value))

    if fact_kind == ("python_parameter_default_candidate"):
        add_identifier(structured_value.get("parameter_name"))

        function_symbol = clean_text(structured_value.get("function_symbol"))

        if (
            "." in function_symbol
            or "_" in function_symbol
            or len(function_symbol) >= 8
        ):
            add_identifier(function_symbol)

        default = structured_value.get("default", {})

        if isinstance(default, dict):
            add_identifier(default.get("symbol"))

            add_identifier(default.get("call_symbol"))

    elif fact_kind == ("python_call_symbol_candidate"):
        call_symbol = clean_text(structured_value.get("call_symbol"))

        if "." in call_symbol or "_" in call_symbol or len(call_symbol) >= 8:
            add_identifier(call_symbol)

    elif fact_kind in {
        "python_keyword_literal_call_candidate",
        "python_keyword_symbol_call_candidate",
        "python_keyword_call_candidate",
    }:
        add_identifier(structured_value.get("keyword_name"))

        call_symbol = clean_text(structured_value.get("call_symbol"))

        if "." in call_symbol or "_" in call_symbol or len(call_symbol) >= 8:
            add_identifier(call_symbol)

        argument_value = structured_value.get("argument_value", {})

        if isinstance(argument_value, dict):
            add_identifier(argument_value.get("symbol"))

            add_identifier(argument_value.get("call_symbol"))

    return anchors


def apply_python_relevance_gate(
    facts: list[dict[str, Any]], support_index: dict[str, dict[str, set[str]]]
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    retained: list[dict[str, Any]] = []

    rejected_kind_counts: Counter[str] = Counter()

    rejected_source_counts: Counter[str] = Counter()

    raw_python_count = 0
    retained_python_count = 0

    for fact in facts:
        fact_kind = clean_text(fact.get("fact_kind"))

        if not fact_kind.startswith("python_"):
            retained.append(fact)
            continue

        raw_python_count += 1

        group_key = evidence_group_key(fact)

        group_support = support_index.get(group_key, {})

        anchors = python_fact_anchor_tokens(fact)

        matched_anchors = sorted(
            anchor for anchor in anchors if anchor in group_support
        )

        if not matched_anchors:
            rejected_kind_counts[fact_kind] += 1

            rejected_source_counts[clean_text(fact.get("source_key"))] += 1

            continue

        supporting_unit_ids: set[str] = set()

        for anchor in matched_anchors:
            supporting_unit_ids.update(group_support.get(anchor, set()))

        fact["relevance_gate"] = {
            "status": "supported",
            "method": PYTHON_RELEVANCE_METHOD,
            "matched_anchors": matched_anchors,
            "supporting_evidence_unit_ids": sorted(supporting_unit_ids),
            "support_is_cross_source": True,
            "support_excludes_python_release_source": True,
            "support_excludes_commit_patch": True,
        }

        retained.append(fact)

        retained_python_count += 1

    return (
        retained,
        {
            "method": PYTHON_RELEVANCE_METHOD,
            "raw_python_candidate_count": raw_python_count,
            "retained_python_candidate_count": retained_python_count,
            "rejected_python_candidate_count": (
                raw_python_count - retained_python_count
            ),
            "rejected_fact_kind_counts": dict(sorted(rejected_kind_counts.items())),
            "rejected_source_counts": dict(sorted(rejected_source_counts.items())),
        },
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Extract conservative atomic Trigger "
            "Evidence candidate facts from the "
            "unified candidate evidence corpus."
        )
    )

    parser.add_argument("--corpus", type=Path, default=DEFAULT_CORPUS)

    parser.add_argument("--out", type=Path, default=DEFAULT_OUTPUT)

    args = parser.parse_args()

    corpus = load_json(args.corpus)

    if corpus.get("status") != "resolved":
        print("[ERROR] Candidate evidence corpus " "must have status=resolved.")

        sys.exit(1)

    entries = dict_rows(corpus.get("entries"))

    support_index = build_cross_source_support_index(entries)

    collector = FactCollector()

    issues: list[dict[str, Any]] = []

    unit_count = 0
    units_with_candidates = 0

    extraction_method_counter: Counter[str] = Counter()

    source_counter: Counter[str] = Counter()

    unit_kind_counter: Counter[str] = Counter()

    for entry in entries:
        if entry.get("corpus_status") != "resolved":
            issues.append(
                {
                    "source_key": entry.get("source_key"),
                    "issue": "non_resolved_corpus_entry",
                }
            )

            continue

        units = dict_rows(entry.get("evidence_units"))

        for unit in units:
            unit_count += 1

            unit_kind = clean_text(unit.get("unit_kind"))

            before = len(collector.facts)

            if unit_kind == STRUCTURED_RECORD_KIND:
                extract_osv_range_facts(
                    entry=entry, unit=unit, collector=collector, issues=issues
                )

                extract_generic_text_facts(entry=entry, unit=unit, collector=collector)

            elif unit_kind == PYTHON_SOURCE_KIND:

                if is_python_release_source_unit(entry, unit):

                    extract_python_source_facts(
                        entry=entry, unit=unit, collector=collector, issues=issues
                    )

                else:

                    extract_generic_text_facts(
                        entry=entry, unit=unit, collector=collector
                    )

            elif unit_kind == PATCH_KIND:
                extract_patch_facts(entry=entry, unit=unit, collector=collector)
            else:
                extract_generic_text_facts(entry=entry, unit=unit, collector=collector)

            after = len(collector.facts)

            if after > before:
                units_with_candidates += 1

    raw_candidate_fact_count = len(collector.facts)

    collector.facts, relevance_gate_summary = apply_python_relevance_gate(
        collector.facts, support_index
    )

    collector.facts.sort(
        key=lambda fact: (
            clean_text(fact.get("distribution")).lower(),
            clean_text(fact.get("source_key")),
            clean_text(fact.get("evidence_unit_id")),
            clean_text(fact.get("fact_kind")),
            clean_text(fact.get("fact_id")),
        )
    )

    fact_kind_counter = Counter(
        clean_text(fact.get("fact_kind")) for fact in collector.facts
    )

    confidence_counter = Counter(
        clean_text(fact.get("confidence_level")) for fact in collector.facts
    )

    for fact in collector.facts:
        extraction_method_counter[clean_text(fact.get("extraction_method"))] += 1

        source_counter[clean_text(fact.get("source_key"))] += 1

        unit_kind_counter[clean_text(fact.get("unit_kind"))] += 1

    sources_with_candidates = len(
        [key for key, count in source_counter.items() if key and count > 0]
    )

    status = (
        "resolved"
        if not any(
            issue.get("issue") == "non_resolved_corpus_entry" for issue in issues
        )
        else "partial"
    )

    result = {
        "schema_version": SCHEMA_VERSION,
        "extractor_version": EXTRACTOR_VERSION,
        "status": status,
        "source_mode": (
            "deterministic_candidate_fact_" "extraction_from_evidence_corpus"
        ),
        "input": {
            "corpus_path": str(args.corpus.resolve()),
            "corpus_schema_version": corpus.get("schema_version"),
            "corpus_builder_version": corpus.get("builder_version"),
        },
        "semantic_boundary": {
            "consumes_candidate_evidence_corpus": True,
            "consumes_trigger_raw_ground_truth": False,
            "uses_llm_semantic_inference": False,
            "creates_candidate_facts": True,
            "creates_resolved_trigger_rules": False,
            "candidate_status_is_ground_truth": False,
            "all_candidates_require_review": True,
            "python_candidates_require_cross_source_identifier_support": True,
            "intended_next_stage": ("conservative_candidate_" "fact_validation"),
        },
        "supported_extraction": {
            "structured_osv_range_events": True,
            "python_ast_parameter_defaults": True,
            "python_ast_call_shapes": True,
            "evidence_code_expression_call_arguments": True,
            "evidence_code_expression_assignments": True,
            "git_patch_assignment_and_call_syntax": True,
            "explicit_text_assignment_literals": True,
            "explicit_text_version_relations": True,
            "markdown_code_spans": True,
            "natural_language_trigger_inference": False,
            "runtime_dataflow_inference": False,
            "cross_source_semantic_rule_composition": False,
        },
        "summary": {
            "corpus_entry_count": len(entries),
            "evidence_unit_count": unit_count,
            "units_with_candidates": units_with_candidates,
            "sources_with_candidates": sources_with_candidates,
            "raw_candidate_fact_count": raw_candidate_fact_count,
            "python_relevance_gate": relevance_gate_summary,
            "candidate_fact_count": len(collector.facts),
            "fact_kind_counts": dict(sorted(fact_kind_counter.items())),
            "confidence_counts": dict(sorted(confidence_counter.items())),
            "extraction_method_counts": dict(sorted(extraction_method_counter.items())),
            "unit_kind_candidate_counts": dict(sorted(unit_kind_counter.items())),
            "issue_count": len(issues),
        },
        "issues": issues,
        "facts": collector.facts,
    }

    write_json(args.out, result)

    print("=" * 60)

    print("TRIGGER CANDIDATE FACT EXTRACTION SUMMARY")

    print("=" * 60)

    print("[OK] schema:", SCHEMA_VERSION)

    print("[OK] status:", status)

    print("[OK] corpus entries:", len(entries))

    print("[OK] evidence units scanned:", unit_count)

    print("[OK] units with candidates:", units_with_candidates)

    print("[OK] sources with candidates:", sources_with_candidates)

    print("[OK] candidate facts:", len(collector.facts))

    print("[OK] extraction issues:", len(issues))

    print("[OK] saved:", args.out.resolve())

    if status not in {"resolved", "partial"}:
        sys.exit(1)


if __name__ == "__main__":
    main()
