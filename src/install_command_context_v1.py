"""Bounded, non-executing workflow/shell extraction for dependency evidence.

YAML supplies step boundaries and decoded scalars.  The shell layer accepts
simple commands separated by newline, ``;`` or ``&&``; it never evaluates
variables, cwd changes, conditionals, substitutions or delegated scripts.
Unsupported install contexts are evidence of uncertainty, never root installs.
"""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from pathlib import Path

import yaml
from packaging.requirements import InvalidRequirement, Requirement
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode
from yaml.tokens import AliasToken, AnchorToken


@dataclass(frozen=True)
class RunPayload:
    text: str
    line: int
    working_directory: str | None = None
    reason: str | None = None
    shell: str = "bash"
    folded: bool = False


@dataclass(frozen=True)
class InstallInvocation:
    args: str
    line: int
    working_directory: str | None = None
    reason: str | None = None


def _mapping(node: Node | None) -> dict[str, Node]:
    if not isinstance(node, MappingNode):
        raise ValueError("workflow_mapping_not_resolved")
    result: dict[str, Node] = {}
    for key, value in node.value:
        if not isinstance(key, ScalarNode) or key.value in result:
            raise ValueError("workflow_duplicate_or_complex_key")
        if key.value == "<<":
            raise ValueError("workflow_merge_key_not_resolved")
        result[key.value] = value
    return result


def _scalar(node: Node | None) -> str | None:
    return node.value if isinstance(node, ScalarNode) else None


def _defaults_run(mapping: dict[str, Node]) -> dict[str, Node]:
    defaults = mapping.get("defaults")
    if defaults is None:
        return {}
    run = _mapping(defaults).get("run")
    return _mapping(run) if run is not None else {}


def workflow_payloads(text: str) -> tuple[list[RunPayload], str | None]:
    """Read only workflow job steps (or controlled root/composite steps)."""
    try:
        # Aliases/merges are deliberately outside the bounded extractor.
        if any(isinstance(token, (AliasToken, AnchorToken))
               for token in yaml.scan(text, Loader=yaml.BaseLoader)):
            return [], "workflow_alias_not_resolved"
        document = yaml.compose(text, Loader=yaml.BaseLoader)
        if document is None:
            return [], None
        top = _mapping(document)
        defaults = _defaults_run(top)
        jobs: list[dict[str, Node]] = []
        if "jobs" in top:
            jobs = [_mapping(job) for job in _mapping(top["jobs"]).values()]
        if "steps" in top:
            jobs.append(top)  # Existing controlled project snapshots.
        if "runs" in top:
            jobs.append(_mapping(top["runs"]))  # Local composite action.
        payloads: list[RunPayload] = []
        for job in jobs:
            steps = job.get("steps")
            if steps is None:
                continue
            if not isinstance(steps, SequenceNode):
                raise ValueError("workflow_steps_not_resolved")
            inherited = {**defaults, **_defaults_run(job)}
            for item in steps.value:
                step = _mapping(item)
                run = step.get("run")
                if run is None:
                    continue
                if not isinstance(run, ScalarNode):
                    raise ValueError("workflow_run_not_scalar")
                reason = None
                wd = _scalar(step.get("working-directory"))
                if "working-directory" in step and wd is None:
                    reason = "workflow_working_directory_not_scalar"
                elif wd is None and "working-directory" in inherited:
                    reason = "workflow_inherited_working_directory_not_resolved"
                if "if" in step or "if" in job:
                    reason = "conditional_workflow_step_not_resolved"
                shell_node = step.get("shell", inherited.get("shell"))
                shell = _scalar(shell_node) if shell_node is not None else "bash"
                runner = job.get("runs-on")
                if shell_node is None and runner is not None:
                    runner_text = _scalar(runner)
                    if runner_text is None or any(
                        marker in runner_text.lower() for marker in ("windows", "$", "{")
                    ):
                        shell = "unknown"
                payloads.append(RunPayload(
                    text=run.value,
                    line=run.start_mark.line + (2 if run.style in {"|", ">"} else 1),
                    working_directory=wd,
                    reason=reason,
                    shell=shell or "unknown",
                    folded=run.style == ">",
                ))
        return payloads, None
    except (yaml.YAMLError, ValueError, RecursionError) as exc:
        reason = str(exc) if isinstance(exc, ValueError) else "workflow_yaml_parse_error"
        return [], reason


def _install_args(tokens: list[str]) -> list[str] | None:
    if not tokens:
        return None
    executable = Path(tokens[0]).name
    if executable in {"pip", "pip3"} and tokens[1:2] == ["install"]:
        return tokens[2:]
    if re.fullmatch(r"python(?:3(?:\.\d+)?)?", executable):
        if tokens[1:4] == ["-m", "pip", "install"]:
            return tokens[4:]
    return None


def _contains_install(tokens: list[str]) -> bool:
    if tokens and "install" in tokens and (
        Path(tokens[0]).name in {"pip.exe", "python.exe", "python3.exe"}
        or any(marker in tokens[0] for marker in ("$", "`"))
    ):
        return True
    return any(re.search(r"\bpip(?:3)?\s+install\b", token)
               for token in tokens) or any(
        tokens[index].lower() in {"pip", "pip3"}
        and tokens[index + 1] == "install"
        for index in range(len(tokens) - 1)
    )


def _strip_shell_comments(text: str) -> str:
    """Remove comments while retaining newlines and quoted argument text."""
    result: list[str] = []
    quote: str | None = None
    escaped = False
    comment = False
    previous = "\n"
    for char in text:
        if comment:
            if char == "\n":
                comment = False
                result.append(char)
            else:
                result.append(" ")
        elif escaped:
            result.append(char)
            escaped = False
        elif char == "\\" and quote != "'":
            result.append(char)
            escaped = True
        elif char in {"'", '"'}:
            if quote is None:
                quote = char
            elif quote == char:
                quote = None
            result.append(char)
        elif char == "#" and quote is None and previous in " \t\r\n;&|()":
            comment = True
            result.append(" ")
        else:
            result.append(char)
        previous = char
    return "".join(result)


def _join_shell_continuations(text: str, first_line: int) -> tuple[str, list[int]]:
    """Join shell escapes outside single quotes, retaining physical positions."""
    characters: list[str] = []
    physical_lines: list[int] = []
    quote: str | None = None
    escaped = False
    line = first_line
    index = 0
    while index < len(text):
        char = text[index]
        if not escaped and quote != "'" and char == "\\":
            width = 3 if text[index:index + 3] == "\\\r\n" else 2
            if text[index:index + width] in {"\\\n", "\\\r\n"}:
                index += width
                line += 1
                continue
        characters.append(char)
        physical_lines.append(line)
        if escaped:
            escaped = False
        elif char == "\\" and quote != "'":
            escaped = True
        elif char in {"'", '"'}:
            if quote is None:
                quote = char
            elif quote == char:
                quote = None
        if char == "\n":
            line += 1
        index += 1
    return "".join(characters), physical_lines


def install_invocations(payload: RunPayload) -> list[InstallInvocation]:
    """Recognize command boundaries without running or expanding shell code."""
    text, physical_lines = _join_shell_continuations(payload.text, payload.line)
    text = _strip_shell_comments(text)
    commands: list[tuple[list[str], int]] = []
    current: list[str] = []
    line = payload.line
    start_line = line
    unsupported = False
    substitution = False
    grammar_state = "start"
    quote: str | None = None
    escaped = False
    index = 0
    try:
        while index < len(text):
            line = physical_lines[index]
            char = text[index]
            if (not current or all(item.isspace() for item in current)) and not char.isspace():
                start_line = line
            if escaped:
                current.append(char)
                escaped = False
            elif char == "\\" and quote != "'":
                current.append(char)
                escaped = True
            elif quote != "'" and (char == "`" or text[index:index + 2] == "$("):
                substitution = True
                current.append(char)
            elif char in {"'", '"'}:
                if quote is None:
                    quote = char
                elif quote == char:
                    quote = None
                current.append(char)
            elif quote is None and char in ";&|()<>\n":
                if current:
                    argv = shlex.split("".join(current), posix=True)
                    if argv:
                        commands.append((argv, start_line))
                        grammar_state = "command"
                    current = []
                if char == "&" and text[index:index + 2] == "&&":
                    if grammar_state != "command":
                        unsupported = True
                    grammar_state = "and"
                    index += 1
                elif char == ";":
                    if grammar_state != "command":
                        unsupported = True
                    grammar_state = "semi"
                elif char == "\n":
                    if grammar_state == "command":
                        grammar_state = "newline"
                elif char not in {";", "\n"}:
                    unsupported = True
                start_line = line + (1 if char == "\n" else 0)
            else:
                current.append(char)
            if char == "\n":
                line += 1
            index += 1
        if current:
            argv = shlex.split("".join(current), posix=True)
            if argv:
                commands.append((argv, start_line))
                grammar_state = "command"
    except ValueError:
        return [InstallInvocation("", payload.line, reason="shell_parse_error")]
    if grammar_state == "and":
        unsupported = True

    # Shell control structures/substitutions cannot be interpreted as flat
    # commands.  Reject the whole install payload before producing any facts.
    control_words = {"if", "then", "else", "elif", "fi", "for", "while", "until",
                     "do", "done", "case", "esac", "function", "{" , "}"}
    if any(command and command[0] in control_words for command, _ in commands):
        unsupported = True
    non_text_commands = [command for command, _ in commands
                         if command and command[0].lower() not in {"echo", "printf"}]
    has_install = any(_install_args(command) is not None or _contains_install(command)
                      for command in non_text_commands)
    # Substitutions execute even in echo/printf arguments. Printed literal
    # install text remains non-evidence; execution inside it is unresolved.
    if substitution and re.search(r"\bpip(?:3)?\b[\s\S]*\binstall\b", text):
        has_install = True
    if not has_install:
        return []
    if unsupported or substitution:
        return [InstallInvocation("", payload.line, reason="compound_shell_context_not_resolved")]
    if payload.shell not in {"bash", "sh", "bash --noprofile --norc -e -o pipefail {0}"}:
        return [InstallInvocation("", payload.line, reason="workflow_shell_not_supported")]

    result: list[InstallInvocation] = []
    context_reason = payload.reason
    cwd_line: int | None = None
    for command, command_line in commands:
        args = _install_args(command)
        if args is not None:
            reason = context_reason
            if cwd_line is not None:
                reason = ("multiline_shell_cd_not_resolved"
                          if cwd_line != command_line or payload.folded
                          else "inline_shell_cd_not_resolved")
            if any(any(marker in token for marker in ("$", "`", "%", "{", "}", "*", "?"))
                   for token in command):
                reason = reason or "dynamic_install_target_not_resolved"
            result.append(InstallInvocation(
                args=shlex.join(args), line=command_line,
                working_directory=payload.working_directory, reason=reason,
            ))
            continue
        if not command:
            continue
        name = command[0].lower()
        if any(any(marker in token for marker in ("$", "`")) for token in command):
            context_reason = "preceding_dynamic_shell_context_not_resolved"
        safe_set = name == "set" and bool(command[1:]) and all(
            token == "pipefail" or re.fullmatch(r"-[euox]+", token)
            for token in command[1:]
        )
        version_only = (
            command[1:] == ["--version"]
            and Path(command[0]).name in {"python", "python3", "pip", "pip3"}
        ) or (command[:3] == ["python", "-m", "pip"] and command[3:] == ["--version"])
        if name in {"cd", "pushd", "popd", "chdir", "set-location", "sl"} or (
            name in {"builtin", "command"} and len(command) > 1
            and command[1].lower() in {"cd", "pushd", "popd"}
        ):
            cwd_line = command_line
        elif name not in {"echo", "printf", "true", "pwd", ":"} and not safe_set and not version_only:
            # source/eval/functions/delegated shells may change command or cwd.
            context_reason = "preceding_shell_context_not_resolved"
            if _contains_install(command):
                result.append(InstallInvocation(
                    "", command_line, reason="delegated_install_command_not_resolved",
                ))
    return result


def install_operands(args: str) -> tuple[list[str], str | None]:
    """Split one pip argv into independently attributable install operands."""
    tokens = shlex.split(args, posix=True)
    result: list[str] = []
    switches = {"--upgrade", "-U", "--no-deps", "--force-reinstall", "--no-cache-dir",
                "--disable-pip-version-check", "-q", "-v", "--quiet", "--verbose"}
    value_options = {"--index-url", "--extra-index-url", "--trusted-host", "--find-links",
                     "--timeout", "--retries", "--progress-bar"}
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in switches:
            index += 1
            continue
        option, separator, value = token.partition("=")
        if option in {"-r", "--requirement", "-e", "--editable"} or option in value_options:
            if not separator:
                index += 1
                if index == len(tokens):
                    return [], "missing_pip_option_value"
                value = tokens[index]
            if option in {"-r", "--requirement"}:
                result.append("-r " + shlex.quote(value))
            elif option in {"-e", "--editable"}:
                result.append("-e " + shlex.quote(value))
            index += 1
            continue
        if token.startswith("-r") and len(token) > 2:
            result.append("-r " + shlex.quote(token[2:]))
        elif token.startswith("-e") and len(token) > 2:
            result.append("-e " + shlex.quote(token[2:]))
        elif token.startswith("-"):
            return [], "unsupported_pip_install_option"
        else:
            if index + 2 < len(tokens) and tokens[index + 1] == "@":
                token = " ".join(tokens[index:index + 3])
                index += 2
            if not (token == "." or token.startswith(("./", "../", "/"))):
                try:
                    Requirement(token)
                except InvalidRequirement:
                    return [], "unsupported_install_operand"
            result.append(shlex.quote(token))
        index += 1
    return (result, None) if result else ([], "empty_pip_install_targets")
