import re
from dataclasses import dataclass
from typing import Any


@dataclass
class RenderContext:
    values: dict[str, Any]

    def get(self, key: str, default: Any = "") -> Any:
        parts = key.split(".")
        current: Any = self.values

        for part in parts:
            if isinstance(current, dict):
                current = current.get(part, default)
            else:
                current = getattr(current, part, default)

        return current


class SimpleTemplateEngine:
    variable_pattern = re.compile(r"\{\{\s*(?P<name>[A-Za-z_][A-Za-z0-9_.]*)\s*\}\}")
    if_pattern = re.compile(
        r"\{% if (?P<condition>[A-Za-z_][A-Za-z0-9_.]*) %\}"
        r"(?P<body>.*?)"
        r"\{% endif %\}",
        re.DOTALL,
    )
    for_pattern = re.compile(
        r"\{% for (?P<item>[A-Za-z_][A-Za-z0-9_]*) in (?P<items>[A-Za-z_][A-Za-z0-9_.]*) %\}"
        r"(?P<body>.*?)"
        r"\{% endfor %\}",
        re.DOTALL,
    )

    def render(self, template: str, context: dict[str, Any]) -> str:
        render_context = RenderContext(context)
        rendered = self._render_blocks(template, render_context)
        return self._render_variables(rendered, render_context)

    def _render_blocks(self, template: str, context: RenderContext) -> str:
        previous = None
        rendered = template

        while previous != rendered:
            previous = rendered
            rendered = self._render_if_blocks(rendered, context)
            rendered = self._render_for_blocks(rendered, context)

        return rendered

    def _render_if_blocks(self, template: str, context: RenderContext) -> str:
        def replace(match: re.Match[str]) -> str:
            condition = match.group("condition")
            body = match.group("body")
            return body if context.get(condition) else ""

        return self.if_pattern.sub(replace, template)

    def _render_for_blocks(self, template: str, context: RenderContext) -> str:
        def replace(match: re.Match[str]) -> str:
            item_name = match.group("item")
            items_name = match.group("items")
            body = match.group("body")
            items = context.get(items_name, [])

            output = []
            for item in items:
                child_context = dict(context.values)
                child_context[item_name] = item
                output.append(self.render(body, child_context))

            return "".join(output)

        return self.for_pattern.sub(replace, template)

    def _render_variables(self, template: str, context: RenderContext) -> str:
        def replace(match: re.Match[str]) -> str:
            name = match.group("name")
            return str(context.get(name, ""))

        return self.variable_pattern.sub(replace, template)


if __name__ == "__main__":
    engine = SimpleTemplateEngine()

    template = """
Hello, {{ user.name }}!

{% if user.active %}
Your tasks:
{% for task in tasks %}
- {{ task }}
{% endfor %}
{% endif %}
"""

    result = engine.render(
        template,
        {
            "user": {"name": "Alice", "active": True},
            "tasks": ["Write tests", "Review code", "Deploy app"],
        },
    )

    print(result)
