from dataclasses import dataclass
from typing import Any

from pyparsing import Group, OneOrMore, Word, alphanums, alphas


@dataclass
class Grammar:
    name: str

    def __post_init__(self) -> None:
        identifier = Word(alphas, alphanums + "_")
        equals = "="
        value = Word(alphanums + "_-./")
        self.expression = OneOrMore(Group(identifier("key") + equals + value("value")))

    def parse_string(self, text: str) -> dict[str, Any]:
        parsed = self.expression.parse_string(text)
        result: dict[str, Any] = {}

        for item in parsed:
            result[item["key"]] = item["value"]

        return result


if __name__ == "__main__":
    grammar = Grammar("key_value_pairs")
    data = grammar.parse_string("name=alice age=20 role=admin")
    print(data)
