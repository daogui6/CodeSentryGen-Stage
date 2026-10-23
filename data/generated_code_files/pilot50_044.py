import ast
from dataclasses import dataclass


@dataclass
class CFunction:
    return_type: str
    name: str
    parameters: list[str]


class CStringVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.string_literals: list[str] = []

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str):
            self.string_literals.append(node.value)


def extract_c_like_function_signatures(source: str) -> list[CFunction]:
    functions: list[CFunction] = []

    for line in source.splitlines():
        line = line.strip()
        if not line.endswith("{") and not line.endswith(";"):
            continue

        signature = line.rstrip("{;").strip()
        if "(" not in signature or ")" not in signature:
            continue

        before_params, params_text = signature.split("(", 1)
        params_text = params_text.rsplit(")", 1)[0]

        parts = before_params.split()
        if len(parts) < 2:
            continue

        return_type = " ".join(parts[:-1])
        name = parts[-1]
        parameters = [param.strip() for param in params_text.split(",") if param.strip()]

        functions.append(CFunction(return_type, name, parameters))

    return functions


def parse_python_source_containing_c_string(source: str) -> list[str]:
    tree = ast.parse(source)
    visitor = CStringVisitor()
    visitor.visit(tree)
    return visitor.string_literals


if __name__ == "__main__":
    python_source = '''
c_code = """
int add(int a, int b) {
    return a + b;
}

void log_message(const char *message);
"""
'''

    strings = parse_python_source_containing_c_string(python_source)

    for text in strings:
        functions = extract_c_like_function_signatures(text)
        for function in functions:
            print(function)
