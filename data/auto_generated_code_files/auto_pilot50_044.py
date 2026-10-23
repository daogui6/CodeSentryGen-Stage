import pycparser
from pycparser import c_ast

class FuncDefVisitor(c_ast.NodeVisitor):
    def visit_FuncDef(self, node):
        print(f"Found function: {node.decl.name}")

def analyze_and_transform_c_code(c_code):
    ast = pycparser.parse_string(c_code)
    visitor = FuncDefVisitor()
    visitor.visit(ast)
    for node in ast.ext:
        if isinstance(node, c_ast.FuncDef):
            pass
    return ast

if __name__ == "__main__":
    c_code = """
    int add(int a, int b) {
        return a + b;
    }
    int main() {
        return add(1, 2);
    }
    """
    parsed_ast = analyze_and_transform_c_code(c_code)
    parsed_ast.show()
