import pyparsing as pp

class Grammar:
    def __init__(self, expression):
        self.expression = expression

    def parse_string(self, input_string, parse_all=True):
        return self.expression.parse_string(input_string, parse_all=parse_all)

greeting = pp.Literal("Hello")
name = pp.Word(pp.alphas)
grammar_expr = greeting + name

my_grammar = Grammar(grammar_expr)

input_str = "Hello World"
matches = my_grammar.parse_string(input_str)

print("Parsed matches:", matches)
