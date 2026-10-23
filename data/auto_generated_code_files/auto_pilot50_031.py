import re
import json

class DotDict(dict):
    def __getattr__(self, key):
        try:
            return self[key]
        except KeyError:
            return None
    def __setattr__(self, key, value):
        self[key] = value

def _to_dotdict(obj):
    if isinstance(obj, dict):
        return DotDict({k: _to_dotdict(v) for k, v in obj.items()})
    elif isinstance(obj, list):
        return [_to_dotdict(i) for i in obj]
    return obj

class Template:
    def __init__(self, source):
        self.source = source
        self.code = self._compile(source)

    def _compile(self, source):
        tokens = re.split(r'(\{\{.*?\}\}|\{%.*?%\})', source)
        lines = ["def render():", "    _r = []"]
        indent = 1

        for token in tokens:
            if not token:
                continue
            if token.startswith('{{') and token.endswith('}}'):
                expr = token[2:-2].strip()
                lines.append("    " * indent + f"_r.append(str({expr}))")
            elif token.startswith('{%') and token.endswith('%}'):
                stmt = token[2:-2].strip()
                if stmt.startswith('if ') or stmt.startswith('for '):
                    lines.append("    " * indent + stmt + ":")
                    indent += 1
                elif stmt == 'else' or stmt.startswith('elif '):
                    indent -= 1
                    lines.append("    " * indent + stmt + ":")
                    indent += 1
                elif stmt == 'endif' or stmt == 'endfor':
                    indent -= 1
                else:
                    lines.append("    " * indent + stmt)
            else:
                lines.append("    " * indent + f"_r.append({json.dumps(token)})")

        lines.append("    " * indent + "return ''.join(_r)")
        return "\n".join(lines)

    def render(self, context=None):
        if context is None:
            context = {}
        namespace = _to_dotdict(context)
        namespace['len'] = len
        namespace['range'] = range
        namespace['str'] = str
        namespace['int'] = int
        namespace['float'] = float
        namespace['True'] = True
        namespace['False'] = False
        namespace['None'] = None

        exec(self.code, namespace)
        return namespace['render']()
