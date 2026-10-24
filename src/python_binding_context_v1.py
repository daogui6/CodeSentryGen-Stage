"""Conservative lexical and source-order bindings for Python API evidence.

This is a bounded static resolver, not execution or interprocedural analysis.
Only unconditional imports, proved literal module loads, simple aliases and
direct factory assignments are resolved. Conditional writes, affected dynamic
namespace mutation and unstable free variables remain unknown. Nested imports
never become module globals.
"""
from __future__ import annotations

import ast
import importlib.util
from dataclasses import dataclass, field
from typing import Any, Callable


def _position(node: ast.AST, *, end: bool = False) -> tuple[int, int]:
    prefix = "end_" if end else ""
    return (int(getattr(node, prefix + "lineno", 0) or 0),
            int(getattr(node, prefix + "col_offset", 0) or 0))


def _root(node: ast.AST) -> str | None:
    while isinstance(node, (ast.Attribute, ast.Subscript)):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


@dataclass
class Binding:
    position: tuple[int, int]
    kind: str
    symbol: str = ""
    value: ast.AST | None = None
    conditional: bool = False


@dataclass
class Scope:
    kind: str
    parent: Scope | None = None
    entry: tuple[int, int] = (0, 0)
    bindings: dict[str, list[Binding]] = field(default_factory=dict)
    declarations: set[str] = field(default_factory=set)
    global_names: set[str] = field(default_factory=set)
    unstable_names: set[str] = field(default_factory=set)
    attribute_mutations: set[str] = field(default_factory=set)
    barriers: list[tuple[int, int]] = field(default_factory=list)
    mutations: list[tuple[tuple[int, int], tuple[str, str]]] = field(default_factory=list)


class _Collector(ast.NodeVisitor):
    def __init__(self, *, postponed_annotations: bool = False) -> None:
        self.scope = Scope("module")
        self.calls: dict[ast.Call, Scope] = {}
        self.possible_imports: dict[str, set[str]] = {}
        self.possible_producers: dict[str, set[str]] = {}
        self.possible_aliases: dict[str, set[str]] = {}
        self.conditional = False
        self.postponed_annotations = postponed_annotations
        self.non_runtime_annotation_calls: set[ast.Call] = set()
        self.runtime_annotation_calls: set[ast.Call] = set()

    def _annotation(self, node: ast.AST | None, *, runtime: bool = True) -> None:
        if node is None:
            return
        if self.postponed_annotations or not runtime:
            # Stringized and local-variable annotations are not evaluated.
            self.non_runtime_annotation_calls.update(
                item for item in ast.walk(node) if isinstance(item, ast.Call)
            )
        else:
            self.runtime_annotation_calls.update(
                item for item in ast.walk(node) if isinstance(item, ast.Call)
            )
            self.visit(node)

    def bind(self, name: str, node: ast.AST, kind: str = "unknown",
             symbol: str = "", value: ast.AST | None = None) -> None:
        binding = Binding(_position(node, end=True), kind, symbol, value, self.conditional)
        self.scope.bindings.setdefault(name, []).append(binding)
        if kind in {"module", "symbol"}:
            self.possible_imports.setdefault(name, set()).add(symbol.split(".")[0])
        if isinstance(value, ast.Call) and _root(value.func):
            self.possible_producers.setdefault(name, set()).add(_root(value.func) or "")
        if kind == "alias" and value is not None and _root(value):
            self.possible_aliases.setdefault(name, set()).add(_root(value) or "")

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.bind(node.id, node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            name = alias.asname or alias.name.split(".")[0]
            self.bind(name, node, "module", alias.name if alias.asname else name)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            if alias.name == "*":
                self.scope.barriers.append(_position(node, end=True))
                continue
            name = alias.asname or alias.name
            if node.level or not node.module:
                self.bind(name, node, "local")
            else:
                self.bind(name, node, "symbol", node.module + "." + alias.name)

    def visit_Call(self, node: ast.Call) -> None:
        self.calls[node] = self.scope
        self.generic_visit(node)
        # No imported binding is provable past arbitrary namespace mutation.
        if isinstance(node.func, ast.Name) and node.func.id in {"exec", "eval"}:
            self.scope.barriers.append(_position(node, end=True))
        if _root(node.func) in {"globals", "locals", "vars"}:
            self.scope.barriers.append(_position(node, end=True))

    def _assign(self, targets: list[ast.AST], value: ast.AST | None,
                node: ast.AST) -> None:
        if value is not None:
            self.visit(value)
        for target in targets:
            if isinstance(target, ast.Name):
                kind = ("receiver" if isinstance(value, ast.Call) else
                        "alias" if isinstance(value, (ast.Name, ast.Attribute)) else "unknown")
                self.bind(target.id, node, kind, value=value if kind != "unknown" else None)
            else:
                self.visit(target)
                # Mutating imported attributes invalidates later API identity.
                name = _root(target)
                if name:
                    self.bind(name, node)
                    if isinstance(target, (ast.Attribute, ast.Subscript)):
                        self.scope.attribute_mutations.add(name)
                        self.scope.unstable_names.add(name)

    def visit_Assign(self, node: ast.Assign) -> None:
        self._assign(node.targets, node.value, node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self._assign([node.target], node.value, node)
        elif isinstance(node.target, ast.Name) and self.scope.kind == "function":
            # A local annotation still creates a Python local name.
            self.bind(node.target.id, node)
        elif not isinstance(node.target, ast.Name):
            # Attribute/subscript targets can evaluate calls even without a
            # value. They do not create a local binding for the base name.
            self.visit(node.target)
        self._annotation(node.annotation, runtime=self.scope.kind != "function")

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.visit(node.value)
        self._assign([node.target], None, node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.visit(node.value)
        previous = self.scope
        while self.scope.kind == "comprehension" and self.scope.parent is not None:
            self.scope = self.scope.parent
        self._assign([node.target], None, node)
        self.scope = previous

    def visit_Delete(self, node: ast.Delete) -> None:
        self._assign(node.targets, None, node)

    def visit_Global(self, node: ast.Global) -> None:
        self.scope.declarations.update(node.names)
        self.scope.global_names.update(node.names)

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
        self.scope.declarations.update(node.names)

    def _child(self, kind: str, node: ast.AST, args: ast.arguments | None,
               body: list[ast.AST]) -> None:
        parent, conditional = self.scope, self.conditional
        self.scope = Scope(kind, parent, _position(node))
        self.conditional = False
        if args is not None:
            params = [*args.posonlyargs, *args.args, *args.kwonlyargs]
            params += [item for item in (args.vararg, args.kwarg) if item is not None]
            for param in params:
                self.scope.bindings.setdefault(param.arg, []).append(Binding((-1, -1), "parameter"))
        for item in body:
            self.visit(item)
        for name in self.scope.declarations.intersection(self.scope.bindings):
            target = parent
            if name in self.scope.global_names:
                while target.parent is not None:
                    target = target.parent
            else:
                while target.parent is not None and (
                    target.kind == "class" or name not in target.bindings
                ):
                    target = target.parent
            target.unstable_names.add(name)
        for name in self.scope.attribute_mutations:
            target = parent
            while target.parent is not None and name not in target.bindings:
                target = target.parent
            if name in target.bindings:
                target.unstable_names.add(name)
        self.scope, self.conditional = parent, conditional

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for item in [*node.decorator_list, *node.args.defaults,
                     *[value for value in node.args.kw_defaults if value is not None]]:
            self.visit(item)
        params = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
        params += [item for item in (node.args.vararg, node.args.kwarg) if item is not None]
        for param in params:
            self._annotation(param.annotation)
        self._annotation(node.returns)
        self.bind(node.name, node)
        self._child("function", node, node.args, list(node.body))

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Lambda(self, node: ast.Lambda) -> None:
        for item in [*node.args.defaults, *[v for v in node.args.kw_defaults if v is not None]]:
            self.visit(item)
        self._child("function", node, node.args, [node.body])

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for item in [*node.decorator_list, *node.bases, *[kw.value for kw in node.keywords]]:
            self.visit(item)
        self.bind(node.name, node)
        self._child("class", node, None, list(node.body))

    def _conditional(self, node: ast.AST) -> None:
        previous = self.conditional
        self.conditional = True
        self.generic_visit(node)
        self.conditional = previous

    visit_If = _conditional
    visit_For = _conditional
    visit_AsyncFor = _conditional
    visit_While = _conditional
    visit_With = _conditional
    visit_AsyncWith = _conditional
    visit_Try = _conditional
    visit_TryStar = _conditional
    visit_Match = _conditional

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.type is not None:
            self.visit(node.type)
        if node.name:
            self.scope.bindings.setdefault(node.name, []).append(
                Binding(_position(node), "unknown", conditional=True))
        for item in node.body:
            self.visit(item)

    def visit_MatchAs(self, node: ast.MatchAs) -> None:
        if node.name:
            self.bind(node.name, node)
        self.generic_visit(node)

    def visit_MatchStar(self, node: ast.MatchStar) -> None:
        if node.name:
            self.bind(node.name, node)

    def visit_MatchMapping(self, node: ast.MatchMapping) -> None:
        if node.rest:
            self.bind(node.rest, node)
        self.generic_visit(node)

    def _comprehension(self, node: ast.AST) -> None:
        generators = node.generators
        self.visit(generators[0].iter)
        parent, previous = self.scope, self.conditional
        self.scope = Scope("comprehension", parent, _position(node))
        self.conditional = True
        for index, generator in enumerate(generators):
            self.visit(generator.target)
            if index:
                self.visit(generator.iter)
            for condition in generator.ifs:
                self.visit(condition)
        for name in ("elt", "key", "value"):
            if hasattr(node, name):
                self.visit(getattr(node, name))
        self.scope, self.conditional = parent, previous

    visit_ListComp = _comprehension
    visit_SetComp = _comprehension
    visit_DictComp = _comprehension
    visit_GeneratorExp = _comprehension


class BindingContexts:
    def __init__(self, tree: ast.AST, resolve: Callable[..., Any] | None = None,
                 shape: Callable[..., Any] | None = None, source_code: str = "") -> None:
        postponed_annotations = isinstance(tree, ast.Module) and any(
            isinstance(node, ast.ImportFrom) and node.module == "__future__"
            and any(alias.name == "annotations" for alias in node.names)
            for node in tree.body
        )
        self.collector = _Collector(postponed_annotations=postponed_annotations)
        self.collector.visit(tree)
        self.resolve = resolve
        self.shape = shape
        self.source_code = source_code
        self.cache: dict[ast.Call, tuple[dict, dict, dict]] = {}
        self.mutation_calls: set[ast.Call] = set()
        self._apply_call_mutations()

    def _builtin_available(self, scope: Scope, name: str, position: tuple[int, int]) -> bool:
        inherited = False
        while scope is not None:
            if name in scope.bindings or name in scope.declarations:
                return False
            if (inherited and scope.barriers) or any(p < position for p in scope.barriers):
                return False
            if inherited and any(ref == ("module", "builtins") for _, ref in scope.mutations):
                return False
            if any(p < position and ref == ("module", "builtins") for p, ref in scope.mutations):
                return False
            inherited = inherited or scope.kind in {"function", "comprehension"}
            position = scope.entry if inherited else position
            scope = scope.parent
        return True

    def _symbol(self, scope: Scope, node: ast.AST, position: tuple[int, int],
                seen: frozenset[int] = frozenset()) -> str | None:
        if isinstance(node, ast.Attribute):
            base = self._symbol(scope, node.value, position, seen)
            return base + "." + node.attr if base else None
        if not isinstance(node, ast.Name):
            return None
        binding = self._binding(scope, node.id, position)
        if binding is None:
            if node.id in {"__import__", "setattr", "delattr", "object", "type"} and self._builtin_available(scope, node.id, position):
                return "builtins." + node.id
            return None
        if id(binding) in seen:
            return None
        if binding.kind in {"module", "symbol"}:
            if self._reference_mutated(scope, ("module", binding.symbol.split(".")[0]), position):
                return None
            return binding.symbol
        if binding.kind == "alias" and binding.value is not None:
            ref = self._reference(scope, node, position)
            if ref is not None and self._reference_mutated(scope, ref, position):
                return None
            return self._symbol(scope, binding.value, binding.position, seen | {id(binding)})
        if binding.kind == "receiver" and isinstance(binding.value, ast.Call):
            dynamic = self.dynamic_import(binding.value)
            if dynamic and dynamic["status"] == "resolved":
                module = dynamic["returned_module"]
                if not self._reference_mutated(scope, ("module", module.split(".")[0]), position):
                    return module
        return None

    def _possible_symbols(self, node: ast.AST, seen: frozenset[str] = frozenset()) -> set[str]:
        """Candidate identities are diagnostics, never confirmed bindings."""
        if isinstance(node, ast.Attribute):
            return {value + "." + node.attr for value in self._possible_symbols(node.value, seen)}
        if not isinstance(node, ast.Name) or node.id in seen:
            return set()
        result = {"builtins." + node.id} if node.id in {
            "__import__", "setattr", "delattr", "object", "type"
        } else set()
        scopes = {id(scope): scope for scope in self.collector.calls.values()}
        for scope in scopes.values():
            for binding in scope.bindings.get(node.id, []):
                if binding.kind in {"module", "symbol"}:
                    result.add(binding.symbol)
                elif binding.kind == "alias" and binding.value is not None:
                    result.update(self._possible_symbols(binding.value, seen | {node.id}))
                elif binding.kind == "receiver" and isinstance(binding.value, ast.Call):
                    loaders = self._possible_symbols(binding.value.func, seen | {node.id})
                    name = binding.value.args[0] if binding.value.args else next(
                        (kw.value for kw in binding.value.keywords if kw.arg == "name"), None)
                    if isinstance(name, ast.Constant) and isinstance(name.value, str) and all(
                        part.isidentifier() for part in name.value.split(".")
                    ):
                        if "importlib.import_module" in loaders:
                            result.add(name.value)
                        if "builtins.__import__" in loaders:
                            result.update({name.value, name.value.split(".")[0]})
        return result

    def dynamic_import(self, node: ast.Call) -> dict[str, Any] | None:
        if node in self.collector.non_runtime_annotation_calls:
            return None
        scope, position = self.collector.calls[node], _position(node)
        symbol = self._symbol(scope, node.func, position)
        if node in self.collector.runtime_annotation_calls:
            root = _root(node.func)
            ref = self._reference(scope, node.func, position)
            if (root and root not in {"__import__"}
                    and self._binding(scope, root, position, inherited=True) is None
                    or ref is not None and self._reference_mutated(scope, ref, (10**9, 0))):
                symbol = None
        # An obscured loader is uncertainty, never proof of a loaded package.
        loaders = {"importlib.import_module", "builtins.__import__"}
        if symbol not in loaders and not self._possible_symbols(node.func).intersection(loaders):
            return None
        name_node = node.args[0] if node.args and not isinstance(node.args[0], ast.Starred) else next(
            (kw.value for kw in node.keywords if kw.arg == "name"), None)
        name = name_node.value if isinstance(name_node, ast.Constant) and isinstance(name_node.value, str) else None
        result = {"status": "unresolved", "reason": "dynamic_import_name_or_loader_unresolved",
                  "requested_module": name, "returned_module": "", "line": node.lineno,
                  "column": node.col_offset + 1, "unresolved_scope": "sample"}
        if symbol not in loaders or not name:
            return result
        if any(isinstance(arg, ast.Starred) for arg in node.args) or any(kw.arg is None for kw in node.keywords):
            return result
        parameters = (("name", "package") if symbol == "importlib.import_module" else
                      ("name", "globals", "locals", "fromlist", "level"))
        keyword_names = [kw.arg for kw in node.keywords]
        if (len(node.args) > len(parameters) or len(keyword_names) != len(set(keyword_names))
                or any(key not in parameters or key in parameters[:len(node.args)] for key in keyword_names)):
            return result
        if symbol == "importlib.import_module":
            if name.startswith("."):
                package_node = node.args[1] if len(node.args) > 1 else next(
                    (kw.value for kw in node.keywords if kw.arg == "package"), None)
                if not isinstance(package_node, ast.Constant) or not isinstance(package_node.value, str):
                    return result
                try:
                    name = importlib.util.resolve_name(name, package_node.value)
                except (ImportError, ValueError):
                    return result
            returned = name
        else:
            level_node = node.args[4] if len(node.args) > 4 else next(
                (kw.value for kw in node.keywords if kw.arg == "level"), ast.Constant(0))
            if not isinstance(level_node, ast.Constant) or level_node.value != 0:
                return result  # Relative __import__ requires runtime globals.
            fromlist_node = node.args[3] if len(node.args) > 3 else next(
                (kw.value for kw in node.keywords if kw.arg == "fromlist"), ast.Tuple(elts=[]))
            try:
                fromlist = ast.literal_eval(fromlist_node)
            except (ValueError, TypeError):
                return result
            if not isinstance(fromlist, (list, tuple)) or not all(isinstance(x, str) for x in fromlist):
                return result
            returned = name if fromlist else name.split(".")[0]
        if not all(part.isidentifier() for part in name.split(".")):
            return result
        result.update(status="resolved", reason="literal_module_load", import_path=name,
                      returned_module=returned)
        result.pop("unresolved_scope")
        return result

    def _reference(self, scope: Scope, node: ast.AST, position: tuple[int, int],
                   seen: frozenset[int] = frozenset()) -> tuple[str, str] | None:
        if isinstance(node, ast.Call):
            dynamic = self.dynamic_import(node)
            return ("module", dynamic["returned_module"].split(".")[0]) if dynamic and dynamic["status"] == "resolved" else None
        name = _root(node)
        if not name:
            return None
        binding = self._binding(scope, name, position)
        if binding is None or id(binding) in seen:
            return None
        if binding.kind in {"module", "symbol"}:
            return "module", binding.symbol.split(".")[0]
        if binding.kind == "alias" and binding.value is not None:
            return self._reference(scope, binding.value, binding.position, seen | {id(binding)})
        if binding.kind == "receiver" and isinstance(binding.value, ast.Call):
            dynamic = self.dynamic_import(binding.value)
            if dynamic and dynamic["status"] == "resolved":
                return "module", dynamic["returned_module"].split(".")[0]
            return "receiver", str(id(binding.value))
        return None

    def _reference_mutated(self, scope: Scope, ref: tuple[str, str], position: tuple[int, int]) -> bool:
        inherited = False
        while scope is not None:
            if any(target == ref and (inherited or at < position) for at, target in scope.mutations):
                return True
            inherited = inherited or scope.kind in {"function", "comprehension"}
            position = scope.entry if inherited else position
            scope = scope.parent
        return False

    def _apply_call_mutations(self) -> None:
        for node, scope in sorted(self.collector.calls.items(), key=lambda item: _position(item[0])):
            if node in self.collector.non_runtime_annotation_calls:
                continue
            symbol = self._symbol(scope, node.func, _position(node))
            targets = []
            setters = {"builtins.setattr", "builtins.delattr", "builtins.object.__setattr__",
                       "builtins.object.__delattr__", "builtins.type.__setattr__", "builtins.type.__delattr__"}
            if symbol in setters or self._possible_symbols(node.func).intersection(setters):
                target = node.args[0] if node.args else next((kw.value for kw in node.keywords if kw.arg in {"object", "obj"}), None)
                if target is not None:
                    targets = [(scope, target, _position(node))]
            else:
                targets = self._bound_mutation_targets(scope, node.func, _position(node))
            if not targets:
                continue
            self.mutation_calls.add(node)
            for captured_scope, target, captured_at in targets:
                refs = self._mutation_target_references(captured_scope, target, captured_at)
                for ref in sorted(refs):
                    # The target is captured at alias creation; the mutation
                    # itself takes effect at this call, preserving earlier proof.
                    mutation_scope = scope
                    # Class bodies execute in their enclosing control flow;
                    # their object mutations outlive the class-local namespace.
                    while mutation_scope.kind == "class" and mutation_scope.parent is not None:
                        mutation_scope = mutation_scope.parent
                    mutation_scope.mutations.append((_position(node, end=True), ref))
                    if mutation_scope.kind in {"function", "comprehension"}:
                        parent = mutation_scope.parent
                        while parent is not None:
                            for name in parent.bindings:
                                if self._reference(parent, ast.Name(id=name), (10**9, 0)) == ref:
                                    parent.unstable_names.add(name)
                            parent = parent.parent
                if not refs and _root(target) is None:
                    scope.barriers.append(_position(node, end=True))

    def _mutation_bindings(self, scope: Scope, name: str, position: tuple[int, int],
                           *, inherited: bool = False) -> list[tuple[Scope, Binding]]:
        """Lexical may-bindings for invalidation, never positive API proof."""
        binding = self._binding(scope, name, position, inherited=inherited)
        if binding is not None:
            owner = scope
            while owner is not None:
                if any(binding is item for item in owner.bindings.get(name, [])):
                    return [(owner, binding)]
                owner = owner.parent
        events = scope.bindings.get(name, [])
        if events:
            candidates = []
            for event in reversed(events):
                if inherited or event.position <= position:
                    candidates.append((scope, event))
                    if not inherited and not event.conditional:
                        break
            if candidates or scope.kind in {"function", "comprehension"}:
                return candidates  # Local parameters/rebindings shadow outer aliases.
        parent = scope.parent
        if parent is None:
            return []
        if name in scope.global_names:
            while parent.parent is not None:
                parent = parent.parent
            return self._mutation_bindings(parent, name, scope.entry, inherited=True)
        if scope.kind in {"function", "comprehension"}:
            while parent is not None and parent.kind == "class":
                parent = parent.parent
            return self._mutation_bindings(parent, name, scope.entry, inherited=True) if parent else []
        return self._mutation_bindings(parent, name, position, inherited=inherited)

    def _mutation_target_references(self, scope: Scope, node: ast.AST, position: tuple[int, int],
                                    seen: frozenset[int] = frozenset()) -> set[tuple[str, str]]:
        if isinstance(node, ast.Call):
            ref = self._reference(scope, node, position)
            return {ref} if ref is not None else set()
        name = _root(node)
        refs = set()
        for owner, binding in self._mutation_bindings(scope, name, position) if name else []:
            if id(binding) in seen:
                continue
            if binding.kind in {"module", "symbol"}:
                refs.add(("module", binding.symbol.split(".")[0]))
            elif binding.kind == "alias" and binding.value is not None:
                refs.update(self._mutation_target_references(
                    owner, binding.value, binding.position, seen | {id(binding)}))
            elif binding.kind == "receiver" and isinstance(binding.value, ast.Call):
                dynamic = self.dynamic_import(binding.value)
                if dynamic and dynamic["status"] == "resolved":
                    refs.add(("module", dynamic["returned_module"].split(".")[0]))
                else:
                    refs.add(("receiver", str(id(binding.value))))
        return refs

    def _dict_targets(self, scope: Scope, node: ast.AST, position: tuple[int, int],
                      seen: frozenset[int]) -> list[tuple[Scope, ast.AST, tuple[int, int]]]:
        if isinstance(node, ast.Attribute) and node.attr == "__dict__":
            return [(scope, node.value, position)]
        targets = []
        if isinstance(node, ast.Name):
            for owner, binding in self._mutation_bindings(scope, node.id, position):
                if binding.kind == "alias" and binding.value is not None and id(binding) not in seen:
                    targets.extend(self._dict_targets(
                        owner, binding.value, binding.position, seen | {id(binding)}))
        return targets

    def _bound_mutation_targets(self, scope: Scope, node: ast.AST, position: tuple[int, int],
                                seen: frozenset[int] = frozenset()
                                ) -> list[tuple[Scope, ast.AST, tuple[int, int]]]:
        if isinstance(node, ast.Attribute):
            if node.attr in {"__setattr__", "__delattr__"}:
                return [(scope, node.value, position)]
            if node.attr in {"update", "clear", "pop", "popitem", "setdefault",
                             "__setitem__", "__delitem__", "__ior__"}:
                return self._dict_targets(scope, node.value, position, seen)
        targets = []
        if isinstance(node, ast.Name):
            for owner, binding in self._mutation_bindings(scope, node.id, position):
                if binding.kind == "alias" and binding.value is not None and id(binding) not in seen:
                    targets.extend(self._bound_mutation_targets(
                        owner, binding.value, binding.position, seen | {id(binding)}))
        return targets

    def _binding(self, scope: Scope, name: str, position: tuple[int, int],
                 *, inherited: bool = False) -> Binding | None:
        if name in scope.unstable_names or (inherited and scope.barriers) or any(
            barrier < position for barrier in scope.barriers
        ):
            return None
        events = scope.bindings.get(name, [])
        if name in scope.declarations and events:
            return None  # Global/nonlocal mutation needs interprocedural proof.
        if name not in scope.declarations and events:
            if inherited:
                # Function bodies execute later: a free binding must be stable
                # across the enclosing scope, not merely visible at definition.
                if len(events) != 1 or events[0].position >= position:
                    return None
                selected = events[0]
            else:
                prior = [event for event in events if event.position <= position]
                if not prior:
                    if scope.kind in {"function", "comprehension"}:
                        return None  # Python's compile-time local shadowing.
                    selected = None
                else:
                    selected = prior[-1]  # Repeated aliases on one import bind last.
            if selected is not None:
                return None if selected.conditional else selected
        parent = scope.parent
        if parent is None:
            return None
        if name in scope.global_names:
            while parent.parent is not None:
                parent = parent.parent
            return self._binding(parent, name, scope.entry, inherited=True)
        if scope.kind in {"function", "comprehension"}:
            while parent is not None and parent.kind == "class":
                parent = parent.parent  # Methods do not close over class locals.
            if parent is None:
                return None
            return self._binding(parent, name, scope.entry, inherited=True)
        return self._binding(parent, name, position, inherited=inherited)

    def for_call(self, node: ast.Call) -> tuple[dict, dict, dict]:
        if node in self.collector.non_runtime_annotation_calls:
            return {}, {}, {}
        if node in self.cache:
            return self.cache[node]
        scope, position = self.collector.calls[node], _position(node)
        names: set[str] = set()
        parent: Scope | None = scope
        while parent is not None:
            names.update(parent.bindings)
            parent = parent.parent
        modules: dict[str, str] = {}
        symbols: dict[str, str] = {}
        receivers: dict[str, list[dict]] = {}
        # Reserve the cache before resolving producer contexts recursively.
        self.cache[node] = (modules, symbols, receivers)
        for name in sorted(names):
            # Defaults and assignment values execute before annotations even
            # when they occur later in source text. Require stable bindings.
            binding = self._binding(
                scope, name, position,
                inherited=node in self.collector.runtime_annotation_calls,
            )
            if binding is None:
                continue
            ref = self._reference(scope, ast.Name(id=name), position)
            mutation_position = (10**9, 0) if node in self.collector.runtime_annotation_calls else position
            if ref is not None and self._reference_mutated(scope, ref, mutation_position):
                continue
            if binding.kind == "alias" and isinstance(binding.value, ast.Name):
                seen: set[int] = set()
                while binding.kind == "alias" and isinstance(binding.value, ast.Name):
                    if id(binding) in seen:
                        binding = None
                        break
                    seen.add(id(binding))
                    binding = self._binding(scope, binding.value.id, binding.position)
                    if binding is None:
                        break
                if binding is None:
                    continue
            if binding.kind == "module":
                modules[name] = binding.symbol
            elif binding.kind == "symbol":
                symbols[name] = binding.symbol
            elif binding.kind == "alias" and binding.value is not None:
                symbol = self._symbol(scope, binding.value, binding.position)
                if symbol:
                    symbols[name] = symbol
            elif binding.kind == "receiver" and isinstance(binding.value, ast.Call):
                dynamic = self.dynamic_import(binding.value)
                if dynamic is not None:
                    if dynamic["status"] == "resolved":
                        modules[name] = dynamic["returned_module"]
                    continue  # A module load is never a generic API factory.
                if self.resolve is None or self.shape is None:
                    continue
                producer_modules, producer_symbols, producer_receivers = self.for_call(binding.value)
                resolved = self.dynamic_api_call(binding.value) or self.resolve(
                    binding.value, producer_modules, producer_symbols, producer_receivers)
                if resolved is not None and resolved[2] != "call_result_method":
                    receivers[name] = [{
                        "assignment_line": binding.position[0],
                        "assignment_column": binding.position[1],
                        "producer_import_root": resolved[0],
                        "producer_api_symbol": resolved[1],
                        "producer_binding_type": resolved[2],
                        "producer_call_shape": self.shape(
                            binding.value, source_code=self.source_code,
                            module_bindings=producer_modules, symbol_bindings=producer_symbols),
                    }]
        return modules, symbols, receivers

    def possible_roots(self, node: ast.Call) -> list[str]:
        if node in self.collector.non_runtime_annotation_calls:
            return []
        names, visited = [_root(node.func)], set()
        roots: set[str] = set()
        scopes = {id(scope): scope for scope in self.collector.calls.values()}
        while names:
            name = names.pop()
            if not name or name in visited:
                continue
            visited.add(name)
            roots.update(self.collector.possible_imports.get(name, set()))
            names.extend(self.collector.possible_producers.get(name, set()))
            names.extend(self.collector.possible_aliases.get(name, set()))
            for scope in scopes.values():
                for binding in scope.bindings.get(name, []):
                    if isinstance(binding.value, ast.Call):
                        for item in ast.walk(binding.value):
                            if not isinstance(item, ast.Call):
                                continue
                            dynamic = self.dynamic_import(item)
                            if dynamic:
                                module = dynamic.get("import_path") or dynamic.get("requested_module") or ""
                                if all(part.isidentifier() for part in module.split(".")):
                                    roots.add(module.split(".")[0])
        for item in ast.walk(node.func):
            if isinstance(item, ast.Call):
                dynamic = self.dynamic_import(item)
                if dynamic and dynamic["status"] == "resolved":
                    roots.add(dynamic["import_path"].split(".")[0])
        return sorted(roots)

    def dynamic_api_call(self, node: ast.Call) -> tuple[str, str, str] | None:
        parts: list[str] = []
        value = node.func
        while isinstance(value, ast.Attribute):
            parts.insert(0, value.attr)
            value = value.value
        if not parts or not isinstance(value, ast.Call):
            return None
        dynamic = self.dynamic_import(value)
        if not dynamic or dynamic["status"] != "resolved":
            return None
        module = dynamic["returned_module"]
        scope = self.collector.calls[node]
        if self._reference_mutated(scope, ("module", module.split(".")[0]), _position(node)):
            return None
        return module.split(".")[0], ".".join([module, *parts]), "module_import"
