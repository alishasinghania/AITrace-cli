"""
Interprocedural, argument-aware taint analysis.

Tracks Origins through assignments, call arguments → parameters, and
callee returns → caller assignments. Call-graph reachability alone is
not treated as a finding.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from ..utils.ast_utils import get_call_chain, walk_python_files
from .dataflow_analyzer import (
    SOURCE_RISK,
    DataFlow,
    DataFlowAnalysisResult,
    _attr_taint_key,
    _get_assign_targets,
    _is_mcp_tool_function,
    _is_sanitization_call,
    _is_sink_call,
    _is_source_value,
    _mcp_arg_source,
    _names_in_expr,
)
from .taint_catalog import (
    http_arg_roles,
    is_http_client_call,
    is_http_factory_call,
    is_parameterized_sql_call,
    is_sql_execute_call,
    is_sql_factory_call,
)

_MAX_ITERS = 24
_MAX_CONTEXTS_PER_FUNC = 48
_SKIP_PARAMS = {"self", "cls"}

# Calls that return a transformation of argument/receiver values, not a new fetch.
_PASSTHROUGH_FUNCS = {"str", "repr", "ascii", "format", "text", "dumps"}
_PASSTHROUGH_METHODS = {
    "strip", "lstrip", "rstrip", "lower", "upper", "title",
    "decode", "encode", "replace", "format", "join", "copy", "clone",
}
# Receiver taint only (field-insensitive container extract).
_RECEIVER_METHODS = {"get", "getvalue", "get_json"}

_COVERAGE_SAMPLE_LIMIT = 8
_COVERAGE_IGNORE = {
    "print", "len", "str", "int", "float", "bool", "list", "dict", "set", "tuple",
    "bytes", "bytearray", "type", "isinstance", "issubclass", "id", "hash",
    "repr", "ascii", "format", "ord", "chr", "hex", "oct", "bin",
    "min", "max", "sum", "abs", "round", "sorted", "reversed", "enumerate",
    "zip", "map", "filter", "any", "all", "iter", "next", "range",
    "open", "super", "property", "staticmethod", "classmethod",
    "getattr", "setattr", "hasattr", "delattr", "vars", "dir",
    "callable", "globals", "locals", "append", "extend", "pop", "update", "add",
} | {n.lower() for n in _PASSTHROUGH_FUNCS} | {n.lower() for n in _PASSTHROUGH_METHODS} | {
    n.lower() for n in _RECEIVER_METHODS
}


def _coverage_add(bucket: Dict[str, Any], sample: Dict[str, Any]) -> None:
    """Increment a bounded coverage bucket."""
    bucket["count"] = int(bucket.get("count", 0) or 0) + 1
    samples = bucket.setdefault("samples", [])
    if len(samples) < _COVERAGE_SAMPLE_LIMIT:
        samples.append(sample)


@dataclass(frozen=True)
class Origin:
    """Provenance of a tainted value.

    kind:
      payload — direct request/user/tool argument value
      identifier — request-derived value used as a lookup key (not copied onto fetch results)
      lookup_result — value produced by an external fetch (db/api/file)
    """

    source_type: str
    file: str
    line: Optional[int]
    function: str
    kind: str = "payload"


@dataclass
class ImportRef:
    """Imported module and optional symbol (None = whole module)."""

    module: str
    symbol: Optional[str] = None


@dataclass
class FuncIR:
    """Indexed function for resolution and analysis."""

    key: str
    file: str
    name: str
    class_name: Optional[str]
    node: ast.FunctionDef | ast.AsyncFunctionDef
    params: List[str]
    source_text: str


@dataclass
class _CallRec:
    lineno: int
    chain: List[str]
    positional: List[ast.expr]
    keywords: List[Tuple[Optional[str], ast.expr]]
    assign_targets: List[str]


ParamCtx = Tuple[Tuple[str, Tuple[Origin, ...]], ...]


def _origin_sort_key(o: Origin) -> Tuple[str, int, str, str, str]:
    return (o.file, o.line or 0, o.function, o.source_type, o.kind)


def _kind_for_source(source_type: str) -> str:
    """Map a source label to a provenance kind."""
    if source_type in {"external_api", "file_read"}:
        return "lookup_result"
    return "payload"


def _freeze_params(params: Dict[str, Set[Origin]]) -> ParamCtx:
    """Hashable incoming-parameter taint; empty dict → empty context."""
    items: List[Tuple[str, Tuple[Origin, ...]]] = []
    for name in sorted(params):
        origs = params[name]
        if not origs:
            continue
        items.append((name, tuple(sorted(origs, key=_origin_sort_key))))
    return tuple(items)


def _unfreeze_params(ctx: ParamCtx) -> Dict[str, Set[Origin]]:
    return {name: set(origs) for name, origs in ctx}


def _import_module_map(imports: Dict[str, ImportRef]) -> Dict[str, str]:
    """Local name → imported module path (for aliased provider calls)."""
    return {name: ref.module for name, ref in imports.items() if ref.module}


def _file_to_module(rel: str) -> str:
    p = rel.replace("\\", "/")
    if p.endswith(".py"):
        p = p[:-3]
    if p.endswith("/__init__"):
        p = p[: -len("/__init__")]
    return p.replace("/", ".")


def _package_of(rel: str) -> str:
    mod = _file_to_module(rel)
    if rel.replace("\\", "/").endswith("__init__.py"):
        return mod
    parts = mod.split(".")
    return ".".join(parts[:-1]) if len(parts) > 1 else ""


def _param_list(func: ast.FunctionDef | ast.AsyncFunctionDef) -> List[str]:
    names: List[str] = []
    for a in list(func.args.posonlyargs) + list(func.args.args):
        if a.arg not in _SKIP_PARAMS:
            names.append(a.arg)
    return names


def _kwonly_params(func: ast.FunctionDef | ast.AsyncFunctionDef) -> List[str]:
    return [a.arg for a in func.args.kwonlyargs if a.arg not in _SKIP_PARAMS]


def _const_true(node: ast.expr) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _is_fstring_or_concat(node: ast.expr) -> bool:
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == "format":
            return True
    return False


def _url_is_chat_api(expr: ast.expr) -> bool:
    """True when a URL expression contains an explicit /api/chat path fragment."""
    for n in ast.walk(expr):
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            if "/api/chat" in n.value.lower():
                return True
    return False


def _http_url_arg(node: ast.Call) -> Optional[ast.expr]:
    """Return the URL expression of an HTTP client call, if present."""
    if node.args:
        return node.args[0]
    for kw in node.keywords:
        if kw.arg == "url":
            return kw.value
    return None


def _sql_executed_expr(node: ast.Call) -> Optional[ast.expr]:
    """SQL value passed to execute, unwrapping sqlalchemy.text(...) once."""
    if not node.args:
        return None
    q = node.args[0]
    if isinstance(q, ast.Call):
        chain = [c.lower() for c in get_call_chain(q)]
        if chain and chain[-1] == "text" and q.args:
            return q.args[0]
    return q


def _classify_precise_sink(
    node: ast.Call,
    import_modules: Optional[Dict[str, str]] = None,
    sql_receivers: Optional[Set[str]] = None,
    http_receivers: Optional[Set[str]] = None,
) -> Optional[Tuple[str, str]]:
    """Return (category, label) only for dangerous sink shapes."""
    llm = _is_sink_call(node, import_modules=import_modules)
    if llm:
        return ("llm", llm)

    chain = get_call_chain(node)
    chain_l = [c.lower() for c in chain]
    attr = chain_l[-1] if chain_l else ""
    parts = set(chain_l)

    if is_http_client_call(node, import_modules, http_receivers):
        url = _http_url_arg(node)
        if attr == "post" and url is not None and _url_is_chat_api(url):
            return ("llm", "ollama /api/chat")
        label = ".".join(chain_l[-2:]) if len(chain_l) >= 2 else (attr or "http")
        return ("http", label)

    if attr in {"system", "popen"} and "os" in parts:
        return ("rce", "os." + attr)
    if "subprocess" in parts and attr in {"run", "popen", "call", "check_output", "check_call"}:
        shell = any(kw.arg == "shell" and _const_true(kw.value) for kw in node.keywords)
        if shell:
            return ("rce", "subprocess." + attr + "(shell=True)")
        return None
    if attr in {"exec", "eval"}:
        return ("rce", attr)

    if is_sql_execute_call(node, sql_receivers):
        q = _sql_executed_expr(node)
        if q is None:
            return None
        if is_parameterized_sql_call(node):
            return None
        label = "session.execute" if "session" in parts or "db" in parts else "cursor.execute"
        return ("sql", label)
    return None


def _parse_imports(tree: ast.AST, file_rel: str) -> Dict[str, ImportRef]:
    """Map local names to module/symbol. Relative imports use the file package."""
    pkg = _package_of(file_rel)
    out: Dict[str, ImportRef] = {}
    for node in getattr(tree, "body", []):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".")[0]
                out[local] = ImportRef(module=alias.name, symbol=None)
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if node.level:
                parts = pkg.split(".") if pkg else []
                drop = node.level - 1
                if drop > 0:
                    parts = parts[: max(0, len(parts) - drop)]
                prefix = ".".join(p for p in parts if p)
                mod = f"{prefix}.{mod}" if prefix and mod else (mod or prefix)
            for alias in node.names:
                if alias.name == "*":
                    continue
                local = alias.asname or alias.name
                out[local] = ImportRef(module=mod, symbol=alias.name)
    return out


def _index_repo(
    repo_root: Path,
) -> Tuple[Dict[str, FuncIR], Dict[str, Dict[str, ImportRef]], Dict[str, str]]:
    functions: Dict[str, FuncIR] = {}
    imports: Dict[str, Dict[str, ImportRef]] = {}
    files_by_mod: Dict[str, str] = {}

    for path in walk_python_files(repo_root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(text)
        except (SyntaxError, OSError, ValueError):
            continue
        rel = str(path.relative_to(repo_root))
        imports[rel] = _parse_imports(tree, rel)
        files_by_mod.setdefault(_file_to_module(rel), rel)

        class_of: Dict[int, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        class_of[id(item)] = node.name

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            cls = class_of.get(id(node))
            qual = f"{cls}.{node.name}" if cls else node.name
            key = f"{rel}::{qual}"
            functions[key] = FuncIR(
                key=key,
                file=rel,
                name=node.name,
                class_name=cls,
                node=node,
                params=_param_list(node) + _kwonly_params(node),
                source_text=text,
            )
    return functions, imports, files_by_mod


def _find_module_file(module: str, files_by_mod: Dict[str, str]) -> Optional[str]:
    if not module:
        return None
    if module in files_by_mod:
        return files_by_mod[module]
    suffix = "." + module
    hits = [f for m, f in files_by_mod.items() if m.endswith(suffix)]
    if len(hits) == 1:
        return hits[0]
    return None


def _resolve_callee(
    chain: List[str],
    caller: FuncIR,
    instance_types: Dict[str, str],
    functions: Dict[str, FuncIR],
    imports: Dict[str, ImportRef],
    files_by_mod: Dict[str, str],
) -> Optional[str]:
    """Resolve a call chain to a unique function key, or None."""
    if not chain:
        return None

    if chain[0] == "self" and caller.class_name and len(chain) >= 2:
        key = f"{caller.file}::{caller.class_name}.{chain[1]}"
        return key if key in functions else None

    if len(chain) >= 2 and chain[0] in instance_types:
        key = f"{instance_types[chain[0]]}.{chain[1]}"
        return key if key in functions else None

    if len(chain) == 1:
        name = chain[0]
        ref = imports.get(name)
        if ref and ref.symbol:
            fpath = _find_module_file(ref.module, files_by_mod)
            if not fpath:
                return None
            key = f"{fpath}::{ref.symbol}"
            return key if key in functions else None
        same = f"{caller.file}::{name}"
        return same if same in functions else None

    head, tail = chain[0], chain[-1]
    ref = imports.get(head)
    if ref:
        fpath = _find_module_file(ref.module, files_by_mod)
        if not fpath:
            return None
        if ref.symbol:
            key = f"{fpath}::{ref.symbol}.{tail}"
            if key in functions:
                return key
            key = f"{fpath}::{tail}"
            return key if key in functions else None
        key = f"{fpath}::{tail}"
        if key in functions:
            return key
        if len(chain) >= 3:
            key = f"{fpath}::{chain[1]}.{tail}"
            if key in functions:
                return key
        return None

    key = f"{caller.file}::{head}.{tail}"
    return key if key in functions else None


class _FuncVisitor(ast.NodeVisitor):
    """Intra-procedural taint for one function given param origins and callee returns."""

    def __init__(
        self,
        ir: FuncIR,
        param_origins: Dict[str, Set[Origin]],
        functions: Dict[str, FuncIR],
        returns_by_ctx: Dict[Tuple[str, ParamCtx], Set[Origin]],
        resolve: Callable[[List[str], Dict[str, str]], Optional[str]],
        imports: Dict[str, ImportRef],
        files_by_mod: Dict[str, str],
    ) -> None:
        self.ir = ir
        self.functions = functions
        self.returns_by_ctx = returns_by_ctx
        self.resolve = resolve
        self.imports = imports
        self.import_modules = _import_module_map(imports)
        self.files_by_mod = files_by_mod
        self.tainted: Dict[str, Set[Origin]] = {k: set(v) for k, v in param_origins.items()}
        self.sanitized: Set[str] = set()
        self.instance_types: Dict[str, str] = {}
        self.sql_receivers: Set[str] = set()
        self.http_receivers: Set[str] = set()
        self.calls: List[_CallRec] = []
        self.sinks: List[Tuple[int, str, str, Set[Origin], str]] = []
        self.coverage_events: List[Tuple[str, Dict[str, Any]]] = []
        self.return_origins: Set[Origin] = set()
        self._branch_depth = 0
        self._target = ir.node
        self._mcp = _is_mcp_tool_function(ir.node, ir.source_text)
        if self._mcp:
            line = getattr(ir.node, "lineno", None)
            for p in ir.params:
                if p not in self.tainted:
                    self.tainted[p] = {
                        Origin("mcp_tool_arg", ir.file, line, ir.name, kind="payload")
                    }

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if node is not self._target:
            return
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        if node is not self._target:
            return
        self.generic_visit(node)

    def _new_origin(self, source_type: str, expr: ast.expr, kind: Optional[str] = None) -> Origin:
        """Build an origin for a source expression."""
        return Origin(
            source_type,
            self.ir.file,
            getattr(expr, "lineno", None),
            self.ir.name,
            kind=kind or _kind_for_source(source_type),
        )

    def _rec_from_call(self, node: ast.Call) -> _CallRec:
        return _CallRec(
            lineno=getattr(node, "lineno", 0) or 0,
            chain=get_call_chain(node),
            positional=list(node.args),
            keywords=[(kw.arg, kw.value) for kw in node.keywords],
            assign_targets=[],
        )

    def _incoming_for_call(self, callee: FuncIR, rec: _CallRec) -> Dict[str, Set[Origin]]:
        incoming: Dict[str, Set[Origin]] = {}
        for pname, expr in _map_call_args(callee, rec).items():
            orig = self._origins_in(expr)
            if orig:
                incoming[pname] = orig
        return incoming

    def _returns_for_call(self, node: ast.Call) -> Set[Origin]:
        """Returns of this call site's callee context only — not a function-wide union."""
        key = self.resolve(get_call_chain(node), self.instance_types)
        if not key or key not in self.functions:
            return set()
        incoming = self._incoming_for_call(self.functions[key], self._rec_from_call(node))
        ctx = _freeze_params(incoming)
        return set(self.returns_by_ctx.get((key, ctx), set()))

    def _passthrough_args(self, node: ast.Call) -> Set[Origin]:
        """Origins of arguments for value-preserving wrappers only."""
        found: Set[Origin] = set()
        for a in node.args:
            found |= self._origins_in(a)
        for kw in node.keywords:
            found |= self._origins_in(kw.value)
        return found

    def _origins_in(self, expr: ast.expr) -> Set[Origin]:
        """Origins of the value this expression *produces*.

        Names that appear only as call arguments are not copied onto the
        call's result. Unresolved non-passthrough calls contribute no
        confirmed origins (uncertainty, not a fabricated path).
        """
        found: Set[Origin] = set()
        src = _is_source_value(expr)
        if src:
            found.add(self._new_origin(src[0], expr))
        if self._mcp:
            mcp = _mcp_arg_source(expr)
            if mcp:
                found.add(self._new_origin(mcp[0], expr))

        if isinstance(expr, ast.Name):
            found |= set(self.tainted.get(expr.id, ()))
            return found

        attr_key = _attr_taint_key(expr)
        if attr_key and attr_key in self.tainted:
            found |= set(self.tainted[attr_key])

        if isinstance(expr, ast.Attribute):
            found |= self._origins_in(expr.value)
            return found

        if isinstance(expr, ast.Call):
            found |= self._returns_for_call(expr)
            func = expr.func
            if isinstance(func, ast.Attribute):
                found |= self._origins_in(func.value)
                method = func.attr.lower()
                if method in _PASSTHROUGH_METHODS:
                    found |= self._passthrough_args(expr)
                elif method in _RECEIVER_METHODS:
                    pass  # receiver taint only; argument identifiers are not the result
            elif isinstance(func, ast.Name) and func.id.lower() in _PASSTHROUGH_FUNCS:
                found |= self._passthrough_args(expr)
            return found

        if isinstance(expr, ast.BoolOp):
            for v in expr.values:
                found |= self._origins_in(v)
            return found
        if isinstance(expr, ast.IfExp):
            found |= self._origins_in(expr.body)
            found |= self._origins_in(expr.orelse)
            return found
        if isinstance(expr, ast.Dict):
            for v in expr.values:
                if v is not None:
                    found |= self._origins_in(v)
            return found
        if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
            for elt in expr.elts:
                found |= self._origins_in(elt)
            return found
        if isinstance(expr, ast.JoinedStr):
            for elt in expr.values:
                if isinstance(elt, ast.FormattedValue):
                    found |= self._origins_in(elt.value)
            return found
        if isinstance(expr, ast.BinOp):
            found |= self._origins_in(expr.left)
            found |= self._origins_in(expr.right)
            return found
        if isinstance(expr, ast.Subscript):
            found |= self._origins_in(expr.value)
            return found
        if isinstance(expr, ast.Starred):
            found |= self._origins_in(expr.value)
            return found
        if isinstance(expr, ast.UnaryOp):
            found |= self._origins_in(expr.operand)
            return found
        if isinstance(expr, ast.FormattedValue):
            found |= self._origins_in(expr.value)
            return found
        if isinstance(expr, ast.Await):
            found |= self._origins_in(expr.value)
            return found
        if isinstance(expr, ast.NamedExpr):
            found |= self._origins_in(expr.value)
            return found
        return found

    def _bind_instance(self, targets: List[str], value: ast.expr) -> None:
        if not isinstance(value, ast.Call) or len(targets) != 1:
            return
        chain = get_call_chain(value)
        if not chain:
            return
        head = chain[0]
        ref = self.imports.get(head)
        if ref and ref.symbol:
            fpath = _find_module_file(ref.module, self.files_by_mod)
            if fpath:
                self.instance_types[targets[0]] = f"{fpath}::{ref.symbol}"
            return
        if len(chain) == 1:
            self.instance_types[targets[0]] = f"{self.ir.file}::{head}"

    def visit_If(self, node: ast.If) -> None:
        """Walk both branches without treating them as straight-line kills."""
        self._branch_depth += 1
        self.generic_visit(node)
        self._branch_depth -= 1

    def visit_Try(self, node: ast.Try) -> None:
        """Retain possible taint across try/except/finally joins."""
        self._branch_depth += 1
        self.generic_visit(node)
        self._branch_depth -= 1

    def visit_For(self, node: ast.For) -> None:
        """Loop bodies are not a straight-line kill; 0 iterations remain possible."""
        self._branch_depth += 1
        self.generic_visit(node)
        self._branch_depth -= 1

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        """Same join semantics as ``for``."""
        self._branch_depth += 1
        self.generic_visit(node)
        self._branch_depth -= 1

    def visit_While(self, node: ast.While) -> None:
        """Loop bodies are not a straight-line kill."""
        self._branch_depth += 1
        self.generic_visit(node)
        self._branch_depth -= 1

    def visit_With(self, node: ast.With) -> None:
        """Context-manager bodies may not run to completion."""
        self._branch_depth += 1
        self.generic_visit(node)
        self._branch_depth -= 1

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        """Same join semantics as ``with``."""
        self._branch_depth += 1
        self.generic_visit(node)
        self._branch_depth -= 1

    def visit_Assign(self, node: ast.Assign) -> None:
        targets = _get_assign_targets(node)
        if not targets:
            self.generic_visit(node)
            return
        if isinstance(node.value, ast.Call) and _is_sanitization_call(node.value):
            refs = _names_in_expr(node.value)
            # Straight-line sanitizer may kill. Inside if/try it must not
            # prove the post-join value is clean.
            if refs & set(self.tainted.keys()) and self._branch_depth == 0:
                for t in targets:
                    self.sanitized.add(t)
                    self.tainted.pop(t, None)
            self.generic_visit(node)
            return
        orig = self._origins_in(node.value)
        self._bind_instance(targets, node.value)
        if isinstance(node.value, ast.Call) and is_sql_factory_call(node.value):
            for t in targets:
                self.sql_receivers.add(t.lower())
        if isinstance(node.value, ast.Call) and is_http_factory_call(node.value, self.import_modules):
            for t in targets:
                self.http_receivers.add(t.lower())
        if orig:
            for t in targets:
                self.tainted[t] = set(orig)
                self.sanitized.discard(t)
        elif self._branch_depth == 0:
            for t in targets:
                self.tainted.pop(t, None)
            refs = _names_in_expr(node.value)
            if refs & self.sanitized:
                for t in targets:
                    self.sanitized.add(t)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if isinstance(node.target, ast.Name) and node.value is not None:
            self.visit_Assign(
                ast.Assign(targets=[node.target], value=node.value, lineno=getattr(node, "lineno", 0))
            )
            return
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> None:
        if node.value is not None:
            self.return_origins |= self._origins_in(node.value)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        rec = _CallRec(
            lineno=getattr(node, "lineno", 0) or 0,
            chain=get_call_chain(node),
            positional=list(node.args),
            keywords=[(kw.arg, kw.value) for kw in node.keywords],
            assign_targets=[],
        )
        self.calls.append(rec)
        if (
            len(rec.chain) == 2
            and rec.chain[1] in {"append", "extend"}
            and rec.chain[0] not in {"self", "cls"}
        ):
            container = rec.chain[0]
            for expr in rec.positional:
                orig = self._origins_in(expr)
                if orig:
                    self.tainted.setdefault(container, set()).update(orig)
                    self.sanitized.discard(container)
        sink = _classify_precise_sink(
            node, self.import_modules, self.sql_receivers, self.http_receivers,
        )
        if sink:
            cat, label = sink
            lineno = getattr(node, "lineno", 0) or 0
            if cat == "http":
                for role, expr in http_arg_roles(node):
                    orig = self._origins_in(expr)
                    names = _names_in_expr(expr)
                    if orig and not (names and names <= self.sanitized):
                        self.sinks.append((lineno, cat, label, orig, role))
            else:
                orig = set()
                if cat == "sql":
                    q = _sql_executed_expr(node)
                    exprs = [q] if q is not None else []
                else:
                    exprs = list(node.args) + [
                        kw.value for kw in node.keywords if kw.arg != "shell"
                    ]
                names = set()
                for expr in exprs:
                    orig |= self._origins_in(expr)
                    names |= _names_in_expr(expr)
                if orig and not (names and names <= self.sanitized):
                    self.sinks.append((lineno, cat, label, orig, ""))
        self._note_coverage(node, rec, bool(sink))
        self.generic_visit(node)

    def _note_coverage(self, node: ast.Call, rec: _CallRec, is_sink: bool) -> None:
        """Record unresolved/unsupported calls that received tainted arguments."""
        lineno = getattr(node, "lineno", None)
        sample = {
            "file": self.ir.file,
            "line": lineno if lineno else None,
            "function": self.ir.name,
        }
        if not isinstance(node.func, (ast.Name, ast.Attribute)):
            orig = self._passthrough_args(node)
            if orig:
                sample["callee"] = "<dynamic>"
                self.coverage_events.append(("unsupported_call_forms", sample))
            return
        if is_sink:
            return
        name = rec.chain[-1].lower() if rec.chain else ""
        if name in _COVERAGE_IGNORE:
            return
        callee_key = self.resolve(rec.chain, self.instance_types)
        if callee_key:
            return
        orig = set()
        for expr in rec.positional:
            orig |= self._origins_in(expr)
        for _, expr in rec.keywords:
            orig |= self._origins_in(expr)
        if not orig:
            return
        sample["callee"] = ".".join(rec.chain) if rec.chain else "<unknown>"
        self.coverage_events.append(("unresolved_calls", sample))


def _map_call_args(callee: FuncIR, rec: _CallRec) -> Dict[str, ast.expr]:
    mapping: Dict[str, ast.expr] = {}
    pos = _param_list(callee.node)
    for i, expr in enumerate(rec.positional):
        if isinstance(expr, ast.Starred):
            continue
        if i < len(pos):
            mapping[pos[i]] = expr
    for name, expr in rec.keywords:
        if name:
            mapping[name] = expr
    return mapping


def _build_hops(origin: Origin, sink_ir: FuncIR, sink_line: int, sink_label: str, edges: List[str]) -> List[str]:
    hops = [f"{origin.file}::{origin.function}:{origin.line or 0} source {origin.source_type}"]
    hops.extend(edges)
    hops.append(f"{sink_ir.file}::{sink_ir.name}:{sink_line} sink {sink_label}")
    return hops


def _record_hop(
    origin_hops: Dict[Origin, Dict[str, List[str]]],
    origin: Origin,
    from_key: str,
    to_key: str,
    edge: str,
) -> None:
    prev = origin_hops.setdefault(origin, {}).get(from_key, [])
    nxt = prev + [edge]
    cur = origin_hops[origin].get(to_key)
    if cur is None or len(nxt) < len(cur):
        origin_hops[origin][to_key] = nxt


def analyze_interproc_dataflows(
    repo_root: Path,
    *,
    max_iters: Optional[int] = None,
    max_contexts_per_func: Optional[int] = None,
) -> DataFlowAnalysisResult:
    """Worklist taint: call-site-sensitive params, returns, precise resolution."""
    functions, imports_by_file, files_by_mod = _index_repo(repo_root)
    iter_cap = _MAX_ITERS if max_iters is None else max_iters
    ctx_cap = _MAX_CONTEXTS_PER_FUNC if max_contexts_per_func is None else max_contexts_per_func

    # Each (function, incoming-param taint) is a separate analysis context.
    # Callers do not union origins into a shared callee summary.
    contexts: Dict[str, Set[ParamCtx]] = {k: {()} for k in functions}
    returns_by_ctx: Dict[Tuple[str, ParamCtx], Set[Origin]] = {}
    origin_hops: Dict[Origin, Dict[str, List[str]]] = {}
    latest_sinks: Dict[Tuple[str, ParamCtx], List[Tuple[int, str, str, Set[Origin], str]]] = {}
    incomplete_reasons: List[str] = []
    coverage: Dict[str, Any] = {
        "unresolved_calls": {"count": 0, "samples": []},
        "unsupported_call_forms": {"count": 0, "samples": []},
    }
    seen_coverage: Set[Tuple[Any, ...]] = set()

    def make_resolve(ir: FuncIR):
        im = imports_by_file.get(ir.file, {})

        def _res(chain: List[str], instance_types: Dict[str, str]) -> Optional[str]:
            return _resolve_callee(chain, ir, instance_types, functions, im, files_by_mod)

        return _res

    def _enqueue_ctx(callee_key: str, ctx: ParamCtx) -> bool:
        known = contexts[callee_key]
        if ctx in known:
            return False
        if len(known) >= ctx_cap:
            if "context_cap" not in incomplete_reasons:
                incomplete_reasons.append("context_cap")
            return False
        known.add(ctx)
        return True

    changed = False
    for _ in range(iter_cap):
        changed = False
        for key, ir in functions.items():
            for ctx in list(contexts[key]):
                vis = _FuncVisitor(
                    ir,
                    _unfreeze_params(ctx),
                    functions,
                    returns_by_ctx,
                    make_resolve(ir),
                    imports_by_file.get(ir.file, {}),
                    files_by_mod,
                )
                vis.visit(ir.node)
                latest_sinks[(key, ctx)] = vis.sinks
                for kind, sample in vis.coverage_events:
                    ident = (
                        kind,
                        sample.get("file"),
                        sample.get("line"),
                        sample.get("callee"),
                    )
                    if ident in seen_coverage:
                        continue
                    seen_coverage.add(ident)
                    bucket = coverage.get(kind)
                    if isinstance(bucket, dict):
                        _coverage_add(bucket, sample)

                ret_key = (key, ctx)
                prev_ret = returns_by_ctx.get(ret_key, set())
                if vis.return_origins != prev_ret:
                    returns_by_ctx[ret_key] = set(vis.return_origins)
                    changed = True

                for rec in vis.calls:
                    callee_key = vis.resolve(rec.chain, vis.instance_types)
                    if not callee_key or callee_key not in functions:
                        continue
                    callee = functions[callee_key]
                    incoming = vis._incoming_for_call(callee, rec)
                    callee_ctx = _freeze_params(incoming)
                    if _enqueue_ctx(callee_key, callee_ctx):
                        changed = True
                    for pname, orig in incoming.items():
                        edge = f"{ir.file}::{ir.name} arg -> {callee_key} param {pname}"
                        for o in orig:
                            _record_hop(origin_hops, o, key, callee_key, edge)
                    ret = returns_by_ctx.get((callee_key, callee_ctx), set())
                    if ret:
                        edge = f"{callee_key} return -> {key}"
                        for o in ret:
                            _record_hop(origin_hops, o, callee_key, key, edge)

        if not changed:
            break
    else:
        if changed and "iteration_cap" not in incomplete_reasons:
            incomplete_reasons.append("iteration_cap")

    incomplete = bool(incomplete_reasons)
    confidence = "may" if incomplete else "high"

    flows: List[DataFlow] = []
    seen: Set[Tuple] = set()
    for (key, _ctx), sinks in latest_sinks.items():
        ir = functions[key]
        for lineno, cat, label, origs, role in sinks:
            for o in origs:
                ident = (o.file, o.line, o.source_type, ir.file, lineno, label, role)
                if ident in seen:
                    continue
                seen.add(ident)
                edges = origin_hops.get(o, {}).get(key, [])
                hops = _build_hops(o, ir, lineno, label, edges)
                flows.append(DataFlow(
                    source=o.source_type,
                    sink=label,
                    file=ir.file,
                    line=lineno,
                    risk=SOURCE_RISK.get(o.source_type, "medium"),
                    source_line=o.line,
                    sanitized=False,
                    source_file=o.file,
                    source_function=o.function,
                    sink_function=ir.name,
                    sink_category=cat,
                    hops=hops,
                    confidence=confidence,
                    taint_kind=o.kind,
                    sink_arg_role=role,
                ))
    return DataFlowAnalysisResult(
        data_flows=flows,
        incomplete=incomplete,
        incomplete_reasons=list(incomplete_reasons),
        coverage=coverage,
    )
