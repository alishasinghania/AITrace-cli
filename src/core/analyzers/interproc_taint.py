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
    _is_bound_tool_argument,
    _is_mcp_tool_function,
    _is_sanitization_call,
    _is_sink_call,
    _is_source_value,
    _is_tool_argument_source,
    _is_tool_calls_collection,
    _literal_str,
    _mcp_arg_source,
    _names_in_expr,
)
from .taint_catalog import (
    collect_http_receivers,
    http_arg_roles,
    http_llm_sink_label,
    http_url_arg,
    is_http_client_call,
    is_http_factory_call,
    is_parameterized_sql_call,
    is_sql_execute_call,
    is_sql_factory_call,
    url_has_chat_api_path,
)

_MAX_ITERS = 24
_MAX_CONTEXTS_PER_FUNC = 48
_SKIP_PARAMS = {"self", "cls"}
# Intra-function parameter provenance used only for HTTP URL sinks.
#
# This is potential taint, not proof that a caller supplied attacker-controlled
# data. A helper such as ``def fetch(url): requests.get(url)`` will surface
# FLOW-HTTP even when every observed caller passes a constant. Callers that
# pass ``request.args`` / ``request.json`` still produce a separate
# ``user_input`` flow with higher confidence.
#
# Must not promote FLOW-SQL / FLOW-RCE / FLOW-LLM, and must not treat
# HTTP body / query / headers as SSRF.
_PARAM_SOURCE = "function_param"

# Calls that return a transformation of argument/receiver values, not a new fetch.
_PASSTHROUGH_FUNCS = {"str", "repr", "ascii", "format", "text", "dumps"}
_PASSTHROUGH_METHODS = {
    "strip", "lstrip", "rstrip", "lower", "upper", "title",
    "decode", "encode", "replace", "format", "join", "copy", "clone",
}
# json.loads/load parse their argument. They are not a new untrusted source
# and must not hide origins already on that argument.
_JSON_PARSE_FUNCS = frozenset({"loads", "load"})
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
    shape: str = ""  # "tool_arg_dict" for an expanded tool-call arguments mapping


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
    targets: List[str]


ParamCtx = Tuple[Tuple[str, Tuple[Origin, ...]], ...]


def _origin_sort_key(o: Origin) -> Tuple[str, int, str, str, str, str]:
    return (o.file, o.line or 0, o.function, o.source_type, o.kind, o.shape)


def _kind_for_source(source_type: str) -> str:
    """Map a source label to a provenance kind."""
    if source_type in {"external_api", "file_read"}:
        return "lookup_result"
    return "payload"  # user_input, mcp_tool_arg, llm_output, …


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
    """True when a URL expression contains a chat/completions or /api/chat path."""
    return url_has_chat_api_path(expr)


def _http_url_arg(node: ast.Call) -> Optional[ast.expr]:
    """Return the URL expression of an HTTP client call, if present."""
    return http_url_arg(node)


def _thread_wrapper_fn_and_args(
    node: ast.Call,
) -> Optional[Tuple[ast.expr, List[ast.expr], List[Tuple[Optional[str], ast.expr]]]]:
    """Unwrap ``asyncio.to_thread`` / ``run_in_executor`` / executor ``submit``.

    Returns ``(fn_expr, remaining_args, keywords)`` so the inner callable
    receives the same argument taint as a direct call.
    """
    chain = get_call_chain(node)
    if not chain:
        return None
    name = chain[-1].lower()
    joined = ".".join(c.lower() for c in chain)
    args = [a for a in node.args if not isinstance(a, ast.Starred)]
    kws = [(kw.arg, kw.value) for kw in node.keywords]
    if name == "to_thread" and args:
        return args[0], args[1:], kws
    if name == "run_in_executor" and len(args) >= 2:
        return args[1], args[2:], kws
    if name == "submit" and args:
        head = chain[0].lower()
        if "executor" in joined or "thread" in joined or head.endswith(
            ("executor", "pool")
        ):
            return args[0], args[1:], kws
    return None


def _chain_for_expr(expr: ast.expr) -> List[str]:
    """Call-chain tokens for a function expression (name or attribute)."""
    if isinstance(expr, ast.Name):
        return [expr.id]
    if isinstance(expr, ast.Attribute):
        return get_call_chain(ast.Call(func=expr, args=[], keywords=[]))
    return []


def _const_false(node: ast.expr) -> bool:
    """True for a literal False."""
    return isinstance(node, ast.Constant) and node.value is False


def _http_redirects_disabled(node: ast.Call) -> bool:
    """True only when the call explicitly disables redirects.

    ``requests`` defaults to following redirects, so an omitted flag is not
    a guarantee. ``httpx`` uses ``follow_redirects``; both keywords count
    when they are the constant False.
    """
    for kw in node.keywords:
        if kw.arg in {"allow_redirects", "follow_redirects"} and _const_false(kw.value):
            return True
    return False


_HOST_ATTRS = frozenset({"hostname", "netloc"})


def _call_ends_with(node: ast.Call, name: str) -> bool:
    """True when the call's last chain token is ``name``."""
    chain = get_call_chain(node)
    return bool(chain) and chain[-1] == name


def _assign_target_names(node: ast.Assign) -> List[str]:
    """Name targets of a simple assignment."""
    return [t.id for t in node.targets if isinstance(t, ast.Name)]


def _is_urlparse_of_name(expr: ast.expr, url_name: str) -> bool:
    """True when ``expr`` is ``urlparse(<url_name>)``."""
    if not isinstance(expr, ast.Call) or not _call_ends_with(expr, "urlparse"):
        return False
    return (
        bool(expr.args)
        and isinstance(expr.args[0], ast.Name)
        and expr.args[0].id == url_name
    )


def _expr_is_hostname_of(expr: ast.expr, url_name: str) -> bool:
    """True when ``expr`` extracts hostname/netloc from ``url_name``."""
    if isinstance(expr, ast.BoolOp):
        return any(_expr_is_hostname_of(v, url_name) for v in expr.values)
    if isinstance(expr, ast.IfExp):
        return _expr_is_hostname_of(expr.body, url_name) or _expr_is_hostname_of(
            expr.orelse, url_name
        )
    if isinstance(expr, ast.Attribute) and expr.attr in _HOST_ATTRS:
        return _is_urlparse_of_name(expr.value, url_name)
    return False


def _stmts_raise_only(body: List[ast.stmt]) -> bool:
    """True when a branch only raises (plus pass / docstring)."""
    raised = False
    for stmt in body:
        if isinstance(stmt, ast.Raise):
            raised = True
        elif isinstance(stmt, ast.Pass):
            continue
        elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
            continue
        else:
            return False
    return raised


def _single_name_predicate(expr: ast.expr) -> Optional[Tuple[ast.Call, str]]:
    """Return ``(call, name)`` for ``call(name)`` / ``call(url=name)``."""
    if not isinstance(expr, ast.Call):
        return None
    names: List[str] = [
        a.id for a in expr.args if isinstance(a, ast.Name)
    ]
    for kw in expr.keywords:
        if kw.arg in {"url", None} and isinstance(kw.value, ast.Name):
            names.append(kw.value.id)
    if len(names) != 1:
        return None
    return expr, names[0]


def _function_is_host_allowlist(fn: ast.AST, param: str) -> bool:
    """True when ``fn`` extracts ``param``'s host, compares it, and can reject.

    Name of ``fn`` is irrelevant — a helper that always returns True is not
    an allow-list even if it is called ``is_safe_url``.
    """
    host_names: Set[str] = set()
    compared = False
    rejects = False
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign) and _expr_is_hostname_of(node.value, param):
            host_names.update(_assign_target_names(node))
        if isinstance(node, ast.Raise):
            rejects = True
        if (
            isinstance(node, ast.Return)
            and isinstance(node.value, ast.Constant)
            and node.value.value is False
        ):
            rejects = True
        if isinstance(node, ast.Compare):
            parts = [node.left, *node.comparators]
            if any(
                (isinstance(p, ast.Name) and p.id in host_names)
                or _expr_is_hostname_of(p, param)
                for p in parts
            ):
                compared = True
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"endswith", "startswith"}
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in host_names
        ):
            compared = True
    return bool(host_names) and compared and rejects


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
    name_bindings: Optional[Dict[str, ast.expr]] = None,
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
        llm_label = http_llm_sink_label(node, name_bindings=name_bindings)
        if llm_label:
            return ("llm", llm_label)
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


def _record_import(node: ast.AST, pkg: str, out: Dict[str, ImportRef]) -> None:
    """Record one Import / ImportFrom into ``out`` (local name → module/symbol)."""
    if isinstance(node, ast.Import):
        for alias in node.names:
            local = alias.asname or alias.name.split(".")[0]
            out[local] = ImportRef(module=alias.name, symbol=None)
        return
    if not isinstance(node, ast.ImportFrom):
        return
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


def _imports_in(tree: ast.AST, file_rel: str) -> Dict[str, ImportRef]:
    """Collect Import / ImportFrom anywhere under ``tree`` (including nested)."""
    pkg = _package_of(file_rel)
    out: Dict[str, ImportRef] = {}
    for node in ast.walk(tree):
        _record_import(node, pkg, out)
    return out


def _parse_imports(tree: ast.AST, file_rel: str) -> Dict[str, ImportRef]:
    """Map local names to module/symbol. Nested function imports are included."""
    return _imports_in(tree, file_rel)


def _index_repo(
    repo_root: Path,
) -> Tuple[
    Dict[str, FuncIR],
    Dict[str, Dict[str, ImportRef]],
    Dict[str, str],
    Dict[str, Dict[str, Set[str]]],
]:
    functions: Dict[str, FuncIR] = {}
    imports: Dict[str, Dict[str, ImportRef]] = {}
    files_by_mod: Dict[str, str] = {}
    trees: List[Tuple[str, ast.AST]] = []

    for path in walk_python_files(repo_root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(text)
        except (SyntaxError, OSError, ValueError):
            continue
        rel = str(path.relative_to(repo_root))
        imports[rel] = _parse_imports(tree, rel)
        files_by_mod.setdefault(_file_to_module(rel), rel)
        trees.append((rel, tree))

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
    registries: Dict[str, Dict[str, Set[str]]] = {}
    for rel, tree in trees:
        registries[rel] = _collect_file_registries(
            tree, rel, functions, imports[rel], files_by_mod
        )
    return functions, imports, files_by_mod, registries


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


def _func_key_for_name(
    name: str,
    file_rel: str,
    functions: Dict[str, FuncIR],
    imports: Dict[str, ImportRef],
    files_by_mod: Dict[str, str],
) -> Optional[str]:
    """Resolve a bare name to an indexed function key."""
    same = f"{file_rel}::{name}"
    if same in functions:
        return same
    ref = imports.get(name)
    if ref and ref.symbol:
        fpath = _find_module_file(ref.module, files_by_mod)
        if fpath:
            key = f"{fpath}::{ref.symbol}"
            if key in functions:
                return key
    return None


def _function_dict_targets(
    value: ast.expr,
    file_rel: str,
    functions: Dict[str, FuncIR],
    imports: Dict[str, ImportRef],
    files_by_mod: Dict[str, str],
) -> Optional[Set[str]]:
    """Return function keys if ``value`` is a ``{str: function}`` dict."""
    if not isinstance(value, ast.Dict) or not value.values:
        return None
    keys: Set[str] = set()
    for elt in value.values:
        if not isinstance(elt, ast.Name):
            return None
        key = _func_key_for_name(elt.id, file_rel, functions, imports, files_by_mod)
        if not key:
            return None
        keys.add(key)
    return keys or None


def _collect_file_registries(
    tree: ast.AST,
    file_rel: str,
    functions: Dict[str, FuncIR],
    imports: Dict[str, ImportRef],
    files_by_mod: Dict[str, str],
) -> Dict[str, Set[str]]:
    """Module-level name → possible function keys for tool registries."""
    out: Dict[str, Set[str]] = {}
    for node in getattr(tree, "body", []):
        if not isinstance(node, ast.Assign):
            continue
        names = [t.id for t in node.targets if isinstance(t, ast.Name)]
        if not names:
            continue
        keys = _function_dict_targets(
            node.value, file_rel, functions, imports, files_by_mod
        )
        if not keys:
            continue
        for n in names:
            out[n] = set(keys)
    return out


def _is_getattr_call(expr: ast.expr) -> bool:
    """True for ``getattr(...)`` or ``builtins.getattr(...)``."""
    if not isinstance(expr, ast.Call):
        return False
    func = expr.func
    if isinstance(func, ast.Name) and func.id == "getattr":
        return True
    return (
        isinstance(func, ast.Attribute)
        and func.attr == "getattr"
        and isinstance(func.value, ast.Name)
        and func.value.id == "builtins"
    )


def _starred_kwargs(rec: _CallRec) -> Optional[ast.expr]:
    """Return the ``**kwargs`` expression of a call, if present."""
    for name, expr in rec.keywords:
        if name is None:
            return expr
    return None


def _literal_dict_bindings(expr: ast.expr) -> Optional[Dict[str, ast.expr]]:
    """Constant-key entries of a dict literal, or None if not fully static."""
    if not isinstance(expr, ast.Dict):
        return None
    items: Dict[str, ast.expr] = {}
    for key, val in zip(expr.keys, expr.values):
        if key is None or val is None:
            return None
        ks = _literal_str(key)
        if not ks:
            return None
        items[ks] = val
    return items


def _class_key_for_name(
    name: str,
    file_rel: str,
    functions: Dict[str, FuncIR],
) -> Optional[str]:
    """Return ``file::Class`` when ``name`` has methods indexed in that file."""
    prefix = f"{file_rel}::{name}."
    if any(k.startswith(prefix) for k in functions):
        return f"{file_rel}::{name}"
    return None


def _instance_type_from_factory(
    ir: FuncIR,
    functions: Dict[str, FuncIR],
) -> Optional[str]:
    """If a factory returns ``SomeClass()``, bind callers to that class.

    ``llm = get_client()`` must resolve ``llm.invoke`` onto ``Client.invoke``,
    not onto the factory function name.
    """
    found: Set[str] = set()
    try:
        for node in ast.walk(ir.node):
            if not isinstance(node, ast.Return) or not isinstance(node.value, ast.Call):
                continue
            chain = get_call_chain(node.value)
            if len(chain) != 1:
                continue
            key = _class_key_for_name(chain[0], ir.file, functions)
            if key:
                found.add(key)
    except Exception:
        return None
    if len(found) == 1:
        return next(iter(found))
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
        file_registries: Optional[Dict[str, Dict[str, Set[str]]]] = None,
    ) -> None:
        self.ir = ir
        self.functions = functions
        self.returns_by_ctx = returns_by_ctx
        self.resolve = resolve
        local_imports = dict(imports)
        try:
            local_imports.update(_imports_in(ir.node, ir.file))
        except Exception:
            pass
        self.imports = local_imports
        self.import_modules = _import_module_map(local_imports)
        self.files_by_mod = files_by_mod
        self.file_registries = file_registries or {}
        self.tainted: Dict[str, Set[Origin]] = {k: set(v) for k, v in param_origins.items()}
        self.sanitized: Set[str] = set()
        # Names that passed a fail-closed, resolved destination check.
        self._url_dest_constrained: Set[str] = set()
        # Names bound to a tool_calls list or a single tool-call object.
        self._tool_call_collections: Set[str] = set()
        self._tool_call_names: Set[str] = set()
        self.func_aliases: Dict[str, Set[str]] = {}
        self.registries: Dict[str, Set[str]] = {}
        self._tool_arg_dicts: Set[str] = {
            p for p, origs in param_origins.items()
            if any(getattr(o, "shape", "") == "tool_arg_dict" for o in origs)
        }
        try:
            self._load_registries()
        except Exception:
            pass
        self.instance_types: Dict[str, str] = {}
        self.sql_receivers: Set[str] = set()
        self.http_receivers: Set[str] = set()
        self._name_bindings: Dict[str, ast.expr] = {}
        try:
            self.http_receivers.update(
                collect_http_receivers(ir.node, self.import_modules)
            )
        except Exception:
            pass
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
        line = getattr(ir.node, "lineno", None)
        for p in ir.params:
            if p in _SKIP_PARAMS or p in self.tainted:
                continue
            self.tainted[p] = {
                Origin(_PARAM_SOURCE, ir.file, line, ir.name, kind="payload")
            }

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if node is not self._target:
            return
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        if node is not self._target:
            return
        self.generic_visit(node)

    def _new_origin(
        self,
        source_type: str,
        expr: ast.expr,
        kind: Optional[str] = None,
        shape: str = "",
    ) -> Origin:
        """Build an origin for a source expression."""
        return Origin(
            source_type,
            self.ir.file,
            getattr(expr, "lineno", None),
            self.ir.name,
            kind=kind or _kind_for_source(source_type),
            shape=shape,
        )

    def _load_registries(self) -> None:
        """Copy module-level and imported function-registry names into this frame."""
        for name, keys in self.file_registries.get(self.ir.file, {}).items():
            self.registries[name] = set(keys)
        for local, ref in self.imports.items():
            if not ref.symbol:
                continue
            fpath = _find_module_file(ref.module, self.files_by_mod)
            if not fpath:
                continue
            keys = self.file_registries.get(fpath, {}).get(ref.symbol)
            if keys:
                self.registries[local] = set(keys)

    def _lookup_registry(self, expr: ast.expr) -> Optional[Set[str]]:
        """Function keys stored in a tool registry expression, if known."""
        if isinstance(expr, ast.Name):
            return self.registries.get(expr.id)
        if isinstance(expr, ast.Attribute) and isinstance(expr.value, ast.Name):
            ref = self.imports.get(expr.value.id)
            if ref and not ref.symbol:
                fpath = _find_module_file(ref.module, self.files_by_mod)
                if fpath:
                    return self.file_registries.get(fpath, {}).get(expr.attr)
        return None

    def _registry_lookup_expr(self, expr: ast.expr) -> Optional[Set[str]]:
        """Registry targets of ``TOOLS.get``, ``TOOLS[name]``, ``getattr(TOOLS, name)``."""
        if (
            isinstance(expr, ast.Call)
            and isinstance(expr.func, ast.Attribute)
            and expr.func.attr == "get"
        ):
            return self._lookup_registry(expr.func.value)
        if _is_getattr_call(expr) and len(expr.args) >= 2:
            return self._lookup_registry(expr.args[0])
        if isinstance(expr, ast.Subscript):
            return self._lookup_registry(expr.value)
        return self._lookup_registry(expr)

    def _functions_of(self, expr: ast.expr) -> Set[str]:
        """Possible in-repo function keys referenced by ``expr``."""
        keys = self._registry_lookup_expr(expr)
        if keys:
            return set(keys)
        if isinstance(expr, ast.Name):
            if expr.id in self.func_aliases:
                return set(self.func_aliases[expr.id])
            key = self.resolve([expr.id], self.instance_types)
            return {key} if key else set()
        return set()

    def _resolve_call_targets(self, node: ast.Call) -> List[str]:
        """Statically resolvable callees of ``node``, including registry lookups."""
        keys = self._functions_of(node.func)
        if keys:
            return sorted(keys)
        key = self.resolve(get_call_chain(node), self.instance_types)
        return [key] if key else []

    def _is_tool_arg_dict(self, expr: ast.expr) -> bool:
        """True when ``expr`` is an identified tool-call arguments mapping."""
        if _is_tool_argument_source(expr) or _is_bound_tool_argument(
            expr, self._tool_call_names
        ):
            return True
        if isinstance(expr, ast.Name) and expr.id in self._tool_arg_dicts:
            return True
        if isinstance(expr, ast.Name):
            return any(
                getattr(o, "shape", "") == "tool_arg_dict"
                for o in self.tainted.get(expr.id, ())
            )
        return False

    def _note_func_binding(self, targets: List[str], value: ast.expr) -> None:
        """Track aliases of functions and local tool-registry dicts."""
        keys = self._functions_of(value)
        if not keys:
            local = _function_dict_targets(
                value, self.ir.file, self.functions, self.imports, self.files_by_mod
            )
            if local:
                for t in targets:
                    self.registries[t] = set(local)
                return
        for t in targets:
            if keys:
                self.func_aliases[t] = set(keys)
            else:
                self.func_aliases.pop(t, None)

    def _note_tool_arg_dict(self, targets: List[str], value: ast.expr) -> None:
        """Record names bound to a tool-call arguments dictionary."""
        if self._is_tool_arg_dict(value):
            self._tool_arg_dicts.update(targets)
        else:
            for t in targets:
                self._tool_arg_dicts.discard(t)

    def _rec_from_call(self, node: ast.Call) -> _CallRec:
        wrapped = _thread_wrapper_fn_and_args(node)
        if wrapped is not None:
            fn_expr, pos, kws = wrapped
            rec = _CallRec(
                lineno=getattr(node, "lineno", 0) or 0,
                chain=_chain_for_expr(fn_expr),
                positional=list(pos),
                keywords=list(kws),
                assign_targets=[],
                targets=[],
            )
            try:
                rec.targets = sorted(self._functions_of(fn_expr))
                if not rec.targets:
                    key = self.resolve(rec.chain, self.instance_types)
                    rec.targets = [key] if key else []
            except Exception:
                rec.targets = []
            return rec
        rec = _CallRec(
            lineno=getattr(node, "lineno", 0) or 0,
            chain=get_call_chain(node),
            positional=list(node.args),
            keywords=[(kw.arg, kw.value) for kw in node.keywords],
            assign_targets=[],
            targets=[],
        )
        try:
            rec.targets = self._resolve_call_targets(node)
        except Exception:
            rec.targets = []
        return rec

    def _incoming_for_call(self, callee: FuncIR, rec: _CallRec) -> Dict[str, Set[Origin]]:
        incoming: Dict[str, Set[Origin]] = {}
        mapping = _map_call_args(callee, rec)
        for pname, expr in mapping.items():
            orig = self._origins_in(expr)
            if orig:
                incoming[pname] = orig
        try:
            self._bind_starred_kwargs(callee, rec, mapping, incoming)
        except Exception:
            pass
        return incoming

    def _bind_starred_kwargs(
        self,
        callee: FuncIR,
        rec: _CallRec,
        mapping: Dict[str, ast.expr],
        incoming: Dict[str, Set[Origin]],
    ) -> None:
        """Map ``**kwargs`` onto unbound callee parameters when keys are known.

        A tool-argument dictionary may bind any still-unbound named parameter
        of this resolved callee. Explicit positional/keyword bindings win.
        Literal dict keys are mapped field-sensitively and do not taint
        other parameters.
        """
        starred = _starred_kwargs(rec)
        if starred is None:
            return
        literal = _literal_dict_bindings(starred)
        if literal is not None:
            for pname, expr in literal.items():
                if pname in mapping or pname not in callee.params:
                    continue
                orig = self._origins_in(expr)
                if orig:
                    incoming[pname] = orig
            return
        if not self._is_tool_arg_dict(starred):
            return
        orig = self._origins_in(starred)
        if not orig:
            return
        payload = {
            Origin(o.source_type, o.file, o.line, o.function, kind=o.kind, shape="")
            for o in orig
        }
        for pname in callee.params:
            if pname in mapping or pname in _SKIP_PARAMS:
                continue
            incoming.setdefault(pname, set()).update(payload)

    def _returns_for_call(self, node: ast.Call) -> Set[Origin]:
        """Returns of this call site's callee context only — not a function-wide union."""
        rec = self._rec_from_call(node)
        found: Set[Origin] = set()
        for key in rec.targets:
            if not key or key not in self.functions:
                continue
            incoming = self._incoming_for_call(self.functions[key], rec)
            ctx = _freeze_params(incoming)
            found |= set(self.returns_by_ctx.get((key, ctx), set()))
        return found

    def _is_json_parse_call(self, node: ast.Call) -> bool:
        """True for ``json.loads`` / ``json.load`` / ``from json import loads``."""
        chain = [c.lower() for c in get_call_chain(node)]
        if not chain or chain[-1] not in _JSON_PARSE_FUNCS:
            return False
        if "json" in chain:
            return True
        if len(chain) == 1:
            ref = self.imports.get(chain[0])
            if ref and (ref.module or "").split(".")[-1].lower() == "json":
                return True
        return False

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
            shape = (
                "tool_arg_dict"
                if (
                    _is_tool_argument_source(expr)
                    or _is_bound_tool_argument(expr, self._tool_call_names)
                )
                else ""
            )
            found.add(self._new_origin(src[0], expr, shape=shape))
        if _is_bound_tool_argument(expr, self._tool_call_names):
            found.add(self._new_origin("llm_output", expr, shape="tool_arg_dict"))
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
                if method in _PASSTHROUGH_METHODS or self._is_json_parse_call(expr):
                    found |= self._passthrough_args(expr)
                elif method in _RECEIVER_METHODS:
                    pass  # receiver taint only; argument identifiers are not the result
            elif isinstance(func, ast.Name) and (
                func.id.lower() in _PASSTHROUGH_FUNCS or self._is_json_parse_call(expr)
            ):
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
        callee = self.resolve(chain, self.instance_types)
        if callee and callee in self.functions:
            inst = _instance_type_from_factory(self.functions[callee], self.functions)
            if inst:
                self.instance_types[targets[0]] = inst
                return
        head = chain[0]
        ref = self.imports.get(head)
        if ref and ref.symbol:
            fpath = _find_module_file(ref.module, self.files_by_mod)
            if fpath:
                cls = _class_key_for_name(ref.symbol, fpath, self.functions)
                self.instance_types[targets[0]] = cls or f"{fpath}::{ref.symbol}"
            return
        if len(chain) == 1:
            cls = _class_key_for_name(head, self.ir.file, self.functions)
            self.instance_types[targets[0]] = cls or f"{self.ir.file}::{head}"

    def visit_If(self, node: ast.If) -> None:
        """Walk both branches without treating them as straight-line kills."""
        self._branch_depth += 1
        self.generic_visit(node)
        self._branch_depth -= 1
        try:
            self._apply_fail_closed_url_guard(node)
        except Exception:
            pass

    def _callee_param_for_name(self, call: ast.Call, url_name: str) -> Optional[str]:
        """Map a caller URL name onto the resolved callee parameter."""
        key = self.resolve(get_call_chain(call), self.instance_types)
        if not key:
            return None
        ir = self.functions.get(key)
        if ir is None:
            return None
        for pname, expr in _map_call_args(ir, self._rec_from_call(call)).items():
            if isinstance(expr, ast.Name) and expr.id == url_name:
                return pname
        if len(call.args) == 1 and ir.params:
            return ir.params[0]
        return None

    def _resolved_is_host_allowlist(self, call: ast.Call, url_name: str) -> bool:
        """True when the resolved callee is an effective host allow-list."""
        param = self._callee_param_for_name(call, url_name)
        key = self.resolve(get_call_chain(call), self.instance_types)
        ir = self.functions.get(key) if key else None
        if not param or ir is None:
            return False
        return _function_is_host_allowlist(ir.node, param)

    def _apply_fail_closed_url_guard(self, node: ast.If) -> None:
        """Mark a URL name constrained after ``if not allowlist(url): raise``.

        The allow-list inspects the same URL string later passed to the HTTP
        client. A separate DNS lookup does not constrain that connection.
        """
        test = node.test
        if not (isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not)):
            return
        parsed = _single_name_predicate(test.operand)
        if parsed and _stmts_raise_only(node.body):
            call, name = parsed
            if self._resolved_is_host_allowlist(call, name):
                self._url_dest_constrained.add(name)

    def _url_destination_prevented(self, sink: ast.Call, names: Set[str]) -> bool:
        """True when the sink URL is the allow-listed string and redirects are off.

        A prior ``getaddrinfo`` / private-IP check is not enough: the client
        still resolves the original URL independently.
        """
        try:
            if not names or not _http_redirects_disabled(sink):
                return False
            return names <= self._url_dest_constrained
        except Exception:
            return False

    def visit_Try(self, node: ast.Try) -> None:
        """Retain possible taint across try/except/finally joins."""
        self._branch_depth += 1
        self.generic_visit(node)
        self._branch_depth -= 1

    def _bind_iter_taint(self, target: ast.expr, iter_expr: ast.expr) -> None:
        """Field-insensitive: iterating a tainted collection taints loop targets."""
        orig = self._origins_in(iter_expr)
        if not orig:
            return
        names: List[str] = []
        if isinstance(target, ast.Name):
            names = [target.id]
        elif isinstance(target, (ast.Tuple, ast.List)):
            names = [e.id for e in target.elts if isinstance(e, ast.Name)]
        for n in names:
            self.tainted.setdefault(n, set()).update(orig)

    def visit_For(self, node: ast.For) -> None:
        """Loop bodies are not a straight-line kill; 0 iterations remain possible."""
        try:
            self._bind_tool_call_loop(node)
            self._bind_iter_taint(node.target, node.iter)
        except Exception:
            pass
        self._branch_depth += 1
        self.generic_visit(node)
        self._branch_depth -= 1

    def _iter_is_tool_calls(self, expr: ast.expr) -> bool:
        """True when a for-iter is a tool_calls collection or an alias of one."""
        if _is_tool_calls_collection(expr):
            return True
        return isinstance(expr, ast.Name) and expr.id in self._tool_call_collections

    def _bind_tool_call_loop(self, node: ast.For) -> None:
        """Mark the loop target as a tool-call object when iterating tool_calls."""
        if isinstance(node.target, ast.Name) and self._iter_is_tool_calls(node.iter):
            self._tool_call_names.add(node.target.id)

    def _note_tool_call_binding(self, targets: List[str], value: ast.expr) -> None:
        """Track names assigned from tool_calls lists or a single call object."""
        is_collection = _is_tool_calls_collection(value)
        is_element = isinstance(value, ast.Subscript) and (
            _is_tool_calls_collection(value.value)
            or (
                isinstance(value.value, ast.Name)
                and value.value.id in self._tool_call_collections
            )
        )
        if isinstance(value, ast.Name) and value.id in self._tool_call_names:
            is_element = True
        for t in targets:
            if is_collection:
                self._tool_call_collections.add(t)
            else:
                self._tool_call_collections.discard(t)
            if is_element:
                self._tool_call_names.add(t)
            else:
                self._tool_call_names.discard(t)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        """Same join semantics as ``for``."""
        try:
            self._bind_iter_taint(node.target, node.iter)
        except Exception:
            pass
        self._branch_depth += 1
        self.generic_visit(node)
        self._branch_depth -= 1

    def visit_While(self, node: ast.While) -> None:
        """Loop bodies are not a straight-line kill."""
        self._branch_depth += 1
        self.generic_visit(node)
        self._branch_depth -= 1

    def _bind_with_http_receivers(self, node: ast.With | ast.AsyncWith) -> None:
        """Treat ``with httpx.Client() as client`` as an HTTP receiver binding."""
        for item in node.items:
            expr = item.context_expr
            if not isinstance(expr, ast.Call):
                continue
            if not is_http_factory_call(expr, self.import_modules):
                continue
            target = item.optional_vars
            names: List[str] = []
            if isinstance(target, ast.Name):
                names = [target.id]
            elif isinstance(target, (ast.Tuple, ast.List)):
                names = [e.id for e in target.elts if isinstance(e, ast.Name)]
            for n in names:
                self.http_receivers.add(n.lower())
                self._name_bindings[n] = expr

    def visit_With(self, node: ast.With) -> None:
        """Context-manager bodies may not run to completion."""
        try:
            self._bind_with_http_receivers(node)
        except Exception:
            pass
        self._branch_depth += 1
        self.generic_visit(node)
        self._branch_depth -= 1

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        """Same join semantics as ``with``."""
        try:
            self._bind_with_http_receivers(node)
        except Exception:
            pass
        self._branch_depth += 1
        self.generic_visit(node)
        self._branch_depth -= 1

    def visit_Assign(self, node: ast.Assign) -> None:
        targets = _get_assign_targets(node)
        if not targets:
            self.generic_visit(node)
            return
        try:
            self._note_tool_call_binding(targets, node.value)
            self._note_func_binding(targets, node.value)
            self._note_tool_arg_dict(targets, node.value)
        except Exception:
            pass
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
        for t in targets:
            self._name_bindings[t] = node.value
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
                self._url_dest_constrained.discard(t)
        elif isinstance(node.value, ast.Name) and node.value.id in self._url_dest_constrained:
            for t in targets:
                self._url_dest_constrained.add(t)
        elif self._branch_depth == 0:
            for t in targets:
                self.tainted.pop(t, None)
                self._url_dest_constrained.discard(t)
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
        rec = self._rec_from_call(node)
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
            node,
            self.import_modules,
            self.sql_receivers,
            self.http_receivers,
            self._name_bindings,
        )
        if sink:
            cat, label = sink
            lineno = getattr(node, "lineno", 0) or 0
            if cat == "http":
                for role, expr in http_arg_roles(node):
                    orig = self._origins_in(expr)
                    if role != "url":
                        orig = {o for o in orig if o.source_type != _PARAM_SOURCE}
                    names = _names_in_expr(expr)
                    if (
                        role == "url"
                        and orig
                        and names
                        and self._url_destination_prevented(node, names)
                    ):
                        continue
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
                orig = {o for o in orig if o.source_type != _PARAM_SOURCE}
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
            if rec.targets:
                return
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
        if rec.targets:
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


def _dedupe_near_identical_flows(flows: List[DataFlow]) -> List[DataFlow]:
    """Keep the most complete hop list per source/sink location."""
    best: Dict[Tuple, DataFlow] = {}
    order: List[Tuple] = []
    for flow in flows:
        key = (
            flow.source,
            flow.source_file,
            flow.source_line,
            flow.file,
            flow.line,
            flow.sink,
            flow.sink_category,
            getattr(flow, "sink_arg_role", "") or "",
        )
        prev = best.get(key)
        if prev is None:
            best[key] = flow
            order.append(key)
            continue
        if len(flow.hops) > len(prev.hops):
            best[key] = flow
    return [best[k] for k in order]


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
    functions, imports_by_file, files_by_mod, file_registries = _index_repo(repo_root)
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
        im = dict(imports_by_file.get(ir.file, {}))
        try:
            im.update(_imports_in(ir.node, ir.file))
        except Exception:
            pass

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
                    file_registries,
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
                    targets = list(rec.targets)
                    if not targets:
                        callee_key = vis.resolve(rec.chain, vis.instance_types)
                        if callee_key:
                            targets = [callee_key]
                    for callee_key in targets:
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
                # function_param and lookup_result (file_read / external_api)
                # are possible paths, not proof of attacker control.
                weak_source = (
                    o.source_type == _PARAM_SOURCE
                    or o.kind == "lookup_result"
                    or o.source_type in {"file_read", "external_api", "config", "environment"}
                )
                flow_confidence = "may" if (incomplete or weak_source) else confidence
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
                    confidence=flow_confidence,
                    taint_kind=o.kind,
                    sink_arg_role=role,
                ))
    flows = _dedupe_near_identical_flows(flows)
    return DataFlowAnalysisResult(
        data_flows=flows,
        incomplete=incomplete,
        incomplete_reasons=list(incomplete_reasons),
        coverage=coverage,
    )
