"""
AI Data Flow Analysis (Taint Analysis).

Tracks how sensitive or external data flows into LLM inference sinks.
Uses Python AST parsing for intra-procedural taint tracking.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from ..utils.ast_utils import walk_python_files, should_skip_path, get_call_chain, get_attr_chain

# Extend path filter to skip dataflow_analyzer itself when used from discovery

# ---------------------------------------------------------------------------
# Source risk classification: risk level by source type
# Used to derive risk for source → LLM flows (e.g. user_input→LLM = high)
# ---------------------------------------------------------------------------

SOURCE_RISK: Dict[str, str] = {
    "user_input": "high",
    "mcp_tool_arg": "high",
    "external_api": "medium",
    "environment": "medium",
    "file_read": "low",
    "config": "low",
    "internal_variable": "low",
}

# Source patterns: (chain_patterns, source_type)
# source_type must be a key in SOURCE_RISK; risk is derived via SOURCE_RISK.get(source_type)
SOURCE_PATTERNS: List[Tuple[List[str], str]] = [
    # HTTP request user input — Flask / raw ASGI
    (["request", "json"], "user_input"),
    (["request", "args"], "user_input"),
    (["request", "form"], "user_input"),
    (["request", "data"], "user_input"),
    (["request", "get_json"], "user_input"),
    (["request", "files"], "user_input"),  # file uploads
    (["request", "get_data"], "user_input"),
    (["flask", "request", "json"], "user_input"),
    (["flask", "request", "args"], "user_input"),
    (["flask", "request", "form"], "user_input"),
    (["flask", "request", "files"], "user_input"),
    # FastAPI — Pydantic model fields read from request body
    # e.g. async def chat(body: ChatRequest): ... body.message
    (["body", "message"], "user_input"),
    (["body", "query"], "user_input"),
    (["body", "prompt"], "user_input"),
    (["body", "input"], "user_input"),
    (["body", "text"], "user_input"),
    (["body", "content"], "user_input"),
    # FastAPI — common Pydantic schema field names used directly as params
    (["message"], "user_input"),
    (["query"], "user_input"),
    (["user_query"], "user_input"),
    (["user_input"], "user_input"),
    (["user_message"], "user_input"),
    (["chat_input"], "user_input"),
    # FastAPI — await request.json() / request.body()
    (["request", "body"], "user_input"),
    (["request", "json"], "user_input"),
    (["input"], "user_input"),
    (["sys", "argv"], "user_input"),
    # Database fields
    (["cursor", "execute"], "external_api"),
    (["session", "query"], "external_api"),
    (["db", "execute"], "external_api"),
    (["conn", "execute"], "external_api"),
    (["fetchall"], "external_api"),
    (["fetchone"], "external_api"),
    # Specific file-read patterns only
    (["open"], "file_read"),
    (["loads"], "file_read"),
    (["read_csv"], "file_read"),
    (["read_json"], "file_read"),
    (["load_json"], "file_read"),
    (["json", "loads"], "file_read"),
    (["json", "load"], "file_read"),
    (["os", "getenv"], "environment"),
    (["os", "environ"], "environment"),
    (["environ", "get"], "environment"),
    (["requests", "get"], "external_api"),
    (["requests", "post"], "external_api"),
    (["requests", "put"], "external_api"),
    (["requests", "patch"], "external_api"),
    (["requests", "request"], "external_api"),
    (["httpx", "get"], "external_api"),
    (["httpx", "post"], "external_api"),
    (["yaml", "safe_load"], "config"),
    (["yaml", "load"], "config"),
    (["toml", "load"], "config"),
]

# Sink patterns: (chain_contains, sink_label)
SINK_PATTERNS: List[Tuple[List[str], str]] = [
    (["openai", "chat", "completions", "create"], "openai.ChatCompletion.create"),
    (["client", "chat", "completions", "create"], "client.chat.completions.create"),
    (["openai", "completion", "create"], "openai.Completion.create"),
    (["openai", "completions", "create"], "openai.completions.create"),
    (["anthropic", "messages", "create"], "anthropic.messages.create"),
    (["anthropic", "client", "messages", "create"], "anthropic.client.messages.create"),
    (["cohere", "chat", "create"], "cohere.chat.create"),
    (["cohere", "generate"], "cohere.generate"),
    (["bedrock", "invoke_model"], "bedrock.invoke_model"),
    (["vertexai", "generate_content"], "vertexai.generate_content"),
    (["generativeai", "generate_content"], "generativeai.generate_content"),
    (["chat", "completions", "create"], "LLM ChatCompletion.create"),
    (["messages", "create"], "LLM messages.create"),
    (["chain", "invoke"], "LangChain chain.invoke"),
    (["llm", "invoke"], "LangChain LLM invoke"),
    (["agent", "invoke"], "LangChain Agent invoke"),
    (["retrieval_chain", "invoke"], "LangChain RetrievalChain"),
    (["qa_chain", "invoke"], "LangChain QA chain"),
    (["agent_executor", "invoke"], "LangChain AgentExecutor"),
    (["llm", "ainvoke"], "LangChain LLM ainvoke"),
    (["chain", "ainvoke"], "LangChain chain.ainvoke"),
    (["agent", "ainvoke"], "LangChain Agent ainvoke"),
    (["query_engine", "query"], "LlamaIndex query engine"),
    (["index", "query"], "LlamaIndex index query"),
    (["as_query_engine"], "LlamaIndex query engine"),
    (["invoke"], "LangChain LLM invoke"),
    (["ainvoke"], "LangChain LLM ainvoke"),
    (["arun"], "LangChain LLM arun"),
    (["astream"], "LangChain LLM astream"),
    (["generate"], "LLM generate"),
    (["pipeline"], "transformers pipeline"),
]

# Provider names that confirm a generic single-token sink is an LLM call.
SINK_PROVIDER_INDICATORS = {
    "openai", "anthropic", "cohere", "vertexai", "bedrock", "mistral",
    "litellm", "llm", "langchain", "llamaindex", "llama_index",
    "langchain_openai", "langchain_core", "langchain_community",
    "completion", "completions", "chat_model", "transformers", "diffusers",
}

# Sanitization functions: call chain pattern -> True if sanitizes
# When tainted_var is passed to these, the result is considered sanitized (mitigated)
SANITIZATION_PATTERNS: List[List[str]] = [
    ["escape"],
    ["sanitize"],
    ["strip_html"],
    ["guardrails", "validate"],
    ["guardrails", "apply"],
    ["prompt_guard"],
    ["moderation"],
    ["input_validation"],
    ["validate_input"],
    ["clean_input"],
    ["html", "escape"],
    ["bleach", "clean"],
    ["markupsafe", "escape"],
]


def _chain_matches(chain: List[str], pattern: List[str]) -> bool:
    """Check if chain contains pattern as contiguous subsequence."""
    chain_lower = [c.lower() for c in chain]
    pat_lower = [p.lower() for p in pattern]
    if len(pat_lower) > len(chain_lower):
        return False
    for i in range(len(chain_lower) - len(pat_lower) + 1):
        if chain_lower[i:i + len(pat_lower)] == pat_lower:
            return True
    return False


def _chain_contains_any(chain: List[str], keywords: Set[str]) -> bool:
    chain_lower = set(c.lower() for c in chain)
    return bool(chain_lower & keywords)


@dataclass
class DataFlow:
    """Single source-to-sink data flow (intra- or inter-procedural)."""

    source: str
    sink: str
    file: str
    line: Optional[int]
    risk: str
    source_line: Optional[int] = None
    sanitized: bool = False  # True when input passed through sanitization before sink
    source_file: str = ""
    source_function: str = ""
    sink_function: str = ""
    sink_category: str = ""  # llm | sql | rce
    hops: List[str] = field(default_factory=list)
    confidence: str = "high"
    # payload = request/user value; identifier = lookup key derived from input;
    # lookup_result = value produced by an external fetch (not request payload).
    taint_kind: str = "payload"
    # HTTP argument role: url | query | body | headers | unresolved | ""
    sink_arg_role: str = ""

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "source_type": self.source,
            "sink": self.sink,
            "file": self.file,
            "line": self.line,
            "risk": self.risk,
            "sanitized": self.sanitized,
            "source_file": self.source_file or self.file,
            "source_function": self.source_function,
            "sink_function": self.sink_function,
            "sink_category": self.sink_category,
            "hops": list(self.hops),
            "confidence": self.confidence,
            "taint_kind": self.taint_kind,
            "sink_arg_role": self.sink_arg_role,
            "source_line": self.source_line,
        }


@dataclass
class DataFlowAnalysisResult:
    """Result of data flow analysis.

    ``incomplete`` is False when the worklist reached a fixpoint under the
    configured iteration and per-function context caps. True means at least
    one cap truncated the analysis; missing flows must not be treated as
    absence of taint.
    """

    data_flows: List[DataFlow] = field(default_factory=list)
    incomplete: bool = False
    incomplete_reasons: List[str] = field(default_factory=list)
    # Coverage limitations (unresolved/unsupported calls). Not findings.
    coverage: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "data_flows": [df.to_dict() for df in self.data_flows],
            "incomplete": self.incomplete,
            "incomplete_reasons": list(self.incomplete_reasons),
            "coverage": dict(self.coverage) if self.coverage else {
                "unresolved_calls": {"count": 0, "samples": []},
                "unsupported_call_forms": {"count": 0, "samples": []},
            },
        }



def _attr_taint_key(node: ast.expr) -> Optional[str]:
    """Instance/module attribute as a taint key, e.g. self.prompt."""
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
        return f"{node.value.id}.{node.attr}"
    return None


def _get_assign_targets(node: ast.Assign) -> List[str]:
    """Get assigned variable names (and simple obj.attr keys) from Assign."""
    names: List[str] = []
    for t in node.targets:
        if isinstance(t, ast.Name):
            names.append(t.id)
        else:
            attr = _attr_taint_key(t)
            if attr:
                names.append(attr)
            elif isinstance(t, ast.Tuple):
                for e in t.elts:
                    if isinstance(e, ast.Name):
                        names.append(e.id)
                    else:
                        nested = _attr_taint_key(e)
                        if nested:
                            names.append(nested)
    return names



def _get_source_risk(source_type: str) -> str:
    """Derive risk level from source type using SOURCE_RISK mapping."""
    return SOURCE_RISK.get(source_type, "medium")


_REQUEST_DATA_ATTRS = {"json", "args", "form", "data", "files", "get_json", "get_data", "body"}
_BODY_FIELD_ATTRS = {
    "message", "query", "prompt", "input", "text",
    "content", "user_query", "user_input", "user_message",
}


def _source_call_matches(chain: List[str], pattern: List[str]) -> bool:
    """Exact one-token match, or contiguous multi-token chain match. No substrings."""
    if not pattern:
        return False
    if len(pattern) == 1:
        return len(chain) == 1 and chain[0].lower() == pattern[0].lower()
    return _chain_matches(chain, pattern)


def _is_source_call(node: ast.Call) -> Optional[Tuple[str, str]]:
    """Return (source_type, risk) if node is a source call."""
    chain = get_call_chain(node)
    hits: List[Tuple[int, str]] = []
    for pattern, source_type in SOURCE_PATTERNS:
        if _source_call_matches(chain, pattern):
            hits.append((len(pattern), source_type))
    if not hits:
        return None
    hits.sort(key=lambda h: -h[0])
    source_type = hits[0][1]
    return (source_type, _get_source_risk(source_type))


def _is_source_value(node: ast.expr) -> Optional[Tuple[str, str]]:
    """Check if expression is a source (call or request/body attribute)."""
    if isinstance(node, ast.Call):
        return _is_source_call(node)
    if isinstance(node, ast.Attribute):
        chain = get_attr_chain(node)
        chain_l = [c.lower() for c in chain]
        for pattern, source_type in SOURCE_PATTERNS:
            if len(pattern) < 2:
                continue
            pat_l = [p.lower() for p in pattern]
            if len(pat_l) <= len(chain_l) and chain_l[-len(pat_l):] == pat_l:
                return (source_type, _get_source_risk(source_type))
        if (
            len(chain_l) >= 2
            and chain_l[0] in {"request", "req"}
            and chain_l[-1] in _REQUEST_DATA_ATTRS
        ):
            return ("user_input", _get_source_risk("user_input"))
        if (
            len(chain_l) >= 2
            and chain_l[0] == "body"
            and chain_l[-1] in _BODY_FIELD_ATTRS
        ):
            return ("user_input", _get_source_risk("user_input"))
    if isinstance(node, ast.Subscript):
        inner = _is_source_value(node.value)
        if inner:
            return inner
        if isinstance(node.value, ast.Attribute):
            chain = get_attr_chain(node.value)
            if chain and chain[0].lower() in ("request", "req") and chain[-1].lower() in ("args", "form", "json", "data"):
                return ("user_input", _get_source_risk("user_input"))
        if isinstance(node.value, ast.Name) and node.value.id.lower() == "sys":
            return ("user_input", _get_source_risk("user_input"))
    if isinstance(node, ast.Name) and node.id == "sys":
        return None  # sys alone isn't a source
    return None


def _is_sanitization_call(node: ast.Call) -> bool:
    """Return True if this call is a sanitization function (escape, sanitize, guardrails, etc.)."""
    chain = get_call_chain(node)
    chain_lower = ".".join(c.lower() for c in chain)
    for pattern in SANITIZATION_PATTERNS:
        pat_str = ".".join(p.lower() for p in pattern)
        if pat_str in chain_lower or _chain_matches(chain, pattern):
            return True
    return False


_GENERIC_SINK_PATTERNS = {
    ("invoke",), ("ainvoke",), ("arun",), ("astream",),
    ("generate",), ("pipeline",),
}


def _canonicalize_sink_chain(
    chain: List[str],
    import_modules: Optional[Dict[str, str]] = None,
) -> Tuple[List[str], Set[str]]:
    """Rewrite aliased import heads (import openai as o) into module tokens."""
    rewritten = list(chain)
    extra: Set[str] = set()
    if chain and import_modules:
        mod = import_modules.get(chain[0])
        if mod:
            prefix = [p for p in mod.split(".") if p]
            rewritten = prefix + chain[1:]
            for part in mod.replace("-", "_").replace(".", "_").split("_"):
                if part:
                    extra.add(part.lower())
    chain_set = {c.lower() for c in rewritten} | extra
    return rewritten, chain_set

_MCP_HANDLER_EXACT = {"call_tool", "handle_tool_call", "dispatch_tool"}
_MCP_ARG_NAMES = {"arguments", "args", "params"}
_MCP_FILE_HINTS = (
    "list_tools", "call_tool", "mcp.tool", "FastMCP", "fastmcp",
    "mcpServers", "types.Tool", "Server(",
)


def _decorator_attr(dec: ast.expr) -> str:
    """Return the last attribute/name of a decorator expression."""
    if isinstance(dec, ast.Attribute):
        return dec.attr.lower()
    if isinstance(dec, ast.Name):
        return dec.id.lower()
    if isinstance(dec, ast.Call):
        if isinstance(dec.func, ast.Attribute):
            return dec.func.attr.lower()
        if isinstance(dec.func, ast.Name):
            return dec.func.id.lower()
    return ""


def _has_tool_decorator(func: ast.AST) -> bool:
    """True if the function is decorated as an MCP/agent tool."""
    for dec in getattr(func, "decorator_list", []) or []:
        if _decorator_attr(dec) in {"tool", "function_tool"}:
            return True
    return False


def _is_mcp_tool_function(func: ast.AST, is_mcp_file: bool) -> bool:
    """True for call_tool / handle_* (MCP files only) / @mcp.tool handlers."""
    if _has_tool_decorator(func):
        return True
    name = getattr(func, "name", "")
    if name in _MCP_HANDLER_EXACT:
        return True
    if is_mcp_file and (name.startswith("handle_") or name.startswith("_handle_")):
        return True
    return False


def _mcp_arg_source(node: ast.expr) -> Optional[Tuple[str, str]]:
    """arguments.get / args['x'] only — not generic dict.get."""
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == "get" and isinstance(node.func.value, ast.Name):
            if node.func.value.id in _MCP_ARG_NAMES:
                return ("mcp_tool_arg", SOURCE_RISK["mcp_tool_arg"])
    if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
        if node.value.id in _MCP_ARG_NAMES:
            return ("mcp_tool_arg", SOURCE_RISK["mcp_tool_arg"])
    return None


def _is_sink_call(
    node: ast.Call,
    import_modules: Optional[Dict[str, str]] = None,
) -> Optional[str]:
    """Return sink label if node is an LLM sink.

    import_modules maps local names to imported module paths so
    ``import openai as o; o.chat.completions.create()`` resolves as OpenAI.
    Generic method names (invoke/ainvoke/chat) still require a provider token.
    """
    raw = get_call_chain(node)
    chain, chain_set = _canonicalize_sink_chain(raw, import_modules)
    for pattern, label in SINK_PATTERNS:
        if not _chain_matches(chain, pattern):
            continue
        if tuple(pattern) in _GENERIC_SINK_PATTERNS:
            if chain_set & SINK_PROVIDER_INDICATORS:
                return label
        else:
            return label
    # Catch-all for .create() — only when an explicit LLM provider is in the chain
    if "create" in chain_set and chain_set & {"openai", "anthropic", "cohere", "completions", "messages"}:
        return "LLM API create"
    return None


def _names_in_expr(node: ast.expr) -> Set[str]:
    """Extract Name ids and simple obj.attr keys referenced in expression."""
    names: Set[str] = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Name):
            names.add(n.id)
        else:
            attr = _attr_taint_key(n)
            if attr:
                names.add(attr)
    return names


class _TaintVisitor(ast.NodeVisitor):
    """Per-function taint analysis visitor with sanitization tracking."""

    def __init__(self, file_path: str, source_text: str = ""):
        self.file_path = file_path
        self.tainted: Dict[str, Tuple[str, str, Optional[int]]] = {}  # var -> (source, risk, line)
        self.sanitized: Set[str] = set()  # vars that passed through sanitization (mitigated)
        self.flows: List[DataFlow] = []
        self._in_function = False
        self._in_mcp_handler = False
        self._is_mcp_file = any(h in source_text for h in _MCP_FILE_HINTS)

    def _visit_function(self, node: ast.AST) -> None:
        saved_tainted = dict(self.tainted)
        saved_sanitized = set(self.sanitized)
        saved_mcp = self._in_mcp_handler
        self._in_function = True
        self._in_mcp_handler = _is_mcp_tool_function(node, self._is_mcp_file)
        if self._in_mcp_handler:
            line = getattr(node, "lineno", None)
            skip = {"self", "cls", "name"}
            for a in node.args.args:
                if a.arg not in skip:
                    self.tainted[a.arg] = ("mcp_tool_arg", SOURCE_RISK["mcp_tool_arg"], line)
            for a in node.args.kwonlyargs:
                if a.arg not in skip:
                    self.tainted[a.arg] = ("mcp_tool_arg", SOURCE_RISK["mcp_tool_arg"], line)
        self.generic_visit(node)
        self.tainted = saved_tainted
        self.sanitized = saved_sanitized
        self._in_mcp_handler = saved_mcp
        self._in_function = False

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        targets = _get_assign_targets(node)
        if not targets:
            self.generic_visit(node)
            return

        # Check for sanitization: target = sanitize(tainted_var)
        if isinstance(node.value, ast.Call) and _is_sanitization_call(node.value):
            refs = _names_in_expr(node.value)
            if refs & set(self.tainted.keys()) and not (refs & self.sanitized):
                for t in targets:
                    self.sanitized.add(t)
            self.generic_visit(node)
            return

        src = None
        if self._in_mcp_handler:
            src = _mcp_arg_source(node.value)
        if src is None:
            src = _is_source_value(node.value)
        if src:
            label, risk = src
            line = getattr(node, "lineno", None)
            for t in targets:
                self.tainted[t] = (label, risk, line)
                self.sanitized.discard(t)  # Fresh source is not sanitized
        else:
            refs = _names_in_expr(node.value)
            had_tainted = False
            had_sanitized = False
            for r in refs:
                if r in self.tainted:
                    had_tainted = True
                    label, risk, _ = self.tainted[r]
                    line = getattr(node, "lineno", None)
                    for t in targets:
                        self.tainted[t] = (label, risk, line)
                    break
                if r in self.sanitized:
                    had_sanitized = True
            if had_sanitized and not had_tainted:
                for t in targets:
                    self.sanitized.add(t)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        sink_label = _is_sink_call(node)
        if sink_label:
            for arg in node.args:
                refs = _names_in_expr(arg)
                for r in refs:
                    if r in self.tainted:
                        src_label, risk, src_line = self.tainted[r]
                        is_sanitized = r in self.sanitized
                        self.flows.append(DataFlow(
                            source=src_label,
                            sink=sink_label,
                            file=self.file_path,
                            line=getattr(node, "lineno", None),
                            risk=risk,
                            source_line=src_line,
                            sanitized=is_sanitized,
                        ))
                        break
            for kw in node.keywords:
                refs = _names_in_expr(kw.value)
                for r in refs:
                    if r in self.tainted:
                        src_label, risk, src_line = self.tainted[r]
                        is_sanitized = r in self.sanitized
                        self.flows.append(DataFlow(
                            source=src_label,
                            sink=sink_label,
                            file=self.file_path,
                            line=getattr(node, "lineno", None),
                            risk=risk,
                            source_line=src_line,
                            sanitized=is_sanitized,
                        ))
                        break
        self.generic_visit(node)


def analyze_dataflows(
    repo_root: Path,
    *,
    max_iters: Optional[int] = None,
    max_contexts_per_func: Optional[int] = None,
) -> DataFlowAnalysisResult:
    """
    Analyze Python files for source-to-sink data flows.

    Runs interprocedural (cross-function / cross-file) taint propagation
    for arguments, parameters, and return values. Falls back to empty
    results on failure rather than raising.

    max_iters / max_contexts_per_func override worklist safety caps (tests).
    """
    try:
        from .interproc_taint import analyze_interproc_dataflows

        return analyze_interproc_dataflows(
            Path(repo_root).resolve(),
            max_iters=max_iters,
            max_contexts_per_func=max_contexts_per_func,
        )
    except Exception:
        return DataFlowAnalysisResult(data_flows=[])
