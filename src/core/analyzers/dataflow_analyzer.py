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
from typing import Dict, List, Optional, Set, Tuple

from ..utils.ast_utils import walk_python_files, should_skip_path, get_call_chain, get_attr_chain

# Extend path filter to skip dataflow_analyzer itself when used from discovery

# ---------------------------------------------------------------------------
# Source risk classification: risk level by source type
# Used to derive risk for source → LLM flows (e.g. user_input→LLM = high)
# ---------------------------------------------------------------------------

SOURCE_RISK: Dict[str, str] = {
    "user_input": "high",
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
    (["query_engine", "query"], "LlamaIndex query engine"),
    (["index", "query"], "LlamaIndex index query"),
    (["as_query_engine"], "LlamaIndex query engine"),
    (["invoke"], "LangChain LLM invoke"),
    (["generate"], "LLM generate"),
    (["pipeline"], "transformers pipeline"),
]

# Provider names that confirm a generic single-token sink is an LLM call.
SINK_PROVIDER_INDICATORS = {
    "openai", "anthropic", "cohere", "vertexai", "bedrock", "mistral",
    "litellm", "llm", "langchain", "llamaindex", "llama_index",
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
    """Single source-to-sink data flow."""

    source: str
    sink: str
    file: str
    line: Optional[int]
    risk: str
    source_line: Optional[int] = None
    sanitized: bool = False  # True when input passed through sanitization before sink

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "source_type": self.source,
            "sink": self.sink,
            "file": self.file,
            "line": self.line,
            "risk": self.risk,
            "sanitized": self.sanitized,
        }


@dataclass
class DataFlowAnalysisResult:
    """Result of data flow analysis."""

    data_flows: List[DataFlow] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "data_flows": [df.to_dict() for df in self.data_flows],
        }



def _get_assign_targets(node: ast.Assign) -> List[str]:
    """Get assigned variable names from Assign node."""
    names: List[str] = []
    for t in node.targets:
        if isinstance(t, ast.Name):
            names.append(t.id)
        elif isinstance(t, ast.Tuple):
            for e in t.elts:
                if isinstance(e, ast.Name):
                    names.append(e.id)
    return names



def _get_source_risk(source_type: str) -> str:
    """Derive risk level from source type using SOURCE_RISK mapping."""
    return SOURCE_RISK.get(source_type, "medium")


def _is_source_call(node: ast.Call) -> Optional[Tuple[str, str]]:
    """Return (source_type, risk) if node is a source call."""
    chain = get_call_chain(node)
    chain_str = ".".join(chain).lower()
    for pattern, source_type in SOURCE_PATTERNS:
        pat_str = ".".join(pattern).lower()
        if pat_str in chain_str or _chain_matches(chain, pattern):
            return (source_type, _get_source_risk(source_type))
    return None


def _is_source_value(node: ast.expr) -> Optional[Tuple[str, str]]:
    """Check if expression is a source (call or attribute like request.json). Returns (source_type, risk)."""
    if isinstance(node, ast.Call):
        return _is_source_call(node)
    if isinstance(node, ast.Attribute):
        chain = get_attr_chain(node)
        for pattern, source_type in SOURCE_PATTERNS:
            if len(pattern) <= len(chain) and pattern == [c.lower() for c in chain[-len(pattern):]]:
                return (source_type, _get_source_risk(source_type))
        if chain and chain[-1].lower() in ("json", "args", "form", "data"):
            if len(chain) >= 2 and chain[0].lower() in ("request", "req"):
                return ("user_input", _get_source_risk("user_input"))
        # FastAPI Pydantic attrs — checked independently (not nested inside json/args/form check)
        _FASTAPI_ATTRS = {
            "message", "query", "prompt", "input", "text",
            "content", "user_query", "user_input", "user_message",
        }
        if len(chain) >= 2 and chain[-1].lower() in _FASTAPI_ATTRS:
            return ("user_input", _get_source_risk("user_input"))
    if isinstance(node, ast.Subscript):
        if isinstance(node.value, ast.Attribute):
            chain = get_attr_chain(node.value)
            if chain and chain[0].lower() in ("request", "req") and chain[-1].lower() in ("args", "form"):
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


_GENERIC_SINK_PATTERNS = {("invoke",), ("generate",), ("pipeline",)}


def _is_sink_call(node: ast.Call) -> Optional[str]:
    """Return sink label if node is an LLM sink."""
    chain = get_call_chain(node)
    chain_set = set(c.lower() for c in chain)
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
    """Extract all Name ids referenced in expression."""
    names: Set[str] = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Name):
            names.add(n.id)
    return names


class _TaintVisitor(ast.NodeVisitor):
    """Per-function taint analysis visitor with sanitization tracking."""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.tainted: Dict[str, Tuple[str, str, Optional[int]]] = {}  # var -> (source, risk, line)
        self.sanitized: Set[str] = set()  # vars that passed through sanitization (mitigated)
        self.flows: List[DataFlow] = []
        self._in_function = False

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._in_function = True
        func_tainted = dict(self.tainted)
        func_sanitized = set(self.sanitized)
        self.generic_visit(node)
        self.tainted = func_tainted
        self.sanitized = func_sanitized
        self._in_function = False

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


def analyze_dataflows(repo_root: Path) -> DataFlowAnalysisResult:
    """
    Analyze Python files for sensitive data flows into LLM sinks.

    Returns DataFlowAnalysisResult with data_flows list.
    """
    repo_root = Path(repo_root).resolve()
    all_flows: List[DataFlow] = []
    seen: Set[Tuple[str, str, str, Optional[int]]] = set()

    for path in repo_root.rglob("*.py"):
        if path.suffix != ".py" or should_skip_path(path, repo_root):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"))
        except (SyntaxError, OSError):
            continue

        rel_path = str(path.relative_to(repo_root))
        visitor = _TaintVisitor(rel_path)
        visitor.visit(tree)

        for df in visitor.flows:
            key = (df.source, df.sink, df.file, df.line)
            if key not in seen:
                seen.add(key)
                all_flows.append(df)

    return DataFlowAnalysisResult(data_flows=all_flows)
