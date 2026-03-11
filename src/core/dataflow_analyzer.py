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

from .detectors._ast_utils import walk_python_files, should_skip_path

# Extend path filter to skip dataflow_analyzer itself when used from discovery
def _should_skip(path: Path, repo_root: Path) -> bool:
    if should_skip_path(path, repo_root):
        return True
    try:
        rel = path.relative_to(repo_root)
    except ValueError:
        return True
    if "core" in rel.parts and "dataflow_analyzer" in rel.parts:
        return True
    return False


# ---------------------------------------------------------------------------
# Source patterns: (chain_patterns, source_label, risk)
# chain = ['requests', 'get'] or ['request', 'json'] etc.
# ---------------------------------------------------------------------------

SOURCE_PATTERNS: List[Tuple[List[str], str, str]] = [
    # (call/attr chain (lowered), source_label, risk)
    (["request", "json"], "user_input", "high"),
    (["request", "args"], "user_input", "high"),
    (["request", "form"], "user_input", "high"),
    (["request", "data"], "user_input", "high"),
    (["request", "get_json"], "user_input", "high"),
    (["request", "form"], "user_input", "high"),
    (["flask", "request", "json"], "user_input", "high"),
    (["flask", "request", "args"], "user_input", "high"),
    (["input"], "user_input", "high"),
    (["sys", "argv"], "user_input", "medium"),
    (["cursor", "execute"], "database", "high"),
    (["session", "query"], "database", "high"),
    (["fetchall"], "database", "high"),
    (["fetchone"], "database", "high"),
    (["execute"], "database", "medium"),  # generic, may be DB
    (["open"], "file_read", "medium"),
    (["read"], "file_read", "medium"),
    (["load"], "file_read", "medium"),
    (["loads"], "file_read", "medium"),
    (["read_csv"], "file_read", "medium"),
    (["read_json"], "file_read", "medium"),
    (["load_json"], "file_read", "medium"),
    (["os", "getenv"], "environment", "medium"),
    (["os", "environ"], "environment", "medium"),
    (["environ", "get"], "environment", "medium"),
    (["requests", "get"], "http_request", "high"),
    (["requests", "post"], "http_request", "high"),
    (["requests", "put"], "http_request", "high"),
    (["requests", "patch"], "http_request", "high"),
    (["requests", "request"], "http_request", "high"),
    (["httpx", "get"], "http_request", "high"),
    (["httpx", "post"], "http_request", "high"),
]

# Sink patterns: (chain_contains, sink_label)
# Full chain must contain these for a match
SINK_PATTERNS: List[Tuple[List[str], str]] = [
    (["openai", "chat", "completions", "create"], "openai.chat.completions.create"),
    (["openai", "completion", "create"], "openai.Completion.create"),
    (["openai", "chat", "completions", "create"], "openai.ChatCompletion.create"),
    (["openai", "completions", "create"], "openai.completions.create"),
    (["anthropic", "messages", "create"], "anthropic.messages.create"),
    (["anthropic", "messages", "create"], "Anthropic.client.messages.create"),
    (["cohere", "chat", "create"], "cohere.chat.create"),
    (["cohere", "generate"], "cohere.generate"),
    (["invoke"], "LangChain LLM invoke"),  # llm.invoke - need chain context
    (["chat", "completions", "create"], "openai.ChatCompletion"),
    (["messages", "create"], "Anthropic messages.create"),
    (["query"], "llama_index query"),  # index.query
    (["chat"], "llama_index chat"),   # index.chat - may overlap, refine by chain
    (["pipeline"], "transformers pipeline"),  # pipeline("text-generation")
    (["generate"], "LLM generate"),
    (["create"], "LLM create"),
]

# Refined sink: require chain to contain provider indicators for generic names
SINK_PROVIDER_INDICATORS = {"openai", "anthropic", "cohere", "vertexai", "bedrock", "mistral", "litellm", "llm", "chat", "completion", "messages", "completions"}


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

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "sink": self.sink,
            "file": self.file,
            "line": self.line,
            "risk": self.risk,
        }


@dataclass
class DataFlowAnalysisResult:
    """Result of data flow analysis."""

    data_flows: List[DataFlow] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "data_flows": [df.to_dict() for df in self.data_flows],
        }


def _get_call_chain(node: ast.Call) -> List[str]:
    """Get full call chain e.g. ['openai', 'chat', 'completions', 'create']."""
    chain: List[str] = []
    n = node.func
    while isinstance(n, ast.Attribute):
        chain.append(n.attr)
        n = n.value
    if isinstance(n, ast.Name):
        chain.append(n.id)
    elif isinstance(n, ast.Call):
        chain.extend(_get_call_chain(n))
    return list(reversed(chain))


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


def _get_attr_chain(node: ast.expr) -> List[str]:
    """Get attribute chain e.g. request.json -> ['request','json']."""
    chain: List[str] = []
    n = node
    while isinstance(n, ast.Attribute):
        chain.append(n.attr)
        n = n.value
    if isinstance(n, ast.Name):
        chain.append(n.id)
    return list(reversed(chain))


def _is_source_call(node: ast.Call) -> Optional[Tuple[str, str]]:
    """Return (source_label, risk) if node is a source call."""
    chain = _get_call_chain(node)
    chain_str = ".".join(chain).lower()
    for pattern, label, risk in SOURCE_PATTERNS:
        pat_str = ".".join(pattern).lower()
        if pat_str in chain_str or _chain_matches(chain, pattern):
            return (label, risk)
    # Check for request.json as attribute (not call)
    return None


def _is_source_value(node: ast.expr) -> Optional[Tuple[str, str]]:
    """Check if expression is a source (call or attribute like request.json)."""
    if isinstance(node, ast.Call):
        return _is_source_call(node)
    if isinstance(node, ast.Attribute):
        chain = _get_attr_chain(node)
        for pattern, label, risk in SOURCE_PATTERNS:
            if len(pattern) <= len(chain) and pattern == [c.lower() for c in chain[-len(pattern):]]:
                return (label, risk)
        if chain and chain[-1].lower() in ("json", "args", "form", "data"):
            if len(chain) >= 2 and chain[0].lower() in ("request", "req"):
                return ("user_input", "high")
    if isinstance(node, ast.Subscript):
        if isinstance(node.value, ast.Attribute):
            chain = _get_attr_chain(node.value)
            if chain and chain[0].lower() in ("request", "req") and chain[-1].lower() in ("args", "form"):
                return ("user_input", "high")
        if isinstance(node.value, ast.Name) and node.value.id.lower() == "sys":
            return ("user_input", "medium")  # sys['argv']-like
    if isinstance(node, ast.Name) and node.id == "sys":
        return None  # sys alone isn't a source
    return None


def _is_sink_call(node: ast.Call) -> Optional[str]:
    """Return sink label if node is an LLM sink."""
    chain = _get_call_chain(node)
    chain_lower = [c.lower() for c in chain]
    chain_set = set(chain_lower)
    for pattern, label in SINK_PATTERNS:
        if not _chain_matches(chain, pattern):
            continue
        if pattern in (["invoke"], ["query"], ["chat"]):
            if chain_set & (SINK_PROVIDER_INDICATORS | {"llm", "chain", "index", "retriever", "agent"}):
                return label
        else:
            return label
    if "create" in chain_set and chain_set & {"openai", "anthropic", "cohere", "completions", "chat", "messages"}:
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
    """Per-function taint analysis visitor."""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.tainted: Dict[str, Tuple[str, str, Optional[int]]] = {}  # var -> (source, risk, line)
        self.flows: List[DataFlow] = []
        self._in_function = False

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._in_function = True
        func_tainted = dict(self.tainted)
        self.generic_visit(node)
        self.tainted = func_tainted
        self._in_function = False

    def visit_Assign(self, node: ast.Assign) -> None:
        targets = _get_assign_targets(node)
        if not targets:
            self.generic_visit(node)
            return

        src = _is_source_value(node.value)
        if src:
            label, risk = src
            line = getattr(node, "lineno", None)
            for t in targets:
                self.tainted[t] = (label, risk, line)
        else:
            refs = _names_in_expr(node.value)
            for r in refs:
                if r in self.tainted:
                    label, risk, _ = self.tainted[r]
                    line = getattr(node, "lineno", None)
                    for t in targets:
                        self.tainted[t] = (label, risk, line)
                    break
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        sink_label = _is_sink_call(node)
        if sink_label:
            for arg in node.args:
                refs = _names_in_expr(arg)
                for r in refs:
                    if r in self.tainted:
                        src_label, risk, src_line = self.tainted[r]
                        self.flows.append(DataFlow(
                            source=src_label,
                            sink=sink_label,
                            file=self.file_path,
                            line=getattr(node, "lineno", None),
                            risk=risk,
                            source_line=src_line,
                        ))
                        break
            for kw in node.keywords:
                refs = _names_in_expr(kw.value)
                for r in refs:
                    if r in self.tainted:
                        src_label, risk, src_line = self.tainted[r]
                        self.flows.append(DataFlow(
                            source=src_label,
                            sink=sink_label,
                            file=self.file_path,
                            line=getattr(node, "lineno", None),
                            risk=risk,
                            source_line=src_line,
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
        if path.suffix != ".py" or _should_skip(path, repo_root):
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
