"""
Sensitive Data Exposure Detector for AITrace.

Detects when variables with sensitive keywords (password, secret, api_key, etc.)
flow into LLM inference calls, indicating potential data leakage to external providers.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

from .detectors._ast_utils import should_skip_path

# Sensitive keywords in variable names -> risk level
SENSITIVE_KEYWORDS: Dict[str, str] = {
    "password": "critical",
    "passwd": "critical",
    "secret": "critical",
    "api_key": "critical",
    "apikey": "critical",
    "token": "critical",
    "auth": "high",
    "ssn": "critical",
    "credit_card": "critical",
    "creditcard": "critical",
    "email": "high",
    "phone": "high",
}

# LLM sink patterns: (chain_pattern, sink_label)
SINK_PATTERNS: List[tuple] = [
    (["openai", "chat", "completions", "create"], "OpenAI API"),
    (["openai", "completion", "create"], "OpenAI API"),
    (["anthropic", "messages", "create"], "Anthropic API"),
    (["cohere", "chat", "create"], "Cohere API"),
    (["cohere", "generate"], "Cohere API"),
    (["invoke"], "LangChain LLM invoke"),
    (["messages", "create"], "LLM API"),
    (["query"], "LlamaIndex query"),
    (["chat"], "LLM chat"),
    (["pipeline"], "Transformers pipeline"),
    (["generate"], "LLM generate"),
    (["create"], "LLM create"),
]
SINK_INDICATORS = {"openai", "anthropic", "cohere", "vertexai", "bedrock", "mistral", "litellm", "llm", "chain", "index", "retriever", "agent", "chat", "completion", "messages", "completions"}


def _var_contains_sensitive(name: str) -> Optional[str]:
    """Return risk level if variable name contains a sensitive keyword."""
    n = name.lower().replace("_", "")
    for kw, risk in SENSITIVE_KEYWORDS.items():
        if kw.replace("_", "") in n or kw in name.lower():
            return risk
    return None


def _get_call_chain(node: ast.Call) -> List[str]:
    chain: List[str] = []
    n = node.func
    while isinstance(n, ast.Attribute):
        chain.append(n.attr)
        n = n.value
    if isinstance(n, ast.Name):
        chain.append(n.id)
    return list(reversed(chain))


def _chain_matches(chain: List[str], pattern: List[str]) -> bool:
    chain_lower = [c.lower() for c in chain]
    pat_lower = [p.lower() for p in pattern]
    if len(pat_lower) > len(chain_lower):
        return False
    for i in range(len(chain_lower) - len(pat_lower) + 1):
        if chain_lower[i : i + len(pat_lower)] == pat_lower:
            return True
    return False


def _is_llm_sink(node: ast.Call) -> Optional[str]:
    chain = _get_call_chain(node)
    chain_set = set(c.lower() for c in chain)
    for pattern, label in SINK_PATTERNS:
        if not _chain_matches(chain, pattern):
            continue
        if pattern in (["invoke"], ["query"], ["chat"]):
            if chain_set & SINK_INDICATORS:
                return label
        else:
            return label
    if "create" in chain_set and chain_set & {"openai", "anthropic", "cohere", "completions", "chat", "messages"}:
        return "LLM API"
    return None


def _names_in_expr(node: ast.expr) -> Set[str]:
    names: Set[str] = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Name):
            names.add(n.id)
    return names


def _get_assign_targets(node: ast.Assign) -> List[str]:
    names: List[str] = []
    for t in node.targets:
        if isinstance(t, ast.Name):
            names.append(t.id)
        elif isinstance(t, ast.Tuple):
            for e in t.elts:
                if isinstance(e, ast.Name):
                    names.append(e.id)
    return names


@dataclass
class SensitiveExposure:
    """Single sensitive variable exposure to LLM sink."""

    variable: str
    sink: str
    file: str
    line: Optional[int]
    risk: str  # "high" | "critical"

    def to_dict(self) -> dict:
        return {
            "variable": self.variable,
            "sink": self.sink,
            "file": self.file,
            "line": self.line,
            "risk": self.risk,
        }


@dataclass
class SensitiveExposureResult:
    """Result of sensitive data exposure analysis."""

    sensitive_exposures: List[SensitiveExposure] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "sensitive_exposures": [e.to_dict() for e in self.sensitive_exposures],
        }


class _SensitiveVisitor(ast.NodeVisitor):
    """Tracks sensitive-named variables and detects flows to LLM sinks."""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.sensitive_vars: Set[str] = set()
        self.exposures: List[SensitiveExposure] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        func_sensitive = set(self.sensitive_vars)
        self.generic_visit(node)
        self.sensitive_vars = func_sensitive

    def visit_Assign(self, node: ast.Assign) -> None:
        targets = _get_assign_targets(node)
        for t in targets:
            risk = _var_contains_sensitive(t)
            if risk:
                self.sensitive_vars.add(t)
            else:
                refs = _names_in_expr(node.value)
                if refs & self.sensitive_vars:
                    self.sensitive_vars.update(targets)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        sink_label = _is_llm_sink(node)
        if sink_label:
            for arg in node.args:
                refs = _names_in_expr(arg)
                for r in refs:
                    if r in self.sensitive_vars:
                        risk = _var_contains_sensitive(r) or "high"
                        self.exposures.append(SensitiveExposure(
                            variable=r,
                            sink=sink_label,
                            file=self.file_path,
                            line=getattr(node, "lineno", None),
                            risk=risk,
                        ))
                        break
            for kw in node.keywords:
                refs = _names_in_expr(kw.value)
                for r in refs:
                    if r in self.sensitive_vars:
                        risk = _var_contains_sensitive(r) or "high"
                        self.exposures.append(SensitiveExposure(
                            variable=r,
                            sink=sink_label,
                            file=self.file_path,
                            line=getattr(node, "lineno", None),
                            risk=risk,
                        ))
                        break
        self.generic_visit(node)


def _should_skip(path: Path, repo_root: Path) -> bool:
    if should_skip_path(path, repo_root):
        return True
    try:
        rel = path.relative_to(repo_root)
    except ValueError:
        return True
    if "core" in rel.parts and "sensitive_data_detector" in rel.parts:
        return True
    return False


def analyze_sensitive_exposures(repo_root: Path) -> SensitiveExposureResult:
    """Analyze Python files for sensitive variables flowing into LLM sinks."""
    repo_root = Path(repo_root).resolve()
    all_exposures: List[SensitiveExposure] = []
    seen: Set[tuple] = set()

    for path in repo_root.rglob("*.py"):
        if path.suffix != ".py" or _should_skip(path, repo_root):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"))
        except (SyntaxError, OSError):
            continue

        rel_path = str(path.relative_to(repo_root))
        visitor = _SensitiveVisitor(rel_path)
        visitor.visit(tree)

        for e in visitor.exposures:
            key = (e.variable, e.sink, e.file, e.line)
            if key not in seen:
                seen.add(key)
                all_exposures.append(e)

    return SensitiveExposureResult(sensitive_exposures=all_exposures)
