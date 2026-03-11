"""
Prompt Injection Exposure Detector for AITrace.

Detects when untrusted input is directly passed to an AI agent or LLM with tool access.
Risk pattern: User input → Agent → Tools
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from .detectors._ast_utils import should_skip_path

# Agent invocation methods
INVOKE_METHODS = {"invoke", "run", "stream", "ainvoke", "arun", "astream", "kickoff"}

# Agent framework patterns (chain must contain these)
AGENT_PATTERNS = {
    "create_react_agent",
    "create_agent",
    "AgentExecutor",
    "initialize_agent",
    "StateGraph",
    "create_crew",
    "Crew",
    "Kernel",
    "SemanticFunction",
    "Pipeline",
    "Agent",
}

# High-risk tools (enable prompt injection to execution)
HIGH_RISK_TOOLS = {
    "searchtool",
    "browsertool",
    "shelltool",
    "pythontool",
    "gmailtoolspec",
    "serperapitool",
    "webtool",
    "bash",
    "shell",
    "python_repl",
    "code_interpreter",
}

# User input variable name patterns (heuristic)
USER_INPUT_NAMES = {
    "user_input",
    "user_query",
    "user_message",
    "query",
    "prompt",
    "message",
    "human_input",
    "request",
    "input_text",
    "user_prompt",
    "question",
    "text",
}


def _get_call_chain(node: ast.Call) -> List[str]:
    chain: List[str] = []
    n = node.func
    while isinstance(n, ast.Attribute):
        chain.append(n.attr)
        n = n.value
    if isinstance(n, ast.Name):
        chain.append(n.id)
    return list(reversed(chain))


def _chain_matches(chain: List[str], pattern: str) -> bool:
    chain_lower = ".".join(c.lower() for c in chain)
    return pattern.lower() in chain_lower or any(
        p.lower() in c.lower() for c in chain for p in pattern.split()
    )


def _is_user_input_source(node: ast.expr) -> bool:
    """Check if RHS of assignment is a user input source."""
    if isinstance(node, ast.Call):
        chain = _get_call_chain(node)
        chain_str = ".".join(chain).lower()
        if "request" in chain_str and ("json" in chain_str or "args" in chain_str or "form" in chain_str):
            return True
        if "input" in chain_str and len(chain) <= 2:
            return True
        if "get_json" in chain_str or "get_data" in chain_str:
            return True
    if isinstance(node, ast.Attribute):
        chain = _get_attr_chain(node)
        if chain and chain[0].lower() in ("request", "req"):
            if any(c in chain[-1].lower() for c in ("json", "args", "form", "data")):
                return True
    return False


def _get_attr_chain(node: ast.expr) -> List[str]:
    chain: List[str] = []
    n = node
    while isinstance(n, ast.Attribute):
        chain.append(n.attr)
        n = n.value
    if isinstance(n, ast.Name):
        chain.append(n.id)
    return list(reversed(chain))


def _is_high_risk_tool(name: str) -> bool:
    n = name.lower().replace("_", "").replace("-", "")
    return any(rt in n or n in rt for rt in HIGH_RISK_TOOLS)


def _get_assigned_names(node: ast.Assign) -> List[str]:
    names: List[str] = []
    for t in node.targets:
        if isinstance(t, ast.Name):
            names.append(t.id)
        elif isinstance(t, ast.Tuple):
            for e in t.elts:
                if isinstance(e, ast.Name):
                    names.append(e.id)
    return names


def _names_in_expr(node: ast.expr) -> Set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _get_strings_in(node: ast.expr) -> Set[str]:
    out: Set[str] = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            out.add(n.value.lower())
    return out


@dataclass
class PromptInjectionRisk:
    """Single prompt injection exposure risk."""

    agent_framework: str
    tools: List[str]
    input_source: str
    risk: str
    file: str
    line: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "agent_framework": self.agent_framework,
            "tools": self.tools,
            "input_source": self.input_source,
            "risk": self.risk,
            "file": self.file,
            "line": self.line,
        }


@dataclass
class PromptInjectionResult:
    """Result of prompt injection detection."""

    prompt_injection_risks: List[PromptInjectionRisk] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "prompt_injection_risks": [r.to_dict() for r in self.prompt_injection_risks],
        }


class _PromptInjectionVisitor(ast.NodeVisitor):
    """Detects agent + tools + user input flows."""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.user_input_vars: Set[str] = set()
        self.agent_vars: Set[str] = set()
        self.tools_in_file: Set[str] = set()
        self.risks: List[PromptInjectionRisk] = []
        self._agent_framework: str = "unknown"

    def _var_looks_like_user_input(self, name: str) -> bool:
        n = name.lower().replace("_", "")
        return any(uin in n or n == uin.replace("_", "") for uin in USER_INPUT_NAMES)

    def visit_Assign(self, node: ast.Assign) -> None:
        targets = _get_assigned_names(node)
        if _is_user_input_source(node.value):
            self.user_input_vars.update(targets)
        else:
            refs = _names_in_expr(node.value)
            if refs & self.user_input_vars:
                self.user_input_vars.update(targets)
        for t in targets:
            if self._var_looks_like_user_input(t):
                self.user_input_vars.add(t)
        # Track agent assignment (for invoke receiver check)
        if isinstance(node.value, ast.Call):
            chain = _get_call_chain(node.value)
            chain_str = ".".join(c.lower() for c in chain)
            if any(ap.lower() in chain_str for ap in AGENT_PATTERNS):
                self.agent_vars.update(targets)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        chain = _get_call_chain(node)
        chain_lower = [c.lower() for c in chain]

        # Agent creation with tools
        for ap in AGENT_PATTERNS:
            if ap.lower() in ".".join(chain_lower):
                if "langchain" in ".".join(chain_lower) or "create_react" in ".".join(chain_lower) or "agentelement" in ".".join(chain_lower):
                    self._agent_framework = "langchain"
                elif "semantic" in ".".join(chain_lower) or "kernel" in ".".join(chain_lower):
                    self._agent_framework = "semantic_kernel"
                elif "haystack" in ".".join(chain_lower) or "pipeline" in ".".join(chain_lower):
                    self._agent_framework = "haystack"
                elif "crew" in ".".join(chain_lower):
                    self._agent_framework = "crewai"
                # Check for tools in args
                for kw in node.keywords:
                    if kw.arg and kw.arg.lower() == "tools":
                        for s in _get_strings_in(kw.value):
                            if _is_high_risk_tool(s):
                                self.tools_in_file.add(s)
                        for n in _names_in_expr(kw.value):
                            self.tools_in_file.add(n)
                if len(node.args) >= 2:
                    for s in _get_strings_in(node.args[1]):
                        if _is_high_risk_tool(s):
                            self.tools_in_file.add(s)
                # LHS receives agent
                break

        # Tool registration: load_tools(["serpapi", "python_repl"]), Tool("name"), SearchTool()
        if "load_tools" in ".".join(chain_lower):
            for arg in node.args:
                for s in _get_strings_in(arg):
                    if 2 <= len(s) <= 50:
                        self.tools_in_file.add(s)
        elif "tool" in ".".join(chain_lower) or "tool" in chain_lower:
            for arg in node.args[:2]:
                for s in _get_strings_in(arg):
                    if _is_high_risk_tool(s):
                        self.tools_in_file.add(s)
            for kw in node.keywords:
                if kw.arg and "name" in kw.arg.lower():
                    for s in _get_strings_in(kw.value):
                        if _is_high_risk_tool(s):
                            self.tools_in_file.add(s)

        # Agent invocation: agent.invoke(user_input)
        if len(chain) >= 2 and chain[-1].lower() in INVOKE_METHODS:
            if node.args:
                arg = node.args[0]
                if isinstance(arg, ast.Name):
                    arg_name = arg.id
                    receiver_name = chain[0] if chain else ""
                    is_agent = receiver_name in self.agent_vars
                    if is_agent and (
                        arg_name in self.user_input_vars or self._var_looks_like_user_input(arg_name)
                    ):
                        tools_list = list(self.tools_in_file)[:10] if self.tools_in_file else ["tools (inferred)"]
                        self.risks.append(PromptInjectionRisk(
                            agent_framework=self._agent_framework or "agent",
                            tools=tools_list,
                            input_source=arg_name,
                            risk="high" if self.tools_in_file else "medium",
                            file=self.file_path,
                            line=getattr(node, "lineno", None),
                        ))
        self.generic_visit(node)


def _should_skip(path: Path, repo_root: Path) -> bool:
    if should_skip_path(path, repo_root):
        return True
    try:
        rel = path.relative_to(repo_root)
    except ValueError:
        return True
    if "core" in rel.parts and "prompt_injection_detector" in rel.parts:
        return True
    return False


def analyze_prompt_injection(repo_root: Path) -> PromptInjectionResult:
    """Analyze Python files for prompt injection exposure (user input → agent with tools)."""
    repo_root = Path(repo_root).resolve()
    all_risks: List[PromptInjectionRisk] = []
    seen: Set[Tuple[str, str, Optional[int]]] = set()

    for path in repo_root.rglob("*.py"):
        if path.suffix != ".py" or _should_skip(path, repo_root):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"))
        except (SyntaxError, OSError):
            continue

        rel_path = str(path.relative_to(repo_root))
        visitor = _PromptInjectionVisitor(rel_path)
        visitor.visit(tree)

        for r in visitor.risks:
            key = (r.input_source, r.file, r.line)
            if key not in seen:
                seen.add(key)
                all_risks.append(r)

    return PromptInjectionResult(prompt_injection_risks=all_risks)
