"""
Prompt Injection Exposure Detector for AITrace.

Context-aware detection of user input flowing to LLM prompts.
- Integrates with data flow analyzer for user_input → LLM sink flows
- Tracks sanitization (escape, sanitize, guardrails, etc.) to reduce false positives
- Agent+tools flows (user input → agent with high-risk tools)
- Output: type, severity, sanitized, source_file, sink_file, evidence
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from .dataflow_analyzer import DataFlow, analyze_dataflows
from .detectors._ast_utils import should_skip_path

# Agent invocation methods — async variants kept; bare "run" and "stream" removed
# because they match subprocess.run(), file.stream(), etc. outside agent context.
INVOKE_METHODS = {"invoke", "ainvoke", "arun", "astream", "kickoff"}

# Agent framework patterns — unambiguous framework-specific names only.
# Removed bare "Pipeline", "Agent", "Kernel", "Crew": too generic (sklearn Pipeline,
# HTTP Agent, Jupyter Kernel, film crew) — they fire without any AI framework context.
AGENT_PATTERNS = {
    "create_react_agent",
    "create_agent",
    "AgentExecutor",
    "initialize_agent",
    "StateGraph",
    "create_crew",
    "CrewAI",
    "SemanticFunction",
    "KernelBuilder",
    "HaystackPipeline",
}

# Sanitization functions for agent flows (same as dataflow_analyzer)
SANITIZATION_NAMES = frozenset({
    "escape", "sanitize", "strip_html", "guardrails", "prompt_guard",
    "moderation", "input_validation", "validate_input", "clean_input",
    "guardrails.validate", "guardrails.apply", "html.escape", "bleach.clean", "markupsafe.escape",
})

# High-risk tools (enable prompt injection to execution)
HIGH_RISK_TOOLS = {
    "searchtool", "browsertool", "shelltool", "pythontool", "gmailtoolspec",
    "serperapitool", "webtool", "bash", "shell", "python_repl", "code_interpreter",
    "execute",
    # PythonREPL variants — LangChain code execution tools
    "pythonrepltool", "pythonrepl", "repl", "python_repl_tool",
    "baseshelltool", "shell_tool",
}

# Dangerous code execution patterns — variable names and call patterns
# that indicate LLM output flows into exec() / eval() / cursor.execute()
EXEC_SINK_NAMES = {
    "exec", "eval", "compile", "subprocess", "os.system",
    "cursor.execute", "conn.execute", "db.execute",
}

# Variable names that suggest they hold LLM-generated content
LLM_OUTPUT_NAMES = {
    "llm_output", "llm_response", "response", "completion", "generated",
    "ai_output", "model_output", "agent_output", "result", "answer",
    "generated_code", "generated_sql", "sql_query", "code",
}

# User input variable name heuristics — require "user_" prefix or explicit input-context suffix.
# Removed: "query", "message", "text", "request" — too common in non-LLM code
# (DB queries, log messages, plain text, HTTP request objects).
# "prompt" is borderline but kept because it's strongly associated with LLM usage.
USER_INPUT_NAMES = {
    "user_input", "user_query", "user_message", "user_prompt",
    "human_input", "input_text", "question", "prompt",
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


def _get_attr_chain(node: ast.expr) -> List[str]:
    chain: List[str] = []
    n = node
    while isinstance(n, ast.Attribute):
        chain.append(n.attr)
        n = n.value
    if isinstance(n, ast.Name):
        chain.append(n.id)
    return list(reversed(chain))


def _is_sanitization_call(node: ast.Call) -> bool:
    """Check if call is a sanitization function."""
    if isinstance(node.func, ast.Name):
        return node.func.id.lower() in SANITIZATION_NAMES
    if isinstance(node.func, ast.Attribute):
        chain = _get_call_chain(node)
        chain_lower = ".".join(c.lower() for c in chain)
        return any(s in chain_lower for s in SANITIZATION_NAMES)
    return False


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


_FASTAPI_INPUT_PARAMS = {
    "message", "query", "user_query", "user_input", "user_message",
    "prompt", "input", "text", "content", "chat_input", "question",
}


def _is_user_input_source(node: ast.expr) -> bool:
    """Check if RHS is a user input source — Flask, FastAPI, WebSocket."""
    if isinstance(node, ast.Call):
        chain = _get_call_chain(node)
        chain_str = ".".join(chain).lower()
        if "request" in chain_str and (
            "json" in chain_str or "args" in chain_str
            or "form" in chain_str or "files" in chain_str
        ):
            return True
        if "input" in chain_str and len(chain) <= 2:
            return True
        if "get_json" in chain_str or "get_data" in chain_str:
            return True
    if isinstance(node, ast.Attribute):
        chain = _get_attr_chain(node)
        if chain and chain[0].lower() in ("request", "req"):
            if any(c in chain[-1].lower() for c in ("json", "args", "form", "data", "files")):
                return True
        if len(chain) >= 2 and chain[-1].lower() in _FASTAPI_INPUT_PARAMS:
            return True
    if isinstance(node, ast.Name) and node.id.lower() in _FASTAPI_INPUT_PARAMS:
        return True
    return False


def _is_high_risk_tool(name: str) -> bool:
    n = name.lower().replace("_", "").replace("-", "")
    return any(rt in n or n in rt for rt in HIGH_RISK_TOOLS)


@dataclass
class PromptInjectionRisk:
    """Single prompt injection exposure risk with context-aware fields."""

    type: str = "prompt_injection"
    severity: str = "medium"
    sanitized: bool = False
    source_file: str = ""
    sink_file: str = ""
    evidence: str = ""
    # Backward compatibility for agent flows
    agent_framework: str = ""
    tools: List[str] = field(default_factory=list)
    input_source: str = ""
    file: str = ""
    line: Optional[int] = None
    risk: str = ""

    def to_dict(self) -> dict:
        d: dict = {
            "type": self.type,
            "severity": self.severity,
            "sanitized": self.sanitized,
            "source_file": self.source_file or self.file,
            "sink_file": self.sink_file or self.file,
            "evidence": self.evidence,
        }
        if self.agent_framework:
            d["agent_framework"] = self.agent_framework
        if self.tools:
            d["tools"] = self.tools
        if self.input_source:
            d["input_source"] = self.input_source
        if self.file:
            d["file"] = self.file
        if self.line is not None:
            d["line"] = self.line
        if self.risk:
            d["risk"] = self.risk
        return d


@dataclass
class PromptInjectionResult:
    """Result of prompt injection detection."""

    prompt_injection_risks: List[PromptInjectionRisk] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "prompt_injection_risks": [r.to_dict() for r in self.prompt_injection_risks],
        }


def _dataflow_to_risk(df: DataFlow) -> PromptInjectionRisk:
    """Convert DataFlow to PromptInjectionRisk with new format."""
    return PromptInjectionRisk(
        type="prompt_injection",
        severity="low" if df.sanitized else ("high" if df.risk == "high" else "medium"),
        sanitized=df.sanitized,
        source_file=df.file,
        sink_file=df.file,
        evidence=f"{df.source} → {df.sink}" + (" (mitigated by sanitization)" if df.sanitized else ""),
        file=df.file,
        line=df.line,
        risk=df.risk,
    )


class _PromptInjectionVisitor(ast.NodeVisitor):
    """Detects agent + tools + user input flows with sanitization tracking."""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.user_input_vars: Set[str] = set()
        self.sanitized_vars: Set[str] = set()
        self.agent_vars: Set[str] = set()
        self.tools_in_file: Set[str] = set()
        self.risks: List[PromptInjectionRisk] = []
        self._agent_framework: str = "unknown"

    def _var_looks_like_user_input(self, name: str) -> bool:
        n = name.lower().replace("_", "")
        return any(uin in n or n == uin.replace("_", "") for uin in USER_INPUT_NAMES)

    def visit_Assign(self, node: ast.Assign) -> None:
        targets = _get_assigned_names(node)

        # Sanitization: target = sanitize(tainted_var)
        if isinstance(node.value, ast.Call) and _is_sanitization_call(node.value):
            refs = _names_in_expr(node.value)
            if refs & self.user_input_vars:
                for t in targets:
                    self.sanitized_vars.add(t)
                    self.user_input_vars.discard(t)
            self.generic_visit(node)
            return

        if _is_user_input_source(node.value):
            self.user_input_vars.update(targets)
            self.sanitized_vars -= set(targets)
        else:
            refs = _names_in_expr(node.value)
            if refs & self.user_input_vars:
                self.user_input_vars.update(targets)
            if refs & self.sanitized_vars:
                self.sanitized_vars.update(targets)
        for t in targets:
            if self._var_looks_like_user_input(t):
                self.user_input_vars.add(t)

        # Track agent assignment
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
                if "langchain" in ".".join(chain_lower) or "create_react" in ".".join(chain_lower):
                    self._agent_framework = "langchain"
                elif "semantic" in ".".join(chain_lower) or "kernel" in ".".join(chain_lower):
                    self._agent_framework = "semantic_kernel"
                elif "haystack" in ".".join(chain_lower) or "pipeline" in ".".join(chain_lower):
                    self._agent_framework = "haystack"
                elif "crew" in ".".join(chain_lower):
                    self._agent_framework = "crewai"
                for kw in node.keywords:
                    if kw.arg and kw.arg.lower() == "tools":
                        for s in _get_strings_in(kw.value):
                            if _is_high_risk_tool(s):
                                self.tools_in_file.add(s)
                if len(node.args) >= 2:
                    for s in _get_strings_in(node.args[1]):
                        if _is_high_risk_tool(s):
                            self.tools_in_file.add(s)
                break

        if "load_tools" in ".".join(chain_lower):
            for arg in node.args:
                for s in _get_strings_in(arg):
                    if 2 <= len(s) <= 50:
                        self.tools_in_file.add(s)
        elif "tool" in ".".join(chain_lower):
            for arg in node.args[:2]:
                for s in _get_strings_in(arg):
                    if _is_high_risk_tool(s):
                        self.tools_in_file.add(s)

        # Agent invocation: agent.invoke/run(user_input or f-string)
        _INVOKE_AND_RUN = INVOKE_METHODS | {"run", "arun"}
        if len(chain) >= 2 and chain[-1].lower() in _INVOKE_AND_RUN:
            receiver_name = chain[0] if chain else ""
            is_agent = (
                receiver_name in self.agent_vars
                or receiver_name.lower() in ("agent", "self")
                or "agent" in receiver_name.lower()
            )

            def _tainted(n):
                if isinstance(n, ast.Name):
                    nm = n.id
                    return (
                        nm in self.user_input_vars or self._var_looks_like_user_input(nm),
                        nm, nm in self.sanitized_vars,
                    )
                if isinstance(n, ast.JoinedStr):
                    for p in ast.walk(n):
                        if isinstance(p, ast.Name):
                            nm = p.id
                            if nm in self.user_input_vars or self._var_looks_like_user_input(nm):
                                return True, f"f-string:{nm}", nm in self.sanitized_vars
                if isinstance(n, ast.Dict):
                    for v in (n.values or []):
                        ok, r, s = _tainted(v)
                        if ok:
                            return True, f"dict:{r}", s
                return False, "", False

            if node.args:
                tainted, arg_repr, is_san = _tainted(node.args[0])
                if is_agent and tainted and not is_san:
                    tl = list(self.tools_in_file)[:10] if self.tools_in_file else ["tools (inferred)"]
                    self.risks.append(PromptInjectionRisk(
                        type="agent_tools",
                        severity="critical" if self.tools_in_file else "high",
                        sanitized=False,
                        source_file=self.file_path,
                        sink_file=self.file_path,
                        evidence=f"agent.{chain[-1]}({arg_repr}) — user input reaches agent",
                        agent_framework=self._agent_framework or "agent",
                        tools=tl,
                        input_source=arg_repr,
                        risk="critical" if self.tools_in_file else "high",
                        file=self.file_path,
                        line=getattr(node, "lineno", None),
                    ))

        # PythonREPL / exec() — user input into code execution
        _cs = ".".join(chain_lower)
        if any(rt in _cs for rt in ("pythonrepl", "python_repl", "exec", "eval", "repl")):
            for arg in node.args:
                refs = {n.id for n in ast.walk(arg) if isinstance(n, ast.Name)}
                if refs & self.user_input_vars or any(
                    self._var_looks_like_user_input(r) for r in refs
                ):
                    self.risks.append(PromptInjectionRisk(
                        type="code_execution", severity="critical", sanitized=False,
                        source_file=self.file_path, sink_file=self.file_path,
                        evidence=f"User input into {_cs} — RCE risk",
                        agent_framework="python_repl", tools=["PythonREPLTool"],
                        input_source=str(refs & self.user_input_vars or refs),
                        risk="critical", file=self.file_path,
                        line=getattr(node, "lineno", None),
                    ))

        # cursor.execute(sql) — LLM-generated SQL without parameterization
        if len(chain_lower) >= 2 and chain_lower[-1] == "execute" and any(
            x in chain_lower for x in ("cursor", "conn", "db")
        ):
            for arg in node.args:
                refs = {n.id for n in ast.walk(arg) if isinstance(n, ast.Name)}
                sql_vars = {
                    r for r in refs if any(
                        kw in r.lower()
                        for kw in ("sql", "query", "result", "response", "output", "generated", "statement")
                    )
                }
                if sql_vars:
                    self.risks.append(PromptInjectionRisk(
                        type="sql_injection_via_llm", severity="critical", sanitized=False,
                        source_file=self.file_path, sink_file=self.file_path,
                        evidence=f"cursor.execute({list(sql_vars)[0]}) — LLM SQL without parameterization",
                        agent_framework="", tools=[],
                        input_source=str(sql_vars), risk="critical",
                        file=self.file_path, line=getattr(node, "lineno", None),
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


def analyze_prompt_injection(
    repo_root: Path,
    dataflow_analysis: Optional[object] = None,
) -> PromptInjectionResult:
    """
    Analyze for prompt injection exposure.

    Integrates with data flow analyzer for user_input → LLM flows.
    Detects agent+tools flows with sanitization awareness.
    Mitigated flows (sanitized=True) are included but marked.
    """
    repo_root = Path(repo_root).resolve()
    all_risks: List[PromptInjectionRisk] = []
    seen: Set[Tuple[str, str, str, Optional[int], bool]] = set()

    # 1. User input → LLM flows from dataflow analyzer
    if dataflow_analysis is not None and hasattr(dataflow_analysis, "data_flows"):
        for df in dataflow_analysis.data_flows:
            risk = _dataflow_to_risk(df)
            key = (risk.source_file, risk.sink_file, risk.evidence, risk.line, risk.sanitized)
            if key not in seen:
                seen.add(key)
                all_risks.append(risk)
    else:
        # Run dataflow analyzer if not provided
        dataflow_result = analyze_dataflows(repo_root)
        for df in dataflow_result.data_flows:
            risk = _dataflow_to_risk(df)
            key = (risk.source_file, risk.sink_file, risk.evidence, risk.line, risk.sanitized)
            if key not in seen:
                seen.add(key)
                all_risks.append(risk)

    # 2. Agent + tools flows (with sanitization)
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
            key = (r.input_source, r.file, r.line, r.evidence, r.sanitized)
            if key not in seen:
                seen.add(key)
                all_risks.append(r)

    return PromptInjectionResult(prompt_injection_risks=all_risks)
