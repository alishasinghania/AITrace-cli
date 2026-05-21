"""
Pattern Analyzer — detects AI security vulnerability shapes in Python files.

Runs 18 pattern detectors against each file independently (no cross-file needed).
Each detector returns PatternFinding instances; the registry runs all of them.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from .detectors._ast_utils import should_skip_path, walk_python_files, get_call_target_chain

# Re-use sensitive keywords rather than duplicating them
from .sensitive_data_detector import SENSITIVE_KEYWORDS


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class PatternFinding:
    vulnerability_id: str
    title: str
    severity: str           # "critical" | "high" | "medium" | "low"
    confidence: str         # "high" | "medium" | "low"
    category: str
    owasp_id: str
    cwe: str
    file: str
    line: Optional[int]
    function_name: Optional[str]
    pattern_matched: str
    evidence: List[str]
    framework: str
    confirmed_by_taint: bool = False
    confirmed_by_llm: bool = False
    dismissed_as_fp: bool = False
    taint_path: List[str] = field(default_factory=list)
    llm_reasoning: str = ""
    remediation: str = ""
    cvss_estimate: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vulnerability_id": self.vulnerability_id,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "category": self.category,
            "owasp_id": self.owasp_id,
            "cwe": self.cwe,
            "file": self.file,
            "line": self.line,
            "function_name": self.function_name,
            "pattern_matched": self.pattern_matched,
            "evidence": self.evidence,
            "framework": self.framework,
            "confirmed_by_taint": self.confirmed_by_taint,
            "confirmed_by_llm": self.confirmed_by_llm,
            "dismissed_as_fp": self.dismissed_as_fp,
            "taint_path": self.taint_path,
            "llm_reasoning": self.llm_reasoning,
            "remediation": self.remediation,
            "cvss_estimate": self.cvss_estimate,
        }


@dataclass
class PatternAnalysisResult:
    findings: List[PatternFinding]
    files_scanned: int
    patterns_evaluated: int
    scan_errors: List[str]
    framework_summary: Dict[str, int]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "findings": [f.to_dict() for f in self.findings],
            "files_scanned": self.files_scanned,
            "patterns_evaluated": self.patterns_evaluated,
            "scan_errors": self.scan_errors,
            "framework_summary": self.framework_summary,
        }


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_LLM_CALL_ATTRS = {
    # Direct provider calls
    "create", "generate_content", "generate", "chat", "complete",
    # LangChain
    "invoke", "run", "stream", "predict", "predict_messages",
    # Async variants
    "ainvoke", "arun", "astream", "agenerate", "acomplete",
}

_LLM_CHAIN_FRAGMENTS = {
    "openai", "anthropic", "cohere", "vertexai", "bedrock", "mistral",
    "litellm", "ollama", "groq", "together", "replicate", "perplexity",
    "chat", "completions", "messages", "llm", "chain", "agent",
    "generativemodel", "generativeai", "chatmodel", "chatanthropic",
    "chatopenai", "azurechatopenai",
}

_RETRIEVAL_ATTRS = {
    "similarity_search", "similarity_search_with_score",
    "max_marginal_relevance_search", "as_retriever",
    "get_relevant_documents", "aget_relevant_documents",
    "asimilarity_search", "query", "search",
    "retriever", "invoke", "batch",
    "as_query_engine",
}

_RETRIEVAL_CHAIN_FRAGMENTS = {
    "vectorstore", "vectordb", "collection", "index", "retriever",
    "chroma", "pinecone", "weaviate", "qdrant", "faiss", "milvus",
    "similarity_search", "as_retriever", "query_engine",
    "get_relevant_documents",
}

_AGENT_CALL_ATTRS = {
    "kickoff", "kickoff_async", "kickoff_for_each",
    "run", "arun", "invoke", "ainvoke",
    "initiate_chat", "run_sync", "run_streamed",
    "chat", "stream", "astream",
}

_AGENT_CHAIN_FRAGMENTS = {
    "crew", "agent", "agentexecutor", "runner", "userproxyagent",
    "assistantagent", "conversableagent", "react", "groupchatmanager",
}

_CODE_EXEC_NAMES = {
    "pythonrepltool", "pythonastrepltool", "bashprocess", "shelltool",
    "bashtool", "codeinterpretertoolspec", "e2btoolspec",
}
_CODE_EXEC_TOOL_KEYWORDS = {"repl", "exec", "shell", "bash", "code", "python", "terminal", "subprocess", "command"}

_SQL_EXEC_ATTRS = {"execute", "executemany", "executescript", "fetch_all", "fetch_one", "fetchrow", "fetchval"}
_SQL_CHAIN_FRAGMENTS = {
    "cursor", "connection", "conn", "session", "db", "database",
    "engine", "asyncpg", "pymysql", "aiomysql",
}

_EXTERNAL_FETCH_ATTRS = {"get", "post", "fetch", "request", "open", "read"}
_EXTERNAL_FETCH_CHAIN_FRAGMENTS = {
    "requests", "httpx", "aiohttp", "urllib", "imap", "gmail",
    "beautifulsoup", "playwright", "scrapy", "feedparser",
}

_MEMORY_WRITE_ATTRS = {"add_documents", "add_texts", "save_context", "upsert"}
_MEMORY_READ_ATTRS = {
    "similarity_search", "load_memory_variables",
    "get_relevant_documents", "query", "search",
}

_TOOL_DECORATORS = {"tool", "function_tool"}
_TOOL_CLASSES = {"tool", "structuredtool", "functiontool"}

_IRREVERSIBLE_ATTRS = {
    "send", "send_email", "send_message", "send_mail", "sendgrid",
    "remove", "unlink", "rmtree", "delete", "drop",
    "charge", "create_charge", "create_payment",
}
_REVERSIBLE_WRITE_ATTRS = {"post", "write", "create", "put", "patch", "notify"}

_HUMAN_APPROVAL_NAMES = {
    "human_in_the_loop", "interrupt", "humanapproval",
    "requires_approval", "confirmation", "ask_human", "await_human",
    "humantool", "human_approval",
}

_SANITIZE_NAMES = {
    "promptguard", "guardrails", "rebuff", "nemo_guardrails",
    "input_validation", "validate_input", "clean_input",
}

_UNSAFE_DESER_ATTRS = {"load", "loads"}
_UNSAFE_DESER_CHAIN = {"pickle", "dill", "cloudpickle", "joblib"}


def _call_chain_str(node: ast.Call) -> str:
    """Return lowercased dot-joined call chain."""
    return ".".join(get_call_target_chain(node)).lower()


def _call_attr(node: ast.Call) -> str:
    """Return the final attribute name of a call."""
    if isinstance(node.func, ast.Attribute):
        return node.func.attr.lower()
    if isinstance(node.func, ast.Name):
        return node.func.id.lower()
    return ""


def _is_llm_call(node: ast.Call) -> bool:
    chain = _call_chain_str(node)
    attr = _call_attr(node)
    if attr not in _LLM_CALL_ATTRS:
        return False
    return bool(set(chain.split(".")) & _LLM_CHAIN_FRAGMENTS)


def _is_retrieval_call(node: ast.Call) -> bool:
    chain = _call_chain_str(node)
    attr = _call_attr(node)
    if attr in _RETRIEVAL_ATTRS:
        return True
    return bool(set(chain.split(".")) & _RETRIEVAL_CHAIN_FRAGMENTS) and attr in _RETRIEVAL_ATTRS


def _is_agent_call(node: ast.Call) -> bool:
    chain = _call_chain_str(node)
    attr = _call_attr(node)
    if attr not in _AGENT_CALL_ATTRS:
        return False
    parts = set(chain.split("."))
    # Exact match first
    if parts & _AGENT_CHAIN_FRAGMENTS:
        return True
    # Substring match — handles names like "agent1", "my_agent", "agent_runner"
    chain_lower = chain.lower()
    return any(frag in chain_lower for frag in _AGENT_CHAIN_FRAGMENTS)


def _is_sql_exec_call(node: ast.Call) -> bool:
    attr = _call_attr(node)
    if attr not in _SQL_EXEC_ATTRS:
        return False
    chain = _call_chain_str(node)
    return bool(set(chain.split(".")) & _SQL_CHAIN_FRAGMENTS) or attr == "execute"


def _get_func_name(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    return func_node.name


def _get_param_names(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> Set[str]:
    params: Set[str] = set()
    args = func_node.args
    for a in args.args + args.posonlyargs + args.kwonlyargs:
        params.add(a.arg)
    if args.vararg:
        params.add(args.vararg.arg)
    if args.kwarg:
        params.add(args.kwarg.arg)
    return params


def _names_in_expr(node: ast.expr) -> Set[str]:
    names: Set[str] = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Name):
            names.add(n.id)
    return names


def _assigned_names_in_func(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> Dict[str, int]:
    """Return {var_name: line} for all assignments in a function."""
    result: Dict[str, int] = {}
    for node in ast.walk(func_node):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    result[t.id] = getattr(node, "lineno", 0)
        elif isinstance(node, (ast.AnnAssign,)) and isinstance(node.target, ast.Name):
            result[node.target.id] = getattr(node, "lineno", 0)
    return result


def _build_import_map(tree: ast.Module) -> Dict[str, str]:
    """Build local_name -> fully_qualified_name from all import statements."""
    imap: Dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                local = alias.asname if alias.asname else alias.name
                imap[local] = f"{node.module}.{alias.name}"
        elif isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname if alias.asname else alias.name
                imap[local] = alias.name
    return imap


def _source_lines(source_text: str, lineno: int, context: int = 0) -> str:
    lines = source_text.splitlines()
    start = max(0, lineno - 1 - context)
    end = min(len(lines), lineno + context)
    return " | ".join(lines[start:end]).strip()


def _func_containing_line(
    tree: ast.Module,
    lineno: int,
) -> Optional[ast.FunctionDef | ast.AsyncFunctionDef]:
    best = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = node.lineno
            end = getattr(node, "end_lineno", node.lineno + 50)
            if start <= lineno <= end:
                if best is None or (node.lineno >= best.lineno):
                    best = node
    return best


def _collect_calls(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> List[ast.Call]:
    calls = []
    for node in ast.walk(func_node):
        if isinstance(node, ast.Call):
            calls.append(node)
    return calls


def _has_name_in_source(source_text: str, names: Set[str]) -> bool:
    src_lower = source_text.lower()
    return any(n.lower() in src_lower for n in names)


# ---------------------------------------------------------------------------
# PAT-001: Unsanitized input into RAG retrieval then LLM
# ---------------------------------------------------------------------------

def detect_pat001(
    tree: ast.Module,
    file_path: str,
    source_text: str,
    import_map: Dict[str, str],
) -> List[PatternFinding]:
    findings: List[PatternFinding] = []

    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        calls = _collect_calls(func)
        retrieval_calls = [(c, getattr(c, "lineno", None)) for c in calls if _is_retrieval_call(c)]
        llm_calls = [(c, getattr(c, "lineno", None)) for c in calls if _is_llm_call(c)]

        if not retrieval_calls or not llm_calls:
            continue

        # Signal C: shared variable between retrieval arg and function param
        params = _get_param_names(func)
        shared_var = None
        for rc, _ in retrieval_calls:
            for arg in list(rc.args) + [kw.value for kw in rc.keywords]:
                names = _names_in_expr(arg)
                if names & params:
                    shared_var = (names & params).pop()
                    break

        rl = retrieval_calls[0][1]
        ll = llm_calls[0][1]
        ev = [
            f"line {rl}: retrieval call {_call_chain_str(retrieval_calls[0][0])}",
            f"line {ll}: LLM call {_call_chain_str(llm_calls[0][0])}",
        ]
        if shared_var:
            ev.append(f"shared variable '{shared_var}' (function param → retrieval → LLM)")
            confidence = "high"
        else:
            confidence = "medium"

        findings.append(PatternFinding(
            vulnerability_id="PAT-001",
            title="Unsanitized input flows into RAG pipeline and LLM",
            severity="high",
            confidence=confidence,
            category="LLM01 Prompt Injection (indirect)",
            owasp_id="LLM01",
            cwe="CWE-74",
            file=file_path,
            line=rl,
            function_name=_get_func_name(func),
            pattern_matched="retrieval_call + llm_call in same function" + (" + shared_param" if shared_var else ""),
            evidence=ev,
            framework="langchain/llamaindex/chromadb",
            remediation="Validate and sanitize user query before passing to retrieval. Use score_threshold to filter low-confidence results.",
            cvss_estimate=8.1,
        ))

    return findings


# ---------------------------------------------------------------------------
# PAT-002: Code execution tool in agent
# ---------------------------------------------------------------------------

def detect_pat002(
    tree: ast.Module,
    file_path: str,
    source_text: str,
    import_map: Dict[str, str],
) -> List[PatternFinding]:
    findings: List[PatternFinding] = []
    src_lower = source_text.lower()

    # Signal A: dangerous tool in import_map
    dangerous_imports: List[str] = []
    for local, fqn in import_map.items():
        if local.lower() in _CODE_EXEC_NAMES:
            dangerous_imports.append(f"import {local} from {fqn}")
        if "programofthought" in fqn.lower() or "codeagent" in fqn.lower():
            dangerous_imports.append(f"import {local} from {fqn}")
        if "load_tools" in fqn.lower():
            dangerous_imports.append(f"import load_tools from {fqn}")

    # Also scan for Tool(name="repl/exec/shell...") instantiations
    tool_instantiations: List[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func_name = _call_attr(node)
            if func_name in {"tool", "structuredtool"}:
                for kw in node.keywords:
                    if kw.arg == "name" and isinstance(kw.value, ast.Constant):
                        val = str(kw.value.value).lower()
                        if any(k in val for k in _CODE_EXEC_TOOL_KEYWORDS):
                            tool_instantiations.append(
                                f"line {getattr(node, 'lineno', '?')}: Tool(name={kw.value.value!r})"
                            )
            # load_tools(["python_repl", ...])
            chain = _call_chain_str(node)
            if "load_tools" in chain:
                for arg in node.args:
                    if isinstance(arg, ast.List):
                        for elt in arg.elts:
                            if isinstance(elt, ast.Constant) and any(
                                k in str(elt.value).lower() for k in _CODE_EXEC_TOOL_KEYWORDS
                            ):
                                tool_instantiations.append(
                                    f"line {getattr(node, 'lineno', '?')}: load_tools([{elt.value!r}])"
                                )

    has_signal_a = bool(dangerous_imports or tool_instantiations)
    if not has_signal_a:
        return []

    # Signal B: agent execution in same file
    agent_calls: List[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _is_agent_call(node):
            agent_calls.append(
                f"line {getattr(node, 'lineno', '?')}: {_call_chain_str(node)}"
            )

    ev = dangerous_imports + tool_instantiations
    if agent_calls:
        ev += agent_calls[:2]
        confidence = "high"
    else:
        confidence = "medium"

    framework = "langchain"
    if any("dspy" in e.lower() or "programofthought" in e.lower() for e in ev):
        framework = "dspy"
    elif any("smolagents" in e.lower() or "codeagent" in e.lower() for e in ev):
        framework = "smolagents"

    findings.append(PatternFinding(
        vulnerability_id="PAT-002",
        title="Code execution tool in agent — RCE risk",
        severity="critical",
        confidence=confidence,
        category="LLM08 Excessive Agency",
        owasp_id="LLM08",
        cwe="CWE-77",
        file=file_path,
        line=None,
        function_name=None,
        pattern_matched="code_execution_tool_import" + (" + agent_call" if agent_calls else ""),
        evidence=ev[:6],
        framework=framework,
        remediation="Sandbox PythonREPLTool in a container with resource limits. Never let untrusted input reach exec().",
        cvss_estimate=9.0,
    ))
    return findings


# ---------------------------------------------------------------------------
# PAT-003: LLM output executed as SQL
# ---------------------------------------------------------------------------

def detect_pat003(
    tree: ast.Module,
    file_path: str,
    source_text: str,
    import_map: Dict[str, str],
) -> List[PatternFinding]:
    findings: List[PatternFinding] = []

    _SQL_KEYWORDS = {"sql", "query", "statement", "result", "response", "output", "generated"}

    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        # Find LLM call assignments
        llm_output_vars: Dict[str, int] = {}  # var_name -> line
        for node in ast.walk(func):
            if not isinstance(node, ast.Assign):
                continue
            if not isinstance(node.value, ast.Call):
                continue
            # Check if RHS is an LLM call or attribute access on an LLM result
            call_node = node.value
            if _is_llm_call(call_node):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        llm_output_vars[t.id] = getattr(node, "lineno", 0)
            # Also catch: sql = response.content[0].text style attribute chains
            chain = _call_chain_str(call_node)
            if any(f in chain for f in {"content", "choices", "message", "text", "generations"}):
                for t in node.targets:
                    if isinstance(t, ast.Name) and any(kw in t.id.lower() for kw in _SQL_KEYWORDS):
                        llm_output_vars[t.id] = getattr(node, "lineno", 0)

        if not llm_output_vars:
            continue

        # Find SQL execution calls using those vars
        for node in ast.walk(func):
            if not isinstance(node, ast.Call):
                continue
            if not _is_sql_exec_call(node):
                continue
            exec_line = getattr(node, "lineno", 0)
            for arg in list(node.args) + [kw.value for kw in node.keywords]:
                names = _names_in_expr(arg)
                matched = names & set(llm_output_vars.keys())
                # Also flag if variable name suggests SQL + heuristic match
                for name in names:
                    if any(kw in name.lower() for kw in _SQL_KEYWORDS):
                        matched.add(name)
                if matched:
                    var = next(iter(matched))
                    src_line = llm_output_vars.get(var, 0)
                    confidence = "high" if var in llm_output_vars else "medium"
                    findings.append(PatternFinding(
                        vulnerability_id="PAT-003",
                        title="LLM-generated SQL executed without parameterization",
                        severity="critical",
                        confidence=confidence,
                        category="LLM02 Insecure Output Handling",
                        owasp_id="LLM02",
                        cwe="CWE-89",
                        file=file_path,
                        line=exec_line,
                        function_name=_get_func_name(func),
                        pattern_matched=f"llm_output_var '{var}' passed to sql execute()",
                        evidence=[
                            f"line {src_line}: LLM call assigns to '{var}'",
                            f"line {exec_line}: {_call_chain_str(node)}({var})",
                        ],
                        framework="sqlalchemy/sqlite3/psycopg2",
                        remediation="Never pass LLM output directly to execute(). Use parameterized queries or a SQL validator to confirm safe syntax before execution.",
                        cvss_estimate=9.0,
                    ))
                    break

    return findings


# ---------------------------------------------------------------------------
# PAT-004: LLM output executed as code
# ---------------------------------------------------------------------------

def detect_pat004(
    tree: ast.Module,
    file_path: str,
    source_text: str,
    import_map: Dict[str, str],
) -> List[PatternFinding]:
    findings: List[PatternFinding] = []
    _CODE_EXEC_FUNCS = {"exec", "eval", "compile"}
    _SUBPROC_ATTRS = {"run", "popen", "system", "call", "check_output", "check_call"}
    _SUBPROC_CHAINS = {"subprocess", "os"}

    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        llm_output_vars: Dict[str, int] = {}
        for node in ast.walk(func):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                if _is_llm_call(node.value):
                    for t in node.targets:
                        if isinstance(t, ast.Name):
                            llm_output_vars[t.id] = getattr(node, "lineno", 0)

        if not llm_output_vars:
            continue

        for node in ast.walk(func):
            if not isinstance(node, ast.Call):
                continue
            attr = _call_attr(node)
            chain = _call_chain_str(node)
            is_exec = attr in _CODE_EXEC_FUNCS
            is_subproc = attr in _SUBPROC_ATTRS and bool(set(chain.split(".")) & _SUBPROC_CHAINS)
            if not (is_exec or is_subproc):
                continue

            for arg in list(node.args) + [kw.value for kw in node.keywords]:
                names = _names_in_expr(arg)
                matched = names & set(llm_output_vars.keys())
                if matched:
                    var = next(iter(matched))
                    src_line = llm_output_vars[var]
                    exec_line = getattr(node, "lineno", 0)
                    findings.append(PatternFinding(
                        vulnerability_id="PAT-004",
                        title="LLM output executed as code via exec/eval",
                        severity="critical",
                        confidence="high",
                        category="LLM02 Insecure Output Handling",
                        owasp_id="LLM02",
                        cwe="CWE-94",
                        file=file_path,
                        line=exec_line,
                        function_name=_get_func_name(func),
                        pattern_matched=f"llm_output '{var}' passed to {attr}()",
                        evidence=[
                            f"line {src_line}: LLM call assigns to '{var}'",
                            f"line {exec_line}: {attr}({var})",
                        ],
                        framework="python_builtins",
                        remediation="Never execute LLM output as code. Use a sandboxed interpreter with resource limits if code execution is required.",
                        cvss_estimate=9.8,
                    ))
                    break

    return findings


# ---------------------------------------------------------------------------
# PAT-005: Agent output used as trusted system context
# ---------------------------------------------------------------------------

def detect_pat005(
    tree: ast.Module,
    file_path: str,
    source_text: str,
    import_map: Dict[str, str],
) -> List[PatternFinding]:
    findings: List[PatternFinding] = []
    _SYSTEM_INDICATORS = {"system", "system_prompt", "systemmessage", "humanmessage", "task", "context"}

    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        agent_output_vars: Dict[str, int] = {}
        for node in ast.walk(func):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                if _is_agent_call(node.value):
                    for t in node.targets:
                        if isinstance(t, ast.Name):
                            agent_output_vars[t.id] = getattr(node, "lineno", 0)

        if not agent_output_vars:
            continue

        # Signal B: used in system context
        for node in ast.walk(func):
            if isinstance(node, ast.Call):
                chain = _call_chain_str(node)
                # Check keyword args for system= param
                for kw in node.keywords:
                    if kw.arg == "system":
                        names = _names_in_expr(kw.value)
                        matched = names & set(agent_output_vars.keys())
                        if matched:
                            var = next(iter(matched))
                            _emit_pat005(findings, file_path, func, var,
                                         agent_output_vars[var], getattr(node, "lineno", 0),
                                         "system= parameter in LLM call")
                # Check for SystemMessage() / HumanMessage() / Task(context=[var])
                if any(s in chain for s in _SYSTEM_INDICATORS):
                    for arg in list(node.args) + [kw.value for kw in node.keywords]:
                        names = _names_in_expr(arg)
                        matched = names & set(agent_output_vars.keys())
                        if matched:
                            var = next(iter(matched))
                            _emit_pat005(findings, file_path, func, var,
                                         agent_output_vars[var], getattr(node, "lineno", 0),
                                         f"agent output used in {chain}")

            # f-string with agent output var as system context
            if isinstance(node, ast.JoinedStr):
                for val in ast.walk(node):
                    if isinstance(val, ast.Name) and val.id in agent_output_vars:
                        # Try to determine if it's used for system prompt
                        lineno = getattr(node, "lineno", 0)
                        src_line = source_text.splitlines()[lineno - 1].lower() if lineno else ""
                        if any(s in src_line for s in ("system", "role", "context", "instruction")):
                            _emit_pat005(findings, file_path, func, val.id,
                                         agent_output_vars[val.id], lineno,
                                         "f-string interpolation in system context")

    return findings


def _emit_pat005(
    findings: List[PatternFinding],
    file_path: str,
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    var: str,
    agent_line: int,
    inject_line: int,
    matched: str,
) -> None:
    # Deduplicate
    for f in findings:
        if f.vulnerability_id == "PAT-005" and f.function_name == func.name and f.line == inject_line:
            return
    findings.append(PatternFinding(
        vulnerability_id="PAT-005",
        title="Agent output injected as trusted system prompt context",
        severity="critical",
        confidence="medium",
        category="LLM01 Prompt Injection",
        owasp_id="LLM01",
        cwe="CWE-74",
        file=file_path,
        line=inject_line,
        function_name=_get_func_name(func),
        pattern_matched=matched,
        evidence=[
            f"line {agent_line}: agent call assigns to '{var}'",
            f"line {inject_line}: {matched}",
        ],
        framework="langchain/crewai/openai_agents",
        remediation="Validate and sanitize agent output before using as system context. Treat agent output as untrusted user input.",
        cvss_estimate=8.8,
    ))


# ---------------------------------------------------------------------------
# PAT-006: Unbounded conversation memory
# ---------------------------------------------------------------------------

_UNBOUNDED_MEMORY_CLASSES = {
    "conversationbuffermemory", "chatmessagehistory",
    "inmemorymessagehistory", "inmemorychatchistory",
    "filechatmessagehistory", "redischatmessagehistory",
    "mongodbchatmessagehistory", "postgreschatmessagehistory",
    "conversationbuffermemory",
}
_SAFE_MEMORY_CLASSES = {
    "conversationsummarymemory", "conversationbufferwindowmemory",
    "conversationtokenbuffermemory",
}
_MEMORY_LIMIT_KWARGS = {"max_token_limit", "k", "max_messages", "max_history"}
_MEMORY_TRIM_ATTRS = {"trim_messages", "summarize", "prune"}


def detect_pat006(
    tree: ast.Module,
    file_path: str,
    source_text: str,
    import_map: Dict[str, str],
) -> List[PatternFinding]:
    findings: List[PatternFinding] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        attr = _call_attr(node)
        if attr.lower() in _SAFE_MEMORY_CLASSES:
            continue
        if attr.lower() not in _UNBOUNDED_MEMORY_CLASSES:
            chain = _call_chain_str(node)
            if not any(m in chain for m in _UNBOUNDED_MEMORY_CLASSES):
                continue
        # Check: does it have a limit kwarg?
        kwarg_names = {kw.arg for kw in node.keywords}
        if kwarg_names & _MEMORY_LIMIT_KWARGS:
            continue
        # Check k= in constructor
        if any(isinstance(kw.value, ast.Constant) and kw.arg == "k" for kw in node.keywords):
            continue

        # Check: is there a trim/summarize call nearby in the file?
        src_lower = source_text.lower()
        has_trim = any(t in src_lower for t in _MEMORY_TRIM_ATTRS)
        has_persistent = any(s in src_lower for s in ("redis", "mongodb", "postgres", "sqlite"))

        severity = "high" if has_persistent else "medium"

        if has_trim:
            continue  # Safe pattern present

        lineno = getattr(node, "lineno", None)
        findings.append(PatternFinding(
            vulnerability_id="PAT-006",
            title="Unbounded conversation memory — token exhaustion risk",
            severity=severity,
            confidence="high",
            category="LLM04 Model Denial of Service",
            owasp_id="LLM04",
            cwe="CWE-400",
            file=file_path,
            line=lineno,
            function_name=None,
            pattern_matched=f"unbounded memory class: {attr}",
            evidence=[
                f"line {lineno}: {attr}() instantiated without max_token_limit/k/max_messages",
                "No trim_messages() or summarize() call found in file",
            ],
            framework="langchain",
            remediation="Use ConversationBufferWindowMemory(k=N) or ConversationSummaryMemory to bound memory. Add trim_messages() before each LLM call.",
            cvss_estimate=5.3,
        ))

    return findings


# ---------------------------------------------------------------------------
# PAT-007: Irreversible action tool without human approval
# ---------------------------------------------------------------------------

def detect_pat007(
    tree: ast.Module,
    file_path: str,
    source_text: str,
    import_map: Dict[str, str],
) -> List[PatternFinding]:
    findings: List[PatternFinding] = []
    src_lower = source_text.lower()

    has_human_approval = any(n in src_lower for n in _HUMAN_APPROVAL_NAMES)

    _IRREVERSIBLE_CHAINS = {
        "smtplib", "sendgrid", "ses", "mailgun", "resend",
        "os.remove", "shutil.rmtree", "path.unlink",
        "stripe", "paypal", "boto3.delete",
    }
    _REVERSIBLE_CHAINS = {"requests.post", "httpx.post", "aiohttp.post"}

    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        # Is this function registered as a tool?
        is_tool = False
        for decorator in func.decorator_list:
            d = ""
            if isinstance(decorator, ast.Name):
                d = decorator.id.lower()
            elif isinstance(decorator, ast.Attribute):
                d = decorator.attr.lower()
            elif isinstance(decorator, ast.Call):
                d = _call_attr(decorator)
            if d in _TOOL_DECORATORS:
                is_tool = True
                break

        if not is_tool:
            # Check if function name appears in a tools=[] list
            func_name_lower = func.name.lower()
            # Simple heuristic: function name referenced in tools keyword
            if f"tools=[" not in source_text and func_name_lower not in src_lower:
                continue
            # Look for tools=[...func_name...] pattern
            in_tools_list = False
            for node in ast.walk(tree):
                if isinstance(node, ast.keyword) and node.arg == "tools":
                    if isinstance(node.value, ast.List):
                        for elt in node.value.elts:
                            if isinstance(elt, ast.Name) and elt.id == func.name:
                                in_tools_list = True
                            elif isinstance(elt, ast.Attribute) and elt.attr == func.name:
                                in_tools_list = True
            if not in_tools_list:
                continue

        # Check for irreversible or reversible actions in function body
        irreversible_found = []
        reversible_found = []
        for node in ast.walk(func):
            if isinstance(node, ast.Call):
                chain = _call_chain_str(node)
                attr = _call_attr(node)
                if any(s in chain for s in _IRREVERSIBLE_CHAINS) or attr in _IRREVERSIBLE_ATTRS:
                    irreversible_found.append(f"line {getattr(node, 'lineno', '?')}: {chain}")
                elif any(s in chain for s in _REVERSIBLE_CHAINS) or attr in _REVERSIBLE_WRITE_ATTRS:
                    if "external" in src_lower or "http" in chain:
                        reversible_found.append(f"line {getattr(node, 'lineno', '?')}: {chain}")

        if not irreversible_found and not reversible_found:
            continue

        if irreversible_found:
            base_severity = "critical"
            actions = irreversible_found
            action_type = "irreversible"
        else:
            base_severity = "high"
            actions = reversible_found
            action_type = "reversible"

        if has_human_approval:
            base_severity = "high" if base_severity == "critical" else "medium"

        findings.append(PatternFinding(
            vulnerability_id="PAT-007",
            title=f"{'Irreversible' if action_type == 'irreversible' else 'Reversible'} action tool registered without human confirmation",
            severity=base_severity,
            confidence="medium",
            category="LLM08 Excessive Agency",
            owasp_id="LLM08",
            cwe="CWE-284",
            file=file_path,
            line=func.lineno,
            function_name=_get_func_name(func),
            pattern_matched=f"tool_function with {action_type} action",
            evidence=[f"@tool or tools=[] registered function: {func.name}"] + actions[:3],
            framework="langchain/pydantic_ai/openai_agents",
            remediation="Add human-in-the-loop confirmation before irreversible actions. Use interrupt() in LangGraph or HumanApproval tool wrapper.",
            cvss_estimate=8.8 if base_severity == "critical" else 6.5,
        ))

    return findings


# ---------------------------------------------------------------------------
# PAT-008: Prompt template with unvalidated external variables
# ---------------------------------------------------------------------------

_PROMPT_TEMPLATE_ATTRS = {
    "from_template", "from_messages", "prompttemplate",
    "chatprompttemplate", "systemmessageprompttemplate",
}
_EXTERNAL_DATA_CHAINS = {
    "fetchall", "fetchone", "fetchrow", "fetch_all", "fetch_one",
    "execute", "query", "json", "read", "get", "response",
    "beautifulsoup", "requests", "httpx", "imap", "gmail",
}


def detect_pat008(
    tree: ast.Module,
    file_path: str,
    source_text: str,
    import_map: Dict[str, str],
) -> List[PatternFinding]:
    findings: List[PatternFinding] = []
    src_lower = source_text.lower()
    has_guardrails = any(g in src_lower for g in _SANITIZE_NAMES)

    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        # Find external data assignments
        external_vars: Dict[str, int] = {}
        for node in ast.walk(func):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                chain = _call_chain_str(node.value)
                if any(f in chain for f in _EXTERNAL_DATA_CHAINS):
                    for t in node.targets:
                        if isinstance(t, ast.Name):
                            external_vars[t.id] = getattr(node, "lineno", 0)

        if not external_vars:
            continue

        # Find prompt template usage or f-strings with those vars
        for node in ast.walk(func):
            if isinstance(node, ast.Call):
                attr = _call_attr(node)
                if attr in _PROMPT_TEMPLATE_ATTRS or attr == "format":
                    # Check args contain external var
                    all_names: Set[str] = set()
                    for arg in list(node.args) + [kw.value for kw in node.keywords]:
                        all_names |= _names_in_expr(arg)
                    matched = all_names & set(external_vars.keys())
                    if matched:
                        var = next(iter(matched))
                        ln = getattr(node, "lineno", 0)
                        _emit_pat008(findings, file_path, func, var,
                                     external_vars[var], ln, attr, has_guardrails)

            elif isinstance(node, ast.JoinedStr):
                all_names: Set[str] = set()
                for val in ast.walk(node):
                    if isinstance(val, ast.Name):
                        all_names.add(val.id)
                matched = all_names & set(external_vars.keys())
                if matched:
                    var = next(iter(matched))
                    ln = getattr(node, "lineno", 0)
                    # Only flag if the f-string looks like a prompt
                    src_line = source_text.splitlines()[ln - 1].lower() if ln else ""
                    if any(p in src_line for p in ("prompt", "message", "instruction", "system", "context")):
                        _emit_pat008(findings, file_path, func, var,
                                     external_vars[var], ln, "f-string prompt", has_guardrails)

    return findings


def _emit_pat008(
    findings: List[PatternFinding],
    file_path: str,
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    var: str,
    data_line: int,
    template_line: int,
    matched: str,
    has_guardrails: bool,
) -> None:
    for f in findings:
        if f.vulnerability_id == "PAT-008" and f.function_name == func.name and f.line == template_line:
            return
    findings.append(PatternFinding(
        vulnerability_id="PAT-008",
        title="Prompt template filled with unvalidated external data",
        severity="high",
        confidence="high" if not has_guardrails else "medium",
        category="LLM01 Prompt Injection",
        owasp_id="LLM01",
        cwe="CWE-74",
        file=file_path,
        line=template_line,
        function_name=_get_func_name(func),
        pattern_matched=f"external_data_var '{var}' in {matched}",
        evidence=[
            f"line {data_line}: external data read into '{var}'",
            f"line {template_line}: '{var}' interpolated into {matched}",
        ] + (["No guardrails/validation found in file"] if not has_guardrails else []),
        framework="langchain/openai",
        remediation="Validate and sanitize external data before injecting into prompts. Use allow-list schemas or Guardrails AI to constrain external content.",
        cvss_estimate=7.5,
    ))


# ---------------------------------------------------------------------------
# PAT-009: Insecure model deserialization
# ---------------------------------------------------------------------------

def detect_pat009(
    tree: ast.Module,
    file_path: str,
    source_text: str,
    import_map: Dict[str, str],
) -> List[PatternFinding]:
    findings: List[PatternFinding] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        chain = _call_chain_str(node)
        attr = _call_attr(node)
        lineno = getattr(node, "lineno", None)

        # pickle.load / pickle.loads — always flag
        if "pickle" in chain and attr in {"load", "loads"}:
            findings.append(PatternFinding(
                vulnerability_id="PAT-009",
                title="Insecure model deserialization — arbitrary code execution",
                severity="critical",
                confidence="high",
                category="LLM05 Supply Chain",
                owasp_id="LLM05",
                cwe="CWE-502",
                file=file_path,
                line=lineno,
                function_name=None,
                pattern_matched=f"pickle.{attr}() — arbitrary code execution",
                evidence=[f"line {lineno}: {chain}"],
                framework="python_stdlib",
                remediation="Replace pickle with safetensors or JSON for model serialization. Never unpickle untrusted data.",
                cvss_estimate=9.8,
            ))
            continue

        # dill / cloudpickle / joblib
        if any(lib in chain for lib in {"dill", "cloudpickle", "joblib"}) and attr in {"load", "loads"}:
            findings.append(PatternFinding(
                vulnerability_id="PAT-009",
                title="Insecure model deserialization — arbitrary code execution",
                severity="critical",
                confidence="high",
                category="LLM05 Supply Chain",
                owasp_id="LLM05",
                cwe="CWE-502",
                file=file_path,
                line=lineno,
                function_name=None,
                pattern_matched=f"{chain} — deserialization RCE risk",
                evidence=[f"line {lineno}: {chain}"],
                framework="python_stdlib",
                remediation="Use safetensors format. If joblib is required, validate source integrity with checksums.",
                cvss_estimate=9.0,
            ))
            continue

        # torch.load without weights_only=True
        if "torch" in chain and attr == "load":
            kwarg_names = {kw.arg for kw in node.keywords}
            weights_only = False
            for kw in node.keywords:
                if kw.arg == "weights_only" and isinstance(kw.value, ast.Constant):
                    weights_only = bool(kw.value.value)
            if not weights_only:
                findings.append(PatternFinding(
                    vulnerability_id="PAT-009",
                    title="Insecure model deserialization — arbitrary code execution",
                    severity="critical",
                    confidence="high",
                    category="LLM05 Supply Chain",
                    owasp_id="LLM05",
                    cwe="CWE-502",
                    file=file_path,
                    line=lineno,
                    function_name=None,
                    pattern_matched="torch.load() without weights_only=True",
                    evidence=[f"line {lineno}: {chain} (missing weights_only=True)"],
                    framework="pytorch",
                    remediation="Add weights_only=True to torch.load(). Better: use safetensors format instead of .pt/.pkl.",
                    cvss_estimate=8.5,
                ))
            continue

        # numpy.load with allow_pickle=True
        if "numpy" in chain and attr == "load":
            for kw in node.keywords:
                if kw.arg == "allow_pickle" and isinstance(kw.value, ast.Constant) and kw.value.value:
                    findings.append(PatternFinding(
                        vulnerability_id="PAT-009",
                        title="Insecure model deserialization — arbitrary code execution",
                        severity="critical",
                        confidence="high",
                        category="LLM05 Supply Chain",
                        owasp_id="LLM05",
                        cwe="CWE-502",
                        file=file_path,
                        line=lineno,
                        function_name=None,
                        pattern_matched="numpy.load(allow_pickle=True)",
                        evidence=[f"line {lineno}: {chain}(allow_pickle=True)"],
                        framework="numpy",
                        remediation="Remove allow_pickle=True from numpy.load(). Store arrays in npy/npz format without pickle.",
                        cvss_estimate=8.5,
                    ))

    return findings


# ---------------------------------------------------------------------------
# PAT-010: Hardcoded credentials
# ---------------------------------------------------------------------------

_CREDENTIAL_PREFIXES = (
    "sk-", "pk-", "key-", "secret-", "token-", "api_",
    "bearer ", "ghp_", "xoxb-", "xoxp-", "aiza", "ya29.",
    "akia", "dp8dt",
)
_PLACEHOLDER_STRINGS = {
    "your-key", "xxx", "placeholder", "changeme", "insert-here",
    "todo", "fixme", "example", "test", "sample", "demo",
    "<your", "your_", "enter_", "<api", "api_key_here",
}


def detect_pat010(
    tree: ast.Module,
    file_path: str,
    source_text: str,
    import_map: Dict[str, str],
) -> List[PatternFinding]:
    findings: List[PatternFinding] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            var_name = target.id.lower()
            # Signal A: variable name matches sensitive keyword
            if not any(kw in var_name for kw in SENSITIVE_KEYWORDS):
                continue
            # Signal B: assigned value is a long string literal
            value_node = node.value
            if not isinstance(value_node, ast.Constant):
                continue
            val = str(value_node.value)
            if len(val) < 20:
                continue
            val_lower = val.lower()
            # Signal C: disqualifiers
            if any(p in val_lower for p in _PLACEHOLDER_STRINGS):
                continue
            if not any(c.isalnum() for c in val):
                continue
            # Looks like a real credential if it starts with known prefix or is long alphanumeric
            is_credential = (
                any(val_lower.startswith(p) for p in _CREDENTIAL_PREFIXES)
                or (len(val) > 20 and re.match(r'^[A-Za-z0-9_\-\.]{20,}$', val))
            )
            if not is_credential:
                continue
            lineno = getattr(node, "lineno", None)
            findings.append(PatternFinding(
                vulnerability_id="PAT-010",
                title="Hardcoded credential or API key in source code",
                severity="critical",
                confidence="high",
                category="LLM09 Misinformation",
                owasp_id="LLM09",
                cwe="CWE-798",
                file=file_path,
                line=lineno,
                function_name=None,
                pattern_matched=f"hardcoded credential in variable '{target.id}'",
                evidence=[
                    f"line {lineno}: {target.id} = {val[:8]}... (length {len(val)})",
                ],
                framework="generic",
                remediation=f"Move '{target.id}' to environment variable: os.environ.get('{target.id.upper()}'). Remove from source code and rotate the credential.",
                cvss_estimate=9.1,
            ))

    return findings


# ---------------------------------------------------------------------------
# PAT-011: LLM output in HTTP response without validation
# ---------------------------------------------------------------------------

_RESPONSE_CLASSES = {"jsonresponse", "htmlresponse", "response", "orjsonresponse"}
_OUTPUT_PARSERS = {
    "pydanticoutputparser", "jsonoutputparser", "outputparser",
    "structuredoutputparser", "xmloutputparser",
    "html.escape", "escape", "sanitize",
}


def detect_pat011(
    tree: ast.Module,
    file_path: str,
    source_text: str,
    import_map: Dict[str, str],
) -> List[PatternFinding]:
    findings: List[PatternFinding] = []
    src_lower = source_text.lower()
    has_output_parser = any(p in src_lower for p in _OUTPUT_PARSERS)

    if has_output_parser:
        return []

    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        llm_output_vars: Dict[str, int] = {}
        for node in ast.walk(func):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                if _is_llm_call(node.value):
                    for t in node.targets:
                        if isinstance(t, ast.Name):
                            llm_output_vars[t.id] = getattr(node, "lineno", 0)

        if not llm_output_vars:
            continue

        # Find return statement or JSONResponse that uses llm var
        for node in ast.walk(func):
            lineno = getattr(node, "lineno", 0)
            if isinstance(node, ast.Return) and node.value is not None:
                names = _names_in_expr(node.value)
                matched = names & set(llm_output_vars.keys())
                if matched:
                    var = next(iter(matched))
                    findings.append(PatternFinding(
                        vulnerability_id="PAT-011",
                        title="LLM output returned to client without output validation",
                        severity="high",
                        confidence="medium",
                        category="LLM02 Insecure Output Handling",
                        owasp_id="LLM02",
                        cwe="CWE-116",
                        file=file_path,
                        line=lineno,
                        function_name=_get_func_name(func),
                        pattern_matched=f"llm_output '{var}' returned directly to client",
                        evidence=[
                            f"line {llm_output_vars[var]}: LLM assigns to '{var}'",
                            f"line {lineno}: return {var} (no output parser)",
                        ],
                        framework="fastapi/flask",
                        remediation="Apply a Pydantic output parser or JSON schema validation before returning LLM output. Escape HTML if rendering in browser.",
                        cvss_estimate=6.5,
                    ))
                    break

            elif isinstance(node, ast.Call):
                attr = _call_attr(node)
                if attr in _RESPONSE_CLASSES:
                    for arg in list(node.args) + [kw.value for kw in node.keywords]:
                        names = _names_in_expr(arg)
                        matched = names & set(llm_output_vars.keys())
                        if matched:
                            var = next(iter(matched))
                            findings.append(PatternFinding(
                                vulnerability_id="PAT-011",
                                title="LLM output returned to client without output validation",
                                severity="high",
                                confidence="medium",
                                category="LLM02 Insecure Output Handling",
                                owasp_id="LLM02",
                                cwe="CWE-116",
                                file=file_path,
                                line=lineno,
                                function_name=_get_func_name(func),
                                pattern_matched=f"llm_output '{var}' in {attr}()",
                                evidence=[
                                    f"line {llm_output_vars[var]}: LLM assigns to '{var}'",
                                    f"line {lineno}: {attr}(... {var} ...) without validation",
                                ],
                                framework="fastapi/flask",
                                remediation="Apply a Pydantic output parser or JSON schema validation before returning LLM output.",
                                cvss_estimate=6.5,
                            ))
                            break

    return findings


# ---------------------------------------------------------------------------
# PAT-012: Lethal Trifecta (repo-level — handled in analyze_patterns)
# ---------------------------------------------------------------------------

# Signals collected per-file and combined at repo level
_ConditionA = Tuple[str, int]  # (file, line)
_ConditionB = Tuple[str, int]
_ConditionC = Tuple[str, int]

_OUTBOUND_ATTRS = {"post", "send", "send_email", "send_message", "publish", "emit", "notify"}
_OUTBOUND_CHAINS = {"requests.post", "httpx.post", "aiohttp.post", "sendgrid", "smtp", "ses", "mailgun"}
_SENSITIVE_DATA_CHAINS = {
    "os.environ", "os.getenv", "getenv",
    "fetchall", "fetchone", "fetchrow",
}


def _collect_pat012_signals(
    tree: ast.Module,
    file_path: str,
    source_text: str,
) -> Tuple[Optional[_ConditionA], Optional[_ConditionB], Optional[_ConditionC]]:
    """Return (cond_a, cond_b, cond_c) signals from this file."""
    src_lower = source_text.lower()
    cond_a: Optional[_ConditionA] = None
    cond_b: Optional[_ConditionB] = None
    cond_c: Optional[_ConditionC] = None

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        chain = _call_chain_str(node)
        attr = _call_attr(node)
        lineno = getattr(node, "lineno", 0)

        if cond_a is None:
            if any(s in chain for s in _SENSITIVE_DATA_CHAINS):
                cond_a = (file_path, lineno)

        if cond_b is None:
            # RAG pipeline + external data
            if _is_retrieval_call(node) or "tavily" in chain or "serpapi" in chain or "duckduckgo" in chain:
                cond_b = (file_path, lineno)
            elif "upload" in src_lower and ("vector" in src_lower or "embed" in src_lower):
                cond_b = (file_path, lineno)

        if cond_c is None:
            if any(s in chain for s in _OUTBOUND_CHAINS) or attr in _OUTBOUND_ATTRS:
                cond_c = (file_path, lineno)

    return cond_a, cond_b, cond_c


# ---------------------------------------------------------------------------
# PAT-013: Multi-agent trust boundary violation
# ---------------------------------------------------------------------------

def detect_pat013(
    tree: ast.Module,
    file_path: str,
    source_text: str,
    import_map: Dict[str, str],
) -> List[PatternFinding]:
    findings: List[PatternFinding] = []
    _SECOND_AGENT_INDICATORS = {
        "task", "context", "instruction", "prompt", "description",
        "system", "input",
    }

    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        agent_output_vars: Dict[str, int] = {}
        for node in ast.walk(func):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                if _is_agent_call(node.value):
                    for t in node.targets:
                        if isinstance(t, ast.Name):
                            agent_output_vars[t.id] = getattr(node, "lineno", 0)

        if not agent_output_vars:
            continue

        # Signal B: used as input to SECOND agent call
        for node in ast.walk(func):
            if isinstance(node, ast.Call) and _is_agent_call(node):
                agent_line = next(iter(agent_output_vars.values()))
                call_line = getattr(node, "lineno", 0)
                if call_line <= agent_line:
                    continue  # Same or earlier call — not second agent
                for arg in list(node.args) + [kw.value for kw in node.keywords]:
                    names = _names_in_expr(arg)
                    matched = names & set(agent_output_vars.keys())
                    if matched:
                        var = next(iter(matched))
                        # Signal C: check for json.loads + pydantic validation
                        src_between = source_text.splitlines()[agent_output_vars[var]:call_line]
                        has_validation = any(
                            "json.loads" in l or "model_validate" in l or "parse_obj" in l
                            for l in src_between
                        )
                        findings.append(PatternFinding(
                            vulnerability_id="PAT-013",
                            title="Agent output used as trusted input to second agent",
                            severity="critical",
                            confidence="low" if has_validation else "medium",
                            category="ASI03 Rogue Agent Actions",
                            owasp_id="ASI03",
                            cwe="CWE-345",
                            file=file_path,
                            line=call_line,
                            function_name=_get_func_name(func),
                            pattern_matched=f"agent output '{var}' used as second agent input",
                            evidence=[
                                f"line {agent_output_vars[var]}: first agent call assigns to '{var}'",
                                f"line {call_line}: '{var}' passed to second agent call",
                            ] + (["json.loads/pydantic validation found between calls"] if has_validation else []),
                            framework="langchain/crewai/openai_agents",
                            remediation="Validate agent output schema before passing to second agent. Treat inter-agent messages as untrusted until verified.",
                            cvss_estimate=8.8,
                        ))
                        break

    return findings


# ---------------------------------------------------------------------------
# PAT-014: Insecure agent memory persistence
# ---------------------------------------------------------------------------

def detect_pat014(
    tree: ast.Module,
    file_path: str,
    source_text: str,
    import_map: Dict[str, str],
) -> List[PatternFinding]:
    findings: List[PatternFinding] = []
    src_lower = source_text.lower()

    has_integrity = any(s in src_lower for s in {"hmac", "signature", "verify", "checksum", "validate"})

    write_lines: List[int] = []
    read_lines: List[int] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        attr = _call_attr(node)
        chain = _call_chain_str(node)
        lineno = getattr(node, "lineno", 0)

        if attr in _MEMORY_WRITE_ATTRS or "save_context" in chain:
            write_lines.append(lineno)
        elif attr in _MEMORY_READ_ATTRS or "load_memory" in chain:
            read_lines.append(lineno)

    if write_lines and read_lines:
        findings.append(PatternFinding(
            vulnerability_id="PAT-014",
            title="Agent memory persisted and read back without integrity check",
            severity="high",
            confidence="medium" if not has_integrity else "low",
            category="LLM02 Insecure Output Handling",
            owasp_id="LLM02",
            cwe="CWE-494",
            file=file_path,
            line=write_lines[0],
            function_name=None,
            pattern_matched="memory_write + memory_read without integrity verification",
            evidence=[
                f"line {write_lines[0]}: memory write (add_documents/save_context)",
                f"line {read_lines[0]}: memory read (similarity_search/load_memory_variables)",
            ] + ([] if not has_integrity else ["integrity check found — verify coverage"]),
            framework="langchain/llamaindex",
            remediation="Sign or HMAC-verify stored memory entries. Validate content schema when loading memory to detect poisoned entries.",
            cvss_estimate=6.8,
        ))

    return findings


# ---------------------------------------------------------------------------
# PAT-015: DSPy ProgramOfThought without sandbox
# ---------------------------------------------------------------------------

def detect_pat015(
    tree: ast.Module,
    file_path: str,
    source_text: str,
    import_map: Dict[str, str],
) -> List[PatternFinding]:
    findings: List[PatternFinding] = []

    has_pot = any(
        "programofthought" in fqn.lower() or "programofthought" in local.lower()
        for local, fqn in import_map.items()
    )
    if not has_pot:
        # Also check source text for direct usage
        has_pot = "programofthought" in source_text.lower()
    if not has_pot:
        return []

    src_lower = source_text.lower()
    has_sandbox = any(s in src_lower for s in {
        "restrictedpython", "sandbox", "resource_limit", "seccomp",
        "nsjail", "pypy_sandbox", "firejail",
    })

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        chain = _call_chain_str(node)
        if "programofthought" in chain:
            lineno = getattr(node, "lineno", None)
            findings.append(PatternFinding(
                vulnerability_id="PAT-015",
                title="DSPy ProgramOfThought executes LLM-generated code",
                severity="critical",
                confidence="high",
                category="LLM08 Excessive Agency",
                owasp_id="LLM08",
                cwe="CWE-77",
                file=file_path,
                line=lineno,
                function_name=None,
                pattern_matched="dspy.ProgramOfThought instantiation",
                evidence=[
                    f"line {lineno}: {chain}",
                    "ProgramOfThought generates and executes Python code without sandbox",
                ] + (["No sandbox detected in file"] if not has_sandbox else ["Sandbox found — verify it covers generated code"]),
                framework="dspy",
                remediation="Wrap DSPy ProgramOfThought execution in a container sandbox with resource limits. Consider using ChainOfThought instead if code execution is not required.",
                cvss_estimate=9.0,
            ))
            break  # One finding per file

    return findings


# ---------------------------------------------------------------------------
# PAT-016: Tool result injected back into agent context
# ---------------------------------------------------------------------------

_FETCH_CHAINS = {
    "requests.get", "httpx.get", "httpx.get", "aiohttp", "urllib",
    "imap", "gmail", "feedparser", "beautifulsoup",
    "playwright", "scrapy",
}


def detect_pat016(
    tree: ast.Module,
    file_path: str,
    source_text: str,
    import_map: Dict[str, str],
) -> List[PatternFinding]:
    findings: List[PatternFinding] = []

    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        # Is this a tool-registered function?
        is_tool = any(
            (isinstance(d, ast.Name) and d.id.lower() in _TOOL_DECORATORS) or
            (isinstance(d, ast.Attribute) and d.attr.lower() in _TOOL_DECORATORS) or
            (isinstance(d, ast.Call) and _call_attr(d) in _TOOL_DECORATORS)
            for d in func.decorator_list
        )
        if not is_tool:
            continue

        # Signal A: fetches external content
        external_fetch_lines: List[int] = []
        for node in ast.walk(func):
            if isinstance(node, ast.Call):
                chain = _call_chain_str(node)
                if any(f in chain for f in _FETCH_CHAINS):
                    external_fetch_lines.append(getattr(node, "lineno", 0))

        if not external_fetch_lines:
            continue

        # Signal B: return value not sanitized
        has_sanitization = False
        for node in ast.walk(func):
            if isinstance(node, ast.Call):
                attr = _call_attr(node)
                if attr in {"escape", "sanitize", "clean", "strip_tags", "bleach"}:
                    has_sanitization = True
                    break

        if not has_sanitization:
            findings.append(PatternFinding(
                vulnerability_id="PAT-016",
                title="External tool result injected unsanitized into agent context",
                severity="high",
                confidence="medium",
                category="LLM01 Prompt Injection (indirect via tool)",
                owasp_id="LLM01",
                cwe="CWE-74",
                file=file_path,
                line=func.lineno,
                function_name=_get_func_name(func),
                pattern_matched="@tool function fetches external content without sanitization",
                evidence=[
                    f"@tool-decorated function: {func.name}",
                    f"line {external_fetch_lines[0]}: external content fetch",
                    "No sanitization before return",
                ],
                framework="langchain/openai_agents/pydantic_ai",
                remediation="Sanitize external content before returning from tool. Strip/escape HTML, validate content length and schema. Consider content allow-listing.",
                cvss_estimate=7.5,
            ))

    return findings


# ---------------------------------------------------------------------------
# PAT-017: Streaming response without output gate
# ---------------------------------------------------------------------------

def detect_pat017(
    tree: ast.Module,
    file_path: str,
    source_text: str,
    import_map: Dict[str, str],
) -> List[PatternFinding]:
    findings: List[PatternFinding] = []

    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        stream_lines: List[int] = []
        for node in ast.walk(func):
            if isinstance(node, ast.Call):
                attr = _call_attr(node)
                chain = _call_chain_str(node)
                if attr in {"stream", "astream"}:
                    stream_lines.append(getattr(node, "lineno", 0))
                # stream=True kwarg in LLM call
                if _is_llm_call(node):
                    for kw in node.keywords:
                        if kw.arg == "stream" and isinstance(kw.value, ast.Constant) and kw.value.value:
                            stream_lines.append(getattr(node, "lineno", 0))

        if not stream_lines:
            continue

        # Signal B: yielded directly to response
        has_direct_stream = False
        for node in ast.walk(func):
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Yield):
                has_direct_stream = True
                break
            if isinstance(node, ast.AsyncFor):
                has_direct_stream = True
                break

        if not has_direct_stream:
            continue

        # Signal C disqualifier: output buffer / accumulation before yield
        src = func_source_text(source_text, func)
        has_buffer = any(s in src.lower() for s in {
            "buffer", "accumulated", "full_response", "complete", "validate_output",
        })
        if has_buffer:
            continue

        findings.append(PatternFinding(
            vulnerability_id="PAT-017",
            title="Streaming LLM response without output validation gate",
            severity="medium",
            confidence="low",
            category="LLM02 Insecure Output Handling",
            owasp_id="LLM02",
            cwe="CWE-116",
            file=file_path,
            line=stream_lines[0],
            function_name=_get_func_name(func),
            pattern_matched="stream=True + direct yield without buffering",
            evidence=[
                f"line {stream_lines[0]}: streaming LLM call",
                "Direct yield/async-for without output accumulation/validation",
            ],
            framework="langchain/openai",
            remediation="Buffer complete response before streaming to client, or add an output gate that validates each chunk before forwarding.",
            cvss_estimate=4.3,
        ))

    return findings


def func_source_text(source_text: str, func: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    lines = source_text.splitlines()
    start = func.lineno - 1
    end = getattr(func, "end_lineno", start + 50)
    return "\n".join(lines[start:end])


# ---------------------------------------------------------------------------
# PAT-018: Prompt injection via external data source
# ---------------------------------------------------------------------------

_DB_RESULT_ATTRS = {"fetchall", "fetchone", "fetchrow", "fetch_all", "fetch_one", "execute"}
_DB_CHAINS = {"cursor", "conn", "session", "db", "database", "engine"}
_EXTERNAL_API_CHAINS = {"requests", "httpx", "aiohttp", "urllib"}
_FILE_READ_ATTRS = {"read", "read_text", "readlines"}
_DISQUALIFIER_VALIDATION = {"model_validate", "parse_obj", "parse_raw", "validate", "schema"}


def detect_pat018(
    tree: ast.Module,
    file_path: str,
    source_text: str,
    import_map: Dict[str, str],
) -> List[PatternFinding]:
    findings: List[PatternFinding] = []
    src_lower = source_text.lower()
    has_validation = any(s in src_lower for s in _DISQUALIFIER_VALIDATION)

    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        external_vars: Dict[str, int] = {}
        for node in ast.walk(func):
            if not isinstance(node, ast.Assign):
                continue
            if not isinstance(node.value, ast.Call):
                continue
            chain = _call_chain_str(node.value)
            attr = _call_attr(node.value)
            is_db = attr in _DB_RESULT_ATTRS and any(d in chain for d in _DB_CHAINS)
            is_api = any(a in chain for a in _EXTERNAL_API_CHAINS)
            is_file = attr in _FILE_READ_ATTRS
            is_email = "imap" in chain or "gmail" in chain or "email" in chain
            if is_db or is_api or is_file or is_email:
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        external_vars[t.id] = getattr(node, "lineno", 0)

        if not external_vars:
            continue

        # Signal B: used in LLM call or prompt template
        for node in ast.walk(func):
            if isinstance(node, ast.Call) and _is_llm_call(node):
                call_line = getattr(node, "lineno", 0)
                for arg in list(node.args) + [kw.value for kw in node.keywords]:
                    names = _names_in_expr(arg)
                    matched = names & set(external_vars.keys())
                    if matched:
                        var = next(iter(matched))
                        confidence = "low" if has_validation else "medium"
                        findings.append(PatternFinding(
                            vulnerability_id="PAT-018",
                            title="External data source content flows into LLM prompt",
                            severity="high",
                            confidence=confidence,
                            category="LLM01 Prompt Injection (indirect)",
                            owasp_id="LLM01",
                            cwe="CWE-74",
                            file=file_path,
                            line=call_line,
                            function_name=_get_func_name(func),
                            pattern_matched=f"external_var '{var}' used in LLM call",
                            evidence=[
                                f"line {external_vars[var]}: external data read into '{var}'",
                                f"line {call_line}: '{var}' passed to LLM call",
                            ] + (["Pydantic/schema validation found — verify it covers this path"] if has_validation else []),
                            framework="generic",
                            remediation="Validate and sanitize external data before injecting into LLM prompts. Use content allow-listing or Guardrails AI.",
                            cvss_estimate=7.5,
                        ))
                        break

    return findings


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_DETECTORS: List[Callable] = [
    detect_pat001,
    detect_pat002,
    detect_pat003,
    detect_pat004,
    detect_pat005,
    detect_pat006,
    detect_pat007,
    detect_pat008,
    detect_pat009,
    detect_pat010,
    detect_pat011,
    # PAT-012 is handled at repo level
    detect_pat013,
    detect_pat014,
    detect_pat015,
    detect_pat016,
    detect_pat017,
    detect_pat018,
]


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def _deduplicate(findings: List[PatternFinding]) -> List[PatternFinding]:
    """Keep highest-severity/confidence finding per (function, line)."""
    _SEV = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    _CONF = {"high": 3, "medium": 2, "low": 1}

    best: Dict[Tuple, PatternFinding] = {}
    for f in findings:
        key = (f.function_name or "", f.line or 0, f.vulnerability_id)
        existing = best.get(key)
        if existing is None:
            best[key] = f
        else:
            if _SEV.get(f.severity, 0) > _SEV.get(existing.severity, 0):
                best[key] = f
            elif _SEV.get(f.severity, 0) == _SEV.get(existing.severity, 0):
                if _CONF.get(f.confidence, 0) > _CONF.get(existing.confidence, 0):
                    best[key] = f
                elif _CONF.get(f.confidence, 0) == _CONF.get(existing.confidence, 0):
                    if len(f.evidence) > len(existing.evidence):
                        best[key] = f
    return list(best.values())


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def analyze_patterns(repo_root: Path) -> PatternAnalysisResult:
    """Run all pattern detectors against every Python file in the repo."""
    repo_root = Path(repo_root).resolve()
    all_findings: List[PatternFinding] = []
    scan_errors: List[str] = []
    files_scanned = 0
    framework_summary: Dict[str, int] = {}

    # Repo-level PAT-012 signal collectors
    cond_a_signals: List[_ConditionA] = []
    cond_b_signals: List[_ConditionB] = []
    cond_c_signals: List[_ConditionC] = []

    for path in walk_python_files(repo_root):
        # Additional skip: migrations, alembic, *.pyi, generated files
        rel = str(path.relative_to(repo_root))
        if any(part in rel for part in ("migrations", "alembic", ".venv", "venv", "dist", "build")):
            continue
        if path.suffix == ".pyi" or rel.endswith(("_pb2.py", "_pb2_grpc.py", "_generated.py")):
            continue

        try:
            source_text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError as e:
            scan_errors.append(f"{rel}: OSError reading file: {e}")
            continue

        try:
            tree = ast.parse(source_text)
        except (SyntaxError, ValueError, UnicodeDecodeError) as e:
            scan_errors.append(f"{rel}: parse error: {e}")
            continue

        files_scanned += 1

        try:
            import_map = _build_import_map(tree)
        except Exception as e:
            scan_errors.append(f"{rel}: import_map error: {e}")
            import_map = {}

        # Collect PAT-012 signals from this file
        try:
            ca, cb, cc = _collect_pat012_signals(tree, rel, source_text)
            if ca:
                cond_a_signals.append(ca)
            if cb:
                cond_b_signals.append(cb)
            if cc:
                cond_c_signals.append(cc)
        except Exception as e:
            scan_errors.append(f"{rel}: PAT-012 signal error: {e}")

        file_findings: List[PatternFinding] = []
        for detector in _DETECTORS:
            try:
                file_findings.extend(detector(tree, rel, source_text, import_map))
            except Exception as e:
                scan_errors.append(f"{rel}: {detector.__name__}: {e}")

        file_findings = _deduplicate(file_findings)

        for f in file_findings:
            fw = f.framework
            framework_summary[fw] = framework_summary.get(fw, 0) + 1

        all_findings.extend(file_findings)

    # PAT-012: repo-level Lethal Trifecta
    if cond_a_signals and cond_b_signals and cond_c_signals:
        fa, la = cond_a_signals[0]
        fb, lb = cond_b_signals[0]
        fc, lc = cond_c_signals[0]
        all_findings.append(PatternFinding(
            vulnerability_id="PAT-012",
            title="Lethal Trifecta: sensitive data + untrusted input + exfiltration",
            severity="critical",
            confidence="high",
            category="ASI01 Agent Goal Hijack",
            owasp_id="ASI01",
            cwe="CWE-284",
            file=fa,
            line=la,
            function_name=None,
            pattern_matched="all three trifecta conditions present in repo",
            evidence=[
                f"(A) Sensitive data access: {fa}:{la}",
                f"(B) Untrusted content in agent context: {fb}:{lb}",
                f"(C) Outbound exfiltration capability: {fc}:{lc}",
            ],
            framework="generic",
            remediation=(
                f"This codebase has: (A) sensitive data in {fa}, "
                f"(B) untrusted external content reaches agent context in {fb}, "
                f"(C) outbound exfiltration capability in {fc}. "
                "An attacker who can inject into the context window can exfiltrate sensitive data through the outbound channel. "
                "Apply strict input validation on external content, output filtering before exfiltration channels, and least-privilege agent permissions."
            ),
            cvss_estimate=9.8,
        ))

    return PatternAnalysisResult(
        findings=all_findings,
        files_scanned=files_scanned,
        patterns_evaluated=len(_DETECTORS) + 1,  # +1 for PAT-012 repo-level
        scan_errors=scan_errors,
        framework_summary=framework_summary,
    )
