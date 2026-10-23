from __future__ import annotations

"""
Shared source/sink catalog for AI analyzers.

Patterns (PAT-*) are labels. This module classifies a Call node by *behavior*:
what kind of untrusted entrypoint or dangerous operation it is.
"""

import ast
from typing import Dict, List, Optional, Set, Tuple

from ..utils.ast_utils import get_call_target_chain

# ---------------------------------------------------------------------------
# Sinks — dangerous operations (attacker-controlled data must not reach these)
# ---------------------------------------------------------------------------

LLM_ATTRS = {
    "create", "generate_content", "generate", "invoke", "ainvoke",
    "run", "arun", "stream", "astream", "predict", "predict_messages",
    "complete", "acomplete", "chat", "kickoff", "kickoff_async",
}
LLM_CHAIN = {
    "openai", "anthropic", "cohere", "vertexai", "bedrock",
    "litellm", "ollama", "groq", "together", "replicate",
    "xai", "grok", "deepseek", "openrouter", "dashscope", "moonshot",
    "perplexity", "generativeai", "mistral", "cerebras", "zhipuai",
    "watsonx", "portkey",
    "llm", "chain", "agent", "agentexecutor", "messages",
    "completions", "chatmodel", "chatanthropic", "chatopenai",
    "runner", "crew",
}

RCE_ATTRS = {
    "exec", "eval", "compile", "system", "popen",
    "check_output", "check_call", "call", "run",
}
RCE_CHAIN = {"subprocess", "os"}

SQL_ATTRS = {"execute", "executemany", "executescript"}
SQL_CHAIN = {"cursor", "conn", "session", "db", "database", "engine", "asyncpg"}
SQL_FACTORY_ATTRS = {"cursor", "connect", "connection"}

HTTP_ATTRS = {
    "get", "post", "put", "patch", "delete", "request", "head",
    "urlopen", "urlretrieve",
}
HTTP_CHAIN = {"requests", "httpx", "aiohttp", "urllib", "urllib3"}
HTTP_FACTORY_ATTRS = {"session", "client", "asyncclient", "clientsession"}
_INBOUND_HTTP_PARTS = {"flask", "django", "fastapi", "starlette", "werkzeug", "sanic"}
_HTTP_URL_KW = {"url"}
_HTTP_QUERY_KW = {"params"}
_HTTP_BODY_KW = {"json", "data", "content", "files", "body"}
_HTTP_HEADER_KW = {"headers"}

EMAIL_ATTRS = {"sendmail", "send_message", "send_mail", "send"}
EMAIL_CHAIN = {"smtplib", "smtp", "sendgrid", "ses", "mailgun", "resend"}

RETRIEVAL_ATTRS = {
    "similarity_search", "similarity_search_with_score",
    "max_marginal_relevance_search", "get_relevant_documents",
    "as_retriever",
}

RAG_INGEST_ATTRS = {
    "add_texts", "add_documents", "from_texts", "from_documents", "upsert",
}

# ---------------------------------------------------------------------------
# Sources — untrusted entry
# ---------------------------------------------------------------------------

SOURCE_CALL_NAMES = {
    "input", "get_json", "get_data", "form", "receive_json",
    "receive_text", "receive_bytes", "ask",
}


def call_chain(node: ast.Call) -> str:
    """Lowercased dotted call target."""
    return ".".join(get_call_target_chain(node)).lower()


def call_attr(node: ast.Call) -> str:
    """Final attribute or name of a call."""
    if isinstance(node.func, ast.Attribute):
        return node.func.attr.lower()
    if isinstance(node.func, ast.Name):
        return node.func.id.lower()
    return ""


def is_parameterized_sql_call(node: ast.Call) -> bool:
    """True when execute() binds values separately from the SQL string."""
    if len(node.args) >= 2:
        return True
    for kw in node.keywords:
        if kw.arg in {"params", "parameters"}:
            return True
    return False


def is_sql_factory_call(node: ast.Call) -> bool:
    """True for cursor()/connect() style constructors."""
    return call_attr(node) in SQL_FACTORY_ATTRS


def collect_sql_receivers(func: ast.AST) -> Set[str]:
    """Names assigned from cursor()/connect() within a function."""
    names: Set[str] = set()
    for node in ast.walk(func):
        if not isinstance(node, ast.Assign):
            continue
        if not isinstance(node.value, ast.Call) or not is_sql_factory_call(node.value):
            continue
        for t in node.targets:
            if isinstance(t, ast.Name):
                names.add(t.id.lower())
    return names


def is_sql_execute_call(node: ast.Call, sql_receivers: Optional[Set[str]] = None) -> bool:
    """True for DB execute APIs, including names bound to cursor()/connect()."""
    attr = call_attr(node)
    if attr not in SQL_ATTRS:
        return False
    chain = call_chain(node)
    parts = set(chain.split(".")) if chain else set()
    if parts & {c.lower() for c in SQL_CHAIN}:
        return True
    head = chain.split(".")[0] if chain else ""
    if sql_receivers and head in sql_receivers:
        return True
    return False


def _imported_root(name: str, import_modules: Optional[Dict[str, str]]) -> str:
    """First segment of the module mapped to a local name, or empty."""
    if not import_modules or not name:
        return ""
    mod = import_modules.get(name) or import_modules.get(name.lower())
    if not mod:
        return ""
    return mod.split(".")[0].lower().replace("-", "_")


def is_http_factory_call(
    node: ast.Call,
    import_modules: Optional[Dict[str, str]] = None,
) -> bool:
    """True for requests.Session / httpx.Client / aiohttp.ClientSession constructors."""
    if call_attr(node) not in HTTP_FACTORY_ATTRS:
        return False
    chain = call_chain(node)
    parts = set(chain.split(".")) if chain else set()
    if parts & HTTP_CHAIN:
        return True
    head = chain.split(".")[0] if chain else ""
    return _imported_root(head, import_modules) in HTTP_CHAIN


def collect_http_receivers(
    func: ast.AST,
    import_modules: Optional[Dict[str, str]] = None,
) -> Set[str]:
    """Names assigned from HTTP client/session constructors."""
    names: Set[str] = set()
    for node in ast.walk(func):
        if not isinstance(node, ast.Assign):
            continue
        if not isinstance(node.value, ast.Call) or not is_http_factory_call(node.value, import_modules):
            continue
        for t in node.targets:
            if isinstance(t, ast.Name):
                names.add(t.id.lower())
    return names


def is_http_client_call(
    node: ast.Call,
    import_modules: Optional[Dict[str, str]] = None,
    http_receivers: Optional[Set[str]] = None,
) -> bool:
    """True for outbound HTTP client APIs, not inbound route handlers or dict.get."""
    attr = call_attr(node)
    if attr not in HTTP_ATTRS:
        return False
    chain = call_chain(node)
    parts = set(chain.split(".")) if chain else set()
    if parts & _INBOUND_HTTP_PARTS:
        return False
    if parts & HTTP_CHAIN:
        return True
    head = chain.split(".")[0] if chain else ""
    if _imported_root(head, import_modules) in HTTP_CHAIN:
        return True
    if http_receivers and head in http_receivers:
        return True
    return False


def http_arg_roles(node: ast.Call) -> List[Tuple[str, ast.expr]]:
    """Map identifiable HTTP arguments to url | query | body | headers | unresolved."""
    roles: List[Tuple[str, ast.expr]] = []
    attr = call_attr(node)
    positional = [a for a in node.args if not isinstance(a, ast.Starred)]
    for a in node.args:
        if isinstance(a, ast.Starred):
            roles.append(("unresolved", a.value))
    url_kw: Optional[ast.expr] = None
    for kw in node.keywords:
        if kw.arg is None:
            roles.append(("unresolved", kw.value))
            continue
        name = kw.arg.lower()
        if name in _HTTP_URL_KW:
            url_kw = kw.value
        elif name in _HTTP_QUERY_KW:
            roles.append(("query", kw.value))
        elif name in _HTTP_BODY_KW:
            roles.append(("body", kw.value))
        elif name in _HTTP_HEADER_KW:
            roles.append(("headers", kw.value))
    if url_kw is not None:
        roles.append(("url", url_kw))
    elif attr == "request" and len(positional) >= 2:
        roles.append(("url", positional[1]))
    elif attr != "request" and positional:
        roles.append(("url", positional[0]))
    return roles


def classify_sink(
    node: ast.Call,
    sql_receivers: Optional[Set[str]] = None,
    import_modules: Optional[Dict[str, str]] = None,
    http_receivers: Optional[Set[str]] = None,
) -> List[str]:
    """Return sink type tags for a call: llm, rce, sql, http, email, retrieval, rag_ingest.

    Generic method names (execute, invoke, run, get, post) are not enough; a
    receiver, import, or framework token from the call chain is required except
    for builtin exec/eval/compile.
    """
    attr = call_attr(node)
    chain = call_chain(node)
    parts = set(chain.split(".")) if chain else set()
    tags: List[str] = []

    if attr in LLM_ATTRS and (parts & LLM_CHAIN):
        tags.append("llm")
    if attr in {"exec", "eval", "compile"}:
        tags.append("rce")
    elif attr in RCE_ATTRS and (parts & RCE_CHAIN):
        tags.append("rce")
    if is_sql_execute_call(node, sql_receivers):
        tags.append("sql")
    if is_http_client_call(node, import_modules, http_receivers):
        tags.append("http")
    if (attr in EMAIL_ATTRS and (parts & EMAIL_CHAIN)) or "sendmail" in chain:
        tags.append("email")
    if attr in RETRIEVAL_ATTRS:
        tags.append("retrieval")
    if attr in RAG_INGEST_ATTRS:
        tags.append("rag_ingest")
    return tags


def is_source_call(node: ast.Call) -> bool:
    """True if this call reads untrusted user/runtime input."""
    attr = call_attr(node)
    chain = call_chain(node)
    if attr in SOURCE_CALL_NAMES:
        return True
    if "prompt.ask" in chain or chain.endswith(".ask"):
        return True
    return False


def function_sink_types(func: ast.FunctionDef | ast.AsyncFunctionDef) -> List[str]:
    """Unique sink tags found in a function body."""
    found: List[str] = []
    receivers = collect_sql_receivers(func)
    http_recv = collect_http_receivers(func)
    for node in ast.walk(func):
        if not isinstance(node, ast.Call):
            continue
        for tag in classify_sink(node, sql_receivers=receivers, http_receivers=http_recv):
            if tag not in found:
                found.append(tag)
    return found


def function_has_source_call(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """True if the function itself reads stdin/HTTP body/prompt input."""
    for node in ast.walk(func):
        if isinstance(node, ast.Call) and is_source_call(node):
            return True
    return False


# LLM is promoted as FLOW-LLM (high, not critical): confirmed payload in a
# prompt is not interchangeable with RCE/SQL injection.
HIGH_IMPACT_SINKS: Set[str] = {"rce", "sql", "http", "email", "rag_ingest", "llm"}

FLOW_META = {
    "rce": (
        "FLOW-RCE",
        "Untrusted input reaches command execution",
        "critical",
        "LLM08 Excessive Agency",
        "CWE-78",
    ),
    "sql": (
        "FLOW-SQL",
        "Untrusted input is interpolated into a SQL string",
        "critical",
        "LLM02 Insecure Output Handling",
        "CWE-89",
    ),
    "llm": (
        "FLOW-LLM",
        "Untrusted input reaches an LLM prompt",
        "high",
        "LLM01 Prompt Injection",
        "CWE-74",
    ),
    "http": (
        "FLOW-HTTP",
        "Untrusted input selects an outbound HTTP destination",
        "high",
        "LLM08 Excessive Agency",
        "CWE-918",
    ),
    "email": (
        "FLOW-EMAIL",
        "Untrusted input reaches an email send",
        "critical",
        "LLM08 Excessive Agency",
        "CWE-284",
    ),
    "rag_ingest": (
        "FLOW-RAG",
        "Untrusted input is written into the vector store",
        "high",
        "LLM03 Training Data Poisoning",
        "CWE-20",
    ),
}
