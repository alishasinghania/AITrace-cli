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


def _bind_target_names(target: Optional[ast.expr]) -> List[str]:
    """Name ids bound by an assignment or ``with`` target."""
    if target is None:
        return []
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        names: List[str] = []
        for elt in target.elts:
            names.extend(_bind_target_names(elt))
        return names
    return []


def collect_http_receivers(
    func: ast.AST,
    import_modules: Optional[Dict[str, str]] = None,
) -> Set[str]:
    """Names bound from HTTP client/session constructors, including ``with``."""
    names: Set[str] = set()
    for node in ast.walk(func):
        if isinstance(node, ast.Assign):
            if not isinstance(node.value, ast.Call) or not is_http_factory_call(
                node.value, import_modules
            ):
                continue
            for t in node.targets:
                if isinstance(t, ast.Name):
                    names.add(t.id.lower())
            continue
        if isinstance(node, ast.AnnAssign) and node.value is not None:
            if (
                isinstance(node.value, ast.Call)
                and is_http_factory_call(node.value, import_modules)
                and isinstance(node.target, ast.Name)
            ):
                names.add(node.target.id.lower())
            continue
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                expr = item.context_expr
                if not isinstance(expr, ast.Call) or not is_http_factory_call(
                    expr, import_modules
                ):
                    continue
                for t in _bind_target_names(item.optional_vars):
                    names.add(t.lower())
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


# OpenAI-compatible / Ollama-style chat HTTP APIs. Matched as path fragments
# so concatenations like base + "/chat/completions" still count.
_CHAT_URL_FRAGMENTS = (
    "/chat/completions",
    "/api/chat",
    "/v1/completions",
)
_CHAT_HTTP_BODY_METHODS = frozenset({"post", "request", "send"})
_CHAT_BODY_MESSAGE_KEYS = frozenset({"messages"})
_CHAT_BODY_PROMPT_KEYS = frozenset({"prompt"})
_CHAT_BODY_PROMPT_COMPANIONS = frozenset({"model", "max_tokens", "temperature"})
_TRANSFORMERS_PIPELINE_MODULES = frozenset({
    "transformers", "huggingface", "huggingface_hub",
})


def string_literals_in(expr: ast.expr) -> List[str]:
    """Lowercased string constants reachable from ``expr`` (including concatenations)."""
    found: List[str] = []
    for n in ast.walk(expr):
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            found.append(n.value.lower())
    return found


def _has_url_fragment(text: str, frag: str) -> bool:
    """True when ``frag`` appears as a path segment, not a mere substring prefix."""
    t = text.lower()
    start = 0
    while True:
        idx = t.find(frag, start)
        if idx < 0:
            return False
        after = t[idx + len(frag): idx + len(frag) + 1]
        if after in {"", "/", "?", "#"}:
            return True
        start = idx + 1


def url_has_chat_api_path(expr: ast.expr) -> bool:
    """True when a URL expression contains an OpenAI-compatible or Ollama chat path."""
    for literal in string_literals_in(expr):
        for frag in _CHAT_URL_FRAGMENTS:
            if _has_url_fragment(literal, frag):
                return True
    return False


def dict_literal_keys(expr: ast.expr) -> Set[str]:
    """Lowercased keys of a dict literal, if ``expr`` is one."""
    if not isinstance(expr, ast.Dict):
        return set()
    keys: Set[str] = set()
    for k in expr.keys:
        if isinstance(k, ast.Constant) and isinstance(k.value, str):
            keys.add(k.value.lower())
    return keys


def http_body_looks_like_chat(expr: ast.expr) -> bool:
    """True for a JSON body that carries chat ``messages`` or a completions ``prompt``."""
    keys = dict_literal_keys(expr)
    if keys & _CHAT_BODY_MESSAGE_KEYS:
        return True
    if (keys & _CHAT_BODY_PROMPT_KEYS) and (keys & _CHAT_BODY_PROMPT_COMPANIONS):
        return True
    return False


def http_url_arg(node: ast.Call) -> Optional[ast.expr]:
    """Return the URL expression of an HTTP client call, if present."""
    for role, expr in http_arg_roles(node):
        if role == "url":
            return expr
    return None


def deref_bound_expr(
    expr: ast.expr,
    name_bindings: Optional[Dict[str, ast.expr]] = None,
    *,
    depth: int = 0,
) -> ast.expr:
    """Follow ``name = <expr>`` aliases a few hops (URL/payload locals)."""
    if not name_bindings:
        return expr
    cur: ast.expr = expr
    seen: Set[str] = set()
    while isinstance(cur, ast.Name) and cur.id in name_bindings and depth < 6:
        if cur.id in seen:
            break
        seen.add(cur.id)
        cur = name_bindings[cur.id]
        depth += 1
    return cur


def collect_name_bindings(func: ast.AST) -> Dict[str, ast.expr]:
    """Simple name → last assigned expression in ``func`` (including nested)."""
    out: Dict[str, ast.expr] = {}
    for node in ast.walk(func):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    out[t.id] = node.value
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.value is not None
        ):
            out[node.target.id] = node.value
    return out


def http_llm_sink_label(
    node: ast.Call,
    name_bindings: Optional[Dict[str, ast.expr]] = None,
) -> Optional[str]:
    """Sink label when an HTTP client call targets a chat/completions-style LLM API.

    Requires either a URL path fragment (``/chat/completions``, ``/api/chat``)
    or a POST-like body that carries ``messages`` / ``prompt``+``model``.
    Local aliases (``url = f".../chat/completions"``; ``json=payload``) count.
    """
    url = None
    bodies: List[ast.expr] = []
    for role, expr in http_arg_roles(node):
        if role == "url":
            url = deref_bound_expr(expr, name_bindings)
        elif role == "body":
            bodies.append(deref_bound_expr(expr, name_bindings))
    if url is not None and url_has_chat_api_path(url):
        frags = string_literals_in(url)
        if any(_has_url_fragment(s, "/api/chat") for s in frags):
            return "ollama /api/chat"
        if any(_has_url_fragment(s, "/chat/completions") for s in frags):
            return "openai-compatible /chat/completions"
        if any(_has_url_fragment(s, "/v1/completions") for s in frags):
            return "openai-compatible /v1/completions"
        return "openai-compatible chat HTTP"
    if call_attr(node) in _CHAT_HTTP_BODY_METHODS and any(
        http_body_looks_like_chat(b) for b in bodies
    ):
        return "openai-compatible chat HTTP"
    return None


def is_transformers_pipeline_call(
    node: ast.Call,
    import_modules: Optional[Dict[str, str]] = None,
) -> bool:
    """True only for Hugging Face ``transformers.pipeline`` (or equivalent) APIs.

    A module path segment ``pipeline`` (e.g. ``app.pipeline.foo``) is not enough.
    """
    chain = get_call_target_chain(node)
    if not chain or chain[-1].lower() != "pipeline":
        return False
    parts = {c.lower() for c in chain}
    if parts & _TRANSFORMERS_PIPELINE_MODULES:
        return True
    if import_modules and chain:
        mod = (import_modules.get(chain[0]) or "").lower().replace("-", "_")
        root = mod.split(".")[0] if mod else ""
        return root in _TRANSFORMERS_PIPELINE_MODULES
    return False


def classify_sink(
    node: ast.Call,
    sql_receivers: Optional[Set[str]] = None,
    import_modules: Optional[Dict[str, str]] = None,
    http_receivers: Optional[Set[str]] = None,
    name_bindings: Optional[Dict[str, ast.expr]] = None,
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
        if http_llm_sink_label(node, name_bindings=name_bindings):
            tags.append("llm")
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
    bindings = collect_name_bindings(func)
    for node in ast.walk(func):
        if not isinstance(node, ast.Call):
            continue
        for tag in classify_sink(
            node,
            sql_receivers=receivers,
            http_receivers=http_recv,
            name_bindings=bindings,
        ):
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
