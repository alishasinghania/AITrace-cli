from __future__ import annotations

"""
Shared source/sink catalog for AI analyzers.

Patterns (PAT-*) are labels. This module classifies a Call node by *behavior*:
what kind of untrusted entrypoint or dangerous operation it is.
"""

import ast
from typing import List, Set

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
    "perplexity", "generativeai", "mistral",
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

HTTP_ATTRS = {"get", "post", "put", "patch", "delete", "request", "head"}
HTTP_CHAIN = {"requests", "httpx", "aiohttp", "urllib"}

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


def classify_sink(node: ast.Call) -> List[str]:
    """Return sink type tags for a call: llm, rce, sql, http, email, retrieval, rag_ingest."""
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
    if attr in SQL_ATTRS and ((parts & SQL_CHAIN) or attr == "execute"):
        tags.append("sql")
    if attr in HTTP_ATTRS and (parts & HTTP_CHAIN):
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
    for node in ast.walk(func):
        if not isinstance(node, ast.Call):
            continue
        for tag in classify_sink(node):
            if tag not in found:
                found.append(tag)
    return found


def function_has_source_call(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """True if the function itself reads stdin/HTTP body/prompt input."""
    for node in ast.walk(func):
        if isinstance(node, ast.Call) and is_source_call(node):
            return True
    return False


HIGH_IMPACT_SINKS: Set[str] = {"rce", "sql", "http", "email", "rag_ingest"}

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
        "Untrusted input reaches a SQL execute call",
        "critical",
        "LLM02 Insecure Output Handling",
        "CWE-89",
    ),
    "http": (
        "FLOW-HTTP",
        "Untrusted input reaches an outbound HTTP call",
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
