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

from ..utils.ast_utils import should_skip_path, get_call_chain

# Sensitive keywords in variable names -> risk level
SENSITIVE_KEYWORDS: Dict[str, str] = {
    "password": "critical",
    "passwd": "critical",
    "secret": "critical",
    "api_key": "critical",
    "apikey": "critical",
    "token": "critical",
    "auth_token": "critical",
    "auth_key": "critical",
    "auth_secret": "critical",
    "ssn": "critical",
    "credit_card": "critical",
    "creditcard": "critical",
    # "auth" alone is too broad — matches author, authorize, oauth, authentication_method, etc.
    # Only match whole-word or clear compound forms (auth_token, auth_key above).
    # email/phone as standalone exact names only (not email_template, phone_format, etc.)
    "user_email": "high",
    "user_phone": "high",
    "phone_number": "high",
    "email_address": "high",
}
# Variable names that are safe despite substring matches (LLM API params, OAuth fields)
SENSITIVE_BLOCKLIST: Set[str] = {
    "max_tokens", "min_tokens", "n_tokens", "num_tokens",
    "input_tokens", "output_tokens", "completion_tokens", "prompt_tokens",
    "expires_at", "expires_in", "issued_at",
    "all_messages",  # conversation history, not secrets
    # auth-adjacent but non-secret variables
    "auth_method", "auth_type", "auth_scheme", "auth_provider", "auth_url",
    "auth_endpoint", "auth_flow", "auth_header_name",
    # generic email/phone that are not PII secrets
    "email_template", "email_subject", "email_body", "email_count",
    "phone_format", "phone_mask",
}

# LLM sink patterns: (chain_pattern, sink_label)
# Specific multi-token patterns are matched directly; single-token generics require SINK_INDICATORS.
SINK_PATTERNS: List[tuple] = [
    (["openai", "chat", "completions", "create"], "OpenAI API"),
    (["client", "chat", "completions", "create"], "OpenAI API"),
    (["openai", "completion", "create"], "OpenAI API"),
    (["openai", "completions", "create"], "OpenAI API"),
    (["anthropic", "messages", "create"], "Anthropic API"),
    (["anthropic", "client", "messages", "create"], "Anthropic API"),
    (["cohere", "chat", "create"], "Cohere API"),
    (["cohere", "generate"], "Cohere API"),
    (["bedrock", "invoke_model"], "Bedrock API"),
    (["vertexai", "generate_content"], "VertexAI API"),
    (["generativeai", "generate_content"], "VertexAI API"),
    # Generic patterns — only matched when SINK_INDICATORS present in chain
    (["invoke"], "LangChain LLM invoke"),
    (["messages", "create"], "LLM API"),
    (["chat", "completions", "create"], "LLM API"),
    (["generate"], "LLM generate"),
    (["pipeline"], "Transformers pipeline"),
]
# Provider-specific names that confirm a generic call is an LLM sink.
# Removed "chain" and "index" — too common in non-LLM code (method chains, DB indexes, etc.)
SINK_INDICATORS = {
    "openai", "anthropic", "cohere", "vertexai", "bedrock", "mistral",
    "litellm", "llm", "langchain", "llamaindex", "llama_index",
    "completion", "completions", "messages", "chat_model",
}
# Sinks that send data to external AI providers (critical when secrets reach these)
EXTERNAL_PROVIDER_SINKS = {"OpenAI API", "Anthropic API", "Cohere API", "LLM API"}

# Secret source patterns: (chain_pattern, risk) - RHS of assign returns secret
SECRET_SOURCE_PATTERNS: List[tuple] = [
    (["os", "getenv"], "critical"),
    (["os", "environ", "get"], "critical"),
    (["os", "environ"], "critical"),
    (["environ", "get"], "critical"),
    (["dotenv", "load_dotenv"], "critical"),  # loads .env into os.environ
    (["python_dotenv", "load_dotenv"], "critical"),
    (["load_dotenv"], "critical"),
    (["get_secret_value"], "critical"),  # boto3 client('secretsmanager').get_secret_value
    (["yaml", "safe_load"], "critical"),
    (["yaml", "load"], "critical"),
    (["json", "load"], "critical"),  # when path suggests config - checked in _is_secret_source_call
]
SECRET_SOURCE_CHAINS = {"os", "getenv", "environ", "dotenv", "load_dotenv", "python_dotenv", "get_secret_value", "yaml", "json"}


def _var_contains_sensitive(name: str) -> Optional[str]:
    """Return risk level if variable name contains a sensitive keyword.

    Uses word-boundary matching on underscore-split tokens to avoid false positives
    like 'author' matching 'auth', or 'tokenizer' matching 'token'.
    """
    if name in SENSITIVE_BLOCKLIST:
        return None
    name_lower = name.lower()
    if name_lower in SENSITIVE_BLOCKLIST:
        return None
    # Split on underscores to get tokens (e.g. "user_api_key" -> ["user", "api", "key"])
    tokens = set(name_lower.replace("-", "_").split("_"))
    name_no_sep = name_lower.replace("_", "").replace("-", "")
    for kw, risk in SENSITIVE_KEYWORDS.items():
        kw_no_sep = kw.lower().replace("_", "").replace("-", "")
        kw_parts = kw.lower().replace("-", "_").split("_")
        if len(kw_parts) > 1:
            # Multi-token keyword (e.g. "api_key", "credit_card"): match as contiguous subsequence
            # of name tokens, so "my_api_key_value" matches but "apikey_manager" won't match "api_key"
            name_tokens_list = name_lower.replace("-", "_").split("_")
            n = len(kw_parts)
            if any(name_tokens_list[i:i + n] == kw_parts for i in range(len(name_tokens_list) - n + 1)):
                return risk
        else:
            # Single-token keyword: must be a whole token in the underscore-split name
            # "token" matches "access_token", "token_value" but NOT "tokenizer"
            if kw_no_sep in tokens:
                return risk
    return None



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
    chain = get_call_chain(node)
    chain_set = set(c.lower() for c in chain)
    # Single-token generic patterns that require a provider indicator in the chain
    _GENERIC_PATTERNS = {("invoke",), ("generate",), ("pipeline",)}
    for pattern, label in SINK_PATTERNS:
        if not _chain_matches(chain, pattern):
            continue
        if tuple(pattern) in _GENERIC_PATTERNS:
            if chain_set & SINK_INDICATORS:
                return label
        else:
            return label
    # Catch-all: .create() with explicit LLM provider in chain
    if "create" in chain_set and chain_set & {"openai", "anthropic", "cohere", "completions", "messages"}:
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


# External LLM providers: sink indicates data reaches external API
EXTERNAL_PROVIDER_SINKS = {"OpenAI API", "Anthropic API", "Cohere API", "LLM API"}


def _is_secret_source_call(node: ast.Call, file_path: str = "") -> bool:
    """Return True if call is a secret source (os.getenv, dotenv, boto3 secrets, config)."""
    chain = get_call_chain(node)
    chain_lower = ".".join(c.lower() for c in chain)
    fp_lower = file_path.lower()
    # os.environ, os.getenv, environ.get
    if "os.getenv" in chain_lower or "os.environ" in chain_lower or "environ.get" in chain_lower:
        return True
    # dotenv.load_dotenv, load_dotenv, python_dotenv
    if "load_dotenv" in chain_lower or "dotenv.load_dotenv" in chain_lower or "python_dotenv" in chain_lower:
        return True
    # boto3 client('secretsmanager').get_secret_value
    if "get_secret_value" in chain_lower:
        return True
    # yaml.safe_load, json.load when path suggests config
    if "yaml.safe_load" in chain_lower or "yaml.load" in chain_lower or "json.load" in chain_lower:
        if any(x in fp_lower for x in ("config", "env", ".yml", ".yaml", ".json", "settings")):
            return True
    return False


@dataclass
class SensitiveExposure:
    """Single sensitive variable exposure to LLM sink."""

    variable: str
    sink: str
    file: str
    line: Optional[int]
    risk: str  # "high" | "critical"
    external_provider: bool = False  # True when sink is OpenAI/Anthropic/Cohere

    def to_dict(self) -> dict:
        d = {
            "variable": self.variable,
            "sink": self.sink,
            "file": self.file,
            "line": self.line,
            "risk": self.risk,
        }
        if self.external_provider:
            d["external_provider"] = True
        return d


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
        refs = _names_in_expr(node.value)
        if refs & self.sensitive_vars:
            for t in targets:
                if t not in SENSITIVE_BLOCKLIST:
                    self.sensitive_vars.add(t)
        # When RHS is a secret source call, add targets to sensitive_vars
        if isinstance(node.value, ast.Call) and _is_secret_source_call(node.value, self.file_path):
            for t in targets:
                if t not in SENSITIVE_BLOCKLIST:
                    self.sensitive_vars.add(t)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        sink_label = _is_llm_sink(node)
        if sink_label:
            external = sink_label in EXTERNAL_PROVIDER_SINKS
            for arg in node.args:
                refs = _names_in_expr(arg)
                for r in refs:
                    if r in self.sensitive_vars and r not in SENSITIVE_BLOCKLIST:
                        risk = _var_contains_sensitive(r) or "high"
                        if external and risk == "critical":
                            pass  # severity stays critical
                        self.exposures.append(SensitiveExposure(
                            variable=r,
                            sink=sink_label,
                            file=self.file_path,
                            line=getattr(node, "lineno", None),
                            risk=risk,
                            external_provider=external,
                        ))
                        break
            for kw in node.keywords:
                refs = _names_in_expr(kw.value)
                for r in refs:
                    if r in self.sensitive_vars and r not in SENSITIVE_BLOCKLIST:
                        risk = _var_contains_sensitive(r) or "high"
                        if external and risk == "critical":
                            pass  # severity stays critical
                        self.exposures.append(SensitiveExposure(
                            variable=r,
                            sink=sink_label,
                            file=self.file_path,
                            line=getattr(node, "lineno", None),
                            risk=risk,
                            external_provider=external,
                        ))
                        break
        self.generic_visit(node)



def _scan_fstring_exposures(repo_root: Path) -> List[SensitiveExposure]:
    """
    Cross-module taint: scan f-strings for sensitive variable names embedded
    in string templates that are passed to LLM sinks.

    Catches patterns like:
        system_prompt = f"...{DB_PASSWORD}...{INTERNAL_API_KEY}..."
        client.messages.create(system=system_prompt, ...)

    where DB_PASSWORD is imported from config.py — invisible to intra-function analysis.
    """
    exposures: List[SensitiveExposure] = []

    for path in walk_python_files_local(repo_root):
        try:
            rel = str(path.relative_to(repo_root))
            source = path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source)
        except (SyntaxError, OSError, ValueError):
            continue

        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            # Look for assignments where the RHS is an f-string (JoinedStr)
            if not isinstance(node.value, ast.JoinedStr):
                continue
            # Collect variable names embedded in the f-string
            fstring_vars: Set[str] = set()
            for piece in ast.walk(node.value):
                if isinstance(piece, ast.Name):
                    fstring_vars.add(piece.id)
            # Check if any embedded var looks sensitive
            for var in fstring_vars:
                risk = _var_contains_sensitive(var)
                if not risk:
                    continue
                # Check if the assigned variable is used in an LLM call nearby
                # (heuristic: flag the f-string assignment itself as exposure)
                exposures.append(SensitiveExposure(
                    variable=var,
                    sink="f-string template (cross-module taint)",
                    file=rel,
                    line=getattr(node, "lineno", None),
                    risk=risk,
                    external_provider=True,
                ))
    return exposures


def walk_python_files_local(repo_root: Path):
    """Walk Python files, skipping common non-source dirs."""
    skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules",
                 ".tox", "dist", "build", "eggs", ".eggs", "site-packages"}
    for path in repo_root.rglob("*.py"):
        if any(part in skip_dirs for part in path.parts):
            continue
        yield path


def _scan_fstring_exposures(repo_root: Path) -> List[SensitiveExposure]:
    """
    Cross-module taint: scan f-strings for sensitive variable names embedded
    in string templates that are passed to LLM sinks.

    Catches patterns like:
        system_prompt = f"...{DB_PASSWORD}...{INTERNAL_API_KEY}..."
        client.messages.create(system=system_prompt, ...)

    where DB_PASSWORD is imported from config.py — invisible to intra-function analysis.
    """
    exposures: List[SensitiveExposure] = []

    for path in walk_python_files_local(repo_root):
        try:
            rel = str(path.relative_to(repo_root))
            source = path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source)
        except (SyntaxError, OSError, ValueError):
            continue

        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            # Look for assignments where the RHS is an f-string (JoinedStr)
            if not isinstance(node.value, ast.JoinedStr):
                continue
            # Collect variable names embedded in the f-string
            fstring_vars: Set[str] = set()
            for piece in ast.walk(node.value):
                if isinstance(piece, ast.Name):
                    fstring_vars.add(piece.id)
            # Check if any embedded var looks sensitive
            for var in fstring_vars:
                risk = _var_contains_sensitive(var)
                if not risk:
                    continue
                # Check if the assigned variable is used in an LLM call nearby
                # (heuristic: flag the f-string assignment itself as exposure)
                exposures.append(SensitiveExposure(
                    variable=var,
                    sink="f-string template (cross-module taint)",
                    file=rel,
                    line=getattr(node, "lineno", None),
                    risk=risk,
                    external_provider=True,
                ))
    return exposures


def walk_python_files_local(repo_root: Path):
    """Walk Python files, skipping common non-source dirs."""
    skip_dirs = {".git", "__pycache__", ".venv", "venv", "node_modules",
                 ".tox", "dist", "build", "eggs", ".eggs", "site-packages"}
    for path in repo_root.rglob("*.py"):
        if any(part in skip_dirs for part in path.parts):
            continue
        yield path


def analyze_sensitive_exposures(repo_root: Path) -> SensitiveExposureResult:
    """Analyze Python files for sensitive variables flowing into LLM sinks."""
    repo_root = Path(repo_root).resolve()
    # Include cross-module f-string taint findings
    all_exposures: List[SensitiveExposure] = _scan_fstring_exposures(repo_root)
    seen: Set[tuple] = set()

    for path in repo_root.rglob("*.py"):
        if path.suffix != ".py" or should_skip_path(path, repo_root):
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
