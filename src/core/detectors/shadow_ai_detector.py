"""
Shadow AI detector – direct API calls to LLM providers.

Detects ungoverned, direct API usage (OpenAI, Anthropic, Cohere, etc.)
that may bypass central governance controls.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional, Set

from .base import DetectionResult
from ._ast_utils import get_call_target, get_call_target_chain, scan_ast

# Direct API patterns – SDK/API call chains
SHADOW_AI_PATTERNS = {
    # OpenAI
    "openai", "ChatCompletion", "Completion", "create", "chat", "Embedding",
    # Anthropic
    "anthropic", "messages", "Anthropic",
    # Cohere
    "cohere", "Cohere", "generate", "embed",
    # Vertex / Google
    "vertexai", "generativeai", "generate_content", "GenerativeModel",
    # AWS Bedrock
    "bedrock", "BedrockRuntime", "invoke_model",
    # Mistral
    "mistral", "Mistral",
    # LiteLLM (proxy – still direct usage)
    "litellm", "completion",
    # Generic
    "client", "Client",
}
# Module/import level
PROVIDER_MODULES = {"openai", "anthropic", "cohere", "google.generativeai", "vertexai"}


def _norm(s: str) -> str:
    return s.lower().replace("-", "_").replace(" ", "_")


def _matches(target: str, patterns: Set[str]) -> bool:
    t = _norm(target)
    return any(t.startswith(_norm(p)) or _norm(p) in t for p in patterns)


def _is_direct_api_call(chain: List[str]) -> bool:
    """Heuristic: chain contains provider name + API method."""
    chain_lower = [c.lower() for c in chain]
    if "openai" in chain_lower or "anthropic" in chain_lower or "cohere" in chain_lower:
        return True
    if "vertexai" in chain_lower or "generativeai" in chain_lower:
        return True
    if "bedrock" in chain_lower or "mistral" in chain_lower:
        return True
    return False


def detect_shadow_ai(repo_root: Path) -> DetectionResult:
    """
    Detect Shadow AI – direct API calls to LLM providers.
    Returns structured result with component, confidence, evidence.
    """
    evidence: List[str] = []
    seen: Set[str] = set()

    def visit(call: ast.Call, file_path: str, line: Optional[int]) -> None:
        target = get_call_target(call)
        if not target:
            return
        chain = get_call_target_chain(call)
        full = ".".join(chain) if chain else target

        if not _matches(target, SHADOW_AI_PATTERNS):
            return
        if full in seen:
            return
        if not _is_direct_api_call(chain) and not _matches(target, {"create", "chat", "complete", "messages", "invoke_model"}):
            return

        seen.add(full)
        loc = f" ({file_path}:{line})" if line else f" ({file_path})"
        evidence.append(f"{full}{loc}")

    scan_ast(repo_root, visit)

    if not evidence:
        return DetectionResult(
            component="Shadow AI",
            confidence="low",
            evidence=[],
            details={"detected": False},
        )

    confidence = "high" if len(evidence) >= 2 else "medium"
    return DetectionResult(
        component="Shadow AI",
        confidence=confidence,
        evidence=evidence[:10],
        details={"detected": True, "direct_api_calls": len(evidence)},
    )
