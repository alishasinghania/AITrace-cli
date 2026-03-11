"""
AI Agents architecture detector.

Uses AST analysis to detect LangChain, LangGraph, Semantic Kernel, CrewAI, AutoGen patterns.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import List, Optional, Set

from .base import DetectionResult
from ._ast_utils import get_call_target, get_call_target_chain, scan_ast

# LangChain / LangGraph
LANGCHAIN_PATTERNS = {
    "create_react_agent", "create_agent", "AgentExecutor", "initialize_agent",
    "ConversationalAgent", "Tool", "load_tools",
}
LANGGRAPH_PATTERNS = {
    "StateGraph", "StateGraphCompiled", "MessagesState", "add_node",
    "add_edge", "invoke", "langgraph",
}
# Semantic Kernel
SEMANTIC_KERNEL_PATTERNS = {
    "Kernel", "KernelBuilder", "SemanticFunction", "Skill", "SkillCollection",
    "OpenAIChatCompletion", "register_completion_service", "invoke_async",
    "create_semantic_function", "PromptTemplateConfig",
}
# CrewAI
CREWAI_PATTERNS = {
    "CrewAgent", "Crew", "Agent", "Task", "CrewAgent", "crew", "kickoff",
    "create_crew", "create_agent",
}
# AutoGen
AUTOGEN_PATTERNS = {
    "AssistantAgent", "UserProxyAgent", "ConversableAgent", "GroupChat",
    "GroupChatManager", "register_for_llm", "register_for_execution",
}
# Generic
AGENT_PATTERNS = (
    LANGCHAIN_PATTERNS | LANGGRAPH_PATTERNS | SEMANTIC_KERNEL_PATTERNS
    | CREWAI_PATTERNS | AUTOGEN_PATTERNS
)


def _norm(s: str) -> str:
    return s.lower().replace("-", "_").replace(" ", "_")


def _matches(target: str, patterns: Set[str]) -> bool:
    t = _norm(target)
    return any(t.startswith(_norm(p)) or _norm(p) in t for p in patterns)


def _classify(target: str, chain: List[str]) -> Optional[str]:
    """Return framework name if target matches."""
    chain_lower = [c.lower() for c in chain]
    # Skip obvious non-AI patterns
    if target.lower() in ("compile", "load", "read", "get", "find") and len(chain) <= 1:
        return None
    if "detect_" in target.lower() or "re." in ".".join(chain_lower):
        return None
    if _matches(target, LANGGRAPH_PATTERNS):
        return "LangGraph"
    if _matches(target, SEMANTIC_KERNEL_PATTERNS):
        return "Semantic Kernel"
    if _matches(target, CREWAI_PATTERNS):
        return "CrewAI"
    if _matches(target, AUTOGEN_PATTERNS):
        return "AutoGen"
    if _matches(target, LANGCHAIN_PATTERNS):
        return "LangChain"
    return None


def detect_agents(repo_root: Path) -> DetectionResult:
    """
    Detect AI agent frameworks via AST analysis.
    Returns structured result with component, confidence, evidence.
    """
    evidence: List[str] = []
    seen: Set[str] = set()
    frameworks: List[str] = []

    def visit(call: ast.Call, file_path: str, line: Optional[int]) -> None:
        target = get_call_target(call)
        if not target:
            return
        chain = get_call_target_chain(call)
        full = ".".join(chain) if chain else target

        fw = _classify(target, chain)
        if fw and full not in seen:
            seen.add(full)
            frameworks.append(fw)
            evidence.append(full)

    scan_ast(repo_root, visit)

    if not evidence:
        return DetectionResult(
            component="AI Agents",
            confidence="low",
            evidence=[],
            details={"detected": False},
        )

    unique_frameworks = list(dict.fromkeys(frameworks))
    confidence = "high" if len(unique_frameworks) >= 2 or len(evidence) >= 3 else "medium"
    return DetectionResult(
        component="AI Agents",
        confidence=confidence,
        evidence=evidence[:8],
        details={
            "detected": True,
            "frameworks": unique_frameworks,
        },
    )
