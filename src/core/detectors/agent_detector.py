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

# LangChain / LangGraph – use specific patterns; avoid generic "invoke", "Agent", "Task"
LANGCHAIN_PATTERNS = {
    "create_react_agent", "create_agent", "AgentExecutor", "initialize_agent",
    "ConversationalAgent", "load_tools",
}
LANGGRAPH_PATTERNS = {
    "StateGraph", "StateGraphCompiled", "MessagesState", "langgraph",
}
# add_node/add_edge only when chain suggests LangGraph (not networkx)
LANGGRAPH_CHAIN_PATTERNS = {"add_node", "add_edge"}
LANGGRAPH_CHAIN_REQUIRED = {"langgraph", "langchain", "stategraph"}
# Semantic Kernel – avoid generic "Skill" alone (matches validate_skill_tree, etc.)
SEMANTIC_KERNEL_PATTERNS = {
    "Kernel", "KernelBuilder", "SemanticFunction", "SkillCollection",
    "OpenAIChatCompletion", "register_completion_service", "invoke_async",
    "create_semantic_function", "PromptTemplateConfig",
}
SEMANTIC_KERNEL_REQUIRED_FOR_SKILL = {"kernel", "semantic", "skill"}
# CrewAI – avoid generic "Agent", "Task", "Crew"; keep framework-specific
CREWAI_PATTERNS = {
    "CrewAgent", "crew", "kickoff", "create_crew", "create_agent",
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
    chain_str = ".".join(chain_lower)
    chain_set = set(chain_lower)
    # Skip obvious non-AI patterns
    if target.lower() in ("compile", "load", "read", "get", "find") and len(chain) <= 1:
        return None
    if "detect_" in target.lower() or "re." in chain_str:
        return None
    # Skip generic REST/API client patterns (api_instance, AgentApi, TaskRequestBody)
    if any(p in chain_str for p in ("api_instance", "api_client", "agentapi", "taskrequestbody")):
        return None
    # create_node: only LangGraph/StateGraph, not generic tree (tree.create_node)
    if "create_node" in target.lower():
        if not (chain_set & LANGGRAPH_CHAIN_REQUIRED):
            return None
    # add_node/add_edge: only LangGraph, not networkx (nx.add_node, nt.add_node)
    if _matches(target, LANGGRAPH_CHAIN_PATTERNS):
        if chain_set & LANGGRAPH_CHAIN_REQUIRED:
            return "LangGraph"
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
