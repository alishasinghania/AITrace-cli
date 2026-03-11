"""
AI architecture pattern detection for AITrace.

Infers high-level architecture types from structured scan results:
- RAG (Retrieval Augmented Generation)
- AI Agents
- Direct LLM inference
- Embedding pipelines
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

# ---------------------------------------------------------------------------
# Package / component mappings for classification (extensible)
# ---------------------------------------------------------------------------

EMBEDDING_PROVIDERS: Set[str] = {
    "openai",
    "cohere",
    "vertexai",
    "voyage",
    "voyageai",
    "bedrock",
    "huggingface",
    "sentence-transformers",
    "instructor",
}

VECTOR_STORES: Set[str] = {
    "chromadb",
    "chroma",
    "pinecone",
    "weaviate",
    "qdrant",
    "milvus",
    "faiss",
    "elasticsearch",
    "vertex_ai_vector_search",
    "pgvector",
    "lance",
}

INFERENCE_PROVIDERS: Set[str] = {
    "openai",
    "anthropic",
    "cohere",
    "mistral",
    "mistralai",
    "vertexai",
    "generativeai",
    "transformers",
    "litellm",
    "llama",
}

AGENT_FRAMEWORKS: Set[str] = {
    "langgraph",
    "crewai",
    "autogen",
    "semantic_kernel",
    "semantic-kernel",
    "haystack",
}


@dataclass
class ScanInput:
    """Structured input for architecture detection."""

    frameworks: List[str] = field(default_factory=list)
    embeddings: List[str] = field(default_factory=list)
    vector_stores: List[str] = field(default_factory=list)
    inference_calls: List[str] = field(default_factory=list)
    agent_frameworks: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "frameworks": self.frameworks,
            "embeddings": self.embeddings,
            "vector_stores": self.vector_stores,
            "inference_calls": self.inference_calls,
            "agent_frameworks": self.agent_frameworks,
        }


@dataclass
class ArchitectureResult:
    """Result of architecture detection."""

    architecture_types: List[str]
    components: List[str]
    confidence: str  # "high" | "medium" | "low"
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "architecture_types": self.architecture_types,
            "architecture_type": self.architecture_types[0] if self.architecture_types else "unknown",
            "components": self.components,
            "confidence": self.confidence,
            "details": self.details,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


# ---------------------------------------------------------------------------
# Detection logic (extensible pattern matchers)
# ---------------------------------------------------------------------------


def _normalize(name: str) -> str:
    return name.lower().replace("-", "_").replace(" ", "_")


def _has_any(detected: List[str], known: Set[str]) -> bool:
    return any(_normalize(d) in known or any(_normalize(d) in k for k in known) for d in detected)


def _detect_rag(scan: ScanInput) -> Optional[tuple[List[str], str]]:
    """
    RAG: embeddings + vector store + inference.
    Returns (components, confidence) or None if not RAG.
    """
    has_embed = bool(scan.embeddings) or _has_any(scan.frameworks, EMBEDDING_PROVIDERS)
    has_vector = bool(scan.vector_stores) or _has_any(scan.frameworks, VECTOR_STORES)
    has_inference = bool(scan.inference_calls) or _has_any(scan.frameworks, INFERENCE_PROVIDERS)
    if has_embed and has_vector and has_inference:
        components = ["embedding_model", "vector_database", "retrieval", "llm_inference"]
        confidence = "high" if (scan.embeddings and scan.vector_stores and scan.inference_calls) else "medium"
        return (components, confidence)
    return None


def _detect_agents(scan: ScanInput) -> Optional[tuple[List[str], str]]:
    """
    AI Agents: semantic_kernel, langgraph, crewai, etc.
    """
    if not scan.agent_frameworks and not _has_any(scan.frameworks, AGENT_FRAMEWORKS):
        return None
    components = ["agent_orchestrator", "tools", "llm_inference"]
    confidence = "high" if scan.agent_frameworks else "medium"
    return (components, confidence)


def _detect_embedding_pipeline(scan: ScanInput) -> Optional[tuple[List[str], str]]:
    """
    Embedding pipeline: embeddings + optional vector store, no inference.
    """
    has_embed = bool(scan.embeddings) or _has_any(scan.frameworks, EMBEDDING_PROVIDERS)
    has_vector = bool(scan.vector_stores) or _has_any(scan.frameworks, VECTOR_STORES)
    has_inference = bool(scan.inference_calls) or _has_any(scan.frameworks, INFERENCE_PROVIDERS)
    if has_embed and not has_inference:
        components = ["embedding_model"]
        if has_vector:
            components.extend(["vector_database", "indexing"])
        confidence = "high" if scan.embeddings else "medium"
        return (components, confidence)
    return None


def _detect_direct_llm(scan: ScanInput) -> Optional[tuple[List[str], str]]:
    """
    Direct LLM: inference calls only, no RAG or agents.
    """
    has_inference = bool(scan.inference_calls) or _has_any(scan.frameworks, INFERENCE_PROVIDERS)
    if not has_inference:
        return None
    components = ["llm_inference"]
    confidence = "high" if scan.inference_calls else "medium"
    return (components, confidence)


# Registry of architecture detectors (extensible)
ARCHITECTURE_DETECTORS = [
    ("RAG", _detect_rag, 1),  # priority 1 (highest)
    ("AI Agents", _detect_agents, 2),
    ("Embedding Pipeline", _detect_embedding_pipeline, 3),
    ("Direct LLM Inference", _detect_direct_llm, 4),
]


def detect_architecture(scan: ScanInput) -> ArchitectureResult:
    """
    Infer AI architecture pattern(s) from structured scan results.

    Args:
        scan: ScanInput with frameworks, embeddings, vector_stores,
              inference_calls, agent_frameworks.

    Returns:
        ArchitectureResult with architecture_types, components, confidence.
        May return multiple architecture types (e.g., RAG + Agents).
        Prefers specific patterns (RAG, Agents) over generic (Direct LLM).
    """
    architecture_types: List[str] = []
    all_components: List[str] = []
    confidences: List[str] = []
    details: Dict[str, Any] = {}
    detected_rag = False
    detected_agents = False

    for arch_name, detector_fn, _ in sorted(ARCHITECTURE_DETECTORS, key=lambda x: x[2]):
        result = detector_fn(scan)
        if result is None:
            continue
        components, confidence = result
        if arch_name == "RAG":
            detected_rag = True
        elif arch_name == "AI Agents":
            detected_agents = True
        elif arch_name == "Direct LLM Inference":
            if detected_rag or detected_agents:
                continue
        elif arch_name == "Embedding Pipeline":
            if detected_rag:
                continue
        architecture_types.append(arch_name)
        for c in components:
            if c not in all_components:
                all_components.append(c)
        confidences.append(confidence)
        details[arch_name] = {"components": components, "confidence": confidence}

    overall_confidence = "high" if "high" in confidences else ("medium" if confidences else "low")

    return ArchitectureResult(
        architecture_types=architecture_types or ["Unknown"],
        components=all_components or [],
        confidence=overall_confidence,
        details=details,
    )


def scan_from_aibom(
    components: List[Any],
    agent_frameworks: List[str],
    findings: Optional[List[Any]] = None,
) -> ScanInput:
    """
    Build ScanInput from AITrace AIBOM and findings.
    Use when integrating with existing AITrace scan results.
    """
    framework_names = [c.name for c in components] if components else []
    norm_frameworks = [_normalize(n) for n in framework_names]

    embeddings: List[str] = []
    for n in norm_frameworks:
        if n in EMBEDDING_PROVIDERS or "embed" in n or "voyage" in n:
            embeddings.append(n)

    vector_stores_list: List[str] = []
    for n in norm_frameworks:
        if n in VECTOR_STORES or "chroma" in n or "pinecone" in n or "qdrant" in n or "weaviate" in n or "faiss" in n:
            vector_stores_list.append(n)

    inference_list: List[str] = []
    if findings:
        for f in findings:
            if getattr(f, "tags", None) and "inference-call" in f.tags:
                title = getattr(f, "title", "") or ""
                if "inference call detected:" in title.lower():
                    part = title.split("inference call detected:")[-1].strip().split()[0]
                    if part not in inference_list:
                        inference_list.append(part)
    for n in norm_frameworks:
        if n in INFERENCE_PROVIDERS and n not in inference_list:
            inference_list.append(n)

    return ScanInput(
        frameworks=framework_names,
        embeddings=list(dict.fromkeys(embeddings)),
        vector_stores=list(dict.fromkeys(vector_stores_list)),
        inference_calls=list(dict.fromkeys(inference_list)),
        agent_frameworks=list(agent_frameworks) if agent_frameworks else [],
    )

