"""
RAG (Retrieval Augmented Generation) architecture detector.

Uses AST analysis to detect:
- Embedding models (OpenAI, Cohere, Voyage, etc.)
- Vector stores (Chroma, Pinecone, Weaviate, Qdrant, FAISS)
- Retrieval patterns (similarity_search, as_retriever)
- LLM inference calls
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional, Set

from .base import DetectionResult
from ._ast_utils import get_call_target, get_call_target_chain, scan_ast

# Exclude generic "encode" (str.encode, base64.b64encode) — use embedding-specific patterns
EMBEDDING_PATTERNS = {
    "embed", "get_embedding", "embedding", "embeddings", "embed_documents",
    "embed_query", "embed_text", "encode_documents",
    "OpenAIEmbeddings", "CohereEmbeddings", "VoyageEmbeddings",
    "HuggingFaceEmbeddings", "VertexAIEmbeddings", "BedrockEmbeddings",
}
VECTOR_STORE_PATTERNS = {
    "Chroma", "chromadb", "Pinecone", "Weaviate", "Qdrant", "FAISS",
    "Milvus", "ElasticsearchStore", "from_documents", "from_texts",
    "add_documents", "add_texts", "VectorStore", "ChromaVectorStore",
}
RETRIEVAL_PATTERNS = {
    "similarity_search", "as_retriever", "max_marginal_relevance",
    "Retriever", "retrieve", "VectorStoreRetriever",
}
LLM_PATTERNS = {
    "chat", "complete", "create", "invoke", "generate", "messages",
    "ChatOpenAI", "ChatAnthropic", "ChatVertexAI", "BedrockChat",
    "OpenAI", "Anthropic", "Cohere", "openai", "anthropic", "vertexai",
}
# Chain must contain a known LLM provider to avoid matching generic create/invoke
LLM_CHAIN_KEYWORDS = {"openai", "anthropic", "cohere", "vertexai", "generativeai", "bedrock", "mistral", "litellm", "chat", "completion", "messages"}
# Embedding evidence: require provider or known embedding class (exclude internal helpers)
EMBEDDING_CHAIN_KEYWORDS = {"openai", "cohere", "voyage", "vertexai", "bedrock", "huggingface", "embedding", "embed", "from_pretrained"}
EMBEDDING_EVIDENCE_BLOCKLIST = {"kwargs", "retry", "_get_", "_create_", "response", "modelresponse"}


def _norm(s: str) -> str:
    return s.lower().replace("-", "_").replace(" ", "_")


def _matches(target: str, patterns: Set[str]) -> bool:
    t = _norm(target)
    return any(t.startswith(_norm(p)) or _norm(p) in t for p in patterns)


def detect_rag(repo_root: Path) -> DetectionResult:
    """
    Detect RAG architecture via AST analysis.
    Returns structured result with component, confidence, evidence.
    """
    evidence: List[str] = []
    seen: Set[str] = set()
    embeddings: List[str] = []
    vector_stores: List[str] = []
    retrievals: List[str] = []
    llms: List[str] = []

    def visit(call: ast.Call, file_path: str, line: Optional[int]) -> None:
        target = get_call_target(call)
        if not target:
            return
        chain = get_call_target_chain(call)
        full = ".".join(chain) if chain else target

        if _matches(target, EMBEDDING_PATTERNS) and full not in seen:
            full_lower = full.lower()
            if not any(bl in full_lower for bl in EMBEDDING_EVIDENCE_BLOCKLIST):
                chain_str = ".".join(c.lower() for c in chain)
                if any(kw in chain_str for kw in EMBEDDING_CHAIN_KEYWORDS):
                    seen.add(full)
                    embeddings.append(full)
        elif _matches(target, VECTOR_STORE_PATTERNS) and full not in seen:
            seen.add(full)
            vector_stores.append(full)
        elif _matches(target, RETRIEVAL_PATTERNS) and full not in seen:
            seen.add(full)
            retrievals.append(full)
        elif _matches(target, LLM_PATTERNS) and full not in seen:
            chain_lower = set(c.lower() for c in chain)
            if chain_lower & LLM_CHAIN_KEYWORDS:
                seen.add(full)
                llms.append(full)

    scan_ast(repo_root, visit)

    # Build evidence list
    for e in embeddings[:3]:
        evidence.append(e)
    for v in vector_stores[:3]:
        evidence.append(f"{v} vector store")
    for r in retrievals[:2]:
        evidence.append(r)
    for l in llms[:3]:
        evidence.append(l)

    # RAG requires embedding + vector store + LLM
    has_embed = bool(embeddings)
    has_vector = bool(vector_stores)
    has_retrieval = bool(retrievals)
    has_llm = bool(llms)

    if has_embed and has_vector and has_llm:
        confidence = "high" if (has_retrieval and len(evidence) >= 4) else "medium"
        return DetectionResult(
            component="RAG",
            confidence=confidence,
            evidence=evidence or ["RAG pattern inferred from components"],
            details={
                "detected": True,
                "embeddings": embeddings,
                "vector_stores": vector_stores,
                "llms": llms,
            },
        )
    if (has_embed or has_vector) and has_llm:
        return DetectionResult(
            component="RAG",
            confidence="low",
            evidence=evidence or ["Partial RAG pattern (embedding/vector + LLM)"],
            details={
                "detected": True,
                "embeddings": embeddings,
                "vector_stores": vector_stores,
                "llms": llms,
            },
        )

    return DetectionResult(
        component="RAG",
        confidence="low",
        evidence=[],
        details={"detected": False},
    )
