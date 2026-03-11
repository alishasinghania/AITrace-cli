"""
Modular architecture detectors for AITrace.

Each detector uses AST analysis and outputs structured results:
{
  "component": "RAG",
  "confidence": "high",
  "evidence": ["OpenAIEmbeddings", "Chroma vector store", "openai.ChatCompletion"]
}
"""

from .base import DetectionResult
from .rag_detector import detect_rag
from .agent_detector import detect_agents
from .mcp_detector import detect_mcp
from .huggingface_detector import detect_huggingface
from .shadow_ai_detector import detect_shadow_ai

__all__ = [
    "DetectionResult",
    "detect_rag",
    "detect_agents",
    "detect_mcp",
    "detect_huggingface",
    "detect_shadow_ai",
]
