"""
Provider usage summarization for AI inference call detections.

Groups detections by AI provider and produces a compact summary
with counts and example file locations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

# Map raw provider identifiers (from code) to display names
PROVIDER_DISPLAY_NAMES: Dict[str, str] = {
    "openai": "OpenAI",
    "anthropic": "Anthropic",
    "cohere": "Cohere",
    "mistral": "Mistral",
    "mistralai": "Mistral",
    "vertexai": "Vertex AI",
    "generativeai": "Google Generative AI",
    "huggingface": "Hugging Face",
    "transformers": "Hugging Face",
    "client": "Client (generic)",  # openai.Client, anthropic.Client - ambiguous
}

# Order for display (known providers first)
PROVIDER_ORDER = (
    "openai",
    "anthropic",
    "cohere",
    "mistral",
    "mistralai",
    "vertexai",
    "generativeai",
    "huggingface",
    "transformers",
    "client",
)


@dataclass
class ProviderSummary:
    """Summary for a single AI provider."""

    provider: str
    display_name: str
    count: int
    example_files: List[str] = field(default_factory=list)


def _infer_provider_from_finding(finding: Any) -> str | None:
    """
    Extract provider identifier from a Finding (inference call or agent pattern).
    Returns None if not an inference/agent detection.
    """
    from ..models import FindingCategory

    # Only consider semantic findings (inference calls, agent patterns)
    cat = getattr(finding, "category", None)
    if cat is not None and cat != FindingCategory.SEMANTIC:
        return None
    title = getattr(finding, "title", "") or ""
    description = getattr(finding, "description", "") or ""
    text = f"{title} {description}".lower()
    # Extract from "Model inference call detected: openai" -> openai
    if "inference call detected:" in text:
        part = text.split("inference call detected:")[-1].strip().split()[0].lower()
        if part in PROVIDER_DISPLAY_NAMES or part in PROVIDER_ORDER:
            return part
    for key in PROVIDER_ORDER:
        if key in text:
            return key
    return None


def findings_to_detections(findings: List[Any]) -> List[Dict[str, str]]:
    """
    Convert Finding objects to detection dicts {provider, file}.
    Only includes inference-call findings with identifiable providers.
    """
    detections: List[Dict[str, str]] = []
    for f in findings:
        tags = getattr(f, "tags", []) or []
        if "inference-call" not in tags:
            continue
        provider = _infer_provider_from_finding(f)
        if not provider:
            continue
        file_path = None
        if getattr(f, "evidence", None):
            ev = f.evidence[0] if f.evidence else None
            if ev:
                file_path = getattr(ev, "file", None)
        if file_path:
            detections.append({"provider": provider, "file": file_path})
    return detections


def summarize_providers(detections: List[Dict[str, str]]) -> List[ProviderSummary]:
    """
    Group detections by AI provider and produce a summary.

    Args:
        detections: List of dicts with keys "provider" and "file".
                    Example: [{"provider": "openai", "file": "a.py"}, ...]

    Returns:
        List of ProviderSummary, sorted by count descending, then by provider order.
        Each summary has: provider, display_name, count, example_files (up to 3).
    """
    by_provider: Dict[str, List[str]] = {}
    for d in detections:
        provider = (d.get("provider") or "").lower().strip()
        file_path = (d.get("file") or "").strip()
        if not provider or not file_path:
            continue
        if provider not in by_provider:
            by_provider[provider] = []
        by_provider[provider].append(file_path)

    summaries: List[ProviderSummary] = []
    for provider, files in by_provider.items():
        display_name = PROVIDER_DISPLAY_NAMES.get(provider, provider.replace("_", " ").title())
        # Dedupe files (same file, multiple calls)
        unique_files = list(dict.fromkeys(files))
        example_files = unique_files[:3]
        summaries.append(
            ProviderSummary(
                provider=provider,
                display_name=display_name,
                count=len(files),
                example_files=example_files,
            )
        )

    # Sort: by count descending, then by provider order
    def sort_key(s: ProviderSummary) -> tuple:
        order_idx = next((i for i, p in enumerate(PROVIDER_ORDER) if p == s.provider), 999)
        return (-s.count, order_idx)

    summaries.sort(key=sort_key)
    return summaries
