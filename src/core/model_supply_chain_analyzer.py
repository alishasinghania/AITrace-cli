"""
AI Model Supply Chain Risk Analyzer for AITrace.

Detects where AI models are downloaded or loaded from external sources
and flags risks from unknown organizations, external URLs, etc.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Set, Tuple

from .detectors._ast_utils import should_skip_path

# Model loading patterns: (chain_pattern, arg_name_for_model_id, source_label)
# arg_name: "0" = first positional arg, or keyword name like "repo_id"
MODEL_LOAD_PATTERNS: List[Tuple[List[str], str, str]] = [
    (["from_pretrained"], "0", "huggingface"),
    (["hf_hub_download"], "repo_id", "huggingface"),
    (["hf_hub_download"], "0", "huggingface"),
    (["snapshot_download"], "repo_id", "huggingface"),
    (["snapshot_download"], "0", "huggingface"),
    (["HfApi", "download"], "repo_id", "huggingface"),
    (["huggingface_hub", "hf_hub_download"], "repo_id", "huggingface"),
    (["torch", "load"], "0", "torch"),
    (["safetensors", "torch", "load_file"], "0", "safetensors"),
    (["load_file"], "0", "safetensors"),
    (["download_model"], "0", "generic"),
    (["load_model"], "0", "generic"),
]

# Known trustworthy HuggingFace orgs (lower risk)
KNOWN_HF_ORGS = {"facebook", "meta-ai", "google", "microsoft", "openai", "anthropic", "stabilityai", "runwayml", "bigscience", "huggingface", "bert", "t5", "gpt2", "roberta", "distilbert", "albert", "electra", "deberta"}

# URL patterns for classification
URL_PATTERNS = {
    "huggingface": re.compile(r"huggingface\.co|hf\.co", re.I),
    "github": re.compile(r"github\.com|raw\.githubusercontent", re.I),
    "s3": re.compile(r"s3://|s3\.amazonaws|\.s3\.", re.I),
    "http": re.compile(r"^https?://", re.I),
    "gcs": re.compile(r"storage\.googleapis|gs://", re.I),
}


def _get_call_chain(node: ast.Call) -> List[str]:
    chain: List[str] = []
    n = node.func
    while isinstance(n, ast.Attribute):
        chain.append(n.attr)
        n = n.value
    if isinstance(n, ast.Name):
        chain.append(n.id)
    return list(reversed(chain))


def _chain_matches(chain: List[str], pattern: List[str]) -> bool:
    chain_lower = [c.lower() for c in chain]
    pat_lower = [p.lower() for p in pattern]
    if len(pat_lower) > len(chain_lower):
        return False
    for i in range(len(chain_lower) - len(pat_lower) + 1):
        if chain_lower[i : i + len(pat_lower)] == pat_lower:
            return True
    return False


def _extract_strings_from(node: ast.expr) -> List[str]:
    """Extract string literals from an expression."""
    out: List[str] = []
    for n in ast.walk(node):
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            out.append(n.value)
    return out


def _get_model_id_from_call(node: ast.Call, arg_spec: str) -> List[str]:
    """Extract model id/url from call args. arg_spec: '0' for first positional, or keyword name."""
    ids: List[str] = []
    if arg_spec.isdigit():
        idx = int(arg_spec)
        if idx < len(node.args):
            ids = _extract_strings_from(node.args[idx])
    else:
        for kw in node.keywords:
            if kw.arg == arg_spec:
                ids = _extract_strings_from(kw.value)
                break
    return ids


def _classify_source(model_id: str) -> Tuple[str, str]:
    """
    Classify model source and return (source_type, risk).
    risk: low, medium, high
    """
    model_id_lower = model_id.lower().strip()
    if not model_id_lower:
        return ("unknown", "medium")

    # URL-based classification
    for name, pat in URL_PATTERNS.items():
        if pat.search(model_id_lower):
            if name == "huggingface":
                return ("huggingface", "medium")
            if name == "github":
                return ("github", "high")
            if name in ("s3", "gcs"):
                return (name, "high")
            if name == "http":
                return ("external_url", "high")

    # HuggingFace model ID format: org/model-name or just model-name
    if "/" in model_id and ":" not in model_id and not model_id.startswith(("http", "/", ".")):
        org = model_id.split("/")[0].lower()
        if org in KNOWN_HF_ORGS:
            return ("huggingface", "low")
        return ("huggingface", "medium")  # Unknown org on HF

    # Single name (no slash) - could be local or HF
    if model_id_lower in KNOWN_HF_ORGS or model_id_lower in {"bert", "gpt2", "t5", "roberta"}:
        return ("huggingface", "low")
    return ("unknown", "medium")


@dataclass
class ModelSource:
    """Single model source detection."""

    model: str
    source: str
    risk: str
    file: str
    line: Optional[int] = None
    loader: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "model": self.model,
            "source": self.source,
            "risk": self.risk,
            "file": self.file,
            "line": self.line,
            "loader": self.loader,
        }


@dataclass
class ModelSupplyChainResult:
    """Result of model supply chain analysis."""

    model_sources: List[ModelSource] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "model_sources": [m.to_dict() for m in self.model_sources],
        }


class _ModelLoadVisitor(ast.NodeVisitor):
    """Finds model loading calls and extracts source identifiers."""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.sources: List[ModelSource] = []

    def visit_Call(self, node: ast.Call) -> None:
        chain = _get_call_chain(node)
        chain_lower = [c.lower() for c in chain]

        for pattern, arg_spec, source_label in MODEL_LOAD_PATTERNS:
            if not _chain_matches(chain, pattern):
                continue

            model_ids = _get_model_id_from_call(node, arg_spec)
            loader = ".".join(chain) if chain else ""

            for mid in model_ids:
                if not mid or len(mid) > 500:
                    continue
                src_type, risk = _classify_source(mid)
                self.sources.append(ModelSource(
                    model=mid,
                    source=src_type,
                    risk=risk,
                    file=self.file_path,
                    line=getattr(node, "lineno", None),
                    loader=loader,
                ))
            break  # One pattern per call
        self.generic_visit(node)


def _should_skip(path: Path, repo_root: Path) -> bool:
    if should_skip_path(path, repo_root):
        return True
    try:
        rel = path.relative_to(repo_root)
    except ValueError:
        return True
    if "core" in rel.parts and "model_supply_chain_analyzer" in rel.parts:
        return True
    return False


def analyze_model_supply_chain(repo_root: Path) -> ModelSupplyChainResult:
    """Analyze Python files for model loading from external sources."""
    repo_root = Path(repo_root).resolve()
    all_sources: List[ModelSource] = []
    seen: Set[Tuple[str, str, Optional[int]]] = set()

    for path in repo_root.rglob("*.py"):
        if path.suffix != ".py" or _should_skip(path, repo_root):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"))
        except (SyntaxError, OSError):
            continue

        rel_path = str(path.relative_to(repo_root))
        visitor = _ModelLoadVisitor(rel_path)
        visitor.visit(tree)

        for m in visitor.sources:
            key = (m.model, m.file, m.line)
            if key not in seen:
                seen.add(key)
                all_sources.append(m)

    return ModelSupplyChainResult(model_sources=all_sources)
