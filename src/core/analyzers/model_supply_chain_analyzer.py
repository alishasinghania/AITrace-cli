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
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from ..utils.ast_utils import should_skip_path, get_call_chain

# Model loading patterns: (chain_pattern, arg_name_for_model_id, source_label)
# arg_name: "0" = first positional arg, or keyword name like "repo_id"
MODEL_LOAD_PATTERNS: List[Tuple[List[str], str, str]] = [
    # HuggingFace — highly specific, low false-positive risk
    (["from_pretrained"], "0", "huggingface"),
    (["hf_hub_download"], "repo_id", "huggingface"),
    (["hf_hub_download"], "0", "huggingface"),
    (["snapshot_download"], "repo_id", "huggingface"),
    (["snapshot_download"], "0", "huggingface"),
    (["HfApi", "download"], "repo_id", "huggingface"),
    (["huggingface_hub", "hf_hub_download"], "repo_id", "huggingface"),
    # PyTorch — require "torch" in chain so bare load_file() doesn't match
    (["torch", "load"], "0", "torch"),
    # safetensors — require library prefix; bare load_file() is too generic
    (["safetensors", "torch", "load_file"], "0", "safetensors"),
    (["safetensors", "load_file"], "0", "safetensors"),
    # Generic loaders — require AI-library prefix to avoid false positives on
    # audio loaders, sklearn joblib, image loaders, etc.
    (["ollama", "download_model"], "0", "generic"),
    (["llm", "download_model"], "0", "generic"),
    (["transformers", "load_model"], "0", "generic"),
    (["diffusers", "load_model"], "0", "generic"),
]

# Trusted model organizations (low risk when org/model format)
# Includes common HuggingFace org names (e.g. meta-ai for Meta AI models)
TRUSTED_MODEL_ORGS: FrozenSet[str] = frozenset({
    "google", "facebook", "meta", "meta-ai", "microsoft", "salesforce", "huggingface",
})

# Clearly not model IDs — variable placeholders, class names, test fixtures
MODEL_ID_BLOCKLIST = {
    "fileheader", "model_name", "modelloader",
    # common placeholder strings in examples/tests
    "your-model-here", "your_model", "model_id", "model-id",
    "path/to/model", "/path/to/model", "./model", "../model",
    "<model>", "<model_id>", "model_name_here",
    # non-AI model identifiers
    "3d", "cad", "mesh",
}

# URL patterns for classification
URL_PATTERNS = {
    "huggingface": re.compile(r"huggingface\.co|hf\.co", re.I),
    "github": re.compile(r"github\.com|raw\.githubusercontent", re.I),
    "s3": re.compile(r"s3://|s3\.amazonaws|\.s3\.", re.I),
    "http": re.compile(r"^https?://", re.I),
    "gcs": re.compile(r"storage\.googleapis|gs://", re.I),
}



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


def _load_trusted_orgs_from_policy(policy_path: Optional[Path]) -> Tuple[Set[str], Set[str]]:
    """
    Load trusted_orgs and verified_orgs from policy.yaml.
    Returns (trusted_orgs, verified_orgs) as lowercase sets.
    """
    trusted: Set[str] = set()
    verified: Set[str] = set()
    if not policy_path or not policy_path.exists():
        return trusted, verified
    try:
        import yaml
        raw = yaml.safe_load(policy_path.read_text(encoding="utf-8")) or {}
    except Exception:
        return trusted, verified
    model_sources = raw.get("model_sources")
    if not isinstance(model_sources, dict):
        return trusted, verified
    for item in (model_sources.get("trusted_orgs") or []):
        if isinstance(item, str) and item.strip():
            trusted.add(item.strip().lower())
    for item in (model_sources.get("verified_orgs") or []):
        if isinstance(item, str) and item.strip():
            verified.add(item.strip().lower())
    return trusted, verified


def _extract_hf_org(model_id: str) -> Optional[str]:
    """Extract org from HuggingFace model ID (org/model-name) or HF URL path."""
    model_id = model_id.strip()
    if not model_id:
        return None
    # HF URL: https://huggingface.co/org/model or hf.co/org/model
    if "huggingface.co/" in model_id.lower() or "hf.co/" in model_id.lower():
        parts = re.split(r"[/?#]", model_id, flags=re.I)
        for i, p in enumerate(parts):
            if p and p.lower() in ("huggingface.co", "hf.co") and i + 1 < len(parts):
                return parts[i + 1].lower() if parts[i + 1] else None
    # Simple org/model format
    if "/" in model_id and not model_id.startswith(("http", "/", ".", "s3:", "gs:")):
        return model_id.split("/")[0].lower()
    return None


def _classify_source(
    model_id: str,
    trusted_orgs: Optional[Set[str]] = None,
    verified_orgs: Optional[Set[str]] = None,
) -> Tuple[str, str]:
    """
    Classify model source and return (source_display, risk).

    Risk rules:
    - trusted org → low
    - verified org (from policy) → low
    - unknown org → medium
    - remote download URLs → high
    """
    model_id_lower = model_id.lower().strip()
    if not model_id_lower:
        return ("unknown", "medium")

    trusted = TRUSTED_MODEL_ORGS | (trusted_orgs or set())
    verified = verified_orgs or set()
    low_risk_orgs = trusted | verified

    # Remote URL classification
    for name, pat in URL_PATTERNS.items():
        if pat.search(model_id_lower):
            if name == "huggingface":
                org = _extract_hf_org(model_id)
                if org and org in low_risk_orgs:
                    label = "trusted org" if org in trusted else "verified org"
                    return (f"huggingface ({label})", "low")
                return ("huggingface (remote URL)", "high")  # Unknown org URL → high
            if name == "github":
                return ("github (remote URL)", "high")
            if name in ("s3", "gcs"):
                return (f"{name} (remote)", "high")
            if name == "http":
                return ("remote URL", "high")

    # HuggingFace model ID: org/model-name
    org = _extract_hf_org(model_id)
    if org is not None:
        if org in low_risk_orgs:
            label = "trusted org" if org in trusted else "verified org"
            return (f"huggingface ({label})", "low")
        return (f"huggingface ({org})", "medium")

    # Local file (e.g. custom_model.bin, model.pt)
    if not model_id_lower.startswith(("http", "s3:", "gs:")) and "/" not in model_id_lower:
        return ("unknown (local or unspecified)", "medium")

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
class AggregatedModel:
    """Model aggregated by name with occurrence count and file locations."""

    model: str
    source: str
    risk: str
    count: int
    files: List[str]  # e.g. ["path/to/file.py:42", "other.py:10"]

    def to_dict(self) -> dict:
        return {
            "model": self.model,
            "source": self.source,
            "risk": self.risk,
            "count": self.count,
            "files": self.files,
        }


def _aggregate_model_sources(sources: List[ModelSource]) -> List[AggregatedModel]:
    """Merge duplicate model findings by model name. Returns aggregated list for reporting."""
    by_model: Dict[str, Dict] = {}
    for m in sources:
        key = m.model
        if key not in by_model:
            by_model[key] = {
                "source": m.source,
                "risk": m.risk,
                "count": 0,
                "locs": set(),
            }
        by_model[key]["count"] += 1
        loc = (m.file, m.line if m.line is not None else 0)
        by_model[key]["locs"].add(loc)
    result = []
    for name, data in sorted(by_model.items()):
        files = sorted(data["locs"], key=lambda x: (x[0], x[1]))
        files_str = [f"{f}:{ln}" if ln else f for f, ln in files]
        result.append(AggregatedModel(
            model=name,
            source=data["source"],
            risk=data["risk"],
            count=data["count"],
            files=files_str,
        ))
    return result


@dataclass
class ModelSupplyChainResult:
    """Result of model supply chain analysis."""

    model_sources: List[ModelSource] = field(default_factory=list)
    _aggregated: Optional[List[AggregatedModel]] = field(default=None, repr=False)

    @property
    def aggregated_models(self) -> List[AggregatedModel]:
        """Models aggregated by name (deduplicated) for reporting."""
        if self._aggregated is None:
            self._aggregated = _aggregate_model_sources(self.model_sources)
        return self._aggregated

    def to_dict(self) -> dict:
        return {
            "model_sources": [m.to_dict() for m in self.model_sources],
            "models": {  # Aggregated: model -> {count, files}
                a.model: {"count": a.count, "files": a.files, "source": a.source, "risk": a.risk}
                for a in self.aggregated_models
            },
        }


class _ModelLoadVisitor(ast.NodeVisitor):
    """Finds model loading calls and extracts source identifiers."""

    def __init__(
        self,
        file_path: str,
        trusted_orgs: Optional[Set[str]] = None,
        verified_orgs: Optional[Set[str]] = None,
    ):
        self.file_path = file_path
        self.trusted_orgs = trusted_orgs or set()
        self.verified_orgs = verified_orgs or set()
        self.sources: List[ModelSource] = []

    def visit_Call(self, node: ast.Call) -> None:
        chain = get_call_chain(node)
        chain_lower = [c.lower() for c in chain]

        for pattern, arg_spec, source_label in MODEL_LOAD_PATTERNS:
            if not _chain_matches(chain, pattern):
                continue

            model_ids = _get_model_id_from_call(node, arg_spec)
            loader = ".".join(chain) if chain else ""

            for mid in model_ids:
                if not mid or len(mid) > 500:
                    continue
                if mid.lower().strip() in MODEL_ID_BLOCKLIST:
                    continue
                src_display, risk = _classify_source(mid, self.trusted_orgs, self.verified_orgs)
                self.sources.append(ModelSource(
                    model=mid,
                    source=src_display,
                    risk=risk,
                    file=self.file_path,
                    line=getattr(node, "lineno", None),
                    loader=loader,
                ))
            break  # One pattern per call
        self.generic_visit(node)



def analyze_model_supply_chain(
    repo_root: Path,
    policy_path: Optional[Path] = None,
) -> ModelSupplyChainResult:
    """
    Analyze Python files for model loading from external sources.

    Trusted/verified orgs from policy.yaml (model_sources.trusted_orgs, verified_orgs)
    are treated as low risk alongside the built-in TRUSTED_MODEL_ORGS.
    """
    repo_root = Path(repo_root).resolve()
    policy_trusted, policy_verified = _load_trusted_orgs_from_policy(policy_path)
    trusted_orgs = TRUSTED_MODEL_ORGS | policy_trusted
    verified_orgs = policy_verified
    all_sources: List[ModelSource] = []
    seen: Set[Tuple[str, str, Optional[int]]] = set()

    for path in repo_root.rglob("*.py"):
        if path.suffix != ".py" or should_skip_path(path, repo_root):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"))
        except (SyntaxError, OSError):
            continue

        rel_path = str(path.relative_to(repo_root))
        visitor = _ModelLoadVisitor(rel_path, trusted_orgs, verified_orgs)
        visitor.visit(tree)

        for m in visitor.sources:
            key = (m.model, m.file, m.line)
            if key not in seen:
                seen.add(key)
                all_sources.append(m)

    return ModelSupplyChainResult(model_sources=all_sources)
