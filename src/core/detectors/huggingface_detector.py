"""
HuggingFace local model detector.

Uses AST analysis and file discovery to detect:
- Transformers pipeline, AutoModel, AutoTokenizer
- Diffusers pipelines
- Model file extensions (.pt, .bin, .safetensors, .onnx)
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional, Set

from .base import DetectionResult
from ._ast_utils import get_call_target, get_call_target_chain, scan_ast

HF_AST_PATTERNS = {
    "AutoModel", "AutoTokenizer", "AutoProcessor", "from_pretrained",
    "BertModel", "GPT2LMHeadModel", "T5ForConditionalGeneration",
    "StableDiffusionPipeline", "DiffusionPipeline", "AutoencoderKL",
    "transformers", "diffusers", "load_model", "PreTrainedModel",
}
# "pipeline" alone matches redis.pipeline; require explicit HF context
HF_PIPELINE_REQUIRED = {"transformers", "diffusers", "from_pretrained"}
MODEL_EXTENSIONS = {".pt", ".bin", ".safetensors", ".onnx", ".pb"}
CONFIG_NAMES = {"config.json", "model_config.json"}


def _norm(s: str) -> str:
    return s.lower().replace("-", "_").replace(" ", "_")


def _matches(target: str, patterns: Set[str]) -> bool:
    t = _norm(target)
    return any(t.startswith(_norm(p)) or _norm(p) in t for p in patterns)


def detect_huggingface(repo_root: Path) -> DetectionResult:
    """
    Detect HuggingFace/local model usage via AST and file discovery.
    Returns structured result with component, confidence, evidence.
    """
    repo_root = repo_root.resolve()
    evidence: List[str] = []
    seen: Set[str] = set()
    ast_evidence: List[str] = []

    def visit(call: ast.Call, file_path: str, line: Optional[int]) -> None:
        target = get_call_target(call)
        if not target:
            return
        chain = get_call_target_chain(call)
        full = ".".join(chain) if chain else target
        chain_lower = set(c.lower() for c in chain)

        if _matches(target, HF_AST_PATTERNS) and full not in seen:
            seen.add(full)
            ast_evidence.append(full)
        elif target.lower() in ("pipeline", "run_pipeline"):
            if (chain_lower & HF_PIPELINE_REQUIRED) and "redis" not in chain_lower and "redis" not in full.lower():
                if full not in seen:
                    seen.add(full)
                    ast_evidence.append(full)

    scan_ast(repo_root, visit)

    # File discovery: model binaries and configs (exclude .git, venv, etc.)
    IGNORED = {"test", "tests", ".git", "venv", ".venv", "node_modules", "site-packages"}
    CONFIG_IGNORED = IGNORED | {"benchmark", "classic", "forge", "agbenchmark", "original_autogpt"}
    MODEL_BIN_EXCLUDE = {"build", "web", "assets", "assetmanifest"}
    MODEL_BIN_NAME_EXCLUDE = {"data_level0.bin", "length.bin", "link_lists.bin", "header.bin"}
    model_files: List[str] = []
    for path in repo_root.rglob("*"):
        if not path.is_file():
            continue
        try:
            rel = path.relative_to(repo_root)
        except ValueError:
            continue
        if set(rel.parts) & IGNORED:
            continue
        if path.suffix.lower() in MODEL_EXTENSIONS:
            if path.suffix.lower() == ".bin":
                rel_parts = set(p.lower() for p in rel.parts)
                if rel_parts & MODEL_BIN_EXCLUDE or "assetmanifest" in rel.name.lower():
                    continue
                if rel.name.lower() in MODEL_BIN_NAME_EXCLUDE:
                    continue
            model_files.append(str(rel))
        if rel.name in CONFIG_NAMES and not (set(rel.parts) & CONFIG_IGNORED):
            evidence.append(f"Config: {rel}")

    for e in ast_evidence[:5]:
        evidence.append(e)
    for m in model_files[:5]:
        evidence.append(f"Model file: {m}")

    has_ast = bool(ast_evidence)
    has_files = bool(model_files)

    if has_ast or has_files:
        confidence = "high" if (has_ast and has_files) else ("medium" if has_ast else "low")
        return DetectionResult(
            component="HuggingFace Local Models",
            confidence=confidence,
            evidence=evidence[:10] or ["HuggingFace/transformers usage inferred"],
            details={
                "detected": True,
                "ast_patterns": ast_evidence,
                "model_files": model_files[:10],
            },
        )

    return DetectionResult(
        component="HuggingFace Local Models",
        confidence="low",
        evidence=[],
        details={"detected": False},
    )
