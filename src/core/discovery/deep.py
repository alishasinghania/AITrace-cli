from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from ..models import Component, ComponentType, Evidence, Finding, FindingCategory, ModelArtifact, Severity


MODEL_EXTENSIONS = {".pt", ".bin", ".safetensors", ".onnx", ".pb"}
CONFIG_FILENAMES = {"config.json", "model_config.json"}


@dataclass
class DeepDiscoveryResult:
    models: List[ModelArtifact]
    components: List[Component]
    findings: List[Finding]


def _infer_framework_from_config(config: Dict) -> Optional[str]:
    if "architectures" in config:
        return "transformers"
    if "hidden_size" in config and "num_attention_heads" in config:
        return "transformers-like"
    if "onnx_opset_version" in config:
        return "onnx"
    return None


def discover_deep(repo_root: Path) -> DeepDiscoveryResult:
    """
    Perform deep inspection of the repository to locate model artefacts and
    basic metadata.
    """
    repo_root = repo_root.resolve()
    models: List[ModelArtifact] = []
    components: List[Component] = []
    findings: List[Finding] = []

    id_counter = 1

    def next_id(prefix: str) -> str:
        nonlocal id_counter
        val = f"{prefix}-{id_counter:04d}"
        id_counter += 1
        return val

    for path in repo_root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(repo_root)

        # Model binaries
        if path.suffix.lower() in MODEL_EXTENSIONS:
            size = None
            try:
                size = path.stat().st_size
            except OSError:
                pass

            artifact = ModelArtifact(
                id=next_id("MODEL"),
                name=rel.name,
                path=str(rel),
                format=path.suffix.lower().lstrip("."),
                size_bytes=size,
            )
            models.append(artifact)

            findings.append(
                Finding(
                    id=next_id("DEEP"),
                    title="Model binary discovered",
                    category=FindingCategory.DEEP,
                    severity=Severity.MEDIUM,
                    description=f"Model artefact '{rel}' detected.",
                    evidence=[Evidence(description="File extension inspection", file=str(rel))],
                    tags=["model-artifact"],
                    component_id=artifact.id,
                )
            )

        # Config files
        if rel.name in CONFIG_FILENAMES:
            try:
                config = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                config = {}

            framework = _infer_framework_from_config(config)
            component = Component(
                id=next_id("CFG"),
                name=rel.name,
                type=ComponentType.MODEL,
                version=None,
                properties={"config": config, "framework": framework},
            )
            components.append(component)

            findings.append(
                Finding(
                    id=next_id("DEEP"),
                    title="Model configuration discovered",
                    category=FindingCategory.DEEP,
                    severity=Severity.INFO,
                    description=f"Model configuration file '{rel}' detected.",
                    component_id=component.id,
                    evidence=[Evidence(description="Config file", file=str(rel))],
                    tags=["model-config"],
                )
            )

    return DeepDiscoveryResult(models=models, components=components, findings=findings)

