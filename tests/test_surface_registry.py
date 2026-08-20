from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from core.discovery.surface import (
    ALL_AI_PACKAGES,
    _ai_package_lookup,
    _normalize_import_to_ai_package,
    _parse_pyproject,
    _scan_manifests,
    discover_surface,
    get_package_category,
)


def test_lookup_hyphen_underscore():
    assert _ai_package_lookup("sentence_transformers") == "sentence-transformers"
    assert _ai_package_lookup("sentence-transformers") in ALL_AI_PACKAGES
    assert _normalize_import_to_ai_package("sentence_transformers") == "sentence-transformers"


def test_torch_and_new_sdks_are_registered():
    assert _ai_package_lookup("torch") == "torch"
    assert get_package_category("torch") == "ml_runtime"
    assert _ai_package_lookup("vllm")
    assert _ai_package_lookup("sglang")
    assert _ai_package_lookup("google-genai")
    assert _ai_package_lookup("browser-use")
    assert _ai_package_lookup("langchain-openai")
    assert _ai_package_lookup("xai") == "xai"
    assert _ai_package_lookup("grok") == "grok"
    assert _ai_package_lookup("openrouter")
    assert _ai_package_lookup("deepseek")


def test_parse_poetry_pyproject(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text(
        """
[tool.poetry.dependencies]
python = ">=3.10.0,<3.11"
langchain = "^0.0.80"
openai = "^0.26.5"
faiss-cpu = "^1.7.3"
tiktoken = "^0.2.0"
flask = "^2.2.0"
""",
        encoding="utf-8",
    )
    names = {n for n, _ in _parse_pyproject(tmp_path / "pyproject.toml")}
    assert "langchain" in names
    assert "openai" in names
    assert "faiss-cpu" in names
    assert "tiktoken" in names
    assert "flask" in names


def test_manifest_filters_non_ai(tmp_path: Path):
    (tmp_path / "requirements.txt").write_text(
        "langchain~=0.0.89\nrich~=13.3.1\nopenai~=0.27.4\n",
        encoding="utf-8",
    )
    comps = _scan_manifests(tmp_path)
    names = {c.name for c in comps}
    assert "langchain" in names
    assert "openai" in names
    assert "rich" not in names


def test_discover_surface_covers_poetry_and_imports(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text(
        '[tool.poetry.dependencies]\npython = "^3.10"\nlangchain = "^0.0.80"\nopenai = "^0.26.5"\nfaiss-cpu = "^1.7.3"\n',
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        "import faiss\nimport torch\nfrom sentence_transformers import SentenceTransformer\n",
        encoding="utf-8",
    )
    result = discover_surface(tmp_path)
    names = {c.name.lower() for c in result.components}
    labels = {ALL_AI_PACKAGES.get(_ai_package_lookup(n) or n, n) for n in names}
    assert "LangChain" in labels
    assert "OpenAI" in labels
    assert "FAISS" in labels
    assert "PyTorch" in labels
    assert "Sentence Transformers" in labels
    assert "rich" not in names
