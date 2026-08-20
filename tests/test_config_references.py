from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from core.detectors.config_reference_detector import (
    detect_config_references,
    detect_model_references,
)


def test_grok_and_modern_model_ids(tmp_path: Path) -> None:
    """String model IDs like grok-3 must map to providers, not only gpt-4/claude-3."""
    (tmp_path / "app.py").write_text(
        '''
MODEL = "grok-3"
BASE = "https://api.x.ai/v1"
OPENAI = "gpt-4.1-mini"
CLAUDE = "claude-sonnet-4-20250514"
GEMINI = "gemini-2.5-pro"
DS = "deepseek-chat"
        '''.strip(),
        encoding="utf-8",
    )
    refs = detect_config_references(tmp_path)
    providers = {p for p, _ in refs}
    assert "xai" in providers

    models = detect_model_references(tmp_path)
    by_provider = {p: mid for p, mid, _, _ in models}
    assert by_provider.get("xai") in {"grok-3", "xai"} or "grok-3" in by_provider.values()
    assert any(mid == "grok-3" for _, mid, _, _ in models)
    assert any(mid.startswith("gpt-4.1") for _, mid, _, _ in models)
    assert any("claude-sonnet-4" in mid for _, mid, _, _ in models)
    assert any("gemini-2.5" in mid for _, mid, _, _ in models)
    assert any(mid == "deepseek-chat" for _, mid, _, _ in models)


def test_xai_url_without_model_id(tmp_path: Path) -> None:
    (tmp_path / "config.yaml").write_text(
        "llm:\n  url: https://api.x.ai/v1/chat/completions\n",
        encoding="utf-8",
    )
    refs = detect_config_references(tmp_path)
    assert ("xai", "config.yaml") in refs
