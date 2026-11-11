"""LLM invocation sink used by the chat path."""
from __future__ import annotations

from langchain_core.language_models import FakeListChatModel

llm = FakeListChatModel(responses=["ok"])


def invoke_chat_model(message: str) -> str:
    return llm.invoke(message)
