"""Request intake — forwards user text to the LLM sink."""
from __future__ import annotations

from app.llm_sink import invoke_chat_model


def accept_user_message(message: str) -> str:
    return invoke_chat_model(message)
