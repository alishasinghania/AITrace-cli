"""Caller reaches a constant-prompt LLM without passing the request value."""

from flask import request


def entry():
    _ = request.json["message"]
    return downstream()


def downstream():
    return llm.invoke("hello")  # gt:FLOW-LLM:structural
