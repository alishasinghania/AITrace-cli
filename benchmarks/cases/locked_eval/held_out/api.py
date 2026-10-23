from flask import request
from db import lookup_safe, lookup_unsafe
from net import ping, post_note


def ask():
    q = request.json["question"]
    llm.invoke(q)  # gt:FLOW-LLM:confirmed_taint


def search():
    name = request.json["name"]
    lookup_safe(name)
    lookup_unsafe(name)


def outbound():
    ping(request)
    post_note(request)
