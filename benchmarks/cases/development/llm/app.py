"""LLM ground-truth fixtures. Markers use gt tags on sink lines."""

from flask import request


def direct_payload():
    msg = request.json["message"]
    llm.invoke(msg)  # gt:FLOW-LLM:confirmed_taint


def interpolated_prompt():
    msg = request.json["message"]
    llm.invoke(f"User said: {msg}")  # gt:FLOW-LLM:confirmed_taint


def constant_prompt():
    llm.invoke("You are a helpful assistant")  # gt:FLOW-LLM:absent


def lookup_identifier_only():
    record_id = request.json["id"]
    obj = repository.load(record_id)
    llm.invoke(f"Brief {obj.title}")  # gt:FLOW-LLM:absent


def unresolved_wrapper():
    msg = request.json["message"]
    y = unknown_transform(msg)
    llm.invoke(y)  # gt:FLOW-LLM:absent


def two_sinks_one_source():
    msg = request.json["message"]
    llm.invoke(msg)  # gt:FLOW-LLM:confirmed_taint
    chain.invoke(msg)  # gt:FLOW-LLM:confirmed_taint
