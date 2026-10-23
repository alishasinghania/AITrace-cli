"""Provenance, sanitization, dynamic dispatch, structural reachability."""

from flask import request
import html as html_mod


def sanitized_then_llm():
    msg = request.json["message"]
    clean = html_mod.escape(msg)
    llm.invoke(clean)  # gt:FLOW-LLM:absent


def dynamic_dispatch():
    msg = request.json["message"]
    getattr(llm, "invoke")(msg)  # gt:unsupported_call_form:coverage


def unresolved_tainted_call():
    msg = request.json["message"]
    vendor_sdk.complete(msg)  # gt:unresolved_call:coverage


def structural_only_sink():
    llm.invoke("fixed")  # gt:FLOW-LLM:structural
