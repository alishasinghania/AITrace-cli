"""HTTP argument roles. FLOW-HTTP is destination control only."""

from flask import request
import requests


def tainted_url():
    target = request.json["url"]
    requests.get(target)  # gt:FLOW-HTTP:confirmed_taint


def interpolated_url():
    host = request.json["host"]
    requests.get(f"https://{host}/v1")  # gt:FLOW-HTTP:confirmed_taint


def tainted_body_constant_url():
    msg = request.json["message"]
    requests.post("https://api.example/x", json=msg)  # gt:http:dataflow_role|role=body


def tainted_query_constant_url():
    q = request.json["q"]
    requests.get("https://api.example/search", params={"q": q})  # gt:http:dataflow_role|role=query


def tainted_headers_constant_url():
    token = request.json["token"]
    requests.get("https://api.example/x", headers={"X-User": token})  # gt:http:dataflow_role|role=headers


def constant_url_and_body():
    requests.post("https://api.example/x", json={"ok": True})  # gt:FLOW-HTTP:absent


def unresolved_url_wrapper():
    target = request.json["url"]
    url = wrap_url(target)
    requests.get(url)  # gt:FLOW-HTTP:absent


def unrelated_get():
    path = request.json["path"]
    config.get(path)  # gt:FLOW-HTTP:absent
