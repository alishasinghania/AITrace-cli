from flask import request
from helper import run_llm


def chat():
    return run_llm(request.json["message"])
