from flask import request
from urls import fetch


def handle():
    return fetch(request)
