from flask import request
import requests


def fetch(req):
    target = req.json["url"]
    return requests.get(target)  # gt:FLOW-HTTP:confirmed_taint
