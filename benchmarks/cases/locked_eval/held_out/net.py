import requests


def ping(req):
    url = req.json["target"]
    requests.get(url)  # gt:FLOW-HTTP:confirmed_taint


def post_note(req):
    note = req.json["note"]
    requests.post("https://api.example/notes", json=note)  # gt:http:dataflow_role|role=body
