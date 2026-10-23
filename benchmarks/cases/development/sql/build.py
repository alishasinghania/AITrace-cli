from flask import request


def make_query(req):
    record_id = req.json["id"]
    return f"SELECT * FROM records WHERE id = {record_id}"
