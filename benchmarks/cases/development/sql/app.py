"""SQL interpolation vs parameterization vs unknown receivers."""

from flask import request


def interpolated_percent():
    record_id = request.json["id"]
    cursor.execute("SELECT * FROM t WHERE id = '%s'" % record_id)  # gt:sql:sql_interpolation


def fstring_then_execute():
    record_id = request.json["id"]
    query = f"SELECT * FROM t WHERE id = {record_id}"
    cursor.execute(query)  # gt:sql:sql_interpolation


def concat_then_execute():
    record_id = request.json["id"]
    query = "SELECT * FROM t WHERE id = " + record_id
    cursor.execute(query)  # gt:sql:sql_interpolation


def parameterized():
    record_id = request.json["id"]
    cursor.execute("SELECT * FROM t WHERE id = ?", (record_id,))  # gt:FLOW-SQL:absent


def llm_generated_sql():
    sql = llm.invoke("write a select")
    cursor.execute(sql)  # gt:PAT-003:pattern  # gt:FLOW-SQL:absent


def two_sinks():
    a = request.json["a"]
    b = request.json["b"]
    cursor.execute(f"SELECT {a}")  # gt:sql:sql_interpolation
    cursor.execute(f"SELECT {b}")  # gt:sql:sql_interpolation


def unknown_execute_receiver():
    q = request.json["q"]
    widget.execute(q)  # gt:FLOW-SQL:absent
