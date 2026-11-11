"""SQL execute sink — present even when no taint path is confirmed."""
from __future__ import annotations

import sqlite3


def run_query(sql: str) -> list:
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute(sql)
    return list(cur.fetchall())
