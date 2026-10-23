def lookup_safe(name):
    cursor.execute("SELECT * FROM t WHERE name = ?", (name,))  # gt:FLOW-SQL:absent


def lookup_unsafe(name):
    cursor.execute(f"SELECT * FROM t WHERE name = '{name}'")  # gt:sql:sql_interpolation
