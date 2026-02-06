def get_user(name, conn):
    # Intentionally vulnerable example for CodeRisk AI demos
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    return conn.execute(query)
