import sqlite3

def login(conn, username, password):
    return conn.execute(
        "SELECT * FROM users WHERE username = ? AND password = ?",
        (username, password),
    ).fetchone()

def count_users(conn):
    return conn.execute("SELECT COUNT(*) FROM users").fetchone()
