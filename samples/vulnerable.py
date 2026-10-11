import sqlite3

def login_concat(conn, username, password):
    query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
    return conn.execute(query).fetchone()

def login_fstring(conn, username):
    return conn.execute(f"SELECT * FROM users WHERE username='{username}'").fetchone()

def login_format(conn, username):
    return conn.execute("SELECT * FROM users WHERE username='{}'".format(username)).fetchone()

def login_percent(conn, username):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username='%s'" % username)
    return cur.fetchone()
