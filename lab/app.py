"""Local CTF lab: 'Hidden Admin Panel' (Flask + SQLite) with the detector attached.

Run only on your own machine (127.0.0.1). The vulnerable login is deliberate.

  create_app(mode="vulnerable"|"fixed", detector="off"|"monitor"|"block")
"""
import hashlib
import sqlite3
import sys
from pathlib import Path

from flask import Flask, jsonify, request

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from detector import Detector  # noqa: E402

FLAG = "ZSSOIB{SQL_INJECTION_SUCCESS}"


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def make_db():
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT,"
                 " password TEXT, role TEXT)")
    conn.executemany(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        [("admin", sha("supersecret123"), "administrator"),
         ("alice", sha("123456"), "user"),
         ("bob", sha("password"), "user")])
    conn.commit()
    return conn


# --- the two implementations the checker compares -------------------------
def login_vulnerable(conn, username, password):
    query = ("SELECT * FROM users WHERE username='" + username +
             "' AND password='" + sha(password) + "'")
    return conn.execute(query).fetchone()


def login_fixed(conn, username, password):
    return conn.execute(
        "SELECT * FROM users WHERE username = ? AND password = ?",
        (username, sha(password)),
    ).fetchone()
# ---------------------------------------------------------------------------


def create_app(mode="vulnerable", detector="monitor"):
    app = Flask(__name__)
    conn = make_db()
    det = Detector() if detector != "off" else None
    app.det = det
    login = login_vulnerable if mode == "vulnerable" else login_fixed

    @app.post("/login")
    def do_login():
        params = request.form.to_dict()
        if det is not None:
            verdict = det.inspect(request.remote_addr or "unknown",
                                  request.headers.get("User-Agent", ""),
                                  params)
            if verdict.attack and detector == "block":
                return jsonify(ok=False, error="request blocked"), 403
        try:
            row = login(conn, params.get("username", ""), params.get("password", ""))
        except sqlite3.Error:
            return jsonify(ok=False, error="invalid credentials"), 401
        if row and row[3] == "administrator":
            return jsonify(ok=True, user=row[1], flag=FLAG)
        if row:
            return jsonify(ok=True, user=row[1])
        return jsonify(ok=False, error="invalid credentials"), 401

    return app


if __name__ == "__main__":
    create_app(mode="vulnerable", detector="monitor").run(host="127.0.0.1", port=5000)
