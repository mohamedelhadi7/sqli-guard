"""Labeled corpus for eval/benchmark.py: one function per entry, each
labeled with the vulnerability category the checker should find, or "safe"
if it should find nothing. Written by hand (not generated), independent
of samples/vulnerable.py and samples/vulnerable_other.py, so this is a
clean multi-class benchmark rather than a re-run of the unit tests.
"""

CORPUS = [
    # ---------------- sql_injection: vulnerable ----------------
    ("sql_concat", "sql_injection", """
def f(conn, user):
    q = "SELECT * FROM t WHERE u='" + user + "'"
    return conn.execute(q).fetchone()
"""),
    ("sql_fstring", "sql_injection", """
def f(conn, user):
    return conn.execute(f"SELECT * FROM t WHERE u='{user}'").fetchone()
"""),
    ("sql_percent", "sql_injection", """
def f(cur, user):
    cur.execute("SELECT * FROM t WHERE u='%s'" % user)
"""),
    ("sql_format", "sql_injection", """
def f(conn, user):
    return conn.execute("SELECT * FROM t WHERE u='{}'".format(user)).fetchone()
"""),
    ("sql_two_hop_taint", "sql_injection", """
def f(conn, user):
    part = "u='" + user + "'"
    q = "SELECT * FROM t WHERE " + part
    return conn.execute(q).fetchone()
"""),
    ("sql_executemany", "sql_injection", """
def f(cur, rows, col):
    q = "INSERT INTO t VALUES ('" + col + "')"
    cur.executemany(q, rows)
"""),
    # ---------------- sql_injection: safe ----------------
    ("sql_safe_params", "safe", """
def f(conn, user, pwd):
    return conn.execute("SELECT * FROM t WHERE u=? AND p=?", (user, pwd)).fetchone()
"""),
    ("sql_safe_const_concat", "safe", """
def f(conn):
    q = "SELECT * " + "FROM t"
    return conn.execute(q).fetchone()
"""),
    ("sql_safe_no_dynamic_text", "safe", """
def f(conn, user, pwd):
    sql = "SELECT * FROM t WHERE u=? AND p=?"
    return conn.execute(sql, (user, pwd)).fetchone()
"""),
    # ---------------- command_injection: vulnerable ----------------
    ("cmd_system_concat", "command_injection", """
import os
def f(host):
    os.system("ping -c 1 " + host)
"""),
    ("cmd_popen_concat", "command_injection", """
import os
def f(host):
    return os.popen("nslookup " + host).read()
"""),
    ("cmd_subprocess_shell_true", "command_injection", """
import subprocess
def f(name):
    cmd = "echo " + name
    subprocess.run(cmd, shell=True)
"""),
    ("cmd_subprocess_call_shell_true", "command_injection", """
import subprocess
def f(name):
    subprocess.call("grep " + name + " file.txt", shell=True)
"""),
    ("cmd_os_system_fstring", "command_injection", """
import os
def f(user):
    os.system(f"id {user}")
"""),
    # ---------------- command_injection: safe ----------------
    ("cmd_safe_list_args", "safe", """
import subprocess
def f(host):
    subprocess.run(["ping", "-c", "1", host], shell=False)
"""),
    ("cmd_safe_const_system", "safe", """
import os
def f():
    os.system("uptime")
"""),
    ("cmd_safe_shell_true_const", "safe", """
import subprocess
def f():
    subprocess.run("echo hello", shell=True)
"""),
    # ---------------- path_traversal: vulnerable ----------------
    ("path_open_concat", "path_traversal", """
def f(base, name):
    p = base + "/" + name
    with open(p) as fh:
        return fh.read()
"""),
    ("path_join_var", "path_traversal", """
import os
def f(base, name):
    full = os.path.join(base, name)
    with open(full) as fh:
        return fh.read()
"""),
    ("path_send_file", "path_traversal", """
def f(upload_dir, filename):
    p = upload_dir + filename
    return send_file(p)
"""),
    # ---------------- path_traversal: safe ----------------
    ("path_safe_const", "safe", """
def f():
    with open("config/settings.json") as fh:
        return fh.read()
"""),
    ("path_safe_validated", "safe", """
import os
def f(base, name):
    p = os.path.realpath(os.path.join(base, name))
    if not p.startswith(os.path.realpath(base)):
        raise ValueError("bad path")
    with open(p) as fh:
        return fh.read()
"""),
    # ---------------- weak_hash: vulnerable ----------------
    ("hash_md5_password", "weak_hash", """
import hashlib
def f(password):
    return hashlib.md5(password.encode()).hexdigest()
"""),
    ("hash_sha1_secret", "weak_hash", """
import hashlib
def f(secret):
    return hashlib.sha1(secret.encode("utf-8")).hexdigest()
"""),
    ("hash_md5_pin_var", "weak_hash", """
import hashlib
def f(pin):
    return hashlib.md5(pin.encode()).digest()
"""),
    # ---------------- weak_hash: safe ----------------
    ("hash_safe_pbkdf2", "safe", """
import hashlib
def f(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
"""),
    ("hash_md5_non_secret", "safe", """
import hashlib
def f(file_bytes):
    return hashlib.md5(file_bytes).hexdigest()
"""),
    ("hash_sha256_password", "safe", """
import hashlib
def f(password):
    return hashlib.sha256(password.encode()).hexdigest()
"""),
    # ---------------- insecure_deserialization: vulnerable ----------------
    ("deser_pickle_loads_param", "insecure_deserialization", """
import pickle
def f(data):
    return pickle.loads(data)
"""),
    ("deser_pickle_load_file", "insecure_deserialization", """
import pickle
def f(fh):
    return pickle.load(fh)
"""),
    ("deser_yaml_load_no_loader", "insecure_deserialization", """
import yaml
def f(raw):
    return yaml.load(raw)
"""),
    ("deser_yaml_load_unsafe_loader", "insecure_deserialization", """
import yaml
def f(raw):
    return yaml.load(raw, Loader=yaml.Loader)
"""),
    # ---------------- insecure_deserialization: safe ----------------
    ("deser_safe_json", "safe", """
import json
def f(data):
    return json.loads(data)
"""),
    ("deser_safe_yaml_safeloader", "safe", """
import yaml
def f(raw):
    return yaml.load(raw, Loader=yaml.SafeLoader)
"""),
    ("deser_safe_yaml_safe_load", "safe", """
import yaml
def f(raw):
    return yaml.safe_load(raw)
"""),
    # ---------------- plain safe code, no security APIs at all ----------------
    ("plain_sum", "safe", """
def f(a, b):
    return a + b
"""),
    ("plain_string_build", "safe", """
def f(name):
    greeting = "Hello, " + name + "!"
    return greeting
"""),
    ("plain_list_comp", "safe", """
def f(items):
    return [x * 2 for x in items if x > 0]
"""),
]
