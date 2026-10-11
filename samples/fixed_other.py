"""Fixed versions of samples/vulnerable_other.py, used by
tests/test_checker_other.py to confirm no false alarms."""
import os
import subprocess
import hashlib
import json
import yaml


def ping_host(host):
    subprocess.run(["ping", "-c", "1", host], shell=False)


def ping_host_shell_true(host):
    return subprocess.run(["ping", "-c", "1", host])


def read_user_file(base_dir, filename):
    path = os.path.realpath(os.path.join(base_dir, filename))
    if not path.startswith(os.path.realpath(base_dir)):
        raise ValueError("path traversal blocked")
    with open(path) as f:
        return f.read()


def hash_password(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)


def load_session(data):
    return json.loads(data)


def load_config(raw_yaml):
    return yaml.load(raw_yaml, Loader=yaml.SafeLoader)
