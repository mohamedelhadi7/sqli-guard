"""Deliberately vulnerable examples for the non-SQLi detectors, used by
tests/test_checker_other.py. Do not run this file."""
import os
import subprocess
import hashlib
import pickle
import yaml


def ping_host(host):
    cmd = "ping -c 1 " + host
    os.system(cmd)


def ping_host_popen(host):
    return os.popen("ping -c 1 " + host).read()


def ping_host_shell_true(host):
    cmd = "ping -c 1 " + host
    return subprocess.run(cmd, shell=True)


def read_user_file(base_dir, filename):
    path = base_dir + "/" + filename
    with open(path) as f:
        return f.read()


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def hash_pwd_sha1(pwd):
    return hashlib.sha1(pwd.encode()).hexdigest()


def load_session(data):
    blob = data
    return pickle.loads(blob)


def load_config(raw_yaml):
    return yaml.load(raw_yaml)
