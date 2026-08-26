import hashlib
import os
import secrets
import subprocess
import tempfile

import requests
import yaml

DB_PASSWORD = os.environ["DB_PASSWORD"]


def run_fixed_command():
    subprocess.run(["ls", "-la"], shell=False, check=False)


def load_config(path):
    with open(path) as f:
        return yaml.safe_load(f)


def hash_password(password, salt):
    return hashlib.sha256((salt + password).encode()).hexdigest()


def generate_session_token():
    return secrets.token_urlsafe(32)


def fetch_internal_api():
    return requests.get("https://internal.example.com/api", verify=True)


def create_scratch_file():
    fd, path = tempfile.mkstemp()
    os.close(fd)
    return path
