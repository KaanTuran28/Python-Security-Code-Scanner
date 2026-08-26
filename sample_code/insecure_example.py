import hashlib
import os
import pickle
import random
import subprocess
import tempfile

import requests
import yaml

DB_PASSWORD = "SuperSecret123"
API_KEY = "sk_live_abcdef123456"


def run_user_command(cmd):
    os.system(cmd)
    subprocess.run(cmd, shell=True, check=False)


def load_config(path):
    with open(path, "rb") as f:
        return pickle.load(f)


def load_yaml_config(path):
    with open(path) as f:
        return yaml.load(f, Loader=yaml.Loader)


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def generate_session_token():
    token = random.random()
    return str(token)


def fetch_internal_api():
    return requests.get("https://internal.example.com/api", verify=False)


def create_scratch_file():
    return tempfile.mktemp()


def run_query(query):
    return eval(query)
