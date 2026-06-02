"""Deliberately vulnerable sample, for testing XSEC.

Run: xsec scan examples/vulnerable.py
"""

import hashlib
import os
import pickle
import subprocess

import requests
import yaml

API_KEY = "EXAMPLE_demo_key_not_a_real_secret"  # fake value, just for testing


def run_command(user_cmd):
    # user input straight into a shell
    os.system("echo " + user_cmd)
    subprocess.run(f"ls {user_cmd}", shell=True)


def calculate(expr):
    return eval(expr)


def load_state(blob):
    return pickle.loads(blob)


def load_config(text):
    return yaml.load(text)  # no safe loader


def fetch(url):
    return requests.get(url, verify=False)  # TLS check off


def fingerprint(data):
    return hashlib.md5(data).hexdigest()  # weak hash


if __name__ == "__main__":
    app_run = lambda **k: None  # noqa
    app_run(debug=True)
