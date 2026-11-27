"""Synthetic vulnerable web security fixture.

SAFETY: Educational test vectors for static AST analysis only. Never executed.
"""

import pickle
import subprocess


def get_user_profile(cursor, user_id: str):
    """Vulnerable to SQL Injection via execute f-string."""
    return cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")


def ping_host(host: str):
    """Vulnerable to Command Injection via shell=True."""
    return subprocess.Popen(f"ping {host}", shell=True)


def read_user_file(filename: str):
    """Vulnerable to Path Traversal via unconstrained open."""
    return open(f"/var/data/{filename}", "r").read()


def restore_session(raw_bytes: bytes):
    """Vulnerable to Insecure Deserialization via pickle.loads."""
    return pickle.loads(raw_bytes)


def execute_dynamic_calculation(user_code: str):
    """Vulnerable to Unsafe Code Execution via eval."""
    return eval(user_code)
