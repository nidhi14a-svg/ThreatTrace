"""Representative clean web application fixture.

Implements parameterized SQL, safe subprocess, and canonical path checks.
"""

import ast
import json
import subprocess
from pathlib import Path

BASE_DIR = Path("/var/data").resolve()


def get_user_profile(cursor, user_id: str):
    """Clean: Uses parameterized SQL query."""
    query = "SELECT * FROM users WHERE id = %s"
    return cursor.execute(query, (user_id,))


def ping_host(host: str):
    """Clean: Uses array subprocess call with shell=False."""
    return subprocess.run(["ping", "-c", "1", host], shell=False, check=True)


def read_user_file(filename: str):
    """Clean: Validates target path against boundary."""
    target = (BASE_DIR / filename).resolve()
    if not target.is_relative_to(BASE_DIR):
        raise ValueError("Path traversal attempt detected")
    with open(target, "r", encoding="utf-8") as f:
        return f.read()


def restore_session(raw_text: str):
    """Clean: Uses safe JSON deserialization."""
    return json.loads(raw_text)


def evaluate_literal(data_str: str):
    """Clean: Uses safe literal evaluation."""
    return ast.literal_eval(data_str)
