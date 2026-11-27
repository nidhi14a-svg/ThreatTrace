"""Synthetic vulnerable authentication fixture.

SAFETY: Educational test vectors for static analysis only. Never executed.
"""

import hashlib
import jwt


def hash_user_password(password: str) -> str:
    """Vulnerable to Weak Cryptographic Hashing using MD5."""
    return hashlib.md5(password.encode()).hexdigest()


def create_token(user_id: str) -> str:
    """Vulnerable to hardcoded static JWT secret."""
    return jwt.encode({"sub": user_id}, "hardcoded-super-secret-jwt-signing-key")
