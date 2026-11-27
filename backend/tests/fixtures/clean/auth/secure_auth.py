"""Representative clean authentication fixture.

Uses secure SHA-256 with salt and loads JWT secrets from environment.
"""

import hashlib
import os

JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "")


def hash_user_password(password: str, salt: bytes) -> str:
    """Clean: Uses SHA-256 with cryptographic salt."""
    return hashlib.sha256(salt + password.encode()).hexdigest()
