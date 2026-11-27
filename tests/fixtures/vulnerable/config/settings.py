"""Synthetic vulnerable configuration fixture.

SAFETY: Educational test vectors for static analysis only.
"""

# Debug mode enabled
DEBUG = True

# Insecure CORS configuration with wildcard and credentials
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
)
