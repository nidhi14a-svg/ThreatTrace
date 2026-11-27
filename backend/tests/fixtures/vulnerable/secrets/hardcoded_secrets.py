"""Synthetic vulnerable secrets fixture for testing.

SAFETY: Contains exclusively synthetic dummy patterns. No real credentials.
"""

# Hardcoded API key
api_key = "ak_live_abcdef1234567890"

# Hardcoded password
db_password = "SuperSecretPassword123!"

# Database connection string with password
DATABASE_URL = "postgres://admin:SuperSecretPassword123@db.internal:5432/prod_db"

# Private cryptographic key
DUMMY_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y3v7X5V5q8L7o1Q8+8cK9xZ1Y2X3W4V5U6T7S8R9Q0P1O2N
3M4L5K6J7I8H9G0F1E2D3C4B5A6Z7Y8X9W0V1U2T3S4R5Q6P7O8N9M0L1K2J3I4H
-----END RSA PRIVATE KEY-----"""
