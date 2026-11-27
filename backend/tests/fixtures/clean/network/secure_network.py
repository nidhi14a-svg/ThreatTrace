"""Representative clean network fixture.

Enforces TLS verification and secure HTTPS transport.
"""

import requests

SECURE_ENDPOINT = "https://api.internal.corp/v1/telemetry"


def fetch_telemetry():
    """Clean: Enforces TLS verification."""
    return requests.get(SECURE_ENDPOINT, verify=True, timeout=10)
