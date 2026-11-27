"""Synthetic vulnerable network fixture.

SAFETY: Educational test vectors for static analysis only. Never executed.
"""

import requests

CLEARTEXT_ENDPOINT = "http://api.internal.corp/v1/telemetry"


def fetch_telemetry():
    """Vulnerable to Disabled TLS Verification and cleartext transport."""
    return requests.get(CLEARTEXT_ENDPOINT, verify=False)
