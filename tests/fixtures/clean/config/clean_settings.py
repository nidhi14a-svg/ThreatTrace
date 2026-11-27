"""Representative clean configuration fixture.

Production debug disabled and strict CORS origin.
"""

DEBUG = False

CORS_ORIGINS = ["https://app.threadtrace.internal"]
CORS_ALLOW_CREDENTIALS = True
