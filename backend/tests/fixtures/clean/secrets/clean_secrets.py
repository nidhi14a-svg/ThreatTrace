"""Representative clean secrets fixture.

Loads credentials safely from environment variables.
"""

import os

AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID", "")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
SLACK_TOKEN = os.environ.get("SLACK_TOKEN", "")
STRIPE_KEY = os.environ.get("STRIPE_KEY", "")
DATABASE_URL = os.environ.get("DATABASE_URL", "")
