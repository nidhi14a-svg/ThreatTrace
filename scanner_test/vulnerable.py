import hashlib
import requests
import subprocess

# Test 1: Hardcoded secret
API_KEY = "ak_live_abcdef1234567890"

# Test 2: Weak password hashing
password_hash = hashlib.md5(b"password").hexdigest()

# Test 3: Disabled TLS verification
requests.get("https://example.com", verify=False)

# Test 4: Unsafe command execution
user_input = input("Enter command: ")
subprocess.call(user_input, shell=True)

# Test 5: Debug mode enabled
DEBUG = True

# Test 6: Hardcoded private key
DUMMY_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y3v7X5V5q8L7o1Q8+8cK9xZ1Y2X3W4V5U6T7S8R9Q0P1O2N
3M4L5K6J7I8H9G0F1E2D3C4B5A6Z7Y8X9W0V1U2T3S4R5Q6P7O8N9M0L1K2J3I4H
-----END RSA PRIVATE KEY-----"""


# Test 6: Hardcoded private key
DUMMY_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y3v7X5V5q8L7o1Q8+8cK9xZ1Y2X3W4V5U6T7S8R9Q0P1O2N
3M4L5K6J7I8H9G0F1E2D3C4B5A6Z7Y8X9W0V1U2T3S4R5Q6P7O8N9M0L1K2J3I4H
-----END RSA PRIVATE KEY-----"""