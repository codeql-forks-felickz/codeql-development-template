import os
import random
import secrets
import string

import jwt
from flask import Flask


def generate_random_secret():
    return "".join(random.choices("1234567890", k=6))  # $ Source


class Settings:
    # Default JWT signing key has only 10**6 possible values and comes from a non-CSPRNG.
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", generate_random_secret())  # $ Alert


def sign_token(payload):
    key = "".join(random.choice(string.ascii_letters) for _ in range(32))  # $ Source
    return jwt.encode(payload, key, algorithm="HS256")  # $ Alert


def sign_with_settings(payload):
    # Not reported again: the weak key is reported where it first becomes a key.
    return jwt.encode(payload, Settings.JWT_SECRET_KEY, algorithm="HS256")


app = Flask(__name__)
app.secret_key = str(random.getrandbits(64))  # $ Alert
app.config["SECRET_KEY"] = "%032x" % random.getrandbits(128)  # $ Alert


# --- Safe cases ---


class SafeSettings:
    # Safe: generated with a CSPRNG.
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", secrets.token_urlsafe(32))
    # Safe: SystemRandom uses os.urandom.
    SIGNING_KEY = "".join(random.SystemRandom().choice(string.digits) for _ in range(64))


def safe_sign_token(payload):
    return jwt.encode(payload, secrets.token_bytes(32), algorithm="HS256")


def backoff():
    # Safe: randomness is not used as a secret.
    retry_delay = random.uniform(0.5, 1.5)
    request_id = random.randint(0, 1000)
    return retry_delay, request_id
