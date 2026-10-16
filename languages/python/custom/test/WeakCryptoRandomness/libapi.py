import hashlib
import os
import random
import secrets
import string
from random import getrandbits, Random


# Reduced from vulpy bad/libapi.py: API key derived from the Mersenne Twister PRNG.
def keygen(username):
    key = hashlib.sha256(str(random.getrandbits(2048)).encode()).hexdigest()  # $ Alert[py/custom/weak-crypto-randomness]
    return key


def make_api_key():
    api_key = random.getrandbits(128)  # $ Alert[py/custom/weak-crypto-randomness]
    return api_key


def generate_token():
    return "%032x" % getrandbits(128)  # $ Alert[py/custom/weak-crypto-randomness]


def new_password(length=12):
    return "".join(random.choice(string.ascii_letters) for _ in range(length))  # $ Alert[py/custom/weak-crypto-randomness]


def reset_code():
    rng = Random()
    code = rng.randint(100000, 999999)  # $ Source[py/custom/weak-crypto-randomness]
    otp_code = str(code)  # $ Alert[py/custom/weak-crypto-randomness]
    return otp_code


class Session:
    def __init__(self):
        self.session_id = random.randbytes(16).hex()  # $ Alert[py/custom/weak-crypto-randomness]


def store(user):
    user["csrf_token"] = str(random.random())  # $ Alert[py/custom/weak-crypto-randomness]


def register(create_user):
    create_user(name="bob", secret=random.randint(0, 2**64))  # $ Alert[py/custom/weak-crypto-randomness]


# Safe counterparts: cryptographically secure sources.
def keygen_safe(username):
    key = hashlib.sha256(secrets.token_bytes(256)).hexdigest()
    return key


def make_api_key_safe():
    api_key = secrets.token_hex(32)
    return api_key


def generate_token_safe():
    return os.urandom(16).hex()


def new_password_safe(length=12):
    return "".join(secrets.choice(string.ascii_letters) for _ in range(length))


def session_id_safe():
    session_id = random.SystemRandom().getrandbits(128)
    return session_id


# Safe counterparts: non-security uses of the random module.
def jitter():
    delay = random.uniform(0.1, 0.5)
    return delay


def pick_color(colors):
    color = random.choice(colors)
    return color


def shuffle_cards(deck):
    random.shuffle(deck)
    sample_ids = random.sample(deck, 3)
    return sample_ids
