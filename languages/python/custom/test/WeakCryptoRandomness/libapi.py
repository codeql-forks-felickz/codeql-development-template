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


def compound_secret_names():
    accesstoken = random.getrandbits(128)  # $ Alert[py/custom/weak-crypto-randomness]
    authtoken = random.getrandbits(128)  # $ Alert[py/custom/weak-crypto-randomness]
    csrftoken = random.getrandbits(128)  # $ Alert[py/custom/weak-crypto-randomness]
    sessionid = random.getrandbits(128)  # $ Alert[py/custom/weak-crypto-randomness]
    apikey = random.getrandbits(128)  # $ Alert[py/custom/weak-crypto-randomness]


def non_secret_names(employees, words):
    secretary = random.choice(employees)
    tokenizer = random.choice(words)
    return secretary, tokenizer


def generate_keypoints():
    return random.randint(0, 100)


def generate_tokenizer():
    return random.randint(0, 100)


def generate_session_timeout():
    return random.randint(60, 300)


def make_token_count():
    return random.randint(1, 10)


def expiry_values():
    token_expiry = random.randint(0, 100)
    password_expiration = random.randint(0, 100)
    token_expires_at = random.randint(0, 100)
    return token_expiry, password_expiration, token_expires_at


def unpacked_values():
    api_key, active = random.getrandbits(128), True  # $ Alert[py/custom/weak-crypto-randomness]
    display_name, valid = random.getrandbits(128), True
    [password, enabled] = [random.getrandbits(128), True]  # $ Alert[py/custom/weak-crypto-randomness]
    [label, is_valid] = [random.getrandbits(128), True]
    return api_key, active, display_name, valid, password, enabled, label, is_valid


def dictionary_values():
    settings = {"api_key": random.getrandbits(128)}  # $ Alert[py/custom/weak-crypto-randomness]
    metadata = {"display_name": random.getrandbits(128)}
    return settings, metadata


def generate_key_and_return():
    weak_value = random.getrandbits(128)  # $ Source[py/custom/weak-crypto-randomness]
    api_key = weak_value  # $ Alert[py/custom/weak-crypto-randomness]
    return weak_value


def shared_random_value():
    return random.getrandbits(128)  # $ Source[py/custom/weak-crypto-randomness]


def generate_api_key_from_shared_value():
    return shared_random_value()  # $ Alert[py/custom/weak-crypto-randomness]


def generate_password_from_shared_value():
    return shared_random_value()  # $ Alert[py/custom/weak-crypto-randomness]


def dsvw_session_cookie():
    cookie = "SESSIONID=%s; path=/" % "".join(random.choices(string.ascii_letters + string.digits, k=20))  # $ Alert[py/custom/weak-crypto-randomness]
    send_header("Set-Cookie", cookie)
    ordinary_cookie = "theme=%s; path=/" % "".join(random.choices(string.ascii_letters + string.digits, k=20))
    send_header("Set-Cookie", ordinary_cookie)


def generate_referral_code():
    return "".join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8))  # $ Source[py/custom/weak-crypto-randomness]


def store_referral_code(user):
    user.referral_code = generate_referral_code()  # $ Alert[py/custom/weak-crypto-randomness]
    user.discount_code = generate_referral_code()


def generate_api_key_from_choices():
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=16))  # $ Alert[py/custom/weak-crypto-randomness]


def generate_display_name_from_choices():
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=16))


def gentckt():
    return "".join(random.choices(string.ascii_uppercase + string.ascii_lowercase, k=10))  # $ Source[py/custom/weak-crypto-randomness]


def issue_ticket():
    ticket_code = gentckt()  # $ Alert[py/custom/weak-crypto-randomness]
    display_code = generate_display_name_from_choices()
    return ticket_code, display_code


def skey_seed():
    key = str(random.getrandbits(2048)).encode()  # $ Source[py/custom/weak-crypto-randomness]
    otp = hashlib.new("sha1", key).hexdigest()  # $ Alert[py/custom/weak-crypto-randomness]
    secure_otp = hashlib.new("sha1", secrets.token_bytes(32)).hexdigest()
    return otp, secure_otp
