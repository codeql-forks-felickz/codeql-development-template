import os

import jwt


def issue_token():
    return jwt.encode({"sub": "admin"}, "hardcoded-signing-key", algorithm="HS256")  # $ Alert


def check_token(token):
    return jwt.decode(token, key="secret", algorithms=["HS256"])  # $ Alert


# GOOD: the key comes from elsewhere
def issue_token_vault():
    return jwt.encode({"sub": "admin"}, load_key_from_vault(), algorithm="HS256")


def issue_token_env_with_default():
    return jwt.encode(
        {"sub": "admin"},
        os.environ["JWT_KEY"] + "0123456789abcdef0123456789abcdef01234567",
        algorithm="HS256",
    )


def issue_token_hardcoded_key():
    return jwt.encode(
        {"sub": "admin"}, "0123456789abcdef0123456789abcdef01234567", algorithm="HS256"
    )  # $ Alert


def check_token_asymmetric(token):
    public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtest
-----END PUBLIC KEY-----"""
    return jwt.decode(token, public_key, algorithms=["RS256"])


def load_key_from_vault():
    pass
