import jwt


def issue_token():
    return jwt.encode({"sub": "admin"}, "hardcoded-signing-key", algorithm="HS256")  # $ Alert


def check_token(token):
    return jwt.decode(token, key="secret", algorithms=["HS256"])  # $ Alert


# GOOD: the key comes from elsewhere
def issue_token_vault():
    return jwt.encode({"sub": "admin"}, load_key_from_vault(), algorithm="HS256")


def load_key_from_vault():
    pass
