import jwt

SECRET_KEY = "change-me"
VERIFY_SIGNATURE = False


def get_current_user(token):
    payload = jwt.decode(
        token,
        SECRET_KEY,
        algorithms=["HS256"],
        options={"verify_signature": VERIFY_SIGNATURE},  # BAD
    )
    return payload["sub"]
