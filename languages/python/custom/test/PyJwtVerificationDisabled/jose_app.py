from jose import JWTError, jwt

SECRET_KEY = "secret"
ALGORITHM = "HS256"
VERIFY_SIGNATURE = False


async def get_current_user(token):
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            options={"verify_signature": VERIFY_SIGNATURE},
        )  # $ Alert
    except JWTError:
        raise
    return payload.get("sub")


def good_jose_verified(token):
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
