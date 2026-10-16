import jwt

SECRET_KEY = "change-me"


def get_current_user(token):
    payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])  # GOOD
    return payload["sub"]
