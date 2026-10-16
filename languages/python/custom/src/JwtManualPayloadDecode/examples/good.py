import os

import jwt

SECRET_KEY = os.environ["JWT_SECRET_KEY"]


def lambda_handler(event, context):
    token = event["headers"]["Authorization"]
    claims = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])  # GOOD
    return claims["username"]
