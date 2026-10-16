import base64
import json


def lambda_handler(event, context):
    auth_header = event["headers"]["Authorization"]
    token_sections = auth_header.split('.')
    try:
        auth_data = base64.b64decode(token_sections[1])  # $ Alert
    except TypeError:
        try:
            auth_data = base64.b64decode(token_sections[1] + "=")  # $ Alert
        except TypeError:
            return {"status": "err"}
    token = json.loads(auth_data)
    return token["username"]


def bad_inline(request):
    payload = base64.urlsafe_b64decode(request.headers["Authorization"].split(".")[1] + "==")  # $ Alert
    return json.loads(payload)["sub"]


def bad_unpacking(request):
    header, payload, signature = request.cookies["session"].split(".")
    return json.loads(base64.urlsafe_b64decode(payload + "=="))  # $ Alert


def bad_bearer_prefix(request):
    token = request.headers["Authorization"].replace("Bearer ", "")
    parts = token.split(".", 2)
    claims = json.loads(base64.b64decode(parts[1]))  # $ Alert
    return claims["role"]


# ---- COMPLIANT ----

def good_homemade_signature_check(token, secret):
    import hashlib
    import hmac
    parts = token.split(".")
    expected = base64.urlsafe_b64encode(
        hmac.new(secret, (parts[0] + "." + parts[1]).encode(), hashlib.sha256).digest()
    ).rstrip(b"=")
    if not hmac.compare_digest(expected, parts[2].encode()):
        raise ValueError("bad signature")
    return json.loads(base64.urlsafe_b64decode(parts[1] + "=="))


def good_unpacking_with_signature_check(token, verify):
    header, payload, signature = token.split(".")
    verify(header, payload, signature)
    return json.loads(base64.urlsafe_b64decode(payload + "=="))


def good_header_only(token):
    # The header is decoded, not the claims.
    return json.loads(base64.urlsafe_b64decode(token.split(".")[0] + "=="))


def good_not_a_token(filename):
    # Splitting on "." for something unrelated.
    return base64.b64decode(filename.split(".")[1])


def good_library(token, key):
    import jwt
    return jwt.decode(token, key, algorithms=["HS256"])
