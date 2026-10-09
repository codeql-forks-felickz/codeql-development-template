import jwt
from jwt import PyJWT

SECRET_KEY = "secret"
VERIFY_SIGNATURE = False
UNVERIFIED_OPTIONS = {"verify_signature": False}


# ---- NON_COMPLIANT ----

def bad_literal_options(token):
    return jwt.decode(token, options={"verify_signature": False})  # $ Alert


def bad_literal_options_with_key(token):
    return jwt.decode(token, SECRET_KEY, algorithms=["HS256"], options={"verify_signature": False})  # $ Alert


def bad_module_constant(token):
    return jwt.decode(token, SECRET_KEY, algorithms=["HS256"], options={"verify_signature": VERIFY_SIGNATURE})  # $ Alert


def bad_options_variable(token):
    opts = {"verify_signature": False, "verify_exp": True}
    return jwt.decode(token, SECRET_KEY, algorithms=["HS256"], options=opts)  # $ Alert


def bad_module_options(token):
    return jwt.decode(token, SECRET_KEY, algorithms=["HS256"], options=UNVERIFIED_OPTIONS)  # $ Alert


def bad_legacy_verify_kwarg(token):
    return jwt.decode(token, SECRET_KEY, verify=False)  # $ Alert


def bad_legacy_verify_positional(token):
    return jwt.decode(token, SECRET_KEY, False)  # $ Alert


def bad_decode_complete(token):
    return jwt.decode_complete(token, options={"verify_signature": False})  # $ Alert


def bad_pyjwt_instance(token):
    return PyJWT().decode(token, options={"verify_signature": False})  # $ Alert


# ---- COMPLIANT ----

def good_verified(token):
    return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])


def good_explicit_true(token):
    return jwt.decode(token, SECRET_KEY, algorithms=["HS256"], options={"verify_signature": True})


def good_other_option_disabled(token):
    return jwt.decode(token, SECRET_KEY, algorithms=["HS256"], options={"verify_exp": False})


def good_verify_true(token):
    return jwt.decode(token, SECRET_KEY, verify=True)


def good_peek_then_verify(token, keys):
    # Reading unverified claims only to select the verification key is fine,
    # because the same token is then decoded with signature verification.
    unverified = jwt.decode(token, options={"verify_signature": False})
    key = keys[unverified["iss"]]
    return jwt.decode(token, key, algorithms=["RS256"])


def good_unrelated_decode(data):
    import base64
    return base64.b64decode(data)
