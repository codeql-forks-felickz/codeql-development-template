import secrets


def keygen():
    # GOOD: uses a cryptographically secure source
    return secrets.token_hex(32)
