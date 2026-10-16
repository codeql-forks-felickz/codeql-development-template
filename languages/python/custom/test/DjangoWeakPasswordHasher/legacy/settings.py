# Safe: a strong primary hasher; MD5 is kept only to verify (and upgrade) legacy hashes.
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    "django.contrib.auth.hashers.MD5PasswordHasher",
]

# Safe: not a Django setting name.
LEGACY_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]


def configure():
    # Safe: local variable, not a module-level setting.
    PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
    return PASSWORD_HASHERS
