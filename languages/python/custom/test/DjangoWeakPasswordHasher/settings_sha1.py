# Primary (first) hasher is weak, later strong entries are only used for verification.
PASSWORD_HASHERS = (  # $ Alert
    "django.contrib.auth.hashers.UnsaltedSHA1PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
)
