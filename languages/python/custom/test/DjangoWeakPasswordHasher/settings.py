# Sole configured hasher is MD5: every new password is stored as a fast, unsalted-strength hash.
PASSWORD_HASHERS = ['django.contrib.auth.hashers.MD5PasswordHasher']  # $ Alert

SECRET_KEY = "not-relevant"
