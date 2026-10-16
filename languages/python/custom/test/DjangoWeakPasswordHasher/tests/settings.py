# Safe: Django recommends a fast hasher in test-only settings to speed up the test suite.
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
