# Weak primary password hasher in Django settings

Django hashes new passwords with the first entry of the `PASSWORD_HASHERS` setting. The remaining entries are only used to verify (and upgrade) existing hashes. Selecting a fast or obsolete hasher such as `MD5PasswordHasher`, `SHA1PasswordHasher`, their unsalted variants, or `CryptPasswordHasher` as the primary hasher means stolen password hashes can be brute-forced very quickly.

This query reports module-level `PASSWORD_HASHERS` assignments whose first entry is one of these weak hashers. Test-only settings files (for example under a `tests/` directory or named `test_settings.py`) are ignored, because Django recommends a fast hasher there to speed up test suites.

## Recommendation

Use a slow, salted password hashing algorithm as the primary hasher, such as `Argon2PasswordHasher`, `PBKDF2PasswordHasher`, `BCryptSHA256PasswordHasher`, or `ScryptPasswordHasher`. Keep a weak hasher later in the list only if you need to verify legacy hashes, so that they are upgraded on the next login.

## Example

The following settings store every new password as an MD5 hash:

```python
PASSWORD_HASHERS = ['django.contrib.auth.hashers.MD5PasswordHasher']
```

Use a strong primary hasher instead:

```python
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
]
```

## References

- Django documentation: [Password management in Django](https://docs.djangoproject.com/en/stable/topics/auth/passwords/).
- OWASP: [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
- Common Weakness Enumeration: [CWE-916](https://cwe.mitre.org/data/definitions/916.html).
- Common Weakness Enumeration: [CWE-328](https://cwe.mitre.org/data/definitions/328.html).
