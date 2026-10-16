---
category: newQuery
---

- Added five Python queries for credential and data exposure that are not covered by the shipped `py/weak-crypto-key`, `py/weak-sensitive-data-hashing`, `py/clear-text-storage-sensitive-data`, `py/insecure-temporary-file`, and `py/overly-permissive-file` queries:
  - `py/django-weak-password-hasher` (CWE-916): Django `PASSWORD_HASHERS` whose primary hasher is MD5, SHA-1, an unsalted variant, or crypt.
  - `py/weak-random-secret-key` (CWE-326, CWE-338): secret or signing keys (for example JWT secrets, including `os.getenv` fallbacks) generated with the non-cryptographic `random` module.
  - `py/cleartext-password-storage` (CWE-256): passwords, including hard-coded seed accounts, written without hashing to a database by SQL `INSERT`/`UPDATE` statements or to a module-level in-memory user store.
  - `py/unencrypted-private-key-temp-file` (CWE-522): unencrypted private keys written to predictable paths in shared temporary directories such as `/tmp`.
  - `py/drf-serializer-sensitive-field-exposure` (CWE-359): Django REST framework model serializers whose readable fields include sensitive data such as passwords, reset tokens, social security numbers, or dates of birth.
