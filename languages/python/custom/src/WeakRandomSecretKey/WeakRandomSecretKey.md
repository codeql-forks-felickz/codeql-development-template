# Secret key generated with a non-cryptographic random generator

The functions of Python's `random` module (such as `random.choice`, `random.choices`, `random.randint`, and `random.getrandbits`) use the Mersenne Twister generator. Its output is predictable and is not suitable for security purposes. A JWT signing key, session secret, or HMAC key generated with it can be guessed or reconstructed, and an attacker who knows the key can forge tokens or sessions. Keys built from a small alphabet or with a short length (for example six digits) are additionally trivial to brute-force.

This query tracks values produced by the `random` module to places where they are used as a secret key:

- assignments to variables, attributes, or configuration keys whose name suggests a secret or signing key (for example `JWT_SECRET_KEY`, `app.secret_key`, or `app.config["SECRET_KEY"]`), including when the value is used as the fallback of `os.getenv`;
- the `key` argument of `jwt.encode` / `jwt.decode` (PyJWT and python-jose);
- the `key` argument of `hmac.new`.

Only the first place a weak value becomes a key is reported.

## Recommendation

Generate secrets with the `secrets` module (for example `secrets.token_urlsafe(32)` or `secrets.token_bytes(32)`) or with `random.SystemRandom`. Prefer requiring the secret to be configured explicitly instead of silently generating a fallback.

## Example

The following configuration falls back to a six-digit key from the `random` module when `JWT_SECRET_KEY` is not set, leaving only one million possible keys:

```python
def generate_random_secret():
    return "".join(random.choices("1234567890", k=6))

class Settings:
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", generate_random_secret())
```

Use a cryptographically secure generator and sufficient length instead:

```python
class Settings:
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", secrets.token_urlsafe(32))
```

## References

- Python documentation: [secrets: Generate secure random numbers for managing secrets](https://docs.python.org/3/library/secrets.html).
- Common Weakness Enumeration: [CWE-326](https://cwe.mitre.org/data/definitions/326.html).
- Common Weakness Enumeration: [CWE-330](https://cwe.mitre.org/data/definitions/330.html).
- Common Weakness Enumeration: [CWE-338](https://cwe.mitre.org/data/definitions/338.html).
