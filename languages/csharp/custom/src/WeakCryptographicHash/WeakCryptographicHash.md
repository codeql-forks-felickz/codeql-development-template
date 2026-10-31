# Weak or unsalted hash used for a secret

MD5 is unsuitable for security-sensitive values, and a fast unsalted hash of a password is vulnerable to guessing and precomputed attacks. This query reports MD5 hash results, or hashes of directly supplied password values, when they flow to a password, credential, secret, or token sink.

Use a password-hashing function with a unique random salt and an appropriately high work factor, such as PBKDF2, bcrypt, or Argon2. Use a modern cryptographic hash for non-password integrity checks.

## Known limitations

Password inputs are recognized when passed directly to `ComputeHash` or `HashData`, or through a direct `Encoding.GetBytes` call. Other password transformations and custom hash wrappers are not modeled.

## References

- CWE-328: [Use of Weak Hash](https://cwe.mitre.org/data/definitions/328.html)
- CWE-759: [Use of a One-Way Hash without a Salt](https://cwe.mitre.org/data/definitions/759.html)
