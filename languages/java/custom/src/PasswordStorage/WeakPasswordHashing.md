# Use of a fast hash function for password hashing

Message digests such as MD4, MD5, SHA-1 and SHA-256 are designed to be fast. When a password is hashed with one of them, with or without a salt, an attacker who obtains the hashes can test billions of candidate passwords per second or use precomputed rainbow tables.

## Recommendation

Hash passwords with a dedicated, deliberately slow password hashing function such as Argon2, scrypt, bcrypt or PBKDF2, using a per-password random salt and a work factor appropriate for current hardware.

## Example

```java
MessageDigest md = MessageDigest.getInstance("MD5");
byte[] hash = md.digest(password.getBytes(StandardCharsets.UTF_8)); // BAD
```

```java
String hash = new BCryptPasswordEncoder(12).encode(password); // GOOD
```

## References

- OWASP: [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- CWE-916: [Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html)
