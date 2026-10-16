# Password-based key derivation with too few iterations

Password-based key derivation functions such as PBKDF2 deliberately repeat a hash function many times so that each password guess is expensive. If the iteration count passed to `javax.crypto.spec.PBEKeySpec` or `javax.crypto.spec.PBEParameterSpec` is very low (for example `1`), an attacker who obtains encrypted data or a derived key can test candidate passwords almost as fast as computing a single hash.

This query reports `PBEKeySpec` and `PBEParameterSpec` constructions whose iteration count is a compile-time constant below 1000, the minimum allowed by NIST SP 800-132. Weak cipher modes such as ECB used with the derived key are reported separately by `java/weak-cryptographic-algorithm`.

## Recommendation

Use a large iteration count. OWASP currently recommends at least 600,000 iterations for PBKDF2-HMAC-SHA256 and 210,000 for PBKDF2-HMAC-SHA512. Prefer a memory-hard function such as Argon2 or scrypt when available.

## Example

The following example derives an AES key with a single PBKDF2 iteration:

```java
SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 1, 128); // BAD
```

Use a sufficiently large iteration count instead:

```java
SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 600_000, 256); // GOOD
```

## References

- NIST SP 800-132: [Recommendation for Password-Based Key Derivation](https://csrc.nist.gov/publications/detail/sp/800-132/final).
- OWASP: [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2).
- Common Weakness Enumeration: [CWE-327](https://cwe.mitre.org/data/definitions/327.html).
- Common Weakness Enumeration: [CWE-916](https://cwe.mitre.org/data/definitions/916.html).
