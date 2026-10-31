# BCrypt with an insufficient work factor

The BCrypt work factor (log rounds) controls how expensive each password hash is to compute. Values below 10 make hashes cheap enough to brute-force efficiently.

## Recommendation

Use a work factor of at least 10 (the Spring Security default), and increase it as hardware improves.

## Example

```java
new BCryptPasswordEncoder(4).encode(password); // BAD
BCrypt.hashpw(password, BCrypt.gensalt(6));    // BAD
new BCryptPasswordEncoder(12).encode(password); // GOOD
```

## References

- OWASP: [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- CWE-916: [Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html)
