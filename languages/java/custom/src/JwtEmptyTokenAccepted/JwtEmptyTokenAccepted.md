# JWT validator accepts a token with no parts

A JSON Web Token (JWT) has three period-separated parts: header, payload and signature. Java's `String.split` drops trailing empty strings, so a token such as `.` or `...` splits into an array of length zero. If a validator returns `true` for that case, an attacker can authenticate without any signature.

This query finds checks that a split JWT has zero parts (`parts.length == 0`, `< 1`, `!= 0` with the valid result in the `else` branch, and similar) that guard a `return true`. A split is treated as a JWT split when the same method reads the `alg` header, or when it splits a variable named like `token` or `jwt` on a literal period.

## Recommendation

Reject tokens that do not have exactly three parts, and always verify the signature with a well-maintained JWT library.

## Example

The following validator treats a token with no parts as valid:

```java
String[] parts = token.split("\\.");
if (parts.length == 0) {
    return true; // BAD: no signature is checked
}
return verifySignature(token, key);
```

The validator should reject malformed tokens instead:

```java
String[] parts = token.split("\\.", -1);
if (parts.length != 3) {
    return false; // GOOD
}
return verifySignature(token, key);
```

## References

- RFC 7519: [JWT format](https://datatracker.ietf.org/doc/html/rfc7519#section-7.2)
- OWASP: [JSON Web Token for Java Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- Common Weakness Enumeration: [CWE-347](https://cwe.mitre.org/data/definitions/347.html)
