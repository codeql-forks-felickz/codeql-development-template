# JWT validator accepts the 'none' algorithm from the token header

A JSON Web Token (JWT) carries its signing algorithm in the `alg` field of its header. That header is controlled by whoever produced the token. If a validator reads `alg` from the token and treats the token as valid whenever `alg` is `none`, an attacker can forge any token by setting `"alg": "none"` and removing the signature.

This query complements `java/missing-jwt-signature-check`, which only covers JJWT `JwtParser` usage. It finds hand-rolled validators that compare the header's `alg` value to the constant `none` and then return `true`.

## Recommendation

Never derive the verification algorithm from the token itself. Configure the expected algorithm (and key) on the server, reject tokens whose `alg` is `none`, and always verify the signature using a well-maintained JWT library.

## Example

The following validator returns `true` for any token whose header declares the `none` algorithm:

```java
String alg = header.getString("alg");
if ("none".equalsIgnoreCase(alg)) {
    return true; // BAD: signature is never checked
}
return verifySignature(token, key);
```

The validator should reject such tokens instead:

```java
String alg = header.getString("alg");
if (!EXPECTED_ALGORITHM.equals(alg)) {
    return false; // GOOD: unexpected algorithms, including 'none', are rejected
}
return verifySignature(token, key);
```

## References

- OWASP: [JSON Web Token for Java Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- RFC 7518: [Using the Algorithm "none"](https://datatracker.ietf.org/doc/html/rfc7518#section-3.6)
- Common Weakness Enumeration: [CWE-347](https://cwe.mitre.org/data/definitions/347.html)
