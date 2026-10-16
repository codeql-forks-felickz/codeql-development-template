# JWT signed or verified with the 'none' algorithm

The JSON Web Token (JWT) `none` algorithm produces tokens with an empty signature. A token signed with `none` carries no integrity or authenticity guarantee, so anyone can create or modify one. A verifier configured for `none` accepts such unsigned tokens.

This query finds `com.auth0.jwt.algorithms.Algorithm.none()` values that are used to sign tokens (`JWTCreator.Builder.sign`) or to build a verifier (`JWT.require`).

## Recommendation

Sign and verify tokens with a strong algorithm and a server-side key, for example `Algorithm.HMAC256(secret)` or `Algorithm.RSA256(publicKey, privateKey)`.

## Example

The following code issues tokens that have no signature:

```java
String token = JWT.create().withClaim("username", username).sign(Algorithm.none()); // BAD
```

The token should be signed with a secret key instead:

```java
String token = JWT.create().withClaim("username", username).sign(Algorithm.HMAC256(secret)); // GOOD
```

## References

- RFC 7518: [Using the Algorithm "none"](https://datatracker.ietf.org/doc/html/rfc7518#section-3.6)
- OWASP: [JSON Web Token for Java Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- Common Weakness Enumeration: [CWE-347](https://cwe.mitre.org/data/definitions/347.html)
