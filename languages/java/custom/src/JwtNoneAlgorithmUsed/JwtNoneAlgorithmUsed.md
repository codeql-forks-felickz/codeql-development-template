# JWT signed or accepted without signature verification

The JSON Web Token (JWT) `none` algorithm produces tokens with an empty signature. A token signed with `none` carries no integrity or authenticity guarantee, so anyone can create or modify one. A verifier configured for `none` accepts such unsigned tokens.

This query finds `com.auth0.jwt.algorithms.Algorithm.none()` values that are used to sign tokens (`JWTCreator.Builder.sign`) or to build a verifier (`JWT.require`).

It also finds a narrow unsigned-token acceptance pattern: a string claim read through Auth0 `JWT.decode`, `DecodedJWT.getClaim`, and `Claim.asString` is compared using `String.equals` or `equalsIgnoreCase` to `HttpSession.getAttribute` with the same constant claim name. The matching branch returns `true` or updates a Spring `Model` through `addAttribute` without successful signature verification before that use. Decoding alone does not authenticate a token, even if its username matches the current session. This comparison therefore permits forged or unsigned tokens to be accepted.

## Recommendation

Sign and verify tokens with a strong algorithm and a server-side key, for example `Algorithm.HMAC256(secret)` or `Algorithm.RSA256(publicKey, privateKey)`.

Before trusting claims, use `JWT.require(algorithm).build().verify(token)` rather than `JWT.decode(token)`.

## Example

The following code issues tokens that have no signature:

```java
String token = JWT.create().withClaim("username", username).sign(Algorithm.none()); // BAD
```

The token should be signed with a secret key instead:

```java
String token = JWT.create().withClaim("username", username).sign(Algorithm.HMAC256(secret)); // GOOD
```

Merely decoding a token and checking its username against the session does not check its signature:

```java
DecodedJWT decoded = JWT.decode(token);
String username = decoded.getClaim("username").asString();
if (username.equalsIgnoreCase((String) session.getAttribute("username"))) { // BAD
    return true;
}
```

Instead, obtain the claims from the verified token:

```java
DecodedJWT decoded = JWT.require(Algorithm.HMAC256(secret)).build().verify(token);
String username = decoded.getClaim("username").asString();
if (username.equalsIgnoreCase((String) session.getAttribute("username"))) { // GOOD
    return true;
}
```

## Known limitations

The decoded-claim branch is method-local and follows value-preserving local aliases. It requires the same compile-time constant claim/session key and a string equality comparison controlling a matching-branch `return true` or Spring `Model.addAttribute` use. Other acceptance sinks are not modeled. It does not report decoding or logging alone, or generic map reads. Servlet session types are recognized through the existing library for both `javax.servlet` and `jakarta.servlet`.

Auth0 `getClaim` is recognized on its declaring interface, `Payload`, inherited by `DecodedJWT`; the receiver must still flow from `JWT.decode`.

Explicit Auth0 `JWTVerifier.verify(token)`, `JWTVerifier.verify(decodedJWT)` (the interface or concrete class), or `Algorithm.verify(decodedJWT)` suppress a finding only when successful verification dominates the acceptance use on the same token, including local aliases. Verification may precede the comparison or gate success inside its matching branch. Verification of a different token, verification after a model update or bypassed on a successful return, conditional verification that does not gate success, or an ignored verification failure do not suppress it. Unsupported verification helpers are not modeled; method names or the mere presence of a verifier elsewhere are not used as evidence of verification.

Verification with a known `Algorithm.none()` is not a signature check and does not suppress the comparison. The query recognizes local algorithm aliases and local `JWT.require(algorithm).build()` verifier construction, using the existing algorithm-flow configuration to identify `none` at `require`. It does not whitelist cryptographic algorithms or infer configurations hidden behind unsupported helpers.

## References

- RFC 7518: [Using the Algorithm "none"](https://datatracker.ietf.org/doc/html/rfc7518#section-3.6)
- OWASP: [JSON Web Token for Java Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- Common Weakness Enumeration: [CWE-347](https://cwe.mitre.org/data/definitions/347.html)
