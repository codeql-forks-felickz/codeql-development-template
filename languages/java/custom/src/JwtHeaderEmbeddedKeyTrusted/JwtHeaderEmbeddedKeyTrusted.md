# JWT verified with a key taken from the token header

A JSON Web Token (JWT) header may carry a `jwk` member containing a public key. That header is controlled by whoever produced the token. If a validator builds its signature verifier from this embedded key, an attacker can generate their own key pair, sign a forged token with the private key, and embed the matching public key in the header. The signature then verifies successfully.

This query finds Nimbus `JWSVerifier` instances (for example `RSASSAVerifier`, `ECDSAVerifier` or `Ed25519Verifier`) constructed from a key that comes from the token's own header: either `header.get*("jwk")` on a decoded header that is also read for its `alg`, or Nimbus `Header.getJWK()`.

## Recommendation

Only verify tokens with keys that the server trusts: keys from server-side configuration or from a JWK Set fetched from a trusted, pinned URL. If the `jwk` or `kid` header is used at all, use it only to select one of those trusted keys.

## Example

The following validator verifies the token with the key the token supplies:

```java
RSAKey rsaKey = RSAKey.parse(header.getJSONObject("jwk").toString());
JWSVerifier verifier = new RSASSAVerifier(rsaKey.toRSAPublicKey()); // BAD
return SignedJWT.parse(token).verify(verifier);
```

The validator should use a key the server already trusts instead:

```java
JWSVerifier verifier = new RSASSAVerifier(trustedPublicKey); // GOOD
return SignedJWT.parse(token).verify(verifier);
```

## References

- RFC 7515: [JSON Web Key header parameter](https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.3)
- PortSwigger: [JWT header parameter injection via jwk](https://portswigger.net/web-security/jwt#injecting-self-signed-jwts-via-the-jwk-parameter)
- Common Weakness Enumeration: [CWE-347](https://cwe.mitre.org/data/definitions/347.html)
