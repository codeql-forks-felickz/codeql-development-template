# JWT parsed after its signature was stripped

JJWT's `parseClaimsJwt`, `parsePlaintextJwt`, `parseUnsecuredClaims`, `parseUnsecuredContent` and single-argument `parse` methods accept unsigned tokens. Code that removes the signature from a client-supplied JWT and then passes it to one of these methods reads the claims without checking that they were signed, so an attacker can change any claim.

The stock `java/missing-jwt-signature-check` query only reports these methods when a signing key was configured on the parser. This query reports them when the token passed in was rebuilt without its signature, either by concatenating split parts 0 and 1 or with `token.substring(0, token.lastIndexOf('.') ...)`.

## Recommendation

Parse the full token with a method that verifies the signature, such as `parseClaimsJws` (JJWT 0.11) or `parseSignedClaims` (JJWT 0.12), on a parser configured with the expected key.

## Example

The following code strips the signature and trusts the remaining claims:

```java
String[] parts = token.split("\\.");
String unsigned = parts[0] + "." + parts[1] + ".";
Claims claims = Jwts.parser().parseClaimsJwt(unsigned).getBody(); // BAD
```

The token should be parsed and verified as a whole instead:

```java
Claims claims = Jwts.parser().setSigningKey(key).parseClaimsJws(token).getBody(); // GOOD
```

## References

- JJWT: [Reading a JWS](https://github.com/jwtk/jjwt#reading-a-jws)
- OWASP: [JSON Web Token for Java Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- Common Weakness Enumeration: [CWE-347](https://cwe.mitre.org/data/definitions/347.html)
