# JWT parsed after its signature was stripped

JJWT's legacy `parseClaimsJwt`, `parsePlaintextJwt` and single-argument `parse` methods accept unsigned tokens. Modern `parseUnsecuredClaims` and `parseUnsecuredContent` methods require a parser built with `JwtParserBuilder.unsecured()`. Code that removes the signature from a client-supplied JWT and then successfully parses it as unsigned reads the claims without checking that they were signed, so an attacker can change any claim.

The stock `java/missing-jwt-signature-check` query only reports these methods when a signing key was configured on the parser. This query reports them when the token passed in was rebuilt without its signature, either by concatenating split parts 0 and 1 or with `token.substring(0, token.lastIndexOf('.') ...)`. Modern unsecured methods are reported only when local builder configuration flows into their parser.

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

## Known limitations

- Analysis is local to a method; helper methods and configuration stored in fields are not tracked. Builder tracking follows local aliases and fluent `JwtParserBuilder` steps, not arbitrary configuration state or execution ordering. In particular, reusing a builder or calling `unsecured()` after `build()` can associate configuration with an already-built parser.
- Concatenation detection requires direct reads of split parts 0 and 1. Later parts retained through value-preserving local aliases are excluded; arbitrary transformations are not modeled.
- Substring detection requires the same variable for both receivers and a constant period delimiter (a character literal or compile-time string). Receiver aliases and computed delimiters are not recognized. Existing end-offset matching is unchanged.
- Only value-preserving local flow from the stripping expression to the parser argument is tracked. Subsequent string transformations are deliberately not followed.

## References

- JJWT: [Reading a JWS](https://github.com/jwtk/jjwt#reading-a-jws)
- OWASP: [JSON Web Token for Java Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- Common Weakness Enumeration: [CWE-347](https://cwe.mitre.org/data/definitions/347.html)
