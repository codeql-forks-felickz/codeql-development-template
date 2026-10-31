# Missing JWT signature check in hand-written JWT decoding

A JSON Web Token (JWT) consists of three base64url-encoded segments separated by dots: a header, a payload containing the claims, and a signature. Applications sometimes decode a token by hand, splitting it on `"."`, base64-decoding the payload segment, and unmarshalling the JSON claims. If the signature segment is never verified, an attacker can forge a token containing arbitrary claims (for example, another user's name) and use it on authenticated endpoints.

The stock `go/missing-jwt-signature-check` query only reports unverified parsing through JWT libraries, so it does not report hand-written decoding.

This query reports user-controlled tokens that are split on `"."`, whose payload segment is base64-decoded with `encoding/base64` and then unmarshalled with `encoding/json`, when neither the function that splits the token nor the function that unmarshals the claims appears to check a signature. Recognized comparison and verification calls suppress an alert only when a read of the token's third (signature) segment reaches one of their arguments. Calls to functions whose names contain `verif` or `signature` also suppress an alert.

## Known limitations

The query does not check whether a verification result actually gates use of the claims. It also does not recognize verification performed solely in a differently named helper function.

## Recommendation

Use a maintained JWT library (for example `github.com/golang-jwt/jwt/v5`) and parse tokens with a function that verifies the signature using an expected algorithm and key. If tokens must be decoded by hand, verify the signature over `header + "." + payload` with a constant-time comparison before trusting any claim.

## Example

The following example decodes the claims of a token from the `Authorization` header without checking its signature:

```go
t := strings.Split(token, ".")
c, err := base64.StdEncoding.WithPadding(base64.NoPadding).DecodeString(t[1])
if err != nil {
	return claims, err
}
err = json.Unmarshal(c, &claims) // BAD: signature in t[2] is never verified
```

The token should instead be parsed with a library that verifies the signature:

```go
claims := &Claims{}
_, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
	return jwtKey, nil
}, jwt.WithValidMethods([]string{"HS256"}))
```

## References

- RFC 7519: [JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519).
- OWASP: [JSON Web Token for Java Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html).
- Common Weakness Enumeration: [CWE-347](https://cwe.mitre.org/data/definitions/347.html).
