# JWT identity from unverified token or verification without algorithm allowlist

A JSON Web Token (JWT) only proves who sent a request after its signature has been checked. This query flags two common mistakes:

1. **Unverified decoding (CWE-347).** The caller identity comes from a token that was decoded but never verified. Examples include `jsonwebtoken.decode`, `jwt-decode`, `jws.decode`, `jose.decodeJwt`, and manually base64(url)-decoding the payload segment (`token.split(".")[1]`). An attacker can then send a token with any claims they like.
2. **No algorithm allowlist (CWE-327).** A token is verified with an asymmetric public key, but no `algorithms` allowlist is set. This applies to `express-jwt`, `koa-jwt`, `jsonwebtoken.verify`, and the two-argument form of `jws.verify`. Without the allowlist, the library may accept the algorithm named in the token header. If an attacker switches the header to `HS256`, the public key (which is not secret) is used as the HMAC secret, so the attacker can forge valid tokens. This is known as RS/HS algorithm confusion.

## Recommendation

Use a verifying API such as `jwt.verify` and read the identity from the value it returns. Do not read it from a decoded but unverified token.

Always pass an explicit `algorithms` allowlist that matches the key type, for example `["RS256"]` for an RSA public key. With `jws`, use `jws.verify(signature, algorithm, key)`.

## Example

The following code reads the identity from an unverified token and sets up `express-jwt` with a public key but no algorithm allowlist:

```javascript
const jwt = require('jsonwebtoken')
const expressJwt = require('express-jwt')

app.use(expressJwt({ secret: publicKey })) // BAD: no algorithms allowlist

app.get('/profile', (req, res) => {
  const claims = jwt.decode(req.headers.authorization) // BAD: not verified
  res.send(claims.username)
})
```

The fix is to pin the accepted algorithms and verify the token before using its claims:

```javascript
app.use(expressJwt({ secret: publicKey, algorithms: ['RS256'] })) // GOOD

app.get('/profile', (req, res) => {
  const claims = jwt.verify(req.headers.authorization, publicKey, { algorithms: ['RS256'] }) // GOOD
  res.send(claims.username)
})
```

## Limitations

- A token counts as verified if the same user-provided value also reaches a call whose name contains `verif`. The query does not check that verification happens before decoding.
- Public keys are recognized heuristically: by variable or property name (`public`, `pubkey`, `cert`), by PEM `PUBLIC KEY`/`CERTIFICATE` literals, or by `fs.readFileSync` of a `.pub`/`.crt`/`.cer`/`public`/`cert` path.
- The query does not check whether an API Gateway authorizer is attached to the endpoint (for example in an AWS SAM template).

## References

- [CWE-347: Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)
- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
- [Auth0: Critical vulnerabilities in JSON Web Token libraries](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
- [express-jwt: `algorithms` option](https://github.com/auth0/express-jwt#required-parameters)
