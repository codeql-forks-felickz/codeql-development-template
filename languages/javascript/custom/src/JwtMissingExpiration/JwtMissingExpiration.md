# JWT issued without expiration

A JSON Web Token (JWT) is a bearer credential: anyone who holds a validly signed token is accepted by every service that trusts the signing key. If the token has no expiration (`exp`) claim, it remains valid forever. Logging out, rotating a password, or revoking a role then has no effect on tokens that were already issued, and a token that leaks (for example through logs, browser storage, or a compromised device) can be replayed indefinitely. This is an instance of insufficient session expiration (CWE-613).

This query flags calls that sign a JWT whose payload is an object literal without an `exp` property, when no expiration is configured in any other way. It recognizes:

- `encode` from `jwt-simple`, which has no expiration option;
- `sign` from `jsonwebtoken` without an `expiresIn` option;
- `SignJWT` builders from `jose` on which `setExpirationTime` is never called.

## Recommendation

Always give issued tokens a short lifetime. Either add an `exp` claim to the payload, or use the library option that sets it (`expiresIn` for `jsonwebtoken`, `setExpirationTime` for `jose`). Pair short-lived access tokens with refresh tokens or server-side revocation if longer sessions are required.

## Example

The following example issues an access token with no expiration:

```javascript
const jwt = require('jsonwebtoken')

function issueAccessToken(user) {
  // BAD: the token has no `exp` claim and is valid forever
  return jwt.sign({ sub: user.id, roles: user.roles }, process.env.JWT_SECRET, {
    algorithm: 'HS256'
  })
}
```

The token can be used for as long as the signing key is trusted. The fixed version sets a 15 minute lifetime with the `expiresIn` option:

```javascript
const jwt = require('jsonwebtoken')

function issueAccessToken(user) {
  // GOOD: the token expires after 15 minutes
  return jwt.sign({ sub: user.id, roles: user.roles }, process.env.JWT_SECRET, {
    algorithm: 'HS256',
    expiresIn: '15m'
  })
}
```

## References

- MITRE: [CWE-613: Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html).
- IETF: [RFC 7519, section 4.1.4: "exp" (Expiration Time) Claim](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4).
- OWASP: [JSON Web Token Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html).
- jsonwebtoken: [jwt.sign options](https://github.com/auth0/node-jsonwebtoken#jwtsignpayload-secretorprivatekey-options-callback).
- jose: [SignJWT](https://github.com/panva/jose/blob/main/docs/jwt/sign/classes/SignJWT.md).
- Common Weakness Enumeration: [CWE-613](https://cwe.mitre.org/data/definitions/613.html).
