# Sensitive data in JWT payload

A JSON Web Token (JWT) payload is only Base64url-encoded, not encrypted. The signature protects it from tampering, but anyone who has the token can decode it and read every claim. Tokens are routinely stored in browser storage, sent in headers and URLs, and written to logs, so they should be treated as readable by the client and by anyone who intercepts them.

If a password (even a hash) or a whole database record that contains a password field is signed into a JWT, the credential is exposed to everyone who sees the token.

## Recommendation

Only put the claims a consumer needs into the payload, such as a user identifier and roles. Build the payload explicitly from non-sensitive fields instead of passing the whole user record, or remove credential fields before signing. If confidential claims really are required, use an encrypted token (JWE) instead.

## Example

The following example signs the complete user document returned by the database into the token. The document includes the `password` field, so the password is readable by anyone holding the token:

```javascript
db.collection('users').findOne({ email: email, password: pass }, function (err, user) {
  if (user !== null) {
    const token = jwt.sign({ user }, SESSION_SECRET); // BAD: includes user.password
    res.json({ token });
  }
});
```

The following example only signs non-sensitive fields of the user document:

```javascript
db.collection('users').findOne({ email: email, password: pass }, function (err, user) {
  if (user !== null) {
    const token = jwt.sign({ id: user._id, email: user.email }, SESSION_SECRET); // GOOD
    res.json({ token });
  }
});
```

## References

- IETF: [RFC 7519 - JSON Web Token (JWT), Section 12 Privacy Considerations](https://datatracker.ietf.org/doc/html/rfc7519#section-12).
- OWASP: [JSON Web Token Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html#token-information-exposure).
- Common Weakness Enumeration: [CWE-522](https://cwe.mitre.org/data/definitions/522.html).
- Common Weakness Enumeration: [CWE-312](https://cwe.mitre.org/data/definitions/312.html).
