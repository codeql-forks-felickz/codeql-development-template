# JWT payload decoded without signature verification

A JSON Web Token (JWT) has three base64url-encoded segments separated by `.`: a header, a payload with the claims, and a signature. The claims can only be trusted after the signature has been checked against a trusted key. Anyone can create a token with any payload, for example one that claims an administrator role.

This query flags code that splits a token on `.` and base64-decodes the payload segment (index `1`) when the signature segment (index `2`) of the same token is never read. Claims decoded this way have not been authenticated (CWE-345, CWE-347).

## Recommendation

Do not parse JWT claims by hand. Use a JWT library such as `System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler.ValidateToken` or `Microsoft.IdentityModel.JsonWebTokens.JsonWebTokenHandler.ValidateTokenAsync`, with `TokenValidationParameters` that require a valid signature. Read the claims from the validated result.

If the token was already validated somewhere else (for example by a remote authentication service), read the claims from that validated result, not from the raw token string.

## Example

In the following example, the payload is decoded and the `roles` claim is trusted without checking the signature. An attacker can send a forged token with `"roles": ["ADMIN"]`:

```csharp
public static IList<string> GetRoles(string jwt)
{
    var payload = jwt.Split('.')[1];
    payload = payload.PadRight(payload.Length + (4 - payload.Length % 4) % 4, '=');
    var json = Encoding.UTF8.GetString(Convert.FromBase64String(payload)); // BAD
    return JObject.Parse(json)["roles"].Values<string>().ToList();
}
```

The following example validates the token signature before it reads any claims:

```csharp
public static IEnumerable<string> GetRoles(string jwt, SecurityKey key)
{
    var parameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = key,
        ValidIssuer = "https://issuer.example",
        ValidAudience = "my-api"
    };
    var principal = new JwtSecurityTokenHandler().ValidateToken(jwt, parameters, out _); // GOOD
    return principal.FindAll(ClaimTypes.Role).Select(c => c.Value);
}
```

## References

- [CWE-345: Insufficient Verification of Data Authenticity](https://cwe.mitre.org/data/definitions/345.html)
- [CWE-347: Improper Verification of Cryptographic Signature](https://cwe.mitre.org/data/definitions/347.html)
- [RFC 7519: JSON Web Token (JWT)](https://www.rfc-editor.org/rfc/rfc7519)
- [OWASP: JSON Web Token Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
