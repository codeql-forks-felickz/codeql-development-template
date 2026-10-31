# Predictable value used as a security token

Session identifiers, authentication tokens, captchas, one-time passwords, and approval or reset codes must not be guessable. Values that come from `System.Random` or from the system clock (`DateTime.Now`, `DateTime.UtcNow`, `Environment.TickCount`, `Stopwatch.GetTimestamp`) are predictable. An attacker who knows roughly when a value was generated, or who has seen a few earlier outputs, can reproduce or brute-force it and take over other users' sessions or bypass the check.

This query reports such values when they are assigned to a sensitively named variable, field, property, or parameter (for example `sessionId`, `token`, `captcha`, `ApprovalCode`), or when they are used as the value of a session or authentication cookie. Values that are also derived from a cryptographically secure generator are not reported. Password-named targets are left to the standard `cs/insecure-randomness` query.

## Recommendation

Generate security-sensitive values with a cryptographically secure random number generator such as `System.Security.Cryptography.RandomNumberGenerator`. Where possible, use the session and anti-forgery mechanisms built into the framework instead of creating your own identifiers.

## Example

The following example builds a session cookie from the current time and a visitor counter. The value is easy to predict:

```csharp
HttpCookie sessionCookie = new HttpCookie("amSessionId");
sessionCookie.Value = DateTime.Now.Hour.ToString() + DateTime.Now.Minute.ToString()
    + DateTime.Now.Second.ToString() + visitors.ToString(); // BAD
```

The following example uses a cryptographically secure generator instead:

```csharp
HttpCookie sessionCookie = new HttpCookie("amSessionId");
sessionCookie.Value = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)); // GOOD
```

## References

- OWASP: [Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html).
- Microsoft Learn: [RandomNumberGenerator Class](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.randomnumbergenerator).
- Common Weakness Enumeration: [CWE-330](https://cwe.mitre.org/data/definitions/330.html).
- Common Weakness Enumeration: [CWE-338](https://cwe.mitre.org/data/definitions/338.html).
