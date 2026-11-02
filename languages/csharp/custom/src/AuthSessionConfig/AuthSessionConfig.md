# Insecure authentication, session or web configuration

ASP.NET and ASP.NET Core applications configure authentication, session management and token validation through `Web.config` settings and code. Several of these settings silently weaken the application when they are disabled or set to extreme values:

- `<pages enableViewStateMac="false">` or `viewStateEncryptionMode="Never"` disables ViewState integrity or confidentiality, allowing ViewState tampering (CWE-554).
- A membership provider `minRequiredPasswordLength`, or ASP.NET Core Identity `PasswordOptions.RequiredLength`, below 8 permits easily guessed passwords (CWE-521).
- A `<sessionState>` or `<forms>` `timeout`, or `HttpSessionState.Timeout`, longer than one day (1440 minutes) means sessions only rarely expire, widening the window in which a stolen session can be used (CWE-613).
- Setting `LockoutOptions.AllowedForNewUsers` to `false` disables account lockout, allowing unlimited password guessing (CWE-307).
- Setting `ValidateIssuer`, `ValidateAudience`, `ValidateLifetime` or `RequireSignedTokens` of `TokenValidationParameters` to `false` makes the application accept tokens that were issued by other issuers, for other services, that have expired, or that are not signed (CWE-287).
- Calling `Response.Redirect` without ending the request (ASP.NET Core always, or `Redirect(url, false)` / `Redirect(url)` in ASP.NET) lets the following code keep running; if that code performs privileged operations or writes sensitive data, an attacker who ignores the redirect still benefits from it (CWE-698).

## Recommendation

Keep ViewState MAC validation and encryption enabled, require passwords of at least 8 characters, use a bounded session and authentication-ticket timeout, keep account lockout enabled, validate the issuer, audience, lifetime and signature of every token, and `return` (or end the response) immediately after redirecting.

## Example

The following configuration and code contain several of these weaknesses:

```xml
<system.web>
  <pages enableViewStateMac="false" viewStateEncryptionMode="Never" />
  <sessionState mode="InProc" timeout="43200" />
</system.web>
```

```csharp
var parameters = new TokenValidationParameters
{
    ValidateIssuer = false,   // BAD
    ValidateAudience = false  // BAD
};

if (!loggedIn)
{
    Response.Redirect("/login"); // BAD: execution continues
}
Response.Write(secret);
```

Fixed versions:

```xml
<system.web>
  <pages enableViewStateMac="true" viewStateEncryptionMode="Always" />
  <sessionState mode="InProc" timeout="20" />
</system.web>
```

```csharp
var parameters = new TokenValidationParameters
{
    ValidateIssuer = true,
    ValidIssuer = "https://issuer.example",
    ValidateAudience = true,
    ValidAudience = "my-api"
};

if (!loggedIn)
{
    Response.Redirect("/login");
    return;
}
Response.Write(secret);
```

## References

- OWASP: [Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html).
- OWASP: [Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html).
- Microsoft Learn: [Configure ASP.NET Core Identity](https://learn.microsoft.com/aspnet/core/security/authentication/identity-configuration).
- Microsoft Learn: [TokenValidationParameters Class](https://learn.microsoft.com/dotnet/api/microsoft.identitymodel.tokens.tokenvalidationparameters).
- Common Weakness Enumeration: [CWE-287](https://cwe.mitre.org/data/definitions/287.html), [CWE-307](https://cwe.mitre.org/data/definitions/307.html), [CWE-521](https://cwe.mitre.org/data/definitions/521.html), [CWE-554](https://cwe.mitre.org/data/definitions/554.html), [CWE-613](https://cwe.mitre.org/data/definitions/613.html), [CWE-698](https://cwe.mitre.org/data/definitions/698.html).
