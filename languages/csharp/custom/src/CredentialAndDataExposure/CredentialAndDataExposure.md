# Credential and sensitive data exposure

## Overview

Passwords, token signing keys and payment-card numbers must be protected whenever they are
transmitted, rendered, logged or stored. This query reports several patterns that the standard
`cs/cleartext-storage-of-sensitive-information`, `cs/exposure-of-sensitive-information`,
`cs/hardcoded-credentials` and `cs/hard-coded-symmetric-encryption-key` queries do not cover:

| CWE | Pattern |
| --- | --- |
| CWE-523 | Generated HTML containing a password input in a form whose `action` is an `http://` URL. |
| CWE-200 | A stored credential written to the `Text`/`Value` of a Web Forms control that is not in password mode. |
| CWE-200 | A Razor view that renders a credential property with `@Model.Password`, `Html.DisplayFor`, `Html.TextBoxFor`, `Html.EditorFor` or `<input asp-for="Password">` without `type="password"`. |
| CWE-256 | A model-bound entity whose password property is persisted through Entity Framework (`Add`/`Update`/`Attach`) without first being replaced, for example by a hash. |
| CWE-256, CWE-315 | A password that is only Base64- or otherwise reversibly encoded before being stored in a database, file or cookie. |
| CWE-257 | A password encrypted with a reversible cipher (`CryptoStream`, `ICryptoTransform`, `SymmetricAlgorithm.Encrypt*`) instead of being hashed. |
| CWE-532 | An object whose `ToString()` includes a password property being written to a log. |
| CWE-798 | A hard-coded string or byte array used as the key of a `SymmetricSecurityKey` that signs tokens. |
| CWE-312 | A payment-card number persisted unencrypted in an Entity Framework entity or an XML file. |

## Recommendation

* Store passwords with an adaptive, salted one-way hash such as PBKDF2 (`Rfc2898DeriveBytes`),
  bcrypt or Argon2. Never encode or encrypt them reversibly.
* Never send credentials back to the client: exclude them from view models, render password
  inputs with `type="password"` and keep them out of `ToString()` overrides used for logging.
* Only submit credentials to `https://` endpoints.
* Load signing keys from a secret store or configuration, not from source code.
* Encrypt or tokenize payment-card data and store only a masked number where possible.

## Example

The following controller stores the bound password unchanged and logs it via `ToString()`:

```csharp
public class User
{
    public string Username { get; set; }
    public string Password { get; set; }
    public override string ToString() => $"{Username}:{Password}";
}

[HttpPost]
public async Task<IActionResult> Edit([Bind("Id,Username,Password")] User user)
{
    _logger.LogInformation("Editing " + user);  // BAD: logs the password
    _context.Update(user);                      // BAD: persists the plaintext password
    await _context.SaveChangesAsync();
    return RedirectToAction("Index");
}
```

Hash the password before persisting it, and exclude it from the string representation:

```csharp
public override string ToString() => Username;

[HttpPost]
public async Task<IActionResult> Edit([Bind("Id,Username,Password")] User user)
{
    _logger.LogInformation("Editing " + user);
    user.Password = _hasher.HashPassword(user, user.Password);
    _context.Update(user);
    await _context.SaveChangesAsync();
    return RedirectToAction("Index");
}
```

## Limitations

Razor views are analyzed through the C# code that the Razor source generator produces, which is
available in databases created with `--build-mode=none` or from a build that runs the Razor
generator. Names are matched heuristically (for example `Password`, `Pwd`, `CreditCardNumber`),
so credentials stored under unusual names are not detected.

## References

* OWASP: [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
* OWASP: [Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html).
* Common Weakness Enumeration: [CWE-200](https://cwe.mitre.org/data/definitions/200.html),
  [CWE-256](https://cwe.mitre.org/data/definitions/256.html),
  [CWE-257](https://cwe.mitre.org/data/definitions/257.html),
  [CWE-312](https://cwe.mitre.org/data/definitions/312.html),
  [CWE-315](https://cwe.mitre.org/data/definitions/315.html),
  [CWE-523](https://cwe.mitre.org/data/definitions/523.html),
  [CWE-532](https://cwe.mitre.org/data/definitions/532.html),
  [CWE-798](https://cwe.mitre.org/data/definitions/798.html).
