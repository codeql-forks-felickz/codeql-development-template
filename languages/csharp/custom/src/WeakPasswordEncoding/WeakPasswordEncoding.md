# Stored password protected only by Base64 encoding

Base64 is a reversible encoding, not encryption. If a password is stored Base64-encoded in a file, in the registry, or in source code, anyone who can read the stored value can decode the plaintext password.

This query reports values that are read from a file, from the Windows registry, or from a hard-coded string, decoded with `Convert.FromBase64String` (or `Convert.FromBase64CharArray`), and then used as a password, for example as the `password` argument of `NetworkCredential` or as a `Password` property. Values that pass through a decryption call (any call into `System.Security.Cryptography`, or a method whose name contains `Decrypt` or `Unprotect`) are not reported. Base64 decoding of request data, such as an HTTP Basic `Authorization` header, is not reported either.

## Recommendation

Do not store passwords in a reversible form. Prefer a secret store (for example Azure Key Vault, the Windows Credential Manager, or DPAPI through `ProtectedData`) or strong encryption with a properly protected key. Where the application only needs to check a password, store a salted hash computed with a slow password-hashing function instead.

## Example

The following example reads a Base64-encoded password from a file and uses it as a network credential:

```csharp
string password = new StreamReader("password.txt").ReadLine();
string decPass = Encoding.UTF8.GetString(Convert.FromBase64String(password));
var credential = new NetworkCredential("user", decPass, ""); // BAD
```

The following example stores the password encrypted with DPAPI instead:

```csharp
byte[] blob = File.ReadAllBytes("password.bin");
string decPass = Encoding.UTF8.GetString(
    ProtectedData.Unprotect(blob, null, DataProtectionScope.CurrentUser));
var credential = new NetworkCredential("user", decPass, ""); // GOOD
```

## References

- OWASP: [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
- Microsoft Learn: [ProtectedData Class](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.protecteddata).
- Common Weakness Enumeration: [CWE-261](https://cwe.mitre.org/data/definitions/261.html).
