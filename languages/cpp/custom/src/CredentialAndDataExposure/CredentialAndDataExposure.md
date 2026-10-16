# Plaintext password read from a file

Storing a password in plaintext in a file means that anyone who can read the file (other local users, backups, a compromised service account, an attacker with a file disclosure bug) obtains a credential that can be used directly. This query finds passwords that are read from a file (for example with `fgets`, `fgetws`, `fread`, `fscanf` or `ReadFile` on a handle returned by `fopen`, `_wfopen`, `fopen_s` or `CreateFile`) and then passed, without being decrypted, to an authentication API such as `LogonUser`, `LogonUserEx`, `CreateProcessWithLogonW`, `mysql_real_connect` or `ldap_simple_bind_s`.

## Recommendation

Do not store passwords in plaintext. Prefer an operating-system credential store (for example the Windows Credential Manager or DPAPI), a secrets manager, or an authentication mechanism that does not need a stored password. If a password must be stored in a file, store it encrypted and decrypt it immediately before use (for example with `CryptDecrypt` or `CryptUnprotectData`), and restrict access to the file.

## Example

In the following example, the password is read from `passwords.txt` and passed directly to `LogonUserA`:

```c
void bad()
{
    char data[100] = "";
    HANDLE pHandle;
    FILE *pFile = fopen("passwords.txt", "r");
    if (pFile != NULL)
    {
        fgets(data, 100, pFile);
        fclose(pFile);
    }
    LogonUserA("User", "Domain", data, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &pHandle);
}
```

In the following example, the file contains an encrypted password, which is decrypted in place before it is used:

```c
void good(HCRYPTKEY hKey)
{
    char data[100] = "";
    DWORD dataLen = 100;
    HANDLE pHandle;
    FILE *pFile = fopen("passwords.txt", "r");
    if (pFile != NULL)
    {
        fgets(data, 100, pFile);
        fclose(pFile);
    }
    if (!CryptDecrypt(hKey, 0, TRUE, 0, (BYTE *)data, &dataLen))
    {
        return;
    }
    LogonUserA("User", "Domain", data, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &pHandle);
}
```

## References

- Common Weakness Enumeration: [CWE-256: Plaintext Storage of a Password](https://cwe.mitre.org/data/definitions/256.html).
- OWASP: [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
- Microsoft Learn: [CryptProtectData function](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata).
