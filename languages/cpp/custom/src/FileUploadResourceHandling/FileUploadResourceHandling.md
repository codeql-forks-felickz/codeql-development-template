# Insecure handling of security-sensitive resources

This query reports C/C++ code that lets untrusted or sensitive data control security-sensitive resources. It covers patterns that the standard CodeQL C/C++ queries do not report:

| CWE               | Pattern                                                                                                                                                               | Why the standard queries miss it                                                                      |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| CWE-15            | Untrusted data (for example from `recv` or `fgets`) used to change a system setting with `SetComputerName*`, `sethostname` or `setdomainname`.                        | No standard query models these APIs.                                                                  |
| CWE-114           | Untrusted data used as the library path of `LoadLibraryExA`/`LoadLibraryExW`.                                                                                         | `cpp/uncontrolled-process-operation` only models `LoadLibrary`, `LoadLibraryA` and `LoadLibraryW`.    |
| CWE-247 / CWE-350 | A host name from a reverse DNS lookup (`gethostbyaddr`, `getnameinfo`) compared to make a decision, such as granting access.                                          | `cpp/user-controlled-bypass` does not treat reverse DNS results as untrusted.                         |
| CWE-428           | `CreateProcess*` called with a NULL application name and a writable `char[]` command line, initialized from a literal whose executable path has spaces and no quotes. | `cpp/unsafe-create-process-call` only follows literals and `char *` pointers, not array initializers. |
| CWE-535           | A password or other sensitive data written to standard error (`fprintf(stderr, ...)`, `fputs`, `perror`, `std::cerr`, `std::clog`).                                   | `cpp/cleartext-storage-file` deliberately excludes the standard streams.                              |

Attackers can use these patterns to rename the host, load and run their own DLL, get past host-name access checks by controlling reverse DNS (PTR) records, run a planted executable such as `C:\Program.exe`, or read credentials from logs and consoles.

## Recommendation

- Do not change system settings based on unauthenticated input. Authenticate and authorize the request, and validate the value against an allow-list.
- Load libraries only from fully qualified, trusted paths. Do not build library paths from user input. Use `LOAD_LIBRARY_SEARCH_SYSTEM32` or similar flags to restrict the search path.
- Never use host names from reverse DNS for security decisions. Authenticate the peer with a cryptographic mechanism such as TLS client certificates.
- Quote the executable path in the command line, or pass the full path as the application name.
- Never write passwords or other secrets to error output or logs.

## Example

The following code sets the computer name from data read from a socket:

```c
recv(acceptSocket, data, 99, 0);
SetComputerNameA(data); // BAD
```

The following code grants access based on a reverse DNS lookup:

```c
hostEntry = gethostbyaddr((char *)&peer.sin_addr, sizeof(peer.sin_addr), AF_INET);
if (hostEntry != NULL && strcmp(hostEntry->h_name, "trustme.example.com") == 0) { // BAD
  grantAccess();
}
```

The following code makes Windows try to run `C:\Program.exe` first:

```c
char commandLine[] = "C:\\Program Files\\GoodApp arg1 arg2";
CreateProcessA(NULL, commandLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi); // BAD
```

Quote the executable path:

```c
char commandLine[] = "\"C:\\Program Files\\GoodApp\" arg1 arg2";
CreateProcessA(NULL, commandLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi); // GOOD
```

The following code writes a password to standard error:

```c
fprintf(stderr, "User attempted access with password: %s\n", password); // BAD
fprintf(stderr, "User attempted access\n");                             // GOOD
```

## Related standard queries

Some related patterns are already reported by standard queries, so this query does not report them again:

- `gets` calls: `cpp/dangerous-function-overflow` (CWE-242, default suite).
- Untrusted data passed to `LoadLibrary`/`LoadLibraryA`/`LoadLibraryW`: `cpp/uncontrolled-process-operation` (CWE-114, `security-extended` suite).
- Unquoted command lines as literals or `char *`: `cpp/unsafe-create-process-call` (CWE-428, `security-extended` suite).

## References

- CWE-15: [External Control of System or Configuration Setting](https://cwe.mitre.org/data/definitions/15.html).
- CWE-114: [Process Control](https://cwe.mitre.org/data/definitions/114.html).
- CWE-247: [Reliance on DNS Lookups in a Security Decision](https://cwe.mitre.org/data/definitions/247.html) (see also [CWE-350](https://cwe.mitre.org/data/definitions/350.html)).
- CWE-428: [Unquoted Search Path or Element](https://cwe.mitre.org/data/definitions/428.html).
- CWE-535: [Exposure of Information Through Shell Error Message](https://cwe.mitre.org/data/definitions/535.html).
- Microsoft: [Dynamic-Link Library Security](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-security).
- Microsoft: [CreateProcessA function](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa).
