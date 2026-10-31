# Unchecked return value of privilege-changing function

Functions such as `ImpersonateNamedPipeClient`, `ImpersonateLoggedOnUser`, `SetThreadToken`, `RevertToSelf` and the POSIX `setuid` family change the security context of the calling thread or process. They can fail. If the result is ignored, the program continues to run with its original (often more privileged) security context while assuming the change succeeded, which can lead to privilege escalation (CWE-273).

The set of functions is defined by the `privilegeChangeFunctionModel` extensible predicate (see `lib/PrivilegeModels.qll`) and populated by the data extension in `ext/privilege.model.yml`. Add rows there to cover additional APIs.

## Recommendation

Always check the return value of privilege-changing functions and stop the privileged operation (or terminate) if the call fails.

## Example

```c
void bad(HANDLE hPipe)
{
    ImpersonateNamedPipeClient(hPipe); // BAD: failure is not detected
    doWorkAsClient();
}

void good(HANDLE hPipe)
{
    if (!ImpersonateNamedPipeClient(hPipe)) // GOOD
    {
        exit(1);
    }
    doWorkAsClient();
}
```

## References

- [CWE-273: Improper Check for Dropped Privileges](https://cwe.mitre.org/data/definitions/273.html)
- [CWE-252: Unchecked Return Value](https://cwe.mitre.org/data/definitions/252.html)
- [ImpersonateNamedPipeClient function](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
