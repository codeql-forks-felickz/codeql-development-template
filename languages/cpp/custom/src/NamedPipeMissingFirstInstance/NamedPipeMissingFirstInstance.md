# Named pipe created without FILE_FLAG_FIRST_PIPE_INSTANCE

When a named pipe server calls `CreateNamedPipe` without `FILE_FLAG_FIRST_PIPE_INSTANCE` in `dwOpenMode`, the call succeeds even if another process has already created an instance of the same pipe name. A malicious local process can pre-create the pipe ("named-pipe squatting") and then receive, tamper with, or impersonate the clients that connect to it (CWE-284).

The query reports calls whose open mode is a compile-time constant that lacks the flag. The named-pipe creation functions are defined by the `namedPipeCreationFunctionModel` extensible predicate (see `lib/PrivilegeModels.qll`) and populated by `ext/privilege.model.yml`.

Servers that deliberately create additional instances of a pipe they already own cannot use the flag for those later instances; such calls may be reported and can be dismissed if the first instance is created with the flag.

## Recommendation

Include `FILE_FLAG_FIRST_PIPE_INSTANCE` in the open mode when creating the first instance of a named pipe, and fail if the call returns `INVALID_HANDLE_VALUE`.

## Example

```c
/* BAD: another process may already own an instance of this pipe */
hPipe = CreateNamedPipeA("\\\\.\\pipe\\TestPipe", PIPE_ACCESS_DUPLEX, ...);

/* GOOD */
hPipe = CreateNamedPipeA("\\\\.\\pipe\\TestPipe",
                         PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE, ...);
```

## References

- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
- [CreateNamedPipeA function](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createnamedpipea)
