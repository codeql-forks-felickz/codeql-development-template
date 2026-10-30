# Uncontrolled search path element

Environment variables such as `PATH`, `LD_LIBRARY_PATH` and `LD_PRELOAD` decide where the operating system looks for programs and shared libraries. If an application sets one of these variables from user-controlled data (for example bytes read from a socket, the console, a file or another environment variable), an attacker can add a directory they control. Any later unqualified program launch or library load may then run the attacker's code with the application's privileges.

This query finds untrusted data that reaches:

- `putenv`, `_putenv` or `_wputenv`, when the `NAME=value` string assigns a search-path variable or the variable name is not a known constant, and
- `setenv`, `_putenv_s`, `_wputenv_s` or `SetEnvironmentVariable[A|W]`, when the variable name is a search-path variable.

## Recommendation

Do not build search-path variables from untrusted input. Set them to a fixed, trusted value, or validate each element against an allowlist of trusted absolute directories.

## Example

The following code appends data received from a socket to `PATH`:

```c
char data[250] = "PATH=";
size_t len = strlen(data);
recv(sock, data + len, sizeof(data) - len - 1, 0);
putenv(data); // BAD: attacker controls the search path
```

Use a fixed, trusted value instead:

```c
char data[250] = "PATH=";
strcat(data, "/bin");
putenv(data); // GOOD: constant search path
```

## References

- MITRE: [CWE-427: Uncontrolled Search Path Element](https://cwe.mitre.org/data/definitions/427.html).
