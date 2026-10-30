# Command executed without a fully qualified path

When a program runs an external command by its bare name (for example `ls -la` or `cmd.exe /c dir`), the operating system locates the executable using the `PATH` environment variable, and on Windows also the current directory. If an attacker can modify `PATH`, or can place a file earlier in the search order, the application will run the attacker's program with its own privileges.

This query finds hard-coded command strings whose program name has no directory component and that flow to a function that resolves the program through the search path: `system`, `_wsystem`, `popen`, `_popen`, `_wpopen`, and the `PATH`-searching `exec*p*` / `_spawn*p*` variants.

## Recommendation

Specify the fully qualified path of the program to run (for example `/usr/bin/ls` or `C:\Windows\System32\cmd.exe`), or resolve it from a trusted, fixed location. Avoid relying on the inherited `PATH`.

## Example

The following code runs `ls` through the search path:

```c
char data[100] = "";
strcpy(data, "ls -la");
system(data); // BAD: `ls` is resolved using PATH
```

Use an absolute path instead:

```c
char data[100] = "";
strcpy(data, "/usr/bin/ls -la");
system(data); // GOOD: fully qualified path
```

## References

- MITRE: [CWE-426: Untrusted Search Path](https://cwe.mitre.org/data/definitions/426.html).
- MITRE: [CWE-427: Uncontrolled Search Path Element](https://cwe.mitre.org/data/definitions/427.html).
