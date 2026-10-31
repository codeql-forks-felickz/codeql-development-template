# Insecure temporary file opened without exclusive creation

Functions such as `tmpnam`, `tmpnam_r`, `tempnam` and `mktemp` only generate a file name that does not exist at the moment of the call. They do not create the file. If the program later creates the file with a call that does not fail when the path already exists (for example `open` with `O_CREAT` but without `O_EXCL`, `creat`, or `fopen` with a `"w"` or `"a"` mode), a local attacker can create a file or a symbolic link at the predicted path in the window between name generation and use. The program may then write to, truncate or disclose an attacker-chosen file, which can lead to data corruption or privilege escalation (CWE-377, CWE-367).

## Recommendation

Use a function that atomically creates and opens a unique temporary file, such as `mkstemp`, `mkostemp` or `tmpfile`. If a name must be generated separately, open it with `O_CREAT | O_EXCL` (or the C11 `"x"` mode for `fopen`) so the call fails if the path already exists.

## Example

In the following example, the name returned by `tmpnam` is opened with `O_CREAT` but without `O_EXCL`:

```c
char *filename = tmpnam(NULL);
int fd = open(filename, O_RDWR | O_CREAT, S_IREAD | S_IWRITE); // BAD
```

The following example uses `mkstemp`, which creates and opens the file atomically:

```c
char filename[] = "/tmp/fileXXXXXX";
int fd = mkstemp(filename); // GOOD
```

## References

- MITRE: [CWE-377: Insecure Temporary File](https://cwe.mitre.org/data/definitions/377.html).
- MITRE: [CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition](https://cwe.mitre.org/data/definitions/367.html).
- Linux manual page: [mktemp(3)](https://man7.org/linux/man-pages/man3/mktemp.3.html), [tmpnam(3)](https://man7.org/linux/man-pages/man3/tmpnam.3.html), [mkstemp(3)](https://man7.org/linux/man-pages/man3/mkstemp.3.html).
