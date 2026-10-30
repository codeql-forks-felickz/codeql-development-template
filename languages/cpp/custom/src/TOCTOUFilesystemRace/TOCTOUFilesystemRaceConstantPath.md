# Time-of-check time-of-use filesystem race condition on a constant path

Checking the state of a file (for example with `access` or `stat`) and then operating on it by name (for example with `fopen`, `remove` or `chmod`) is a time-of-check time-of-use (TOCTOU) race condition. Between the check and the use, an attacker can replace the file, for example with a symbolic link to `/etc/passwd`. This is especially easy when the file name is a predictable constant such as `/tmp/file.tmp`.

The standard `cpp/toctou-race-condition` query only relates a check and a use when both refer to the same local variable. This query reports the same pattern when the path is a constant: the same string literal (including via a macro) or the same global variable.

## Recommendation

Do not check a file by name and then operate on it by name. Open the file once and perform any checks on the resulting file descriptor (for example with `fstat`). When creating a file, use `open` with `O_CREAT | O_EXCL` (or `fopen` with the `"x"` mode), and prefer `mkstemp` over predictable temporary file names.

## Example

The following code checks whether `/tmp/file.tmp` exists and then opens it for writing. An attacker can create a symbolic link at that path after the check.

```c
#define MY_TMP_FILE "/tmp/file.tmp"

if (!access(MY_TMP_FILE, F_OK)) {
    return EXIT_FAILURE;
}
FILE *f = fopen(MY_TMP_FILE, "w"); // BAD
```

Instead, create the file exclusively, so that the call fails if the path already exists:

```c
int fd = open(MY_TMP_FILE, O_WRONLY | O_CREAT | O_EXCL, 0600); // GOOD
```

## References

- CWE-367: [Time-of-check Time-of-use (TOCTOU) Race Condition](https://cwe.mitre.org/data/definitions/367.html).
- CERT C: [FIO45-C. Avoid TOCTOU race conditions while accessing files](https://wiki.sei.cmu.edu/confluence/display/c/FIO45-C.+Avoid+TOCTOU+race+conditions+while+accessing+files).
