# Path manipulation function called with a buffer smaller than the maximum path size

## Overview

Windows shell path functions such as `PathAppend`, `PathCombine` and `PathCanonicalize` do not take the size of their output buffer and assume that it can hold `MAX_PATH` (260) characters. POSIX `realpath` similarly assumes that a non-null output buffer holds `PATH_MAX` bytes. Passing a smaller fixed-size array can overflow it.

This query relies on the declared size of the array. When a database is built without the Windows SDK headers (for example with `build-mode: none` on Linux), `MAX_PATH` and the `Path*` functions are unresolved and the buffers have no known size, so these calls are not reported.

## Recommendation

Allocate output buffers of at least `MAX_PATH` (or `PATH_MAX`) elements, or use the size-checked replacements such as `PathCchAppend` and `PathCchCombine`, or pass a null buffer to `realpath` so that it allocates the result.

## Example

```c
void bad(void) {
  char path[MAX_PATH / 2];
  GetCurrentDirectoryA(MAX_PATH / 2, path);
  PathAppendA(path, "file.txt"); // BAD: path is smaller than MAX_PATH
}

void good(void) {
  char path[MAX_PATH];
  GetCurrentDirectoryA(MAX_PATH, path);
  PathAppendA(path, "file.txt"); // GOOD
}
```

## References

- MITRE CWE: [CWE-785: Use of Path Manipulation Function without Maximum-sized Buffer](https://cwe.mitre.org/data/definitions/785.html).
- Microsoft Learn: [PathAppendA function](https://learn.microsoft.com/en-us/windows/win32/api/shlwapi/nf-shlwapi-pathappenda).
