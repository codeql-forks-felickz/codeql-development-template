# Use of `gets` without a declaration

## Overview

The `gets` function reads a line from standard input into a buffer without any limit on the length of the line, so any input longer than the buffer overflows it. Recent C libraries no longer declare `gets`, so code that still calls it compiles with an implicit declaration. The standard `cpp/dangerous-function-overflow` query only recognizes `gets` when it is declared with exactly one parameter, so calls through an implicit declaration are not reported. This query reports those calls.

## Recommendation

Replace `gets` with `fgets`, passing the size of the destination buffer, or with `getline`.

## Example

```c
void bad(void) {
  char buf[16];
  gets(buf); // BAD: no limit on the input length
}

void good(void) {
  char buf[16];
  fgets(buf, sizeof(buf), stdin); // GOOD: input is limited to the buffer size
}
```

## References

- MITRE CWE: [CWE-242: Use of Inherently Dangerous Function](https://cwe.mitre.org/data/definitions/242.html).
- MITRE CWE: [CWE-120: Buffer Copy without Checking Size of Input](https://cwe.mitre.org/data/definitions/120.html).
