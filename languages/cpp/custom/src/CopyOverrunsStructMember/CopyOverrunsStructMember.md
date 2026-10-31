# Copy overruns structure member array

## Overview

A call to a function such as `memcpy` or `memset` writes more bytes into an array member of a structure than the member can hold. The extra bytes overwrite the members that follow, which may include pointers. Because the write stays inside the enclosing structure, the standard `cpp/overflow-buffer` query does not report it.

## Recommendation

Use the size of the member, not the size of the enclosing structure, as the copy length.

## Example

```c
typedef struct {
  char charFirst[16];
  void *voidSecond;
  void *voidThird;
} charVoid;

void bad(void) {
  charVoid s;
  memcpy(s.charFirst, SRC_STR, sizeof(s)); // BAD: overwrites voidSecond and voidThird
}

void good(void) {
  charVoid s;
  memcpy(s.charFirst, SRC_STR, sizeof(s.charFirst)); // GOOD
}
```

## References

- MITRE CWE: [CWE-121: Stack-based Buffer Overflow](https://cwe.mitre.org/data/definitions/121.html).
- MITRE CWE: [CWE-122: Heap-based Buffer Overflow](https://cwe.mitre.org/data/definitions/122.html).
- MITRE CWE: [CWE-805: Buffer Access with Incorrect Length Value](https://cwe.mitre.org/data/definitions/805.html).
