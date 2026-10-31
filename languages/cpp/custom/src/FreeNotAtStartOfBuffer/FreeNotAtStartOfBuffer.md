# Free of pointer not at start of buffer

## Overview

A pointer returned by an allocation function is advanced with pointer arithmetic (for example `data++` while scanning a string) and the advanced pointer is then passed to `free`. Allocators require the exact pointer that they returned; freeing any other address corrupts allocator state and can lead to a crash or to code execution.

## Recommendation

Keep the original pointer returned by the allocation function and free that pointer. Use a separate pointer or an index to walk through the buffer.

## Example

```c
void bad(void) {
  char *data = (char *)malloc(100);
  while (*data != '\0') {
    if (*data == 'S')
      break;
    data++;
  }
  free(data); // BAD: data may no longer point to the start of the buffer
}

void good(void) {
  char *data = (char *)malloc(100);
  size_t i;
  for (i = 0; data[i] != '\0'; i++) {
    if (data[i] == 'S')
      break;
  }
  free(data); // GOOD
}
```

## References

- MITRE CWE: [CWE-761: Free of Pointer not at Start of Buffer](https://cwe.mitre.org/data/definitions/761.html).
- MITRE CWE: [CWE-763: Release of Invalid Pointer or Reference](https://cwe.mitre.org/data/definitions/763.html).
