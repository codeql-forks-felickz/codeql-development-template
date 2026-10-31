# Free of memory not on the heap

## Overview

Passing a pointer to a stack array, a static array or memory obtained with `alloca` to `free` (or another heap deallocation function) is undefined behavior. The allocator may crash, or it may add the memory to its free lists so that a later allocation returns memory that is also in use as a local or global variable, which can lead to memory corruption.

## Recommendation

Only free memory that was returned by a matching heap allocation function such as `malloc`, `calloc` or `realloc`. Make sure every path that reaches a call to `free` uses heap memory, or track whether the buffer needs to be freed.

## Example

```c
void bad(void) {
  char data[100];
  data[0] = '\0';
  free(data); // BAD: data is a stack array
}

void good(void) {
  char *data = (char *)malloc(100);
  if (data == NULL) return;
  data[0] = '\0';
  free(data); // GOOD: data was allocated on the heap
}
```

## References

- MITRE CWE: [CWE-590: Free of Memory not on the Heap](https://cwe.mitre.org/data/definitions/590.html).
- MITRE CWE: [CWE-763: Release of Invalid Pointer or Reference](https://cwe.mitre.org/data/definitions/763.html).
