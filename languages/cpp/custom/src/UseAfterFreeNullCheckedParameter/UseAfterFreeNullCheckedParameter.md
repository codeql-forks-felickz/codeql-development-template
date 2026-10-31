# Use after free through null-checked callee parameter

## Overview

A pointer is passed to a function after the memory it points to has been freed, and the called function dereferences that parameter on every path on which it is not null. A freed pointer is not null, so the callee reads or writes released heap memory. This is undefined behavior and can lead to information disclosure, crashes, or code execution when an attacker can influence allocator reuse.

The standard `cpp/use-after-free` query only treats an argument as a use when the callee dereferences the parameter on *every* path through the function. Helpers that guard the dereference with a null check (for example a logging helper such as `printLine`) are therefore not considered uses. This query covers that case and does not report arguments that `cpp/use-after-free` already reports.

## Recommendation

Do not use a pointer after passing it to `free`. Set the pointer to `NULL` immediately after freeing it, or restructure the code so the last use happens before the memory is released.

## Example

```c
void printLine(const char *line) {
  if (line != NULL) {
    printf("%s\n", line);
  }
}

void bad() {
  char *data = (char *)malloc(100);
  if (data == NULL) exit(-1);
  memset(data, 'A', 99);
  data[99] = '\0';
  free(data);
  printLine(data); // BAD: printLine dereferences the freed (non-null) pointer
}

void good() {
  char *data = (char *)malloc(100);
  if (data == NULL) exit(-1);
  memset(data, 'A', 99);
  data[99] = '\0';
  printLine(data); // GOOD: used before it is freed
  free(data);
}
```

## References

- MITRE CWE: [CWE-416: Use After Free](https://cwe.mitre.org/data/definitions/416.html).
- SEI CERT C Coding Standard: [MEM30-C. Do not access freed memory](https://wiki.sei.cmu.edu/confluence/display/c/MEM30-C.+Do+not+access+freed+memory).
