# Untrusted value multiplied in allocation size without upper bound check

## Overview

An untrusted integer is multiplied into the size of a heap allocation, for example `malloc(data * sizeof(int))`, without first being checked against an upper bound. A large value makes the multiplication overflow, so the allocation is smaller than intended, and code that later writes `data` elements overflows the heap buffer.

The standard `cpp/uncontrolled-allocation-size` query treats any comparison of the value as a bounds check, including a later loop condition such as `i < (size_t)data`, so it does not report these cases.

## Recommendation

Check that the untrusted value is within a safe range in the code that guards the allocation, or use an allocation function that checks the multiplication for overflow (such as `calloc` or `reallocarray`).

## Example

```c
void bad(int data) {
  int *p = (int *)malloc(data * sizeof(int)); // BAD: may overflow
  for (size_t i = 0; i < (size_t)data; i++)
    p[i] = 0;
}

void good(int data) {
  if (data > 0 && data < 1000) {
    int *p = (int *)malloc(data * sizeof(int)); // GOOD
    for (size_t i = 0; i < (size_t)data; i++)
      p[i] = 0;
  }
}
```

## References

- MITRE CWE: [CWE-680: Integer Overflow to Buffer Overflow](https://cwe.mitre.org/data/definitions/680.html).
- MITRE CWE: [CWE-190: Integer Overflow or Wraparound](https://cwe.mitre.org/data/definitions/190.html).
- MITRE CWE: [CWE-789: Memory Allocation with Excessive Size Value](https://cwe.mitre.org/data/definitions/789.html).
