# Untrusted array index checked only against its lower bound

## Overview

Data from an untrusted source (for example a network socket, a file, or the command line) is used as an array index after the code checks that it is non-negative, but without checking it against the size of the array. An attacker can supply an index that is too large and read or write memory past the end of a stack or heap buffer.

A check of only the lower bound shows that the developer intended to validate the index, which makes a missing upper bound check a strong signal of a real bug. The standard `cpp/unclear-array-index-validation` query also flags these accesses, but it has low precision and is not part of the default or `security-extended` suites. This query only reports indexes that have a lower bound check but no upper bound check, and that range analysis cannot show to be within a fixed-size array.

## Recommendation

Check the index against both bounds of the array before using it, for example `if (data >= 0 && data < 10)`.

## Example

```c
void bad(int s) {
  int buffer[10] = {0};
  int data = readIndexFromSocket(s);
  if (data >= 0) {
    buffer[data] = 1; // BAD: data may be 10 or larger
  }
}

void good(int s) {
  int buffer[10] = {0};
  int data = readIndexFromSocket(s);
  if (data >= 0 && data < 10) {
    buffer[data] = 1; // GOOD
  }
}
```

## References

- MITRE CWE: [CWE-129: Improper Validation of Array Index](https://cwe.mitre.org/data/definitions/129.html).
- MITRE CWE: [CWE-121: Stack-based Buffer Overflow](https://cwe.mitre.org/data/definitions/121.html).
- MITRE CWE: [CWE-122: Heap-based Buffer Overflow](https://cwe.mitre.org/data/definitions/122.html).
- SEI CERT C Coding Standard: [ARR30-C. Do not form or use out-of-bounds pointers or array subscripts](https://wiki.sei.cmu.edu/confluence/display/c/ARR30-C.+Do+not+form+or+use+out-of-bounds+pointers+or+array+subscripts).
