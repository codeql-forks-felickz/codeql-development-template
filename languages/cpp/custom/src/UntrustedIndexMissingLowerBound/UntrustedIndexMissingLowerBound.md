# Untrusted signed index or size checked only against its upper bound

## Overview

A signed integer read from an untrusted source (for example parsed with `atoi` from `fgets` or socket input) is checked against an upper bound, such as `data < 10`, but never against a lower bound. A negative value passes the check. Used as an array index it writes before the start of the buffer (buffer underwrite), and used as a copy size it is converted to a very large unsigned value (unexpected sign extension).

The standard queries `cpp/unclear-array-index-validation` and `cpp/uncontrolled-arithmetic` do not report a use once any bound check is present.

## Recommendation

Check both bounds of untrusted signed values, or convert them to an unsigned type before checking.

## Example

```c
void bad(int data) {
  int buffer[10] = {0};
  if (data < 10)
    buffer[data] = 1; // BAD: data may be negative
}

void good(int data) {
  int buffer[10] = {0};
  if (data >= 0 && data < 10)
    buffer[data] = 1; // GOOD
}
```

## References

- MITRE CWE: [CWE-124: Buffer Underwrite ('Buffer Underflow')](https://cwe.mitre.org/data/definitions/124.html).
- MITRE CWE: [CWE-129: Improper Validation of Array Index](https://cwe.mitre.org/data/definitions/129.html).
- MITRE CWE: [CWE-194: Unexpected Sign Extension](https://cwe.mitre.org/data/definitions/194.html).
