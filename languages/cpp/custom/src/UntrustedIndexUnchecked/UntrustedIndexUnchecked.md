# Unchecked untrusted index into fixed-size array

## Overview

A value derived from untrusted data (for example a field of a structure read with `fread`) is used as an index into a fixed-size array without any bounds check. An attacker can choose the value so that the access reads or writes outside the array, corrupting the stack or disclosing memory.

## Recommendation

Check that the index is at least zero and less than the number of elements in the array before using it.

## Example

```c
void bad(FILE *fp) {
  struct Image img;
  fread(&img, sizeof(img), 1, fp);
  int size = img.width / img.height;
  char buf[10];
  buf[size + 100] = 'c'; // BAD: index is not checked
}

void good(FILE *fp) {
  struct Image img;
  fread(&img, sizeof(img), 1, fp);
  int i = img.width;
  char buf[10];
  if (i >= 0 && i < 10)
    buf[i] = 'c'; // GOOD
}
```

## References

- MITRE CWE: [CWE-129: Improper Validation of Array Index](https://cwe.mitre.org/data/definitions/129.html).
- MITRE CWE: [CWE-787: Out-of-bounds Write](https://cwe.mitre.org/data/definitions/787.html).
