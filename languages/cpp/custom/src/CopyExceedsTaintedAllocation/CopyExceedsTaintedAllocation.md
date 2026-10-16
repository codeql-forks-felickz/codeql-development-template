# Fixed-size copy into buffer with untrusted allocation size

## Overview

A heap buffer is allocated with a size computed from untrusted data (for example fields read from a file with `fread`), and a fixed number of bytes is then copied into it with a function such as `memcpy` or `memset`. If the computed size is smaller than the copy, for example because the arithmetic wraps, divides, or subtracts attacker-controlled values, the copy writes past the end of the allocation.

The standard `cpp/overflow-buffer` and `cpp/overrun-write` queries need a known allocation size to compare against the copy, so they do not report allocations whose size is unbounded. This query reports constant-size writes into such allocations when neither range analysis nor a dominating guard shows that the allocation size is at least the copy size.

## Recommendation

Validate untrusted sizes before allocating, and make sure the allocation is at least as large as every write into it. Alternatively, derive the copy length from the allocation size.

## Example

```c
void bad(FILE *fp) {
  struct Image img;
  fread(&img, sizeof(img), 1, fp);
  int size = img.width / img.height;
  char *buf = malloc(size);
  memcpy(buf, img.data, sizeof(img.data)); // BAD: size may be less than 10
}

void good(FILE *fp) {
  struct Image img;
  fread(&img, sizeof(img), 1, fp);
  int size = img.width / img.height;
  if (size < (int)sizeof(img.data))
    return;
  char *buf = malloc(size);
  memcpy(buf, img.data, sizeof(img.data)); // GOOD
}
```

## References

- MITRE CWE: [CWE-122: Heap-based Buffer Overflow](https://cwe.mitre.org/data/definitions/122.html).
- MITRE CWE: [CWE-131: Incorrect Calculation of Buffer Size](https://cwe.mitre.org/data/definitions/131.html).
- MITRE CWE: [CWE-787: Out-of-bounds Write](https://cwe.mitre.org/data/definitions/787.html).
