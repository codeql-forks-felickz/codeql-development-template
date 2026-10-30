# Uncontrolled allocation size from a struct field

Code that reads a whole record from external input, for example with `fread(&img, sizeof(img), 1, fp)`, and then uses integer fields of that record in arithmetic that determines an allocation size is vulnerable to integer overflow (CWE-190) and uncontrolled memory allocation (CWE-789). A signed addition or multiplication of two attacker-controlled dimensions can wrap around, so the allocated buffer is much smaller than expected, or it can request an arbitrarily large amount of memory.

The standard `cpp/uncontrolled-allocation-size` query treats the struct written by `fread` as tainted, but does not propagate that taint to the individual fields read from it. This query adds that step and only reports paths that go through such a field read, so it does not duplicate results of the standard query.

## Recommendation

Validate every externally supplied field before using it in size arithmetic. Check both the lower and upper bounds, and use an unsigned type wide enough for the computation (or an overflow-checked helper) when combining values.

## Example

In the following example, the image dimensions are read from a file and added in signed `int` arithmetic before being passed to `malloc`:

```c
struct Image { char header[4]; int width; int height; char data[10]; };

void process_image(FILE *fp) {
  struct Image img;
  while (fread(&img, sizeof(img), 1, fp) > 0) {
    int size = img.width + img.height; // BAD: may overflow
    char *buf = malloc(size);
    /* ... */
  }
}
```

The fields should be bounds checked before they are used:

```c
void process_image(FILE *fp) {
  struct Image img;
  while (fread(&img, sizeof(img), 1, fp) > 0) {
    if (img.width < 0 || img.width > 4096 || img.height < 0 || img.height > 4096)
      continue;
    char *buf = malloc((size_t)img.width + (size_t)img.height); // GOOD
    /* ... */
  }
}
```

## References

- Common Weakness Enumeration: [CWE-190](https://cwe.mitre.org/data/definitions/190.html).
- Common Weakness Enumeration: [CWE-789](https://cwe.mitre.org/data/definitions/789.html).
