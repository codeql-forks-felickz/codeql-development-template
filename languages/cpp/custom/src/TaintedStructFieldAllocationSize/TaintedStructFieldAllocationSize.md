# Uncontrolled allocation size from struct field

Binary file formats and network protocols are commonly parsed by reading a fixed-size header directly into a struct, for example with `fread(&hdr, sizeof(hdr), 1, fp)` or `recv(sock, &hdr, sizeof(hdr), 0)`. Every field of such a struct is controlled by whoever produced the input. If the fields are combined in arithmetic and the result is used as an allocation size without range validation, the computation can underflow (CWE-191) or overflow (CWE-190). A negative `int` converted to `size_t` becomes a huge value, and an overflowed sum can become a tiny one. Either way, the program allocates an unexpected amount of memory, which can lead to denial of service or to out-of-bounds writes when the buffer is used later.

The standard `cpp/uncontrolled-allocation-size` query does not report these cases. Its taint source is the whole struct, and the C++ taint-tracking library does not propagate taint from a wholly tainted struct to reads of its individual fields. This query adds that step. It reports only allocations that `cpp/uncontrolled-allocation-size` does not already report.

## Recommendation

Validate every field read from untrusted input before using it in arithmetic. Check that each value lies in an expected range, for example that dimensions are positive and below a sensible maximum, and that the computed size cannot underflow or overflow, before passing it to an allocation function.

## Example

In the following example, an image header is read from a file and its `width` and `height` fields are subtracted to compute a buffer size. If `height` is larger than `width + 100`, the result is negative and becomes a very large `size_t` when passed to `malloc`.

```c
struct Image {
  char header[4];
  int width;
  int height;
  char data[10];
};

void process_image(FILE *fp) {
  struct Image img;
  while (fread(&img, sizeof(img), 1, fp) > 0) {
    int size = img.width - img.height + 100; // BAD: can underflow
    char *buf = (char *)malloc(size);
    /* ... */
    free(buf);
  }
}
```

The fixed version validates the fields before using them:

```c
void process_image(FILE *fp) {
  struct Image img;
  if (fread(&img, sizeof(img), 1, fp) != 1)
    return;
  if (img.width > MAX_DIM || img.height > MAX_DIM || img.width < img.height)
    return; // GOOD: fields are range checked
  char *buf = (char *)malloc(img.width - img.height + 100);
  /* ... */
  free(buf);
}
```

## References

- Common Weakness Enumeration: [CWE-190](https://cwe.mitre.org/data/definitions/190.html).
- Common Weakness Enumeration: [CWE-191](https://cwe.mitre.org/data/definitions/191.html).
- Common Weakness Enumeration: [CWE-789](https://cwe.mitre.org/data/definitions/789.html).
