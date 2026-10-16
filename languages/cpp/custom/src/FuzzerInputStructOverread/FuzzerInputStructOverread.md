# Fuzzer input read as a structure larger than the checked input size

## Overview

A libFuzzer entry point (`LLVMFuzzerTestOneInput`) reinterprets the fuzzer-provided buffer as a pointer to a structure and reads a field that lies beyond the minimum input length guaranteed by its size check. For inputs shorter than the structure, the read goes past the end of the fuzzer buffer. The harness then reports out-of-bounds reads in the harness itself instead of bugs in the code under test, or hides real issues.

The query computes the smallest input size guaranteed by guards on the `size` parameter (for example `if (size <= 12) return 0;` guarantees 13 bytes) and reports field accesses whose end offset is larger than that size.

## Recommendation

Reject inputs that are smaller than the structure, for example `if (size < sizeof(struct Image)) return 0;`, or copy the input into a properly sized and initialized local structure.

## Example

```c
struct Image {
  char header[4];
  int width;
  int height;
  char data[10];
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size <= 12)
    return 0;
  struct Image *img = (struct Image *)data;
  use(img->data); // BAD: `data` spans bytes 12 to 22, but only 13 bytes are guaranteed
  return 0;
}
```

## References

- MITRE CWE: [CWE-125: Out-of-bounds Read](https://cwe.mitre.org/data/definitions/125.html).
- LLVM: [libFuzzer, a library for coverage-guided fuzz testing](https://llvm.org/docs/LibFuzzer.html).
