# Fuzzer input buffer used as a null-terminated string

## Overview

Fuzzer test cases are arbitrary binary data with an explicit length. The libFuzzer `data` buffer passed to `LLVMFuzzerTestOneInput` and the AFL++ shared-memory buffer `__AFL_FUZZ_TESTCASE_BUF` are not null-terminated. Passing them to functions that expect a null-terminated string, such as `strlen`, `atoi`, `strcpy`, or `printf` with a `%s` conversion (or as the format string), reads past the end of the input when it contains no zero byte.

The AFL++ buffer is recognized through `__afl_fuzz_ptr`, which `__AFL_FUZZ_TESTCASE_BUF` expands to when the code is compiled with `afl-cc`. If the AFL++ macros are not defined during database creation (for example with `build-mode: none`), the buffer cannot be identified.

## Recommendation

Use the length provided by the fuzzer (`size` or `__AFL_FUZZ_TESTCASE_LEN`). Use length-bounded functions such as `strnlen` or `printf("%.*s", len, buf)`, or copy the input into a buffer that is explicitly null-terminated.

## Example

```c
int ProcessImage(void) {
  unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
  int len = strlen((char *)buf); // BAD: the test case is not null-terminated
  printf("input: %s\n", buf);    // BAD
  return len;
}

int ProcessImageGood(void) {
  unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
  int len = __AFL_FUZZ_TESTCASE_LEN;   // GOOD: use the provided length
  printf("input: %.*s\n", len, buf); // GOOD
  return len;
}
```

## References

- MITRE CWE: [CWE-126: Buffer Over-read](https://cwe.mitre.org/data/definitions/126.html).
- MITRE CWE: [CWE-170: Improper Null Termination](https://cwe.mitre.org/data/definitions/170.html).
- AFL++: [Persistent mode and shared memory test cases](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.persistent_mode.md).
