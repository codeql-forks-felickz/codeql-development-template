---
category: newQuery
---
* Added new queries to extend C/C++ memory safety coverage:
  * `cpp/custom/use-after-free-null-checked-parameter` (CWE-416) finds freed pointers passed to functions that dereference the parameter whenever it is non-null (for example a `printLine` helper that guards `printf("%s", line)` with `line != NULL`). The standard `cpp/use-after-free` query misses these because the dereference does not post-dominate the callee entry.
  * `cpp/custom/array-index-missing-upper-bound` (CWE-121, CWE-122, CWE-129) finds untrusted array indexes that are checked against a lower bound (for example `data >= 0`) but not against the array size. Previously only the low-precision `cpp/unclear-array-index-validation` query reported these.
  * `cpp/custom/fuzzer-input-struct-overread` (CWE-125) finds libFuzzer harnesses that read structure fields beyond the input size guaranteed by their length check.
  * `cpp/custom/copy-exceeds-tainted-allocation` (CWE-122, CWE-131) finds fixed-size copies (for example `memcpy(buf, img.data, 10)`) into heap buffers whose allocation size is computed from untrusted data and is not checked to be large enough.
  * `cpp/custom/fuzzer-input-not-null-terminated` (CWE-126) finds libFuzzer and AFL++ test case buffers passed to functions that expect a null-terminated string.
* Added regression tests confirming that `cpp/tainted-format-string` (CWE-134), `cpp/double-free` (CWE-415) and `cpp/use-after-free` (CWE-416) already detect the Juliet `printf(data)` (socket and console input) and `free(data); free(data);` patterns, and the Damn_Vulnerable_C_Program conditional double free and use after free inside a read loop.
