---
category: newQuery
---
* Added new queries to extend C/C++ memory safety coverage:
  * `cpp/custom/use-after-free-null-checked-parameter` (CWE-416) finds freed pointers passed to functions that dereference the parameter whenever it is non-null (for example a `printLine` helper that guards `printf("%s", line)` with `line != NULL`). The standard `cpp/use-after-free` query misses these because the dereference does not post-dominate the callee entry.
  * `cpp/custom/array-index-missing-upper-bound` (CWE-121, CWE-122, CWE-129) finds untrusted array indexes that are checked against a lower bound (for example `data >= 0`) but not against the array size. Previously only the low-precision `cpp/unclear-array-index-validation` query reported these.
  * `cpp/custom/fuzzer-input-struct-overread` (CWE-125) finds libFuzzer harnesses that read structure fields beyond the input size guaranteed by their length check.
  * `cpp/custom/copy-exceeds-tainted-allocation` (CWE-122, CWE-131) finds fixed-size copies (for example `memcpy(buf, img.data, 10)`) into heap buffers whose allocation size is computed from untrusted data and is not checked to be large enough.
  * `cpp/custom/fuzzer-input-not-null-terminated` (CWE-126) finds libFuzzer and AFL++ test case buffers passed to functions that expect a null-terminated string.
  * `cpp/custom/untrusted-index-missing-lower-bound` (CWE-124, CWE-194) finds untrusted signed values used as an array index or copy size after being checked only against an upper bound, so a negative value can write before the buffer or become a huge size.
  * `cpp/custom/allocation-size-overflow` (CWE-680) finds untrusted values multiplied into an allocation size without an upper bound check guarding the allocation. The standard `cpp/uncontrolled-allocation-size` query treats a later loop condition such as `i < (size_t)data` as a bounds check.
  * `cpp/custom/free-not-at-start-of-buffer` (CWE-761) finds heap pointers advanced with pointer arithmetic and then passed to `free`.
  * `cpp/custom/untrusted-pointer-write` (CWE-123) finds writes through pointers read from untrusted data, such as a linked-list unlink after `fgets((char *)&data, sizeof(data), stdin)`.
  * `cpp/custom/path-function-small-buffer` (CWE-785) finds `PathAppend`-style functions and `realpath` called with a fixed-size buffer smaller than `MAX_PATH` or `PATH_MAX`. Calls are only reported when the Windows SDK headers are available to the extractor.
* Added regression tests confirming that `cpp/tainted-format-string` (CWE-134), `cpp/double-free` (CWE-415) and `cpp/use-after-free` (CWE-416) already detect the Juliet `printf(data)` (socket and console input) and `free(data); free(data);` patterns, and the Damn_Vulnerable_C_Program conditional double free and use after free inside a read loop.
* Added a regression test confirming that `cpp/overflow-buffer` (in the `security-extended` suite) detects the Juliet CWE-131 `malloc(10)` followed by `memcpy` of `10 * sizeof(int)` bytes, and the CWE-805 copy of 100 bytes into a 50-byte heap buffer.
