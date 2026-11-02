# Untrusted divisor without zero check

## Overview

Integer division and remainder by zero is undefined behavior in C and C++ and, on most platforms, terminates the process with a fault such as `SIGFPE`. When the divisor comes from untrusted input (a file, a network socket, an environment variable or the command line) and is not checked against zero, an attacker can crash the program by supplying `0`. This is a denial-of-service vulnerability (CWE-369).

The query tracks untrusted data to the divisor of `/`, `%`, `/=` and `%=` on integer types. Fields read from a structure that was filled as a whole (for example `fread(&img, sizeof(img), 1, fp)`) are treated as untrusted. Any comparison of the divisor, or a truthiness test such as `if (n)`, is treated as validation, and divisors that range analysis shows to be non-zero (such as `(x % 10) + 1`) are not reported.

## Recommendation

Check every divisor that is derived from external input before using it, and reject or handle the zero case explicitly.

## Example

The following example reads an image header from a file and divides by its `height` field without checking it:

```c
struct Image img;
while (fread(&img, sizeof(img), 1, fp) > 0) {
  int ratio = img.width / img.height; // BAD: height may be 0
}
```

The corrected version rejects a zero height before the division:

```c
struct Image img;
while (fread(&img, sizeof(img), 1, fp) > 0) {
  if (img.height == 0)
    continue;
  int ratio = img.width / img.height; // GOOD
}
```

## References

- Common Weakness Enumeration: [CWE-369: Divide By Zero](https://cwe.mitre.org/data/definitions/369.html).
- SEI CERT C Coding Standard: [INT33-C. Ensure that division and remainder operations do not result in divide-by-zero errors](https://wiki.sei.cmu.edu/confluence/display/c/INT33-C.+Ensure+that+division+and+remainder+operations+do+not+result+in+divide-by-zero+errors).
