# Command-line argument accessed without checking argument count

## Overview

The C and C++ standards guarantee that `argv[argc]` is a NULL pointer. A program that reads `argv[n]` without first checking that `argc > n` therefore receives NULL (or reads past the end of the argument vector) when it is started with fewer arguments than expected. Passing that pointer on, for example to `fopen` or `strcpy`, dereferences NULL and crashes the program (CWE-476).

The query reports reads of `argv[n]` and `*(argv + n)` in `main` with a constant index `n >= 1` that are not protected by a check of `argc`. An access is considered protected when it is only evaluated on one branch of a condition that reads `argc`, when a preceding `if` statement that reads `argc` leaves the current path (by returning, exiting, or calling a function that may exit), or when `argc` is passed to a function such as `getopt` before the access.

## Recommendation

Check `argc` before reading command-line arguments and print a usage message when too few arguments were supplied.

## Example

The following program passes `argv[1]` to `ProcessImage` without checking `argc`:

```c
int main(int argc, char **argv) {
  ProcessImage(argv[1]); // BAD: NULL when run without arguments
  return 0;
}
```

The corrected version checks the argument count first:

```c
int main(int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s <file>\n", argv[0]);
    return 1;
  }
  ProcessImage(argv[1]); // GOOD
  return 0;
}
```

## References

- Common Weakness Enumeration: [CWE-476: NULL Pointer Dereference](https://cwe.mitre.org/data/definitions/476.html).
- Common Weakness Enumeration: [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html).
