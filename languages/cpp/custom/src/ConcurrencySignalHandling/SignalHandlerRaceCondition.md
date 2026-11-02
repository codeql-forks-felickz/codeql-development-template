# Shared data freed while signal handler is installed

When a signal handler accesses a global variable, the main program must not perform non-atomic updates on that variable while the handler can run. A common example is a check/free/reset sequence on a global pointer:

```c
if (gPtr != NULL) {
  free(gPtr);
  gPtr = NULL;
}
```

If the signal is delivered after `free` but before the pointer is reset, the handler dereferences (and may write through) freed memory, resulting in a use-after-free, double free or heap corruption.

This query finds calls that free a global variable after a handler that accesses that variable (directly or through functions it calls) has been installed with `signal` or `sigaction` in the same function, with no intervening call that blocks the signal (for example `sigprocmask`) or changes its disposition (for example `signal(sig, SIG_DFL)`).

## Recommendation

Block the signal (with `sigprocmask` or `pthread_sigmask`) or temporarily restore the default disposition around the update, or restructure the handler so that it only sets a `volatile sig_atomic_t` flag.

## Example

In the following example the handler can run between `free` and the assignment of `NULL`:

```c
signal(SIGINT, handler); // handler accesses gPtr
if (gPtr != NULL) {
  free(gPtr); // BAD
  gPtr = NULL;
}
```

The signal is blocked during the update in the corrected version:

```c
signal(SIGINT, handler);
sigemptyset(&set);
sigaddset(&set, SIGINT);
sigprocmask(SIG_BLOCK, &set, &old);
if (gPtr != NULL) {
  free(gPtr); // GOOD
  gPtr = NULL;
}
sigprocmask(SIG_SETMASK, &old, NULL);
```

## References

- SEI CERT C Coding Standard: [SIG31-C. Do not access shared objects in signal handlers](https://wiki.sei.cmu.edu/confluence/display/c/SIG31-C.+Do+not+access+shared+objects+in+signal+handlers).
- Common Weakness Enumeration: [CWE-364](https://cwe.mitre.org/data/definitions/364.html).
- Common Weakness Enumeration: [CWE-416](https://cwe.mitre.org/data/definitions/416.html).
