# Non-async-signal-safe function called from signal handler

A signal handler can interrupt the program at any point, including in the middle of a call to a C library function. Only the functions that POSIX lists as *async-signal-safe* (see `signal-safety(7)`) may be called from a signal handler. Functions such as `malloc`, `free`, `printf`, `fprintf` and `exit` use locks, global state or the heap allocator; if the handler calls one of them while the interrupted code is executing the same (or a related) function, the program can deadlock or corrupt its heap or stream buffers.

This query finds signal handlers (functions passed to `signal`, or stored in the `sa_handler`/`sa_sigaction` field of a `struct sigaction`) that call, directly or through other functions, a well-known non-async-signal-safe function.

## Recommendation

Keep signal handlers minimal. Set a `volatile sig_atomic_t` flag and handle the signal in the main program loop, or only call async-signal-safe functions such as `write` and `_exit`.

## Example

The following handler allocates and frees memory, and may call `exit`:

```c
static void handler(int sig)
{
  void *p = malloc(10); // BAD
  if (p == NULL) {
    exit(-1);           // BAD
  }
  free(p);              // BAD
}

signal(SIGINT, handler);
```

The handler below only records that the signal was received:

```c
static volatile sig_atomic_t gotSignal = 0;

static void handler(int sig)
{
  gotSignal = sig; // GOOD
}
```

## References

- POSIX: [signal-safety(7)](https://man7.org/linux/man-pages/man7/signal-safety.7.html).
- SEI CERT C Coding Standard: [SIG30-C. Call only asynchronous-safe functions within signal handlers](https://wiki.sei.cmu.edu/confluence/display/c/SIG30-C.+Call+only+asynchronous-safe+functions+within+signal+handlers).
- Common Weakness Enumeration: [CWE-479](https://cwe.mitre.org/data/definitions/479.html).
- Common Weakness Enumeration: [CWE-828](https://cwe.mitre.org/data/definitions/828.html).
