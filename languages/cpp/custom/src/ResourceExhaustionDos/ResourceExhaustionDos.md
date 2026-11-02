# Resource exhaustion and denial of service

## Overview

An attacker can deny service by making a program use up CPU, memory, stack, or threads. This query reports these C/C++ patterns:

- **Unchecked loop bound (CWE-606):** untrusted input sets the upper bound of a loop, and the code never checks it against an upper limit.
- **Untrusted sleep duration (CWE-400):** untrusted input sets the argument of `sleep`, `usleep`, `Sleep`, or `SleepEx` without an effective range limit, so an attacker can stall the thread for too long.
- **Uncontrolled allocation size (CWE-789):** untrusted input sets the size of a heap allocation, and the size variable is only compared against a lower limit (for example `if (n > strlen(s))`). `cpp/uncontrolled-allocation-size` treats any comparison as a sanitizer, so it misses this case. Allocations with no comparison at all are left to that query.
- **Reachable assertion (CWE-617):** untrusted input reaches an `assert`, so an attacker can make the assertion fail and abort the process.
- **Uncontrolled recursion (CWE-674):**
  - a function calls itself on every path, so it never returns;
  - a recursive function's depth parameter comes from untrusted input, or from a very large constant such as `UINT_MAX`, and its additive recursive updates are not bounded.
- **Lock not released (CWE-667):** a function acquires a non-pointer local lock object by address and never releases it, so other threads that wait for the lock block forever.

The query does not report memory or file handle leaks (CWE-401, CWE-775). The existing queries `cpp/memory-never-freed`, `cpp/memory-may-not-be-freed`, `cpp/file-never-closed`, and `cpp/file-may-not-be-closed` already find them, including pointers that are overwritten before they are freed and handles leaked on early returns.

## Recommendation

Check untrusted values against a sensible upper limit before using them as loop bounds, recursion depths, sleep durations, or allocation sizes. Validate input with error handling, not `assert`. Make sure every recursive function has a reachable base case. Release every lock you acquire on all paths, or use RAII types such as `std::lock_guard`.

## Example

In the following example, a number read from a socket bounds a loop and is then asserted:

```c
n = atoi(buf);            // buf was read with recv()
for (i = 0; i < n; i++)   // BAD: unbounded loop
    count++;
assert(n > 5);            // BAD: the attacker controls whether the process aborts
```

The fixed code checks the value first and handles errors explicitly:

```c
n = atoi(buf);
if (n <= 5 || n > MAX_LOOP)
    return -1;            // GOOD: rejected with an error
for (i = 0; i < n; i++)
    count++;
```

## Known limitations

- Depth-based recursion checks recognize additive updates such as `p - 1`, `p + 1`, and `p++`. Geometrically shrinking updates such as `p / 2` or `p >> 1` are not reported as excessive recursion depth.
- Lock checks only track non-pointer local lock objects passed by address. Pointer-valued locals and aliases are skipped, and releases in other functions are not matched.

## References

- [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)
- [CWE-606: Unchecked Input for Loop Condition](https://cwe.mitre.org/data/definitions/606.html)
- [CWE-617: Reachable Assertion](https://cwe.mitre.org/data/definitions/617.html)
- [CWE-667: Improper Locking](https://cwe.mitre.org/data/definitions/667.html)
- [CWE-674: Uncontrolled Recursion](https://cwe.mitre.org/data/definitions/674.html)
- [CWE-789: Memory Allocation with Excessive Size Value](https://cwe.mitre.org/data/definitions/789.html)
