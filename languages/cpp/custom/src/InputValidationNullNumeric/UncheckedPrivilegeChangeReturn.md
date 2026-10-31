# Unchecked return value of privilege-changing function

## Overview

Functions that change the security context of a thread or process, such as the Windows `ImpersonateSelf`, `ImpersonateLoggedOnUser` and `RevertToSelf`, or the POSIX `setuid`, `setgid` and `setresuid`, can fail. If the program ignores the return value, it continues to run in a different security context than it expects. For example, after a failed `ImpersonateSelf` the thread still runs with the (possibly privileged) process token, and after a failed `setuid` the process keeps its elevated privileges (CWE-252, CWE-273).

The query reports calls to these functions whose result is discarded.

## Recommendation

Always check the return value of privilege-changing functions and stop processing (or abort) when the call fails.

## Example

The following code ignores the result of `ImpersonateSelf`:

```c
ImpersonateSelf(SecurityImpersonation); // BAD
do_restricted_work();
RevertToSelf(); // BAD
```

The corrected version stops when either call fails:

```c
if (!ImpersonateSelf(SecurityImpersonation))
  exit(1);
do_restricted_work();
if (!RevertToSelf())
  exit(1);
```

## References

- Common Weakness Enumeration: [CWE-252: Unchecked Return Value](https://cwe.mitre.org/data/definitions/252.html).
- Common Weakness Enumeration: [CWE-273: Improper Check for Dropped Privileges](https://cwe.mitre.org/data/definitions/273.html).
- SEI CERT C Coding Standard: [POS37-C. Ensure that privilege relinquishment is successful](https://wiki.sei.cmu.edu/confluence/display/c/POS37-C.+Ensure+that+privilege+relinquishment+is+successful).
