# Lock order inversion in request handler

## Overview

A servlet container creates one instance of each servlet (and Spring creates one instance of
each controller) and uses it for all requests at the same time. Fields of that instance, and
static fields, are shared by every request thread.

If one request path holds the monitor of lock `A` while it waits for lock `B`, and another
path holds `B` while it waits for `A`, two concurrent requests can deadlock. Both threads
then wait forever, and every later request that needs either lock hangs too. An
unauthenticated user can do this on purpose to make the application stop responding
(CWE-833).

This query reports `synchronized` statements on shared fields that are reachable from a
servlet `service`/`do*` method or a Spring request mapping method, where the second lock is
taken while the first is held (directly or through a called method), and another statement
takes the same two locks in the opposite order.

The standard `java/lock-order-inconsistency` query also finds some of these cases, but it has
`recommendation` severity and `medium` precision, so it is not part of the default or
`security-extended` suites. This query limits results to code that handles requests.

## Recommendation

Always acquire multiple locks in the same global order, or use a single lock to protect the
related state. Where possible, avoid holding a lock while you acquire another one, or use
`java.util.concurrent.locks.Lock.tryLock` with a timeout.

## Example

In the following servlet, consecutive requests take `lock1` and `lock2` in opposite orders:

```java
@WebServlet("/deadlock")
public class DeadlockServlet extends HttpServlet {
  private final Object lock1 = new Object();
  private final Object lock2 = new Object();
  private boolean switchFlag = true;

  protected void service(HttpServletRequest req, HttpServletResponse res) {
    switchFlag = !switchFlag;
    if (switchFlag) {
      synchronized (lock1) { synchronized (lock2) { work(); } }
    } else {
      synchronized (lock2) { synchronized (lock1) { work(); } }
    }
  }
}
```

The fixed version always takes `lock1` first:

```java
synchronized (lock1) { synchronized (lock2) { work(); } }
```

## References

- Oracle: [The Java Tutorials, Deadlock](https://docs.oracle.com/javase/tutorial/essential/concurrency/deadlock.html)
- SEI CERT Oracle Coding Standard for Java: [LCK07-J. Avoid deadlock by requesting and releasing locks in the same order](https://wiki.sei.cmu.edu/confluence/display/java/LCK07-J.+Avoid+deadlock+by+requesting+and+releasing+locks+in+the+same+order)
- CWE: [CWE-833: Deadlock](https://cwe.mitre.org/data/definitions/833.html)
- CWE: [CWE-667: Improper Locking](https://cwe.mitre.org/data/definitions/667.html)
