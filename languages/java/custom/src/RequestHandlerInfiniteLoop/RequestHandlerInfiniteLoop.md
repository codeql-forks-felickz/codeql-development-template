# Request handler with unexitable loop

A loop whose condition is constant `true` (for example `while (true)` or `for (;;)`) and that contains no reachable `break`, `return`, labeled `continue` to an outer loop, or exception that escapes the loop never terminates. When such a loop runs while a Servlet, Spring MVC or JAX-RS request is being handled, the request never completes. Each request occupies a server worker thread and CPU time forever, so a remote attacker can exhaust the server by sending a handful of requests (CWE-835, denial of service).

The standard query `java/unreachable-exit-in-loop` only reports loops whose exit condition is a comparison that is always true or always false. It does not report loops that have no exit condition at all, which is what this query covers.

## Recommendation

Make sure every loop that runs on a request-handling path has a reachable exit, for example a bounded iteration count, a time-out, or a condition that depends on state updated inside the loop. Long-running background work should be moved off the request thread.

## Example

The following servlet never returns from `doGet`:

```java
@WebServlet(urlPatterns = {"/infiniteloop"})
public class InfiniteLoopServlet extends HttpServlet {
  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse res) {
    while (true) {
      String contextPath = req.getContextPath();
      log.debug("contextPath: {}", contextPath);
    }
  }
}
```

Give the loop an exit condition:

```java
  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse res) {
    for (int i = 0; i < MAX_ITERATIONS; i++) {
      String contextPath = req.getContextPath();
      log.debug("contextPath: {}", contextPath);
    }
  }
```

Loops that can be left through a checked exception declared by a call in the loop (for example `IOException` when streaming a response to a client that has disconnected) are not reported.

## References

- Common Weakness Enumeration: [CWE-835: Loop with Unreachable Exit Condition ('Infinite Loop')](https://cwe.mitre.org/data/definitions/835.html).
