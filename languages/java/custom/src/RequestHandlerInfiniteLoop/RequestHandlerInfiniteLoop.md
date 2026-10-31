# Request handler with unexitable loop

A loop whose condition is constant `true` (for example `while (true)` or `for (;;)`) and that contains no reachable `break`, `return`, labeled `continue` to an outer loop, or exception that escapes the loop never terminates. When such a loop runs while a Servlet, Spring MVC or JAX-RS request is being handled, the request never completes. The query also checks exported Android activities, where an externally launched `onCreate` callback can block the UI thread. A remote attacker can exhaust server threads or repeatedly disrupt an Android application (CWE-835, denial of service).

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

Loops that can be left through a checked exception declared by a call in the loop (for example `IOException` when streaming a response to a client that has disconnected) are not reported. An `InputStream.read()` exception alone does not count as a loop exit because the call can instead return `-1`, after which the loop may continue.

The query recognizes Servlet request methods (`isServletRequestMethod`), Spring `SpringRequestMappingMethod` (including composed annotations such as `@GetMapping`), JAX-RS `JaxRsResourceMethod`, and `onCreate(Bundle)` methods on exported Android activities.

Only exported Android activity `onCreate(Bundle)` callbacks are modelled; other Android component callbacks are not included.

## References

- Common Weakness Enumeration: [CWE-835: Loop with Unreachable Exit Condition ('Infinite Loop')](https://cwe.mitre.org/data/definitions/835.html).
