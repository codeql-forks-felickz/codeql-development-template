# Unbounded servlet request dispatch loop

## Overview

`RequestDispatcher.forward` and `RequestDispatcher.include` pass the current request to the
resource mapped to a path, on the same thread. If a servlet always dispatches to a path that
is mapped to itself, or to another servlet that always dispatches back, each request is
dispatched again and again. There is no termination condition, so a single unauthenticated
request uses a request thread until the stack is exhausted, and many requests can make the
application stop responding (CWE-835, CWE-674).

This query reports `forward` and `include` calls in a servlet `service` or `do*` method that:

- dispatch to a constant context-relative path (starting with `/`),
- are not guarded by a condition, a `switch` case or an early return, and are not in a
  `catch` block, and
- target a servlet (mapped with `@WebServlet` or in `web.xml`) that dispatches back to the
  calling servlet in the same unconditional way, or the calling servlet itself. Servlet
  mappings are resolved by exact match, longest path-prefix match, then extension match.

## Known limitations

- XML mappings are scoped to their `web.xml` descriptor. Annotated servlet mappings are grouped
  together because the deployment they belong to cannot be inferred from source alone. The
  query does not resolve precedence between annotations and XML mappings, and may connect or
  suppress routes between annotated servlets from separate applications in a database containing
  multiple applications.
- Overlapping extension mappings are not ordered relative to each other.

## Recommendation

Do not dispatch a request to the same servlet unconditionally. Forward to a different
resource (for example a JSP view), or make sure the dispatch only happens once, for example
by checking a request attribute that you set before forwarding.

## Example

The following servlet is mapped to `/forwardloop` and forwards every request to
`/forwardloop`:

```java
@WebServlet(urlPatterns = { "/forwardloop" })
public class ForwardLoopServlet extends HttpServlet {
  protected void doGet(HttpServletRequest req, HttpServletResponse res)
      throws ServletException, IOException {
    RequestDispatcher dispatch = req.getRequestDispatcher("/forwardloop");
    dispatch.forward(req, res);
  }
}
```

The fixed version forwards to the view that renders the response:

```java
req.getRequestDispatcher("/WEB-INF/forward.jsp").forward(req, res);
```

## References

- Jakarta Servlet Specification: [Dispatching Requests](https://jakarta.ee/specifications/servlet/6.0/jakarta-servlet-spec-6.0#dispatching-requests)
- CWE: [CWE-835: Loop with Unreachable Exit Condition ('Infinite Loop')](https://cwe.mitre.org/data/definitions/835.html)
- CWE: [CWE-674: Uncontrolled Recursion](https://cwe.mitre.org/data/definitions/674.html)
- CWE: [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)
