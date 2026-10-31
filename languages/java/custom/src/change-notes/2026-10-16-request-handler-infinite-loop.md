---
category: newQuery
---
* Added a new query, `java/request-handler-infinite-loop`, to detect loops with no reachable exit (for example `while (true)` without a `break`, `return` or escaping exception) that execute while handling a Servlet, Spring or JAX-RS request. The existing `java/unreachable-exit-in-loop` query only reports loops whose exit condition is a comparison that is always true or always false, so it does not report loops that have no exit at all.
