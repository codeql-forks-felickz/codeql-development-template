---
category: newQuery
---

- Added a new query, `go/custom/sql-injection`, which extends the standard `go/sql-injection` query to follow taint into functions that are invoked through function-typed struct fields (for example, handlers registered as `[]*Sink{{Handler: v.method}}` and later invoked as `s.Handler(input)`). The standard Go call graph does not resolve the target of such calls, so SQL injection inside the stored handler was previously missed.
