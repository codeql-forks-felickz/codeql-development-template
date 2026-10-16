---
category: newQuery
---

- Added a new query, `go/request-forgery-function-field`, which extends `go/request-forgery` (CWE-918) to follow calls made through function-valued struct fields (for example route tables such as `[]*Sink{{Handler: httpHandler}}` invoked as `s.Handler(mode, input)`). Such calls have no resolved callee in the standard Go call graph, so user-controlled URLs passed through them to `net/http` requests were previously missed. Sinks already reported by `go/request-forgery` are not reported again.
