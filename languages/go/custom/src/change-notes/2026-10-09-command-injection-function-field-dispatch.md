---
category: minorAnalysis
---

- The customized `go/command-injection` query (`CommandInjection/CommandInjection.ql`) now tracks arguments of calls through function-typed struct fields (such as `s.Handler(mode, input)`) into the parameters of the functions stored in that field, either in a composite literal (including the elided `&T` elements of a `[]*T{...}` literal) or by assignment. This finds command injection in handlers that are registered in a table and dispatched through a struct field.
