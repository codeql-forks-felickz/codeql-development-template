---
category: newQuery
---
* Added a new query, `go/path-injection-function-value`. It extends `go/path-injection` to follow user input into functions called through function values stored in struct fields, such as `s.Wrapper(payload)`, including fields set through elided pointer struct literals like `[]*T{{Wrapper: fn}}`.
