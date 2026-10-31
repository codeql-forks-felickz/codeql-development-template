---
category: newQuery
---

- Added a new query, `go/custom/unvalidated-url-redirection`, which extends the standard `go/unvalidated-url-redirection` query. It follows taint into functions that are invoked through function-typed struct fields (for example, `s.VulnerableFnWrapper(opaque, payload)`), which the standard Go call graph does not resolve. It also suppresses a result only when the safe request-URL flow (such as `r.URL.Path`) starts at that result's own source, so a sink that is also reached by other untrusted input is still reported.
- Added the `languages-go-custom-models` model pack with a `url-redirection` sink model for `github.com/gin-gonic/gin.Context.Redirect`.
