---
category: minorAnalysis
---

- The customized `js/case-sensitive-middleware-path` query (`CaseSensitiveMiddlewarePath/CaseSensitiveMiddlewarePath.ql`) now also reports middleware that is skipped for request paths matching a case-sensitive exclusion regular expression, either through an `unless({ path: ... })` option (as in `express-unless` and `express-jwt`) or through an early `return next()` guarded by a regular expression test of `req.path`, `req.url` or `req.originalUrl`. An alert is only reported when a route path guarded by the middleware is processed by it while a differently cased variant of that path is excluded. Exclusion patterns of the form `^(?!prefix).*` (negative lookahead) are supported.
