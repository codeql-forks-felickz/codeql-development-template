---
category: minorAnalysis
---

- Added a custom variant of the `js/missing-token-validation` query (`MissingCsrfMiddleware/MissingCsrfMiddleware.ql`). In addition to the standard query, it flags state-changing routes that do not read cookies themselves but are guarded by an earlier cookie/session-dependent middleware (for example a global session authentication check, including middleware wrapped with `express-unless`) while CSRF middleware is missing or only mounted after the routes. It also models the `client-sessions` package as a cookie middleware.
