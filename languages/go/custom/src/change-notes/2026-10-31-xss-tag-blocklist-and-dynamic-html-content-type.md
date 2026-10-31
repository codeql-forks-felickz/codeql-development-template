---
category: newQuery
---

- Added a new query, `go/custom/reflected-xss`, which extends the standard `go/reflected-xss` query. It does not treat regular-expression replacements that only remove specific tag names (such as `<script>`) as XSS sanitizers, follows taint into functions invoked through function-typed struct fields, and reports a response body whose content type is set from a non-constant value that may hold an HTML MIME type (for example `RawMime: "text/html"`).
- Added a new query, `go/custom/html-template-escaping-bypass-xss`, which extends the standard `go/html-template-escaping-bypass-xss` query. It does not treat regular-expression replacements that only remove specific tag names as XSS sanitizers, so request data that passes through such a filter before being converted to `template.HTML` is reported.
