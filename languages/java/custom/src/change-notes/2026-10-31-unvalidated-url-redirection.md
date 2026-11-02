---
category: minorAnalysis
---
* Added the `java/custom/unvalidated-url-redirection` query, which extends `java/unvalidated-url-redirection` (CWE-601) to report remote input that reaches a Spring `"redirect:"` view name (returned from a method or passed to `ModelAndView`), a `Location` header on a Spring `HttpHeaders` object or `ResponseEntity` builder, or a redirect target built as `"/" + input`, which can yield a scheme-relative `//host` URL. Values checked for equality with a constant string are treated as safe.
