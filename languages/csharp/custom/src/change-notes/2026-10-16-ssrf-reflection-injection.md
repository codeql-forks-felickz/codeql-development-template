---
category: newQuery
---

- Added `cs/request-forgery-extended` (CWE-918), a taint-tracking server-side request forgery query that covers `HttpClient`, `HttpRequestMessage`, `WebRequest.Create`, `BaseAddress`/`RequestUri` assignments and `WebClient` `Download*`/`Upload*`/`Open*` methods. Unlike the deprecated experimental `cs/request-forgery`, it follows taint through indexers and `ToString()` (for example `HttpContext.Request.Query["url"].ToString()`).
- Added `cs/unsafe-reflection` (CWE-470), which reports user-controlled type or assembly names reaching `Activator.CreateInstance*`, `AppDomain.CreateInstance*`, `Assembly.CreateInstance` and `Type.InvokeMember`, including via `Type.GetType`/`Assembly.GetType`.
- Added `cs/assembly-load-relative-path` (CWE-426, CWE-114), an audit query for assemblies loaded from constant relative file names that are resolved through an untrusted search path.
- Command injection from command-line arguments (CWE-78) is already reported by the standard `cs/command-line-injection` query when the `local` threat model is enabled; a regression test documents this, and no query change was needed.
