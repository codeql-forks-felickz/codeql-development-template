---
category: newQuery
---

- Added a new query, `cs/web/http-response-splitting` (CWE-113), that detects user-controlled data flowing into `System.Web` HTTP response header values (`AddHeader`, `AppendHeader`, `Headers.Add`/`Set`/indexer, `RedirectLocation`).
- Added a new query, `cs/web/stored-xss` (CWE-79), that detects data read from a database (Entity Framework mapped properties, data readers, `DataRow` values) being written to HTML or JavaScript, regardless of the enabled threat models.
- Added a new query, `cs/web/content-result-xss` (CWE-79), that detects user-controlled data returned in an ASP.NET Core `ContentResult` (or `ControllerBase.Content(content, contentType)`) whose content type is HTML. Results with the default `text/plain` content type are not reported.
- The `cs/web/http-response-splitting` alert message now notes when header checking is disabled in `Web.config` or through `HttpRuntimeSection.EnableHeaderChecking`.
