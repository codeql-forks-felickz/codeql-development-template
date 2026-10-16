---
category: newQuery
---

- Added a new query, `cs/web/http-response-splitting` (CWE-113), that detects user-controlled data flowing into `System.Web` HTTP response header values (`AddHeader`, `AppendHeader`, `Headers.Add`/`Set`/indexer, `RedirectLocation`).
- Added a new query, `cs/web/stored-xss` (CWE-79), that detects data read from a database (Entity Framework mapped properties, data readers, `DataRow` values) being written to HTML or JavaScript, regardless of the enabled threat models.
