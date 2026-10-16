---
category: newQuery
---
* Added `cs/path-injection-extended`, a variant of `cs/path-injection` that does not treat null checks, NUL-character checks, or single-character/`Length` checks as path validation, keeps taint through `char` values, and includes `path-injection` sinks from models-as-data.
* Added the `languages-csharp-custom-models` model pack with summaries for `IFormFile.FileName`/`IFormFile.Name`, `Page.MapPath`, `HttpServerUtility.MapPath` and `String.get_Chars`, and `path-injection` sinks for the `StreamReader(string, ...)` constructors. The summaries also improve the standard `cs/path-injection` query (for example ASP.NET Core uploads that use `IFormFile.FileName`).
