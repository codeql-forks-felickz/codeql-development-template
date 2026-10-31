---
category: minorAnalysis
---

- `System.Web.UI.WebControls.Literal.Text` is now modeled as an `html-injection` sink, so `cs/web/xss` reports untrusted data written to a `Literal` control.
- Values read from `System.Data.DataRow` (indexers, `ItemArray`, `DataRowExtensions.Field<T>`) are now modeled as `database` sources.
- `System.Web.HttpResponse.StatusDescription` (and `HttpResponseBase` overrides) is now modeled as an `html-injection` sink, so `cs/web/xss` reports untrusted data reflected into an HTTP status description or error message.
- `Microsoft.AspNetCore.Http.HttpResponseWritingExtensions.WriteAsync(HttpResponse, string, ...)` is now modeled as an `html-injection` sink, so `cs/web/xss` reports untrusted data written directly to an ASP.NET Core response body.
