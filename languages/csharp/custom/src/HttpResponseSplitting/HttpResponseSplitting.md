# HTTP response splitting

Writing user-controlled data into an HTTP response header without removing carriage return (`\r`) and line feed (`\n`) characters lets an attacker terminate the header early. The attacker can then inject additional headers (for example `Set-Cookie`), or a second response body, which can lead to cache poisoning, session fixation, or cross-site scripting.

This query tracks remote user input (and any other enabled threat-model sources) into header values written through the ASP.NET (`System.Web`) `HttpResponse` and `HttpResponseBase` APIs: `AddHeader`, `AppendHeader`, `Headers.Add`, `Headers.Set`, `Headers[name] = value`, and `RedirectLocation`.

ASP.NET encodes CR/LF characters in header values by default, but applications that set `enableHeaderChecking="false"` (see `cs/web/disabled-header-checking`) or run on older frameworks are exploitable. `System.Net.HttpListenerResponse` and ASP.NET Core reject CR/LF characters in header values and are not considered by this query.

When the project's `Web.config` sets `enableHeaderChecking="false"`, or code sets `HttpRuntimeSection.EnableHeaderChecking` to `false`, the alert message says so, because ASP.NET's built-in CR/LF encoding is then switched off and the flow is directly exploitable.

## Recommendation

Do not place untrusted data in response headers. If you must, URL-encode it (for example with `HttpUtility.UrlEncode`) or remove all `\r` and `\n` characters first. Note that HTML encoding does **not** remove these characters. Keep `enableHeaderChecking` enabled.

## Example

The following page copies a query string parameter directly into a response header:

```csharp
string header = Request.QueryString["Header"];
Response.Headers.Add("X-Header", header);
```

Strip CR/LF characters, or URL-encode the value, before writing it:

```csharp
string header = Request.QueryString["Header"];
Response.Headers.Add("X-Header", header.Replace("\r", "").Replace("\n", ""));
```

## References

- OWASP: [HTTP Response Splitting](https://owasp.org/www-community/attacks/HTTP_Response_Splitting).
- Microsoft Learn: [httpRuntime enableHeaderChecking](https://learn.microsoft.com/en-us/dotnet/api/system.web.configuration.httpruntimesection.enableheaderchecking).
- Common Weakness Enumeration: [CWE-113](https://cwe.mitre.org/data/definitions/113.html).
- Common Weakness Enumeration: [CWE-79](https://cwe.mitre.org/data/definitions/79.html).
