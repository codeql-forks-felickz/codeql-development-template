# Cross-site scripting through an HTML ContentResult

An ASP.NET Core action that returns user-controlled data in a `ContentResult` with an HTML content type (for example `text/html`) makes the browser render that data as HTML. Without HTML encoding, an attacker can inject script that runs in the victim's browser.

This query tracks remote user input (and any other enabled threat-model sources) into:

- the `Content` property of a `ContentResult` whose `ContentType` is set to a constant HTML content type, either in the same object initializer or on the same local variable, and
- the `content` argument of `ControllerBase.Content(content, contentType, ...)` when `contentType` is a constant HTML content type.

A `ContentResult` without an explicit content type is served as `text/plain; charset=utf-8`, which modern browsers do not render as HTML, so such results are not reported.

## Recommendation

HTML-encode untrusted data (for example with `System.Net.WebUtility.HtmlEncode` or `HtmlEncoder.Default.Encode`) before including it in an HTML response, or return a non-HTML content type. Prefer Razor views, which encode values by default.

## Example

The following action reflects the `query` parameter into an HTML response:

```csharp
[HttpGet]
public IActionResult Search(string query)
{
    return new ContentResult { Content = "<p>" + query + "</p>", ContentType = "text/html" };
}
```

Encode the value instead:

```csharp
[HttpGet]
public IActionResult Search(string query)
{
    return new ContentResult { Content = "<p>" + WebUtility.HtmlEncode(query) + "</p>", ContentType = "text/html" };
}
```

## References

- OWASP: [Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html).
- Microsoft Learn: [ContentResult Class](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.mvc.contentresult).
- Common Weakness Enumeration: [CWE-79](https://cwe.mitre.org/data/definitions/79.html).
- Common Weakness Enumeration: [CWE-116](https://cwe.mitre.org/data/definitions/116.html).
