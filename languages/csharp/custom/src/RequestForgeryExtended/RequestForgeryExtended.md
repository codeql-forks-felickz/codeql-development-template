# Server-side request forgery (extended)

Directly incorporating user input into the destination URL of an outgoing HTTP request lets an attacker make the server send requests to arbitrary hosts. This can be used to reach internal services, cloud metadata endpoints, or other resources that are not reachable from outside the network, and the response is often returned to the attacker.

This query is a non-deprecated, taint-tracking replacement for the experimental `cs/request-forgery` query. In addition to `HttpClient`, `HttpRequestMessage`, `WebRequest.Create` and `BaseAddress` sinks, it models `WebClient.Download*`, `Upload*` and `Open*` methods, and follows taint through indexers and `ToString()` calls such as `HttpContext.Request.Query["url"].ToString()`.

## Recommendation

Do not let users choose the scheme or host of an outgoing request. Prefer selecting the destination from a server-side allowlist, or validate the parsed `Uri` (for example with `Uri.IsBaseOf` or by comparing `Uri.Host`) before making the request. Building the URL from a constant prefix that already fixes the scheme and host (for example `"https://api.example.com/users/" + id`) is also safe.

## Example

The following action passes a query-string value directly to `HttpClient.GetAsync`:

```csharp
[HttpGet("import")]
public async Task<IActionResult> Import()
{
    var url = HttpContext.Request.Query["url"].ToString();
    var response = await client.GetAsync(url); // BAD
    return Ok(await response.Content.ReadAsStringAsync());
}
```

The fixed version only fetches URLs under a trusted base:

```csharp
var trusted = new Uri("https://imports.example.com/");
var target = new Uri(url);
if (trusted.IsBaseOf(target))
{
    return await client.GetStringAsync(target); // GOOD
}
```

## References

- OWASP: [Server Side Request Forgery](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery).
- Common Weakness Enumeration: [CWE-918](https://cwe.mitre.org/data/definitions/918.html).
