# JSON injection

If JSON text is built by concatenating, interpolating or formatting user-provided values, a malicious user can include characters such as `"`, `,` and `}` to break out of a JSON string and change the structure of the document. For example, the user can add or override properties such as a role or an identifier, or make the document invalid. This is a problem when the JSON text is sent to another service as a JSON request body, or is parsed and then trusted by the application.

This query reports user-provided values that are inserted into JSON-like text (a string with a quoted member name followed by `:`) when that text is later:

- sent as the content of a `System.Net.Http.StringContent` with a JSON media type, or
- parsed or deserialized with `System.Text.Json` (`JsonDocument.Parse`, `JsonNode.Parse`, `JsonSerializer.Deserialize`) or Newtonsoft.Json (`JsonConvert.DeserializeObject`, `JsonConvert.PopulateObject`, `JToken.Parse`, `JObject.Parse`, `JArray.Parse`).

## Recommendation

Do not build JSON text by hand. Create an object and serialize it with a JSON serializer, such as `System.Text.Json.JsonSerializer.Serialize`, `JsonContent.Create` or `JsonConvert.SerializeObject`. If a value must be inserted into existing JSON text, encode it first, for example with `JsonSerializer.Serialize(value)` or `JavaScriptEncoder.Default.Encode(value)`.

## Example

The following example builds the JSON request body for an authentication service by concatenating a cookie value into a string:

```csharp
var jwt = Request.Cookies["jwt"];
var payload = "{\"jwt\":\"" + jwt + "\"}"; // BAD
var content = new StringContent(payload, Encoding.UTF8, "application/json");
await httpClient.PostAsync(authServiceUri, content);
```

A cookie value such as `x","admin":true,"jwt":"y` adds an `admin` property to the request body. The following example serializes an object instead, so the value is always encoded as a JSON string:

```csharp
var jwt = Request.Cookies["jwt"];
var payload = JsonSerializer.Serialize(new { jwt }); // GOOD
var content = new StringContent(payload, Encoding.UTF8, "application/json");
await httpClient.PostAsync(authServiceUri, content);
```

## Known limitations

- Only JSON text sent with `StringContent` and a JSON media type, or passed to the listed parsers, is considered. JSON text written to a response, a file or a log is not reported.
- The media type must be given to the `StringContent` constructor. Setting `Content-Type` later through `content.Headers.ContentType` is not recognized.
- `cs/web/xss` models the first `StringContent` constructor argument as a `js-injection` sink, so a flow into a JSON `StringContent` can be reported by both queries. This query reports the inserted value, and `cs/web/xss` reports the `StringContent` argument. Flows into JSON parsers are only reported by this query.

## References

- OWASP: [Injection Theory](https://owasp.org/www-community/Injection_Theory).
- Microsoft Learn: [How to serialize JSON in C#](https://learn.microsoft.com/en-us/dotnet/standard/serialization/system-text-json/how-to).
- Common Weakness Enumeration: [CWE-74](https://cwe.mitre.org/data/definitions/74.html).
- Common Weakness Enumeration: [CWE-116](https://cwe.mitre.org/data/definitions/116.html).
