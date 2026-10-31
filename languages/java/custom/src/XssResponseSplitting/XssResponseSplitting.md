# HTTP header splitting in outgoing request

Directly writing user input (for example, an HTTP request parameter) to a header of an outgoing HTTP client request can allow an attacker to inject additional headers or split the request that the application sends to a downstream server. If the value contains carriage return (`\r`) or line feed (`\n`) characters, and the HTTP client does not reject or neutralize them, the attacker controls the raw request seen by the downstream service.

The standard `java/http-response-splitting` query only models headers of the HTTP *response* returned to the client. This query covers headers set on *outgoing* requests made with Apache HttpClient 4.x (`org.apache.http`) and 5.x (`org.apache.hc`), including `addHeader`/`setHeader` on request objects and request builders, and the `BasicHeader` constructor.

## Recommendation

Do not place user-controlled values in outgoing request headers. If this is required, validate the value against an allow-list (for example, a fixed set of supported languages for `Accept-Language`), or remove or reject carriage return and line feed characters before use.

## Example

In the following example, the `header` request parameter is written verbatim to the `Accept-Language` header of an outgoing request:

```java
@RequestMapping("/proxy")
public void proxy(@RequestParam String url, @RequestParam String header) {
  HttpGet httpget = new HttpGet(url);
  httpget.addHeader("Accept-Language", header); // BAD
}
```

The following version removes carriage return and line feed characters before using the value:

```java
@RequestMapping("/proxy")
public void proxy(@RequestParam String url, @RequestParam String header) {
  HttpGet httpget = new HttpGet(url);
  httpget.addHeader("Accept-Language", header.replaceAll("[\r\n]", "")); // GOOD
}
```

## References

- OWASP: [HTTP Response Splitting](https://owasp.org/www-community/attacks/HTTP_Response_Splitting).
- Common Weakness Enumeration: [CWE-113](https://cwe.mitre.org/data/definitions/113.html).
