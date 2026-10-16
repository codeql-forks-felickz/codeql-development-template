# Reflected cross-site scripting via attacker-chosen URL

If a server fetches a URL whose scheme and host are controlled by the user, and then writes the
fetched response directly into its own HTTP response, the user can point the request at a server
they control and make the application serve arbitrary HTML and script from its own origin. This is
a reflected cross-site scripting (XSS) vulnerability, usually combined with server-side request
forgery.

The standard `js/reflected-xss` query does not report this, because the written value is the
response of an outgoing HTTP request rather than the user input itself.

## Recommendation

Do not let users choose the origin of URLs fetched by the server; use a fixed scheme and host, or
validate the URL against an allow-list. Escape or sanitize the fetched content before writing it
into an HTML response, or serve it with a non-HTML content type.

## Example

The following handler fetches a user-provided URL with `needle` and writes the response body back
to the client:

```javascript
app.get("/research", (req, res) => {
  const url = req.query.url + req.query.symbol;
  needle.get(url, (error, response, body) => {
    res.write(body); // BAD: the user controls the fetched content
    res.end();
  });
});
```

Fixing the origin of the request means the user can no longer choose the content that is
reflected:

```javascript
app.get("/research", (req, res) => {
  needle.get("https://stocks.example.com/quote?symbol=" + encodeURIComponent(req.query.symbol),
    (error, response, body) => {
      res.write(escapeHtml(body)); // GOOD
      res.end();
    });
});
```

## References

- OWASP: [XSS (Cross Site Scripting) Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html).
- OWASP: [Server Side Request Forgery](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery).
- Common Weakness Enumeration: [CWE-79](https://cwe.mitre.org/data/definitions/79.html).
- Common Weakness Enumeration: [CWE-116](https://cwe.mitre.org/data/definitions/116.html).
- Common Weakness Enumeration: [CWE-918](https://cwe.mitre.org/data/definitions/918.html).
