# http4k model limitations

## Known limitations

- `HttpMessage` accessors are modeled as remote sources, so locally constructed responses can also be marked remote. Data extensions cannot restrict these sources to inbound requests or client responses, and they cannot model lambda handler parameters as sources.
- Response body methods are modeled as HTML sinks without checking the response `Content-Type`. This can report XSS for JSON or plain-text responses; unknown or unset content types also cannot be distinguished from HTML by a data extension.
- `LensExtractor` methods are modeled as remote sources for every extractor output. This can mark values from local objects or `RequestContextKey` as remote; limiting sources to known lens factories could miss custom lenses.
- URI update summaries preserve taint on the original `Uri`. They do not distinguish replaced from preserved components, so replacing a tainted component with a constant may still leave the resulting URI tainted.

Redirect sinks for http4k are handled by the custom Java query in `languages/java/custom/src/http4k/UrlRedirect.ql`, which only treats `Location` header values as redirects.
