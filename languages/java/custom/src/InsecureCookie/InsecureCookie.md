# Failure to use secure cookies

Failing to set the `Secure` attribute on a cookie allows the browser to send it over an unencrypted HTTP connection, where it can be intercepted.

This is a customized variant of the standard `java/insecure-cookie` query. In addition to servlet `Cookie` objects added with `HttpServletResponse.addCookie` (unchanged upstream logic), it reports:

- Spring `org.springframework.http.ResponseCookie` instances built with `ResponseCookie.from(...)` whose builder never calls `.secure(...)` with a value other than `false`, and that are written to a response through a `Set-Cookie` header (`ResponseEntity.HeadersBuilder.header`, `HttpHeaders.add`/`set`, `HttpServletResponse.addHeader`/`setHeader`) or WebFlux `ServerHttpResponse.addCookie`.
- Raw `Set-Cookie` header values built from a `name=value` string constant that never include the `Secure` attribute.

Cookies that are removed (`.maxAge(0)` or `.maxAge(Duration.ZERO)`) and cookies derived from an existing cookie with `ResponseCookie.mutate()` are not reported.

## Recommendation

Always set the `Secure` attribute on cookies: call `cookie.setSecure(true)` on servlet cookies, `.secure(true)` on `ResponseCookie` builders, or include `; Secure` in raw `Set-Cookie` header values.

## Example

```java
// BAD: the cookie is sent over plain HTTP.
ResponseCookie cookie = ResponseCookie.from("SESSION", sessionId).path("/app").build();
return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString()).body(content);

// GOOD: the cookie is only sent over HTTPS.
ResponseCookie ok = ResponseCookie.from("SESSION", sessionId)
        .path("/app").secure(true).httpOnly(true).sameSite("Strict").build();
return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, ok.toString()).body(content);
```

## References

- [CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute](https://cwe.mitre.org/data/definitions/614.html)
- [Spring Framework `ResponseCookie`](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/http/ResponseCookie.html)
