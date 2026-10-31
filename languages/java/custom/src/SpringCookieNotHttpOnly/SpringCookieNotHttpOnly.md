# Sensitive Spring ResponseCookie without the HttpOnly flag set

A sensitive cookie (for example a session or authentication token) without the `HttpOnly` attribute can be read by client-side scripts, so a cross-site scripting (XSS) vulnerability can be used to steal it.

This query complements the standard `java/sensitive-cookie-not-httponly` query, which only models servlet cookies. It tracks cookie names that look sensitive (containing `auth`, `session`, `token`, `key` or `credential`, but not `csrf`/`xsrf`) into `ResponseCookie.from(name, ...)` and reports the cookie when it is written to a response (`Set-Cookie` header or WebFlux `ServerHttpResponse.addCookie`) and its builder never calls `.httpOnly(...)` with a value other than `false`. Removed cookies (`.maxAge(0)`) and cookies derived with `ResponseCookie.mutate()` are not reported.

## Recommendation

Call `.httpOnly(true)` on the `ResponseCookie` builder of every sensitive cookie.

## Example

```java
// BAD: the session cookie can be read by JavaScript.
ResponseCookie cookie = ResponseCookie.from("SESSION", sessionId).path("/app").build();

// GOOD
ResponseCookie ok = ResponseCookie.from("SESSION", sessionId).path("/app").httpOnly(true).secure(true).build();
```

## References

- [CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag](https://cwe.mitre.org/data/definitions/1004.html)
- [Spring Framework `ResponseCookie`](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/http/ResponseCookie.html)
