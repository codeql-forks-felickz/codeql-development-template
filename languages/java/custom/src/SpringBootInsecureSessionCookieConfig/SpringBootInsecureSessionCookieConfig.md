# Spring Boot session cookie configured without Secure or HttpOnly

Spring Boot configures the container session cookie (for example `JSESSIONID`) with the `server.servlet.session.cookie.*` properties (`server.reactive.session.cookie.*` for WebFlux, `server.session.cookie.*` for Spring Boot 1.x). Explicitly setting `secure` to `false` lets the session identifier be sent over plain HTTP (CWE-614), and setting `http-only` to `false` lets client-side scripts read it (CWE-1004).

The query reports these properties when they are explicitly set to `false` in an `application.properties` or `application-<profile>.properties` file. Relaxed binding forms such as `http-only`, `http_only` and `httpOnly` are recognized. Properties that are absent or commented out are not reported, because the container default then applies.

## Recommendation

Set `server.servlet.session.cookie.secure=true` and `server.servlet.session.cookie.http-only=true` (or remove the properties that disable these attributes).

## Example

```properties
# BAD
server.servlet.session.cookie.secure=false
server.servlet.session.cookie.http-only=false

# GOOD
server.servlet.session.cookie.secure=true
server.servlet.session.cookie.http-only=true
```

## References

- [CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute](https://cwe.mitre.org/data/definitions/614.html)
- [CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag](https://cwe.mitre.org/data/definitions/1004.html)
- [Spring Boot common application properties](https://docs.spring.io/spring-boot/appendix/application-properties/index.html)
