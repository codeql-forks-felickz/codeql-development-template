# Unauthenticated access to state-changing endpoint

Spring Security rules such as `requestMatchers(HttpMethod.POST, "/mail").permitAll()` allow anyone to send state-changing requests (POST, PUT, PATCH or DELETE) to an endpoint without authenticating. Unless the endpoint is part of the authentication flow, or verifies the caller in another way, this lets unauthenticated users create, modify or delete data.

Paths that look like authentication or account-recovery endpoints (for example `/login`, `/register`, `/oauth2/token` or `/password/reset`) are not reported. Because it cannot tell whether an endpoint performs its own verification (such as a signed webhook), this query has low precision and is intended for review.

## Recommendation

Require authentication (and, where appropriate, a specific role) for state-changing endpoints. If the endpoint must accept machine-to-machine calls, authenticate the caller with a dedicated mechanism such as a shared secret, signature or client certificate.

## Example

```java
http.authorizeHttpRequests(auth -> auth
    .requestMatchers(HttpMethod.POST, "/mail").permitAll()        // BAD
    .requestMatchers(HttpMethod.POST, "/mail").authenticated()    // GOOD
    .anyRequest().authenticated());
```

## References

- [CWE-306: Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)
- [Spring Security: Authorize HttpServletRequests](https://docs.spring.io/spring-security/reference/servlet/authorization/authorize-http-requests.html)
