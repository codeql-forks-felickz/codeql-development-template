# Host header poisoning in reset email content

Using an incoming `Host` header to construct an absolute password-reset link in an email can let an attacker direct the recipient to an attacker-controlled host. This query reports flows from `HttpServletRequest.getHeader("Host")` to content setters on email- or mail-named types.

This is a heuristic community-pack query. It does not prove that the content is a password-reset link or that the email is ultimately sent, and it may report benign email content. Review each flow and validate the generated link against a configured, trusted application origin rather than the request's `Host` header.

## Example

```java
String host = request.getHeader("Host");
emailBuilder.contents(String.format("https://%s/reset/%s", host, token)); // BAD
```

```java
String host = configuredPublicHost;
emailBuilder.contents(String.format("https://%s/reset/%s", host, token)); // GOOD
```

## References

- CWE-640: [Weak Password Recovery Mechanism for Forgotten Password](https://cwe.mitre.org/data/definitions/640.html)
