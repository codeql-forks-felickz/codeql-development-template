# Weak CORS, CSP or framing security headers

Browsers rely on response headers to limit what other sites can do with a page:

- `Content-Security-Policy` (CSP) restricts which scripts may run. Allowing `'unsafe-inline'` or `'unsafe-eval'` for scripts lets injected inline JavaScript and dynamically evaluated code run, which removes most of the protection CSP gives against cross-site scripting (CWE-693).
- `X-Frame-Options` and the CSP `frame-ancestors` directive stop other sites from framing a page. Without them, an attacker can overlay a framed page and trick an authenticated user into clicking on it (clickjacking, CWE-1021).
- Cross-Origin Resource Sharing (CORS) controls which origins may read responses from cross-origin requests. A mapping that allows every origin lets any website call the endpoints and read the responses (CWE-942).

This query reports:

- an enforced CSP (a raw response header, or Spring Security `contentSecurityPolicy`/`policyDirectives`) whose effective script directive (the first `script-src`, otherwise the first `default-src`) contains `'unsafe-eval'`, or contains `'unsafe-inline'` without a nonce, hash or `'strict-dynamic'` (when one of these is present, browsers ignore `'unsafe-inline'`);
- `X-Frame-Options` set to a value other than `DENY` or `SAMEORIGIN`, such as `ALLOWALL` or the obsolete `ALLOW-FROM`, which modern browsers ignore;
- a CSP `frame-ancestors` directive that allows a wildcard such as `*` or `https://*`, or a bare scheme such as `https:`;
- framing protection that is applied only when a condition on the request path (`getRequestURI`, `getRequestURL`, `getServletPath` or `getPathInfo`) holds, when no other framing protection in the same method is applied outside that branch;
- Spring Security configuration that disables `frameOptions()` or all `headers()`;
- a public request handler (a method annotated with a `*Mapping` annotation, or JAX-RS `@GET`/`@POST`/...) that sets no framing header while another handler in the same class does set effective framing protection. This check is skipped when there is evidence of global framing protection: a filter or interceptor (`doFilter`, `doFilterInternal`, `preHandle`, `postHandle` or `filter`) that sets it without a request-path condition, or a Spring Security configuration (which sends `X-Frame-Options: DENY` by default) that does not disable frame options;
- a Spring `CorsRegistry.addMapping` registration that never restricts its allowed origins (Spring defaults them to `*`) or allows `*` explicitly (registrations passed to another method, returned or stored in a field are not reported as unconfigured), and `CorsConfiguration` calls that allow `*` through `addAllowedOrigin`, `addAllowedOriginPattern`, `setAllowedOrigins` or `setAllowedOriginPatterns`.

Only header names and values that are compile-time constants (possibly through a local variable) are considered. `Content-Security-Policy-Report-Only` is ignored because it is not enforced.

## Recommendation

- Remove `'unsafe-inline'` and `'unsafe-eval'` from `script-src` and `default-src`. Move inline scripts to external files, or allow them with a per-response nonce or a hash.
- Send `X-Frame-Options: DENY` (or `SAMEORIGIN`) and `Content-Security-Policy: frame-ancestors 'none'` (or `'self'`) on every response, including responses for sensitive actions. Do not exempt individual paths, and do not disable Spring Security's frame options.
- Restrict CORS mappings to an explicit list of trusted origins with `allowedOrigins` or `allowedOriginPatterns`, and only for the paths that need cross-origin access.

## Example

The following filter sets a CSP that allows inline scripts and `eval`, and it skips framing protection for one path:

```java
public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
    throws IOException, ServletException {
  HttpServletRequest request = (HttpServletRequest) req;
  HttpServletResponse response = (HttpServletResponse) res;
  // BAD: inline scripts and eval allowed.
  response.setHeader("Content-Security-Policy", "default-src 'unsafe-inline' 'unsafe-eval' 'self'");
  // BAD: /admins/clickjacking can be framed.
  if (!request.getRequestURI().startsWith("/admins/clickjacking")) {
    response.addHeader("X-Frame-Options", "DENY");
  }
  chain.doFilter(req, res);
}
```

A safer filter applies a strict policy and framing protection to every response:

```java
public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
    throws IOException, ServletException {
  HttpServletResponse response = (HttpServletResponse) res;
  // GOOD
  response.setHeader("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'");
  response.setHeader("X-Frame-Options", "DENY");
  chain.doFilter(req, res);
}
```

The following Spring MVC configuration allows every HTTP method from any origin, because `allowedOrigins` is left at its default of `*`:

```java
@Override
public void addCorsMappings(CorsRegistry registry) {
  // BAD
  registry.addMapping("/**").allowedMethods("*");
}
```

Restrict the mapping to trusted origins:

```java
@Override
public void addCorsMappings(CorsRegistry registry) {
  // GOOD
  registry.addMapping("/api/**").allowedOrigins("https://app.example.com").allowedMethods("GET", "POST");
}
```

## References

- OWASP: [Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html).
- OWASP: [Clickjacking Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html).
- MDN: [X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options) and [CSP frame-ancestors](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors).
- Spring Framework: [CORS](https://docs.spring.io/spring-framework/reference/web/webmvc-cors.html).
- Common Weakness Enumeration: [CWE-693](https://cwe.mitre.org/data/definitions/693.html).
- Common Weakness Enumeration: [CWE-942](https://cwe.mitre.org/data/definitions/942.html).
- Common Weakness Enumeration: [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html).
