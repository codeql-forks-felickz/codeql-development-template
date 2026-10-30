# Tomcat context disables HttpOnly session cookies

Apache Tomcat marks the `JSESSIONID` session cookie as `HttpOnly` by default, which prevents
JavaScript running in the page from reading it. Setting `useHttpOnly="false"` on a `<Context>`
element in `META-INF/context.xml`, `conf/context.xml`, a per-application context descriptor or
`conf/server.xml` removes this protection. Any cross-site scripting vulnerability in the
application can then be used to steal session identifiers and hijack authenticated sessions.

Tomcat parses this attribute with `Boolean.parseBoolean`, so any value other than `true` (ignoring
case), such as `false` or `no`, disables the flag. Values that use `${...}` property placeholders
are not reported because they are resolved at runtime.

## Recommendation

Remove the `useHttpOnly` attribute, or set it to `true`. If client-side code needs session-related
data, expose it through a separate, non-sensitive value.

## Example

The following context descriptor disables the `HttpOnly` flag:

```xml
<Context path="/shop" useHttpOnly="false">
</Context>
```

The following context descriptor keeps the default, secure behavior:

```xml
<Context path="/shop" useHttpOnly="true">
</Context>
```

## References

- Apache Tomcat: [The Context Container, `useHttpOnly`](https://tomcat.apache.org/tomcat-9.0-doc/config/context.html).
- OWASP: [HttpOnly](https://owasp.org/www-community/HttpOnly).
- Common Weakness Enumeration: [CWE-1004](https://cwe.mitre.org/data/definitions/1004.html).
