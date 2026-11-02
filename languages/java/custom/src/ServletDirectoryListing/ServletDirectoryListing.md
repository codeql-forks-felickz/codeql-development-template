# Directory listing enabled on default servlet

Servlet containers serve static content through a default servlet. When that servlet is configured to render directory listings (Tomcat `listings=true`, Jetty `dirAllowed=true`), any web-accessible directory without a welcome file shows an index of its contents. Attackers can use this to discover and download backups, configuration files, uploaded files and other resources that were never meant to be linked.

## Recommendation

Set the `listings` (Tomcat) or `dirAllowed` (Jetty) init parameter of the default servlet to `false`, and do not store sensitive files in web-accessible directories.

## Example

```xml
<servlet>
    <servlet-name>default</servlet-name>
    <servlet-class>org.apache.catalina.servlets.DefaultServlet</servlet-class>
    <init-param>
        <param-name>listings</param-name>
        <param-value>true</param-value> <!-- BAD: use false -->
    </init-param>
</servlet>
```

## References

- [CWE-548: Exposure of Information Through Directory Listing](https://cwe.mitre.org/data/definitions/548.html)
- [Apache Tomcat: Default Servlet Reference](https://tomcat.apache.org/tomcat-10.1-doc/default-servlet.html)
