# JDBC connection string injection

## Overview

A JDBC connection URL holds the database host, the database name, and driver-specific
properties, separated by delimiters such as `/`, `?`, `&`, and `;`. If user-provided data
is added to the URL without validation, an attacker can insert those delimiters and
change the connection. For example, they can select a different database, override
credentials, or turn on dangerous driver features such as MySQL Connector/J's
`allowLoadLocalInfile` or `autoDeserialize`, which can lead to file disclosure or
remote code execution (CWE-99, CWE-74).

This query reports user-provided data that reaches a JDBC URL argument, such as
`DriverManager.getConnection`, `Driver.connect`, `HikariConfig.setJdbcUrl`, or the
Spring `DriverManagerDataSource` and `DataSourceBuilder.url` APIs. If the user controls
the whole URL, including the host, `java/ssrf` already reports the flow, so this query
leaves it out to avoid duplicate alerts.

## Recommendation

Do not build JDBC URLs from user input. If the user needs to choose a database, check
the value against a fixed allowlist, or map it to a server-side constant. If that is not
possible, match the value against a strict pattern such as `[A-Za-z0-9_]+` that rejects
URL delimiters.

## Example

In the following example, the `selectedDB` request parameter is appended to the JDBC URL.
A value such as `app?allowLoadLocalInfile=true&autoDeserialize=true` adds properties to
the connection.

```java
String url = "jdbc:mysql://10.12.1.34/" + request.getParameter("selectedDB");
Connection conn = DriverManager.getConnection(url, username, password);
```

The fixed version accepts the value only if it is in an allowlist:

```java
private static final Set<String> ALLOWED_DBS = Set.of("inventory", "reports");

String db = request.getParameter("selectedDB");
if (ALLOWED_DBS.contains(db)) {
  Connection conn = DriverManager.getConnection("jdbc:mysql://10.12.1.34/" + db, username, password);
}
```

## References

- CWE: [CWE-99: Improper Control of Resource Identifiers ('Resource Injection')](https://cwe.mitre.org/data/definitions/99.html)
- CWE: [CWE-74: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')](https://cwe.mitre.org/data/definitions/74.html)
- MySQL: [Connector/J configuration properties](https://dev.mysql.com/doc/connector-j/en/connector-j-reference-configuration-properties.html)
