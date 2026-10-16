# SQL query built from user-controlled sources in a JSP scriptlet

Java code embedded in JSP pages (`<% ... %>` scriptlets) is not extracted by the CodeQL Java extractor, so `java/sql-injection` cannot see SQL injection in JSP files. The JavaScript extractor does extract `.jsp` files as HTML templates and records each scriptlet as a template placeholder tag. This query inspects that scriptlet text and reports SQL execution calls (`executeQuery`, `executeUpdate`, `execute`, `addBatch`, `prepareStatement`, `prepareCall`, `createQuery`, `createNativeQuery`, `createSQLQuery`, ...) whose argument contains request data (`request.getParameter(...)`, `request.getHeader(...)`, ...) or a variable assigned from request data anywhere in the same JSP file.

The analysis is textual (no Java parsing or data flow), so its precision is medium. Values converted with `Integer.parseInt`, `Long.valueOf` and similar, or encoded with `encodeForSQL`, are treated as safe.

## Recommendation

Use a `PreparedStatement` with `?` placeholders and bind request values with `setString`/`setInt`. Better still, move database access out of JSP pages into servlets or service classes, where `java/sql-injection` can analyze it.

## Example

The following scriptlet concatenates the `info` request parameter into an `UPDATE` statement:

```jsp
<%
  String info = request.getParameter("info");
  Statement stmt = con.createStatement();
  stmt.executeUpdate("Update users set about='" + info + "' where id=" + id);
%>
```

Bind the value as a parameter instead:

```jsp
<%
  String info = request.getParameter("info");
  PreparedStatement ps = con.prepareStatement("Update users set about=? where id=?");
  ps.setString(1, info);
  ps.setString(2, id);
  ps.executeUpdate();
%>
```

## References

- OWASP: [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html).
- Common Weakness Enumeration: [CWE-89](https://cwe.mitre.org/data/definitions/89.html).
