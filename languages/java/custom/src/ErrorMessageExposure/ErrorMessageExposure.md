# Information exposure through an error message or stack trace (extended)

Software developers often add stack traces or exception messages to error responses, as a debugging aid. Whenever that error response reaches a regular user, the developer has given an attacker useful information. Stack traces expose class names, method names and file paths, and exception messages from libraries (for example `SQLException` messages produced by a JDBC driver) can reveal the structure of SQL statements, table names and other implementation details.

This query extends the standard `java/stack-trace-exposure` and `java/error-message-exposure` queries. In addition to the results of those queries, it reports:

- exception text obtained from `getLocalizedMessage()`, `toString()` and overridden `getMessage()` methods on any `Throwable`, and
- stack traces and exception messages that are stored as Spring MVC model attributes (`Model.addAttribute`, `ModelMap.addAttribute` and `ModelAndView.addObject`), which are rendered by the view.

## Recommendation

Send the user a generic error message that does not contain exception details. Write the stack trace and the exception message to a server-side log instead.

## Example

In the following JAX-RS resource, the message of a `SQLException` is returned in the response body, and in the Spring MVC controller the message and stack trace are placed in the model, which a JSP then renders:

```java
@GET
public Response getAccount(String id) {
  try {
    return Response.ok().entity(lookup(id)).build();
  } catch (SQLException e) {
    // BAD: the SQL error message is returned to the client
    return Response.serverError().entity("Error: " + e.getLocalizedMessage()).build();
  }
}

@RequestMapping("/login")
public String login(String user, Model model) {
  try {
    query(user);
  } catch (SQLException e) {
    // BAD: the error message and stack trace are rendered by the view
    model.addAttribute("error", e.getMessage() + "<br/>" + displayErrorForWeb(e));
  }
  return "login";
}
```

Log the details and return a generic message instead:

```java
  } catch (SQLException e) {
    // GOOD: details are logged, the user sees a generic message
    log.error("Account lookup failed", e);
    return Response.serverError().entity("An internal error occurred").build();
  }
```

## Limitations

Sinks that only exist in JSP files (for example `<%= bean.getDebugOutput() %>`) are not visible to the Java extractor, so flows that end only in a JSP scriptlet are not reported.

## References

- OWASP: [Improper Error Handling](https://owasp.org/www-community/Improper_Error_Handling).
- CERT Java Coding Standard: [ERR01-J. Do not allow exceptions to expose sensitive information](https://wiki.sei.cmu.edu/confluence/display/java/ERR01-J.+Do+not+allow+exceptions+to+expose+sensitive+information).
- Common Weakness Enumeration: [CWE-209](https://cwe.mitre.org/data/definitions/209.html).
- Common Weakness Enumeration: [CWE-497](https://cwe.mitre.org/data/definitions/497.html).
