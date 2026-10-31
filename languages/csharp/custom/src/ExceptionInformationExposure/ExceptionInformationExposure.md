# Information exposure through an exception (extended)

Software developers often add stack traces or exception messages to error responses, as a debugging aid. Whenever that error response is shown to an end user, it provides a way for an attacker to learn about the internals of the application, such as file paths, SQL statements, connection details, class names and library versions. The same applies to details of the server environment, such as the machine name, the account the application runs as, or the current directory.

This query extends the standard `cs/information-exposure-through-exception` query. In addition to the remote output sinks that the standard query uses, it reports exception and environment information that reaches:

- the `Message` property of an exception (the standard query does not track `Exception.Message`),
- the return value of an ASMX `[WebMethod]`, including fields and properties of a returned object,
- the return value of an ASP.NET MVC, Web API or ASP.NET Core controller action method,
- the response body argument of ASP.NET Core controller helpers such as `Ok`, `Json`, `Content`, `StatusCode(500, ...)` and `BadRequest`, and the `ObjectResult` and `JsonResult` constructors,
- values written by a Razor view, for example `@Model.Error.StackTrace`,
- the message of an exception thrown from an ASP.NET Web Forms page or handler when `customErrors` is set to `Off` in `Web.config` (only for environment information, such as `Environment.UserName`).

Values are also tracked through JSON documents built with `Newtonsoft.Json.Linq` or `System.Text.Json.Nodes`.

## Recommendation

Send the user a generic error message that does not reveal implementation details. Log the full exception, including its message and stack trace, on the server instead.

## Example

In the following example, the exception message is returned to the client. An attacker can trigger a database error and read the failing SQL statement from the response:

```csharp
catch (Exception ex)
{
    return StatusCode(500, ex.Message);
}
```

Instead, log the exception and return a generic message:

```csharp
catch (Exception ex)
{
    _logger.LogError(ex, "Membership lookup failed");
    return StatusCode(500, "Internal server error");
}
```

## References

- OWASP: [Improper Error Handling](https://owasp.org/www-community/Improper_Error_Handling).
- Common Weakness Enumeration: [CWE-209](https://cwe.mitre.org/data/definitions/209.html).
- Common Weakness Enumeration: [CWE-497](https://cwe.mitre.org/data/definitions/497.html).
