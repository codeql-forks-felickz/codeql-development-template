# XPath injection from an unresolved ASP.NET Core controller

If an XPath expression is built by concatenating user-provided values, a malicious user can change the meaning of the expression and read arbitrary data from the XML document.

The standard `cs/xml/xpath-injection` query treats parameters of ASP.NET Core controller action methods as user-provided values. It recognizes controllers through the resolved `Microsoft.AspNetCore.Mvc.ControllerBase` or `Microsoft.AspNetCore.Mvc.Controller` base types and the `[ApiController]`/`[Controller]` attributes. When a database is created without the ASP.NET Core assemblies (for example, `build-mode: none` on loose `.cs` files that have no `Microsoft.NET.Sdk.Web` project file), these types are unknown, so the controller and its action parameters are not recognized.

This query uses the compiler errors recorded by the extractor for the unresolved `ControllerBase` or `Controller` base type to recognize such controllers. It reports XPath injection only from their public, non-static action method parameters, so it does not duplicate results of `cs/xml/xpath-injection`.

## Recommendation

Do not build XPath expressions from user input. Use a parameterized XPath expression with an `XsltContext` that resolves variables, or validate the input against a strict allow-list before using it.

## Example

The following action concatenates the `user` route value into the XPath expression passed to `SelectSingleNode`:

```csharp
[Route("api/[controller]")]
[ApiController]
public class XPath : ControllerBase
{
    [HttpGet("{user}")]
    public void Lookup(string user)
    {
        XmlDocument doc = new XmlDocument();
        doc.Load("bookstore.xml");
        XmlNode node = doc.SelectSingleNode("//book[author='" + user + "']"); // BAD
    }
}
```

## Limitations

* Only controllers whose unresolved base type is named `ControllerBase` or `Controller` are recognized. Controllers identified only by an unresolved `[ApiController]` or `[Controller]` attribute are not.
* Unresolved `[NonAction]` attributes are not extracted, so such methods are still treated as action methods.

## References

* OWASP: [XPath injection](https://owasp.org/www-community/attacks/XPATH_Injection).
* Microsoft Learn: [Handle requests with controllers in ASP.NET Core MVC](https://learn.microsoft.com/en-us/aspnet/core/mvc/controllers/actions).
* Common Weakness Enumeration: [CWE-643](https://cwe.mitre.org/data/definitions/643.html).
