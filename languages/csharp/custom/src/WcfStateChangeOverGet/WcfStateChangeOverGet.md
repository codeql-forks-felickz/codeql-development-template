# WCF service operation changes state over HTTP GET

## Overview

A WCF web operation annotated with `[WebGet]` or `[WebInvoke(Method = "GET")]` can be called with a plain `GET` request. Browsers send `GET` requests cross-site without any user interaction, for example for an image tag, and include the victim's cookies. If the operation modifies data and the service relies on cookie authentication (for example with `AspNetCompatibilityRequirements`), an attacker can make a logged-in victim perform the change. This is a cross-site request forgery (CSRF).

Checking that the caller owns the resource does not help, because the forged request is sent with the victim's credentials.

The existing `cs/web/missing-token-validation` query only covers ASP.NET MVC and ASP.NET Core actions.

This query reports WCF service operations exposed over `GET` whose names indicate that they create, update, delete or otherwise change data.

## Recommendation

Expose state-changing operations only with `POST`, `PUT` or `DELETE` (`[WebInvoke(Method = "POST")]`), and require an anti-forgery token or a custom request header that cross-site requests cannot set.

## Example

The following operation updates an order's shipping address on a `GET` request:

```csharp
[OperationContract]
[WebInvoke(Method = "GET")]
public void UpdateShipAddress(int OrderId, string Address) // BAD
{
    _repository.UpdateShipAddress(OrderId, Address);
}
```

Requiring `POST` fixes the problem:

```csharp
[OperationContract]
[WebInvoke(Method = "POST")]
public void UpdateShipAddress(int OrderId, string Address) // GOOD
{
    _repository.UpdateShipAddress(OrderId, Address);
}
```

## References

- OWASP: [Cross-Site Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).
- Microsoft Learn: [WebInvokeAttribute Class](https://learn.microsoft.com/en-us/dotnet/api/system.servicemodel.web.webinvokeattribute).
- Common Weakness Enumeration: [CWE-352](https://cwe.mitre.org/data/definitions/352.html).
