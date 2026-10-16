# Missing access control on WCF service operation

Methods marked with `[OperationContract]` on a `[ServiceContract]` type (or implementing such an operation of a service contract interface) are remotely callable WCF endpoints. If such an operation modifies a resource selected by a caller-supplied ID, it must check that the caller is authorized to modify that resource. Otherwise anyone who can reach the service can modify arbitrary resources. If the operation also accepts HTTP `GET` (for example through `[WebInvoke(Method = "GET")]`), it can be triggered cross-site as well.

The `cs/web/insecure-direct-object-reference` and `cs/web/missing-function-level-access-control` queries only model ASP.NET MVC and Web Forms actions, so they do not consider WCF service operations. This query models WCF service operations as endpoints. It reports state-changing operations with an ID parameter that never inspect the caller (for example `ServiceSecurityContext`, `Thread.CurrentPrincipal` or `IsInRole`), are not protected by an authorization attribute such as `[PrincipalPermission]`, and are not covered by a `web.config` `<authorization>` rule.

## Recommendation

Authenticate the caller and check that they own the resource, or that they have a role that allows them to modify it, before making the change. Do not allow state-changing operations to be invoked with HTTP `GET`.

## Example

In the following example, `UpdateShipAddress` lets anyone redirect the shipment of any order. `ChangeShipAddress` checks that the order belongs to the caller.

```csharp
[ServiceContract]
public class Orders
{
    // BAD: no authentication or ownership check.
    [OperationContract]
    [WebInvoke(Method = "GET")]
    public void UpdateShipAddress(int orderId, string address)
    {
        var order = repo.GetOrderById(orderId);
        order.ShipAddress = address;
        repo.UpdateOrder(order);
    }

    // GOOD: the order must belong to the caller.
    [OperationContract]
    [WebInvoke(Method = "POST")]
    public void ChangeShipAddress(int orderId, string address)
    {
        var order = repo.GetOrderById(orderId);
        if (order.CustomerName != ServiceSecurityContext.Current.PrimaryIdentity.Name)
            throw new UnauthorizedAccessException();
        order.ShipAddress = address;
        repo.UpdateOrder(order);
    }
}
```

## References

- Microsoft Learn: [Authorization in WCF](https://learn.microsoft.com/en-us/dotnet/framework/wcf/feature-details/authorization-in-wcf).
- OWASP: [Insecure Direct Object Reference Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html).
- Common Weakness Enumeration: [CWE-285](https://cwe.mitre.org/data/definitions/285.html).
- Common Weakness Enumeration: [CWE-639](https://cwe.mitre.org/data/definitions/639.html).
- Common Weakness Enumeration: [CWE-862](https://cwe.mitre.org/data/definitions/862.html).
