# Missing function level access control

Sensitive actions, such as editing or deleting content, or accessing admin pages, should have authorization checks to ensure that they cannot be used by malicious actors.

This query extends the standard CodeQL query `cs/web/missing-function-level-access-control` by additionally modeling ASP.NET web service operations: any method annotated with `[System.Web.Services.WebMethod]` (ASMX web service operations and ASP.NET page methods) is treated as a remotely invocable action. Web methods whose names indicate a transfer, withdrawal, deposit, update or removal are considered sensitive, in addition to the edit, delete and admin heuristics of the standard query.

## Recommendation

Ensure that proper authorization checks are made for sensitive actions. For ASMX web services, check `Context.User.Identity.IsAuthenticated` or `Context.User.IsInRole(...)`, or protect the service with an authorization attribute or a `<location>` configuration that denies unauthorized users.

## Example

In the following example, any remote caller can transfer funds between arbitrary accounts:

```csharp
[WebMethod]
public string TransferBalance(long from, long to, double amount)
{
    Withdraw(from, amount);
    Deposit(to, amount);
    return "OK";
}
```

The method is fixed by checking that the caller is authenticated (and, ideally, owns the debited account):

```csharp
[WebMethod]
public string TransferBalance(long from, long to, double amount)
{
    if (!Context.User.Identity.IsAuthenticated)
        return "Unauthorized";
    Withdraw(from, amount);
    Deposit(to, amount);
    return "OK";
}
```

## References

- OWASP: [Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/).
- Microsoft Learn: [WebMethodAttribute Class](https://learn.microsoft.com/en-us/dotnet/api/system.web.services.webmethodattribute).
- Common Weakness Enumeration: [CWE-285](https://cwe.mitre.org/data/definitions/285.html), [CWE-284](https://cwe.mitre.org/data/definitions/284.html), [CWE-862](https://cwe.mitre.org/data/definitions/862.html).
