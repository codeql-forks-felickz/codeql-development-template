# CORS policy allows credentials from any origin

A Cross-Origin Resource Sharing (CORS) policy controls which other websites can make requests to an application from the browser and read the responses. If a policy allows credentials (`AllowCredentials()`) and also accepts every origin (`AllowAnyOrigin()`, or `SetIsOriginAllowed` with a predicate that always returns `true`), any website can send requests that include the user's cookies or HTTP authentication and read the responses. A malicious page can then steal data from logged-in users or perform actions on their behalf.

ASP.NET Core 2.2 and later throws an exception when `AllowAnyOrigin()` and `AllowCredentials()` are combined. However, earlier versions reflect the caller's origin, and `SetIsOriginAllowed(_ => true)` bypasses the check in every version.

## Recommendation

Allow credentials only for an explicit list of trusted origins configured with `WithOrigins(...)`, or validate the origin in `SetIsOriginAllowed` against an allow list. If the endpoint must be callable from any origin, don't allow credentials.

## Example

The following policy allows credentialed requests from every origin:

```csharp
services.AddCors(options =>
{
    options.AddPolicy("CorsPolicy",
        builder => builder.AllowAnyOrigin()
            .AllowAnyMethod()
            .AllowAnyHeader()
            .AllowCredentials());
});
```

The fixed version restricts the policy to trusted origins:

```csharp
services.AddCors(options =>
{
    options.AddPolicy("CorsPolicy",
        builder => builder.WithOrigins("https://app.example.com")
            .AllowAnyMethod()
            .AllowAnyHeader()
            .AllowCredentials());
});
```

## References

- Microsoft Learn: [Enable Cross-Origin Requests (CORS) in ASP.NET Core](https://learn.microsoft.com/en-us/aspnet/core/security/cors).
- MDN: [Access-Control-Allow-Credentials](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Credentials).
- Common Weakness Enumeration: [CWE-942](https://cwe.mitre.org/data/definitions/942.html).
