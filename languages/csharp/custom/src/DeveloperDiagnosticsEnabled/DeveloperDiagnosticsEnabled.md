# Developer diagnostics exposed to remote users

ASP.NET Core's developer exception page (`UseDeveloperExceptionPage`) and database error page (`UseDatabaseErrorPage`) show stack traces, source code fragments, file paths, request data and database details for unhandled exceptions. They are intended for local development only. Registering them without checking the hosting environment enables them in production as well.

Similarly, ASP.NET page tracing (`Trace.IsEnabled = true`) appends request headers, cookies, session state, application state and server variables to the page output. Enabling it at runtime, for example based on a query string parameter, lets any visitor read this information.

## Recommendation

Only register the developer exception page and database error page when the application runs in the development environment, and use a generic exception handler otherwise. Do not enable page tracing in production, or only enable it for local requests (`Request.IsLocal`).

## Example

In the following example, the developer exception page is enabled in every environment:

```csharp
public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
{
    app.UseDeveloperExceptionPage();
}
```

Instead, restrict it to the development environment:

```csharp
public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
{
    if (env.IsDevelopment())
    {
        app.UseDeveloperExceptionPage();
    }
    else
    {
        app.UseExceptionHandler("/error");
    }
}
```

In the following example, any visitor can enable tracing by adding `?trace=true` to the URL:

```csharp
if (Request.QueryString["trace"] == "true")
{
    Trace.IsEnabled = true;
}
```

## References

- Microsoft Learn: [Handle errors in ASP.NET Core](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/error-handling).
- Microsoft Learn: [TraceContext.IsEnabled Property](https://learn.microsoft.com/en-us/dotnet/api/system.web.tracecontext.isenabled).
- Common Weakness Enumeration: [CWE-209](https://cwe.mitre.org/data/definitions/209.html).
- Common Weakness Enumeration: [CWE-489](https://cwe.mitre.org/data/definitions/489.html).
