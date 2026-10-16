# State-changing action reachable without authentication

## Overview

ASP.NET Core and ASP.NET MVC actions are reachable by anonymous clients unless an authorization requirement applies to them. Requirements can come from an `[Authorize]` attribute on the action or controller, from a global `AuthorizeFilter` or fallback policy, or from a check of the current user in the action. An action that changes server state without any of these lets any remote client create, modify or delete data, or run privileged operations such as writing files or executing commands.

`[AllowAnonymous]` overrides `[Authorize]`, so marking an action that acts on an existing resource with `[AllowAnonymous]` removes the protection of its controller.

This query reports actions that handle `POST`, `PUT`, `PATCH` or `DELETE` requests, or whose names indicate that they change state, when:

- no authorization attribute, `Web.config` `<deny>` rule or global authorization policy applies, and the action does not check the current user, or
- `[AllowAnonymous]` on the action overrides an authorization attribute of its controller, and the action modifies a resource selected by ID.

Authentication flows such as `Login` or `Register` are not reported. Actions already reported by `cs/web/missing-function-level-access-control` are also skipped.

## Recommendation

Require authentication for state-changing actions, for example with `[Authorize]` on the controller or a global fallback policy, and opt out only the actions that must be anonymous. Do not use `[AllowAnonymous]` on actions that modify existing resources.

## Example

In the following example, any client can create a comment or delete any account:

```csharp
public class CommentsController : Controller
{
    [HttpPost]
    public IActionResult Create(Comment comment) { /* BAD */ }
}

[Authorize]
public class AccountsController : Controller
{
    [AllowAnonymous]
    [HttpDelete("{id}")]
    public IActionResult DeleteAccount(int id) { /* BAD: overrides [Authorize] */ }
}
```

Requiring authentication globally fixes the first problem:

```csharp
builder.Services.AddAuthorization(options =>
    options.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build());
```

## References

- Microsoft Learn: [Require authenticated users](https://learn.microsoft.com/en-us/aspnet/core/security/authorization/secure-data#require-authenticated-users).
- Microsoft Learn: [Simple authorization in ASP.NET Core](https://learn.microsoft.com/en-us/aspnet/core/security/authorization/simple).
- Common Weakness Enumeration: [CWE-284](https://cwe.mitre.org/data/definitions/284.html).
- Common Weakness Enumeration: [CWE-306](https://cwe.mitre.org/data/definitions/306.html).
- Common Weakness Enumeration: [CWE-862](https://cwe.mitre.org/data/definitions/862.html).
