# Insecure direct object reference protected only by authentication

An action that edits or deletes a resource identified by a caller-supplied ID must check that the current user is allowed to act on _that_ resource. A plain `[Authorize]` attribute (without `Roles`, `Users` or a policy) only proves that the caller is authenticated. Any signed-in user can then modify or delete other users' resources by changing the ID.

The `cs/web/insecure-direct-object-reference` and `cs/web/missing-function-level-access-control` queries treat any `[Authorize]` attribute as sufficient. This query reports the remaining cases: state-changing actions (edit/update/delete-style names, or `[HttpPut]`, `[HttpPatch]` and `[HttpDelete]`) that take an ID parameter, are protected only by a plain `[Authorize]`, and never inspect the current principal (for example `User`, `IsInRole`, claims or `IAuthorizationService`).

## Recommendation

Check that the current user owns the resource, or restrict the action to a privileged role or authorization policy, before modifying the resource.

## Example

In the following example, the `Delete` action requires only an authenticated caller, so any user can delete any account. `DeleteOwn` checks that the account belongs to the current user. `DeleteAny` is restricted to administrators.

```csharp
[Route("api/[controller]")]
public class UsersController : Controller
{
    // BAD: any authenticated user can delete any account.
    [Authorize]
    [HttpDelete("{id}")]
    public IActionResult Delete(int id)
    {
        _store.Remove(_store.Find(id));
        return Ok();
    }

    // GOOD: the account must belong to the current user.
    [Authorize]
    [HttpDelete("me/{id}")]
    public IActionResult DeleteOwn(int id)
    {
        var user = _store.Find(id);
        if (user.Name != User.Identity.Name)
            return Forbid();
        _store.Remove(user);
        return Ok();
    }

    // GOOD: restricted to administrators.
    [Authorize(Roles = "Administrator")]
    [HttpDelete("admin/{id}")]
    public IActionResult DeleteAny(int id)
    {
        _store.Remove(_store.Find(id));
        return Ok();
    }
}
```

## References

- OWASP: [Insecure Direct Object Reference Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html).
- Microsoft Learn: [Resource-based authorization in ASP.NET Core](https://learn.microsoft.com/en-us/aspnet/core/security/authorization/resourcebased).
- Common Weakness Enumeration: [CWE-639](https://cwe.mitre.org/data/definitions/639.html).
- Common Weakness Enumeration: [CWE-862](https://cwe.mitre.org/data/definitions/862.html).
