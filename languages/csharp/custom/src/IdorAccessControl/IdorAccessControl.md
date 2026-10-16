# Insecure direct object reference without ownership check

Web handlers often use an identifier supplied by the client (a route value such as `{id}`, a query or form parameter such as `orderNumber`, or a cookie such as `userId`) to choose which database record to read, change, or delete. If the handler doesn't check that the authenticated user owns that record or is otherwise allowed to access it, an attacker can change the identifier and access other users' data. This is called an insecure direct object reference (IDOR), or authorization bypass through a user-controlled key.

Authenticating the caller with `[Authorize]` or a session flag isn't enough. It proves who the caller is, but it doesn't prove that the caller may access the requested record.

This query tracks identifier-like request values to record lookups: SQL command text, SQL parameter values, Entity Framework `Find`, and `IQueryable` predicates. It reports a lookup when neither the handler that reads the identifier nor the method that performs the lookup refers to the current user (`User`, `IPrincipal`/`IIdentity`, `UserManager`, `IAuthorizationService.AuthorizeAsync`, or a user-keyed session value). The query ignores handlers that are restricted to roles or policies (for example `[Authorize(Roles = "Administrator")]`) and handlers with "admin" in their name.

## Recommendation

Get the current user from server-side state, such as the authenticated principal or the session. Don't take it from a client-controlled cookie or parameter. Before you use a client-supplied identifier, check that the record belongs to the current user, or scope the lookup to that user (for example `WHERE id = @id AND owner = @currentUser`).

## Example

The following ASP.NET Core action loads and updates any user selected by `{id}`. Its only protection is `[Authorize]`:

```csharp
[Authorize]
[HttpPut("{id}")]
public IActionResult Put(int id, [FromBody] UserUpdateRequest user)
{
    var existingUser = _context.Users.SingleOrDefault(m => m.ID == id);
    existingUser.email = user.email;
    _context.SaveChanges();
    return Ok(existingUser);
}
```

The fixed version checks that the requested record belongs to the authenticated user:

```csharp
[Authorize]
[HttpPut("{id}")]
public IActionResult Put(int id, [FromBody] UserUpdateRequest user)
{
    if (User.FindFirst("sub")?.Value != id.ToString())
        return Forbid();
    var existingUser = _context.Users.SingleOrDefault(m => m.ID == id);
    existingUser.email = user.email;
    _context.SaveChanges();
    return Ok(existingUser);
}
```

The following Web Forms page takes the current customer from a cookie that the client can change:

```csharp
int.TryParse(Request.Cookies["customerNumber"].Value, out id);
DataSet orders = du.GetOrders(id);
```

Use the authenticated principal or server-side session instead.

## References

- OWASP: [Insecure Direct Object Reference Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html).
- Common Weakness Enumeration: [CWE-566](https://cwe.mitre.org/data/definitions/566.html).
- Common Weakness Enumeration: [CWE-639](https://cwe.mitre.org/data/definitions/639.html).
