# Forms authentication ticket protection disabled

ASP.NET forms authentication stores the user's identity in an authentication ticket that is sent to the client in a cookie. The `protection` attribute of the `<forms>` element in `Web.config` controls how this ticket is protected. Setting `protection="None"` disables both encryption and validation of the ticket, so an attacker who can set the cookie can forge or tamper with it and impersonate any user, including administrators.

## Recommendation

Use `protection="All"` (the default), which both encrypts and validates the forms authentication ticket. Alternatively, remove the `protection` attribute so that the default applies.

## Example

The following configuration disables protection of the forms authentication ticket:

```xml
<configuration>
  <system.web>
    <authentication mode="Forms">
      <forms loginUrl="~/Account/Login" protection="None" />
    </authentication>
  </system.web>
</configuration>
```

The following configuration encrypts and validates the ticket:

```xml
<configuration>
  <system.web>
    <authentication mode="Forms">
      <forms loginUrl="~/Account/Login" protection="All" />
    </authentication>
  </system.web>
</configuration>
```

## References

- Microsoft Learn: [forms Element for authentication (ASP.NET Settings Schema)](https://learn.microsoft.com/en-us/previous-versions/dotnet/netframework-4.0/1d3t3c61(v=vs.100)).
- Common Weakness Enumeration: [CWE-287](https://cwe.mitre.org/data/definitions/287.html).
