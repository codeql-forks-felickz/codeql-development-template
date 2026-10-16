# Web.config authorization allows all users

## Overview

In ASP.NET, `<authorization>` rules in `Web.config` decide which users can request a resource. The first rule that matches the user applies. An application that configures Forms or Windows authentication but has an application-wide rule `<allow users="*" />`, with no earlier `<deny users="?" />`, lets anonymous users reach every page that is not denied by a more specific `<location>` rule. Authentication is then never enforced.

This query reports application-wide `<allow users="*" />` and `<allow users="?" />` rules in `Web.config` files that configure Forms or Windows authentication and do not deny anonymous users first.

## Recommendation

Deny anonymous users by default, and use `<location>` elements to allow anonymous access only to the pages that need it, such as the login page.

## Example

The following configuration allows anonymous access to the whole application:

```xml
<system.web>
  <authentication mode="Forms" />
  <authorization>
    <allow users="*" /> <!-- BAD -->
  </authorization>
</system.web>
```

Denying anonymous users fixes the problem:

```xml
<system.web>
  <authentication mode="Forms" />
  <authorization>
    <deny users="?" />
  </authorization>
</system.web>
<location path="Login.aspx">
  <system.web>
    <authorization>
      <allow users="*" />
    </authorization>
  </system.web>
</location>
```

## References

- Microsoft Learn: [authorization element (ASP.NET Settings Schema)](<https://learn.microsoft.com/en-us/previous-versions/dotnet/netframework-4.0/8d82143t(v=vs.100)>).
- Common Weakness Enumeration: [CWE-284](https://cwe.mitre.org/data/definitions/284.html).
- Common Weakness Enumeration: [CWE-862](https://cwe.mitre.org/data/definitions/862.html).
