# Web Forms route bypasses physical URL authorization

## Overview

`RouteCollection.MapPageRoute` checks authorization for the physical page mapped to a
route by default. Setting `checkPhysicalUrlAccess` to `false` bypasses that check, so a
route can expose a page that would otherwise be protected by its physical URL's
authorization rules.

## Recommendation

Keep `checkPhysicalUrlAccess` enabled unless the application performs equivalent
authorization checks for every route to the page.

## References

- Microsoft Learn: [RouteCollection.MapPageRoute Method](https://learn.microsoft.com/en-us/dotnet/api/system.web.routing.routecollection.mappageroute).
- Common Weakness Enumeration: [CWE-862](https://cwe.mitre.org/data/definitions/862.html).
