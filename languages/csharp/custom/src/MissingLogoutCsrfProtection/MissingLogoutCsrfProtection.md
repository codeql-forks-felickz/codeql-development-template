# Logout action lacks CSRF protection

## Overview

A cross-site request can sign a user out if a logout action can be reached without an
anti-forgery token. Logout actions should accept only POST requests and validate an
anti-forgery token.

This query reports ASP.NET Core MVC actions whose names indicate logout or sign-out
and call a sign-out method without anti-forgery protection. It recognizes
`[ValidateAntiForgeryToken]` and direct validation calls in the action or its called
methods. `[AutoValidateAntiforgeryToken]` suppresses a result only when the action is
restricted to POST.

## Known limitations

Globally registered and custom anti-forgery filters are not modeled and may cause false
positives.

## Recommendation

Restrict logout actions to POST and apply `[ValidateAntiForgeryToken]` or an equivalent
anti-forgery check.

## References

- OWASP: [Cross-Site Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).
- Common Weakness Enumeration: [CWE-352](https://cwe.mitre.org/data/definitions/352.html).
