# State-changing action routed from a GET request

## Overview

Rails' cross-site request forgery (CSRF) protection (`protect_from_forgery`) only verifies authenticity tokens for unsafe HTTP methods such as POST, PATCH, PUT and DELETE. GET requests are assumed to be safe and are never checked. If a route maps a GET request to a controller action that creates, updates or deletes data, a malicious site can make a logged-in victim's browser issue that request (for example through an `<img>` tag or a link) and perform the action without a CSRF token (CWE-352).

This query reports Rails routes that map the GET method (including `via: :all`) to the `create`, `update`, `destroy` or `delete` actions.

## Recommendation

Only route state-changing actions from unsafe HTTP methods (POST, PATCH, PUT or DELETE), so that Rails' CSRF verification applies to them.

## Example

The following route lets a GET request delete a record:

```ruby
match 'todos/:id/complete', to: "todos#destroy", via: [:get, :delete]
```

Instead, only allow the DELETE method:

```ruby
match 'todos/:id/complete', to: "todos#destroy", via: :delete
```

## References

- Rails Guides: [Securing Rails Applications, Cross-Site Request Forgery](https://guides.rubyonrails.org/security.html#cross-site-request-forgery-csrf).
- OWASP: [Cross-Site Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).
- Common Weakness Enumeration: [CWE-352](https://cwe.mitre.org/data/definitions/352.html).
