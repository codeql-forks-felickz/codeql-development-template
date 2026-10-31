# Insecure authentication session cookie configuration

## Overview

Session and authentication cookies identify a logged-in user. If such a cookie is sent without the `Secure` attribute, the browser will also send it over cleartext HTTP, where it can be intercepted (CWE-614). If it is sent without the `HttpOnly` attribute, any script running in the application's origin (for example, injected through a cross-site scripting flaw) can read and exfiltrate it (CWE-1004).

This query reports:

- Rails `config.session_store` calls that set `httponly: false` or `secure: false`, or that omit `secure` while the application does not enable `config.force_ssl` (which marks all cookies as `Secure`).
- `set_cookie` calls (for example on a Rack or Sinatra `response`) for cookies whose name suggests a session or authentication cookie, when the value is passed without attributes or the attributes hash lacks or disables `secure` or `httponly`.

## Recommendation

Set `secure: true` and keep `httponly` enabled for session and authentication cookies, or enable `config.force_ssl = true` in production so Rails marks cookies as `Secure`.

## Example

The following session store configuration disables `HttpOnly` and does not set `Secure`:

```ruby
Rails.application.config.session_store :cookie_store, key: "_app_session", httponly: false
```

Instead, keep `HttpOnly` enabled and mark the cookie as `Secure`:

```ruby
Rails.application.config.session_store :cookie_store, key: "_app_session", secure: true, httponly: true
```

Similarly, a session cookie set from a Sinatra or Rack handler should include the attributes:

```ruby
response.set_cookie("SessionID", value: token, secure: true, httponly: true, same_site: :strict)
```

## References

- OWASP: [Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#cookies).
- Rails Guides: [Configuring Rails Applications, `config.session_store`](https://guides.rubyonrails.org/configuring.html#config-session-store).
- Common Weakness Enumeration: [CWE-614](https://cwe.mitre.org/data/definitions/614.html).
- Common Weakness Enumeration: [CWE-1004](https://cwe.mitre.org/data/definitions/1004.html).
