# Rails cookie session store patched to decode unsigned JSON

Rails' `ActionDispatch::Session::CookieStore` keeps the whole session in a cookie. The cookie is signed and encrypted using the application's `secret_key_base`, so the client can read the cookie but cannot change it.

Some applications patch the cookie store or the cookie jar to read the session in a different format. They do this by prepending or including a module, reopening the class, using `class_eval`, or subclassing it. If the patched method decodes the raw cookie value with `JSON.parse` (or a similar JSON decoder) and doesn't use the signed or encrypted cookie jars, a message verifier, or the original implementation (`super`), Rails never checks the session's integrity. An attacker can then write their own session cookie, for example `{"user_id": 1}`, and log in as any user.

This query is a heuristic. It reports JSON decoding calls inside methods that are added to `ActionDispatch::Session::CookieStore` or to the `ActionDispatch::Cookies` jar classes when the same method doesn't call `signed`, `encrypted`, `signed_or_encrypted`, `verify`, `verified`, `valid_message?`, `decrypt_and_verify`, or `super`.

## Recommendation

Don't replace how Rails decodes session cookies. If you need a JSON session format, set `Rails.application.config.action_dispatch.cookies_serializer = :json` and keep the built-in signed and encrypted cookie store. If you need custom decoding, read the value through `cookies.signed` or `cookies.encrypted`, or verify it with `ActiveSupport::MessageVerifier` or `ActiveSupport::MessageEncryptor` before you decode it.

## Example

In the following example, a module is prepended to the cookie store. It parses the raw session cookie as JSON, so a client can forge any session:

```ruby
module InsecureStore
  def unpacked_cookie_data(req)
    JSON.parse(req.cookies[@key]) # BAD: no signature or encryption check
  end
end
ActionDispatch::Session::CookieStore.prepend(InsecureStore)
```

The following version reads the value through the encrypted cookie jar, so Rails checks the cookie before it's decoded:

```ruby
module JsonStore
  def unpacked_cookie_data(req)
    JSON.parse(req.cookie_jar.encrypted[@key]) # GOOD: authenticated encryption is checked
  end
end
ActionDispatch::Session::CookieStore.prepend(JsonStore)
```

## References

- Rails Guides: [Securing Rails Applications: Sessions](https://guides.rubyonrails.org/security.html#sessions).
- Rails API: [ActionDispatch::Session::CookieStore](https://api.rubyonrails.org/classes/ActionDispatch/Session/CookieStore.html).
- Common Weakness Enumeration: [CWE-565](https://cwe.mitre.org/data/definitions/565.html).
- Common Weakness Enumeration: [CWE-345](https://cwe.mitre.org/data/definitions/345.html).
