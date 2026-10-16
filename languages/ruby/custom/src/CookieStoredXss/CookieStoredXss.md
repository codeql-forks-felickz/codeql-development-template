# Stored cross-site scripting through a request-controlled cookie

Rails applications sometimes copy a request parameter into a cookie (for example, to remember a user preference) and later render that cookie in a view without escaping, typically with `raw` or `html_safe`.

`rb/reflected-xss` does not treat cookie reads as attacker controlled, because a third party usually cannot set a victim's cookies. That assumption does not hold when the application writes the cookie itself from request data: an attacker can send the victim a link such as `/dashboard/home?font=</style><script>...</script>`, and the payload is stored in the victim's cookie and emitted on every page that renders it.

This query tracks request input into a cookie write (`cookies[:name] = ...`, including `cookies.permanent`, `cookies.signed` and `cookies.encrypted`, and the `{ value: ... }` hash form), continues from reads of the same cookie name (`cookies[:name]`, `cookies.fetch(:name)`), and reports when that value reaches a server-side XSS sink.

## Recommendation

Do not emit cookie values with `raw` or `html_safe`. Let ERB escape the value, use `sanitize`, or validate the parameter against an allow list before storing it in the cookie.

## Example

The controller stores the `font` parameter in a cookie, and the layout emits it unescaped inside a `<style>` element:

```ruby
class DashboardController < ApplicationController
  def home
    cookies[:font] = params[:font] if params[:font]
  end
end
```

```erb
<style>
  body { font-size:<%= raw cookies[:font] %> !important; }
</style>
```

The fix is to escape the value (or validate it before storing it):

```erb
<style>
  body { font-size:<%= cookies[:font] %> !important; }
</style>
```

## References

- OWASP: [XSS (Cross Site Scripting) Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html).
- Rails guides: [Cross-Site Scripting (XSS)](https://guides.rubyonrails.org/security.html#cross-site-scripting-xss).
- Common Weakness Enumeration: [CWE-79](https://cwe.mitre.org/data/definitions/79.html).
- Common Weakness Enumeration: [CWE-116](https://cwe.mitre.org/data/definitions/116.html).
