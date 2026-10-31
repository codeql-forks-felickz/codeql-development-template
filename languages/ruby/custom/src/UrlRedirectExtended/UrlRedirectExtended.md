# URL redirection from remote source (extended coverage)

Directly incorporating user input into a URL redirect request without validating the input can facilitate phishing attacks. In these attacks, unsuspecting users can be redirected to a malicious site that looks very similar to the real site they intend to visit, but which is controlled by the attacker.

This query complements the shipped `rb/url-redirection` query and only reports redirects that the shipped query does not report:

- **Post-login style redirects in non-GET actions.** `rb/url-redirection` ignores redirects in actions that do not handle GET requests (such as `create`). However, a redirect-target parameter (for example `url`, `return_to`, `redirect_uri` or `next`) is commonly carried from a GET page's query string into a form, so a phishing link still controls the redirect performed after the form is submitted.
- **`Hash#update` / `Hash#merge!` on `params`.** `redirect_to(params.update(action: "main"))` passes the user-controlled `host` key on to `url_for`.
- **Standalone controller-action snippets.** A top-level method calling `redirect_to` with `params`, when no Rails controller class is present in the database.

## Recommendation

To guard against untrusted URL redirection, it is advisable to avoid putting user input directly into a redirect URL. Instead, maintain a list of authorized redirects on the server; then choose from that list based on the user input provided. If a full URL must be accepted, pass `allow_other_host: false` to `redirect_to` or check that the target is a relative path on the same host.

## Example

The following login action redirects to the `url` parameter after a successful login. An attacker can send a victim a link to the login page with `url=https://evil.example`; the login form carries the value in a hidden field and the victim is redirected to the attacker's site after logging in.

```ruby
class SessionsController < ApplicationController
  def create
    path = params[:url].present? ? params[:url] : home_dashboard_index_path
    if User.authenticate(params[:email], params[:password])
      redirect_to path
    end
  end
end
```

Restricting the redirect to the same host fixes the problem:

```ruby
class SessionsController < ApplicationController
  def create
    path = params[:url].present? ? params[:url] : home_dashboard_index_path
    if User.authenticate(params[:email], params[:password])
      redirect_to path, allow_other_host: false
    end
  end
end
```

## References

- OWASP: [Unvalidated Redirects and Forwards Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html).
- Rails: [ActionController::Redirecting#redirect_to](https://api.rubyonrails.org/classes/ActionController/Redirecting.html#method-i-redirect_to).
- Common Weakness Enumeration: [CWE-601](https://cwe.mitre.org/data/definitions/601.html).
