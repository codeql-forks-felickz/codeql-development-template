# Rails production configuration does not enforce SSL

When `config.force_ssl` is not enabled for the production environment of a Rails application, Rails does not redirect HTTP requests to HTTPS, does not send a `Strict-Transport-Security` (HSTS) header and does not mark cookies as `Secure`. If the application can be reached over plain HTTP, a network attacker can read or modify the traffic, including login credentials and the session cookie.

This query reports a `config/environments/production.rb` file that either explicitly sets `config.force_ssl` to `false` (or `nil`), or does not set it at all. No alert is reported when the application's own `config/`, `app/` or `lib/` code enables SSL in a way that applies to production, for example:

- `config.force_ssl = true` (or a non-constant value) in `config/application.rb`, an initializer, or the production environment file;
- a controller-level `force_ssl` call;
- adding an SSL-enforcing middleware (`ActionDispatch::SSL`, `Rack::SSL` or `Rack::SslEnforcer`) with `config.middleware.use`, `unshift`, `insert_before` or `insert_after`.

Settings in other environment files (for example `development.rb`), vendored gems and tests do not suppress the alert, and neither does removing the middleware (for example `config.middleware.delete ActionDispatch::SSL`).

## Recommendation

Set `config.force_ssl = true` in `config/environments/production.rb`. Also enforce HTTPS at the edge (load balancer or reverse proxy). If TLS is terminated by a proxy, also consider setting `config.assume_ssl = true`.

## Example

The following production configuration leaves `force_ssl` commented out, so the application accepts cleartext HTTP traffic:

```ruby
Rails.application.configure do
  config.cache_classes = true
  # config.force_ssl = true
end
```

The fix is to enable the setting:

```ruby
Rails.application.configure do
  config.cache_classes = true
  config.force_ssl = true
end
```

## Limitations

TLS can also be enforced outside the repository, for example by a reverse proxy or the hosting platform. The query cannot see that configuration, so its precision is medium.

## References

- Rails Guides: [Configuring Rails Applications, `config.force_ssl`](https://guides.rubyonrails.org/configuring.html#config-force-ssl).
- Rails Guides: [Securing Rails Applications, Session Hijacking](https://guides.rubyonrails.org/security.html#session-hijacking).
- OWASP: [Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html).
- Common Weakness Enumeration: [CWE-319](https://cwe.mitre.org/data/definitions/319.html).
- Common Weakness Enumeration: [CWE-614](https://cwe.mitre.org/data/definitions/614.html).
