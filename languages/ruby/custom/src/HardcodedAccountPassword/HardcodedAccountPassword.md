# Hard-coded password stored on an application account

Creating or updating an application account (an Active Record model) with a password taken from a string literal ships a default credential in source control. Seed scripts such as `db/seeds.rb` are often run in production (`rails db:seed`), so anyone who can read the source can log in with the seeded account.

The stock `rb/hardcoded-credentials` query ignores short literals such as `"password"` to limit false positives. This query instead relies on the sink: a string literal written to a password-named attribute (`password`, `passwd`, `admin_password`, ...) through an Active Record persistent write (`create`, `create!`, `find_or_create_by`, `update`, `update_attribute`, or `record.password = ...`). Empty strings, digest/encrypted attributes, and test code (`test/`, `spec/`, `*_test.rb`, ...) are ignored.

## Recommendation

Do not seed accounts with fixed passwords. Read the initial password from the environment or a secret store, generate a random one, or force a password reset on first login.

## Example

```ruby
# BAD: anyone who reads the source knows the admin password
User.create(login: 'admin', password: 'password')

# GOOD
User.create(login: 'admin', password: ENV.fetch('ADMIN_PASSWORD'))
```

## References

- [CWE-1392: Use of Default Credentials](https://cwe.mitre.org/data/definitions/1392.html)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [CWE-259: Use of Hard-coded Password](https://cwe.mitre.org/data/definitions/259.html)
