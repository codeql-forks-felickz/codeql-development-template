# Hard-coded password in model creation

Creating an application account with a password that is written into the source code (for example an administrator account in `db/seeds.rb`) means that every deployment initialized from that code shares a known, often trivially guessable, login.

This query reports non-empty string literals that reach a password attribute (`password`, `password_confirmation`, `*_password`, `passwd`, `passphrase`) of an ActiveRecord model created with `new`, `create`, `create!`, `find_or_create_by`, `create_or_find_by`, `find_or_initialize_by`, or `insert`. The attributes may be passed as keyword arguments, as a hash literal, or as a hash built elsewhere (such as an array of seed records).

The stock `rb/hardcoded-credentials` query only considers literals of at least 10 characters and only direct keyword arguments, so it misses short passwords and seed records defined as hashes.

## Recommendation

Read initial passwords from the environment or a secrets store, or generate a random password and force a reset on first login.

## Example

```ruby
users = [{ email: "admin@example.com", password: "admin1234", admin: true }]
users.each { |u| User.create!(u) } # BAD

User.create!(email: "admin@example.com", password: ENV.fetch("ADMIN_PASSWORD")) # GOOD
```

## References

- [CWE-259: Use of Hard-coded Password](https://cwe.mitre.org/data/definitions/259.html)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
