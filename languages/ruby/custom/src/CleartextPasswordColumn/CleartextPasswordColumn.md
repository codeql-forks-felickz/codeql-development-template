# Password stored in a clear-text database column

A `string` or `text` column named like a password (`password`, `passwd`, `passphrase`, `admin_password`, ...) declared in `db/schema.rb` or a migration usually means the application stores and compares passwords in clear text. A database dump, backup, or SQL injection then exposes reusable passwords.

The stock `rb/clear-text-storage-sensitive-data` query tracks sensitive _values_ into persistent writes; it does not look at the schema, so an application that writes request parameters or literals straight into a `password` column is missed. This query reports the column declaration itself.

It also reports Active Record lookups that authenticate by comparing a value directly against such a column, which confirms the passwords are stored recoverably. For example, `User.find_by(login: l, password: pw)`, `User.where(password: pw)` or `User.where("login = ? AND password = '#{pw}'", l)`. These lookups are reported only when the model's table has a reported clear-text password column.

A column is not reported when its name indicates a hashed or encrypted value (`password_digest`, `encrypted_password`, `crypted_password`, `password_hash`, ...), or when the Active Record model for the table (found via the Rails naming convention, for example `User` for `users`) uses `encrypts`/`attr_encrypted` on the column, uses `has_secure_password`, Devise, Authlogic or Sorcery, or references `BCrypt`, `Argon2`, `SCrypt` or `Digest`.

## Recommendation

Store only a salted, slow password hash, for example with `has_secure_password` (bcrypt) and a `password_digest` column, and verify passwords with `authenticate`.

## Example

```ruby
# BAD
create_table "users" do |t|
  t.string "password", null: false
end

User.find_by(login: params[:login], password: params[:password])

# GOOD
create_table "users" do |t|
  t.string "password_digest", null: false
end

class User < ApplicationRecord
  has_secure_password
end

User.find_by(login: params[:login])&.authenticate(params[:password])
```

## References

- [CWE-256: Plaintext Storage of a Password](https://cwe.mitre.org/data/definitions/256.html)
- [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
- [Rails `has_secure_password`](https://api.rubyonrails.org/classes/ActiveModel/SecurePassword/ClassMethods.html)
