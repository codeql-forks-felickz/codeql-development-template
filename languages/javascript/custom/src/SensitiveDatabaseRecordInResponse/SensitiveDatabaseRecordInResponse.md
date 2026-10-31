# Database record with sensitive fields sent in an HTTP response

Sending a whole database record, such as a user returned by a query or by `user.update(...)`, in an HTTP response serializes every field of that record. If the model declares a password field, the response discloses the stored password or password hash to the client. A password hash can be cracked offline, and a stored clear-text password can be reused directly.

This query reports records that are read or updated through a Mongoose or Sequelize model whose schema declares a password field, and that then flow to an HTTP response, such as `res.json(user)` or `res.send({ user })`.

A record is not reported when:

- the model customizes serialization, for example with a `toJSON` method or a Mongoose `toJSON` transform;
- the query restricts the returned fields, for example with a Mongoose projection or `select`, or a Sequelize `attributes` option;
- the password path is declared with `select: false`, or the Sequelize model declares a `defaultScope`;
- the record is copied into an object that overrides the password field, as in `{ ...user.dataValues, password: '********' }`;
- only non-sensitive properties of the record are sent, such as `user.email`.

Private data, such as an address or phone number, is not reported by this query, because it is often returned to its owner by design.

## Recommendation

Do not send whole database records to clients. Send only the fields the client needs, or remove sensitive fields when records are serialized, for example in a `toJSON` method.

## Example

The following example returns the whole updated user after a password reset, including the password hash:

```javascript
const updatedUser = await user.update({ password: newPassword })
res.json({ user: updatedUser }) // BAD: includes the password hash
```

Instead, return only the fields the client needs:

```javascript
const updatedUser = await user.update({ password: newPassword })
res.json({ user: { id: updatedUser.id, email: updatedUser.email } }) // GOOD
```

Or remove the password whenever a record is serialized:

```javascript
class User extends Model {
  toJSON() {
    const values = { ...this.get() }
    delete values.password
    return values
  }
}
```

## References

- OWASP: [API3:2023 Broken Object Property Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/).
- Sequelize: [Model instances](https://sequelize.org/docs/v6/core-concepts/model-instances/).
- Mongoose: [toJSON transforms](<https://mongoosejs.com/docs/api/document.html#Document.prototype.toJSON()>).
- Common Weakness Enumeration: [CWE-200](https://cwe.mitre.org/data/definitions/200.html).
- Common Weakness Enumeration: [CWE-359](https://cwe.mitre.org/data/definitions/359.html).
