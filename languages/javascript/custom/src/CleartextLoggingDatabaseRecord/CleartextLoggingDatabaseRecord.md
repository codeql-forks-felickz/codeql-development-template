# Clear-text logging of a database record with sensitive fields

Logging a whole database record, such as a user document returned by a query, writes every field of that record to the application logs. If the model declares a password or private field, such as a Social Security number, that value ends up in the logs as well. Logs are usually kept longer, protected less carefully and read by more people and systems than the database itself.

This query complements `js/clear-text-logging`, which reports values whose own name suggests sensitive data, such as `password`. It does not recognize a record like `users` as sensitive. This query reports records that are read through a Mongoose or Sequelize model whose schema declares a password or private field, and that then flow to a logging call such as `console.log`.

A record is not reported when:

- the query restricts the returned fields, for example with a Mongoose projection or `select`, or a Sequelize `attributes` option;
- the sensitive Mongoose path is declared with `select: false`, so that it is excluded from query results by default;
- the Sequelize model declares a `defaultScope`;
- only a non-sensitive property of the record is logged, such as `user.username`.

## Recommendation

Do not log whole database records. Log only the fields you need, such as an identifier, or exclude sensitive fields from the query results. With Mongoose, declare sensitive paths with `select: false` so that they are only loaded when explicitly requested.

## Example

The following example logs the whole administrator user document, including its password:

```javascript
User.find({ username: 'admin@example.com' }).exec(function (err, users) {
  console.log(users) // BAD: logs the password field
})
```

Instead, log only the fields you need:

```javascript
User.find({ username: 'admin@example.com' }).exec(function (err, users) {
  console.log(users.map(u => u.username)) // GOOD: no sensitive fields
})
```

Or exclude the password from query results by default:

```javascript
const User = new Schema({
  username: String,
  password: { type: String, select: false }
})
```

## References

- OWASP: [Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html).
- Mongoose: [SchemaType select option](<https://mongoosejs.com/docs/api/schematype.html#SchemaType.prototype.select()>).
- Common Weakness Enumeration: [CWE-312](https://cwe.mitre.org/data/definitions/312.html).
- Common Weakness Enumeration: [CWE-359](https://cwe.mitre.org/data/definitions/359.html).
- Common Weakness Enumeration: [CWE-532](https://cwe.mitre.org/data/definitions/532.html).
