# Clear text storage of sensitive information in a database

Passwords and private data, such as Social Security numbers, should not be stored in a database as clear text. Anyone who can read the database can then read the data, including through a backup, a log, a replica or a separate injection flaw. A password should be stored only as the output of a slow, salted password hashing function. Private data that must be recovered later should be encrypted.

This query complements `js/clear-text-storage-of-sensitive-data`, which covers cookies, Web Storage and AngularJS storage but not databases. It reports password or private data that is written to MongoDB without a hashing or encryption step in between. It covers two kinds of writes:

- a value written to a field of a document passed to a MongoDB collection write, such as `insert`, `insertOne`, `updateOne` or `findAndModify`, or to a Mongoose model, such as `new Model(doc)`, `Model.create` or `Model.findByIdAndUpdate`;
- a whole remote object, such as `req.body`, passed to a Mongoose model whose schema declares a password or private path.

A value is reported when it comes from an expression whose name suggests a password or private data. A remote user-controlled value is also reported when it is stored in a field whose name suggests a password or private data, for example `{ password: req.body.pass }`.

Writes through a Mongoose model are not reported when the schema may transform documents before they are saved. This includes a schema with a `pre` hook or a `plugin`, a sensitive path with a `set` function, or a schema that cannot be resolved.

## Recommendation

Hash passwords with a password hashing function such as `bcrypt`, `scrypt`, `argon2` or PBKDF2 before you store them. Encrypt private data that must be recovered later with a strong cipher, and keep the key outside the database.

## Example

The following example stores the password from a registration request in MongoDB as is:

```javascript
app.post('/register', async (req, res) => {
  await db.collection('users').insertOne({
    email: req.body.email,
    password: req.body.password // BAD: stored as clear text
  })
  res.end()
})
```

Instead, hash the password before you store it:

```javascript
const bcrypt = require('bcrypt')

app.post('/register', async (req, res) => {
  await db.collection('users').insertOne({
    email: req.body.email,
    password: await bcrypt.hash(req.body.password, 12) // GOOD: hashed
  })
  res.end()
})
```

With Mongoose, hash the password in a `pre('save')` hook so that every way of creating a document is protected:

```javascript
accountSchema.pre('save', async function () {
  if (this.isModified('password')) {
    this.password = await bcrypt.hash(this.password, 12)
  }
})
```

## References

- OWASP: [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
- OWASP: [Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html).
- Mongoose: [Middleware](https://mongoosejs.com/docs/middleware.html).
- Common Weakness Enumeration: [CWE-256](https://cwe.mitre.org/data/definitions/256.html).
- Common Weakness Enumeration: [CWE-311](https://cwe.mitre.org/data/definitions/311.html).
- Common Weakness Enumeration: [CWE-312](https://cwe.mitre.org/data/definitions/312.html).
- Common Weakness Enumeration: [CWE-359](https://cwe.mitre.org/data/definitions/359.html).
