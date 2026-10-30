# Privilege field assigned from user input

Applications commonly store the privileges of an account in a field such as `is_admin`, `isAdmin` or `role`. If a request handler lets the client choose the value of that field when it creates or updates a stored user record, any user, or even an anonymous visitor, can grant themselves administrative rights. This is a form of mass assignment that leads to improper privilege management.

The query reports:

- writes to a privilege-named property of an object that is stored in a database (for example passed to `insert`, `create`, `findOneAndUpdate` or `save`), where the stored value is derived from request data, or chosen by an `if` statement or conditional expression that tests a privilege-named field of request data such as `req.body.is_admin`;
- generated REST resources (`finale-rest` / `epilogue`) that expose `create` or `update` endpoints for a Sequelize model that declares a privilege attribute, since these endpoints copy every attribute of the request body into the model.

## Recommendation

Never take privilege fields from the request. Assign them on the server, for example by giving every new account the least privileged role. If privileges must be changeable through an endpoint, check that the current user is already authorized to grant them, and restrict the accepted value to an allow-list. For generated REST resources, restrict the `actions` to read-only operations, or strip privilege attributes from the request body in a `create.write.before` / `update.write.before` milestone.

## Example

The following registration handler lets the client decide whether the new account is an administrator:

```javascript
app.post('/api/register', function (req, res) {
  var admin = req.body.is_admin ? true : false;
  db.collection('users').insertOne({ email: req.body.email, is_admin: admin });
});
```

Instead, the server should decide the privilege level of new accounts:

```javascript
app.post('/api/register', function (req, res) {
  db.collection('users').insertOne({ email: req.body.email, is_admin: false });
});
```

## References

- MITRE: [CWE-269: Improper Privilege Management](https://cwe.mitre.org/data/definitions/269.html).
- MITRE: [CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html).
- OWASP: [Mass Assignment Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html).
