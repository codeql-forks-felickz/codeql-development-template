# User-controlled object used in ORM model or query

## Overview

Object-relational mappers (ORMs) such as Mongoose and Sequelize accept plain JavaScript objects
to create or update records and to describe query conditions. When such an object comes directly
from the user, for example the whole `req.body` of an Express request or the result of calling
`JSON.parse` on a request parameter, the user decides which properties it contains.

- When the object is passed to a model constructor or a create/update method, the user can set
  any attribute defined in the model schema, including privileged attributes such as `isAdmin`,
  `role` or `createdAt` (mass assignment, CWE-915).
- When the object is used as a Sequelize `where` condition, or as the value of a property in
  that condition, the user can supply an array or a nested object instead of a scalar value and
  so change which records the query returns.

This query reports deeply user-controlled objects that reach:

- Mongoose: `new Model(obj)`, `Model.create(obj)`, `Model.insertMany(obj)`, `doc.set(obj)` and
  `doc.overwrite(obj)`.
- Sequelize: `new Model(obj)`, `Model.build(obj)`, `Model.create(obj)`, `Model.bulkCreate(obj)`,
  `Model.upsert(obj)`, `Model.update(obj, options)`, `instance.set(obj)` and
  `instance.update(obj)`, as well as the `where` option of finder, count, destroy and update
  methods.

MongoDB query objects that are already reported by `js/sql-injection` are not reported again.

## Recommendation

Copy only the fields that the user is allowed to set into a new object, either explicitly or with
an allow-list helper such as lodash's `_.pick`. Make sure that values used in query conditions
have the expected primitive type, for example by converting them with `Number(...)` or `String(...)`
or by checking them with `typeof`.

## Example

The following Express handler passes the whole request body to a Mongoose model, so a client can
create an administrator account by sending `"isAdmin": true`:

```javascript
router.post('/accounts', async (req, res) => {
  const account = new Account(req.body) // BAD
  await account.save()
  res.status(201).end()
})
```

Only copy the fields that the client is allowed to set:

```javascript
router.post('/accounts', async (req, res) => {
  const account = new Account({
    name: req.body.name,
    email: req.body.email,
    password: req.body.password
  }) // GOOD
  await account.save()
  res.status(201).end()
})
```

The following handler parses a path parameter as JSON and uses the result as a Sequelize
condition. A request for `/recycles/[1,2,3]` returns every record with one of the listed IDs:

```javascript
RecycleModel.findAll({
  where: {
    id: JSON.parse(req.params.id) // BAD
  }
})
```

Use the path parameter as a scalar value instead:

```javascript
RecycleModel.findAll({
  where: {
    id: Number(req.params.id) // GOOD
  }
})
```

## References

- MITRE: [CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html).
- MITRE: [CWE-943: Improper Neutralization of Special Elements in Data Query Logic](https://cwe.mitre.org/data/definitions/943.html).
- OWASP: [Mass Assignment Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html).
- Sequelize: [Model Querying - Basics](https://sequelize.org/docs/v6/core-concepts/model-querying-basics/).
- Mongoose: [Models](https://mongoosejs.com/docs/models.html).
