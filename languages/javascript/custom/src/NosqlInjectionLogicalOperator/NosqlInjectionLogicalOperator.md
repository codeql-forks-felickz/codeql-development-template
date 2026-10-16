# Database query built from user-controlled sources in a NoSQL logical operator

MongoDB-style query documents interpret object values as query operators. If a value parsed from an HTTP request (for example `req.query` or a JSON `req.body`) is used as a field value, an attacker can send an object such as `{"$ne": null}` instead of a string and change the meaning of the query, for example to bypass a login check.

The standard `js/sql-injection` query reports such values when they are stored directly in the query object. It does not follow values stored in the sub-documents of the logical operators `$and`, `$or` and `$nor`, even though MongoDB interprets each of those sub-documents as a full query. This query reports those additional flows.

## Recommendation

Make sure that user-controlled values used in a query are primitive values, for example by checking `typeof value === "string"` or by converting them with `String(value)`. Alternatively, use the `$eq` operator so that the value is always compared literally.

## Example

In the following example, both `email` and `password` come from the JSON request body. An attacker can send `{"email": "admin@example.com", "password": {"$ne": ""}}` to log in without knowing the password.

```javascript
server.post('/login', async (request, response) => {
  const { email, password } = request.body;
  const users = await User.find({ $and: [{ email: email }, { password: password }] });
  // ...
});
```

The query is safe if both values are checked to be strings first.

```javascript
server.post('/login', async (request, response) => {
  const { email, password } = request.body;
  if (typeof email !== 'string' || typeof password !== 'string') {
    return response.status(400).end();
  }
  const users = await User.find({ $and: [{ email: email }, { password: password }] });
  // ...
});
```

## References

* OWASP: [Testing for NoSQL Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection).
* MongoDB: [Logical Query Operators](https://www.mongodb.com/docs/manual/reference/operator/query-logical/).
* Common Weakness Enumeration: [CWE-943](https://cwe.mitre.org/data/definitions/943.html).
