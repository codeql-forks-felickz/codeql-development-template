---
category: newQuery
---
* Added a new query, `js/nosql-injection-logical-operator`, which complements `js/sql-injection` by detecting user-controlled objects that reach a NoSQL query through sub-documents of the `$and`, `$or` and `$nor` logical operators (for example `User.find({ $and: [{ email: req.body.email }] })`). Results already reported by `js/sql-injection` are not repeated.
