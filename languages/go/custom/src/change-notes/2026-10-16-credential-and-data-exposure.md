---
category: newQuery
---
* Added a new query, `go/clear-text-logging-token`, to detect authentication tokens (signed JWTs, access, refresh and session tokens) that are written to logs. The standard `go/clear-text-logging` query only treats password-like values as sensitive, so generated tokens were previously missed.
* Added a new query, `go/cleartext-password-storage-database`, to detect passwords that are written to MongoDB (`gopkg.in/mgo`, `go.mongodb.org/mongo-driver`), GORM, or `database/sql` insert/update statements without first being hashed.
