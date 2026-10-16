---
category: newQuery
---

- Added a new query, `js/clear-text-storage-of-sensitive-data-in-database`, which detects passwords and private data that are persisted to a database (through the `mongodb` driver, Mongoose models or Sequelize models) without being hashed or encrypted. It complements `js/clear-text-storage-of-sensitive-data`, which does not model database persistence sinks. Hard-coded clear-text passwords, such as seeded administrator accounts, are also reported.
