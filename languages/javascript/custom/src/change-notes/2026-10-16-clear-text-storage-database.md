---
category: newQuery
---

- Added a new query, `js/clear-text-storage-of-sensitive-data-in-database`, which detects passwords and private data that are persisted to MongoDB (through the `mongodb` driver or Mongoose models) without being hashed or encrypted. It complements `js/clear-text-storage-of-sensitive-data`, which does not model database persistence sinks.
