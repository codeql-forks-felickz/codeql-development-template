---
category: newQuery
---

- Added a new query, `js/clear-text-logging-of-sensitive-database-record`, which detects whole database records read through Mongoose or Sequelize models that declare a password or private field, and that are then written to a log. It complements `js/clear-text-logging`, which does not treat database records as sensitive.
