---
category: newQuery
---

- Added a new query, `js/sensitive-database-record-in-response`, which detects whole database records read or updated through Mongoose or Sequelize models that declare a password field, and that are then sent in an HTTP response.
