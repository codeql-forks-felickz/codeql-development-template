---
category: minorAnalysis
---
* Added `sql-injection` sink models for the SQL command text argument of the `System.Data.OleDb.OleDbDataAdapter`, `System.Data.Odbc.OdbcDataAdapter`, and `MySql.Data.MySqlClient.MySqlDataAdapter` constructors. The `cs/sql-injection` query now reports user input concatenated into SQL text passed to these adapters.
