---
category: minorAnalysis
---
* Added `sql-injection` sink models for the SQL command text argument of the `System.Data.OleDb.OleDbDataAdapter`, `System.Data.Odbc.OdbcDataAdapter`, `MySql.Data.MySqlClient.MySqlDataAdapter`, and `Mono.Data.Sqlite.SqliteDataAdapter` constructors. The `cs/sql-injection` query now reports user input concatenated into SQL text passed to these adapters.
