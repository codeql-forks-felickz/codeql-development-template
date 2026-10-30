---
category: minorAnalysis
---

- Added SQL injection sinks for the legacy `mysql` / `ruby-mysql` gem `Mysql` class (`query`, `real_query` and `prepare`), including connections created with `Mysql.new`, `Mysql.connect`, `Mysql.real_connect` and `Mysql.init.real_connect`. `Mysql#escape_string` / `Mysql#quote` (and the class-method forms) are modeled as barriers. Previously only `Mysql2` was covered, so `rb/sql-injection` missed request parameters concatenated into `Mysql#query` calls.
