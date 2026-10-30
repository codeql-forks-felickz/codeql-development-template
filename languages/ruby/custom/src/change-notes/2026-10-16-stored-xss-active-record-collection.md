---
category: newQuery
---
* Added a new query, `rb/stored-xss-active-record-collection`, which extends `rb/stored-xss` to treat database fields read from records yielded by iterating an ActiveRecord relation (for example `Todo.where(...).each { |todo| raw(todo.body) }`) as stored values. The stock query only models single-record finders such as `find` and `find_by`, so stored XSS in list views backed by `where`, `all`, `order` and similar relation methods was missed.
