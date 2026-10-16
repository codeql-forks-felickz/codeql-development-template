---
category: minorAnalysis
---

- Added taint flow summaries for `String#to_sym` and `String#intern`. Previously, request data converted to a Symbol (for example `params.require(:field).keys.map { |k| k.to_sym }`) lost its taint, so `rb/sql-injection` missed it being joined or interpolated into raw SQL fragments such as `select("#{cols}")`.
