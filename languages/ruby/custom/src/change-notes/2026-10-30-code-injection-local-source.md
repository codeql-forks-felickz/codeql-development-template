---
category: newQuery
---
* Added a new query, `rb/code-injection-local-source`, to detect Ruby code injection where command-line arguments (`ARGV`) or standard input (`STDIN`, `$stdin`, `ARGF`, `Kernel#gets`/`readline`/`readlines`) flow to code evaluation such as `eval`, `instance_eval` or `class_eval`. The standard `rb/code-injection` query only considers remote flow sources.
