---
category: newQuery
---

- Added `rb/hardcoded-account-password` (CWE-1392, CWE-798, CWE-259), which reports string-literal passwords written to Active Record accounts (for example in `db/seeds.rb`), including short literals that `rb/hardcoded-credentials` ignores.
- Added `rb/cleartext-password-column` (CWE-256, CWE-312), which reports password-named `string`/`text` columns in `db/schema.rb` and migrations when the corresponding model shows no hashing or encryption, a case `rb/clear-text-storage-sensitive-data` does not cover.
