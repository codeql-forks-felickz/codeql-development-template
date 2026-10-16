---
category: newQuery
---

- Added a new query, `js/zipslip-extended`, which extends `js/zipslip` with models for entry paths read from `unzipper.Open.*(...)` central directories (`directory.files[].path`) and for `extractAllTo`, `extractAllToAsync` and `extractEntryTo` on `adm-zip` archives (created with or without `new`) when `package.json` pins an `adm-zip` version older than 0.4.11.
