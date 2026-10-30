---
category: newQuery
---

- Added a new query, `cpp/uncontrolled-allocation-size-struct-field`, which detects allocation sizes computed from integer fields of a struct filled with external input (for example by `fread`). The standard `cpp/uncontrolled-allocation-size` query does not propagate taint from such a struct to its fields.
