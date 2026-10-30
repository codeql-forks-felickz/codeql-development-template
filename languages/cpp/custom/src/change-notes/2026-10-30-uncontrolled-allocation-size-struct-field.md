---
category: newQuery
---
* Added a new query, `cpp/uncontrolled-allocation-size-struct-field`, to detect allocation sizes computed from fields of a struct that was filled from user input (for example by `fread` or `recv`). Such sizes can underflow (CWE-191) or overflow (CWE-190). The standard `cpp/uncontrolled-allocation-size` query misses these cases because C++ taint tracking does not propagate taint from a wholly tainted struct to its field reads. The new query reports only allocations that the standard query does not already report.
