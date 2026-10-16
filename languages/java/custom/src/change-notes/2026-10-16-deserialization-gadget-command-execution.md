---
category: newQuery
---
* Added a new query, `java/deserialization-gadget-command-execution`, to detect serializable classes whose `readObject`, `readObjectNoData`, `readResolve` or `readExternal` callback runs an external command built from deserialized state (CWE-78, CWE-502).
