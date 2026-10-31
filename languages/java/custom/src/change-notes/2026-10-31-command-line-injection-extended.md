---
category: newQuery
---

- Added a new query, `java/command-line-injection-extended`, which extends `java/command-line-injection` with fields read in a custom `readObject` deserialization method as sources and a taint step for Kotlin `toString()` calls on Android `Editable` text. Results already reported by `java/command-line-injection` are not repeated.
