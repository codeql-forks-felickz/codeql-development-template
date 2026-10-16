---
category: newQuery
---
* Added a new query, `java/unsafe-reflection-instantiation`, to detect classes selected from user-controlled input via `Class.forName`/`ClassLoader.loadClass` that are then instantiated or invoked reflectively without an allowlist check (CWE-470).
