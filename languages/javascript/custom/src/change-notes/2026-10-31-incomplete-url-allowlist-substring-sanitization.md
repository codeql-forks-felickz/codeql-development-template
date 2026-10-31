---
category: newQuery
---
* Added a new query, `js/incomplete-url-allowlist-substring-sanitization`, which extends `js/incomplete-url-substring-sanitization` (CWE-020, CWE-601) to substring checks (`includes`, `indexOf`, `startsWith`, `endsWith`) whose substring is an element of an array or `Set` literal URL allowlist, iterated with `for-of` or an array callback method such as `some`.
