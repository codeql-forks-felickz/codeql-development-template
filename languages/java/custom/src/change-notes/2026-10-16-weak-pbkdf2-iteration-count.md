---
category: newQuery
---
* Added a new query, `java/weak-pbkdf2-iteration-count`, which detects password-based key derivation (`PBEKeySpec`, `PBEParameterSpec`) using a constant iteration count below 1000. This complements `java/weak-cryptographic-algorithm`, which already reports ECB and other weak cipher modes but not low PBKDF2 iteration counts.
