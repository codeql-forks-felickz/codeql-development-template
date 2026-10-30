---
category: newQuery
---
* Added a new query, `cs/reverse-dns-user-controlled-bypass`, which extends `cs/user-controlled-bypass` with reverse DNS sources (`Dns.GetHostEntry(IPAddress)` and `Dns.GetHostEntryAsync(IPAddress)`) and with comparisons of the resulting host name against non-constant values (CWE-350).
