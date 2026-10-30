---
category: newQuery
---
* Added a new query, `cs/reverse-dns-user-controlled-bypass`, which extends `cs/user-controlled-bypass` with reverse DNS sources (`Dns.GetHostEntry(IPAddress)` and `Dns.GetHostEntryAsync(IPAddress)`). It also includes `Dns.GetHostByAddress`, whose constant-comparison coverage overlaps with the stock query, and detects comparisons of the resulting host name against non-constant values (CWE-350).
