---
category: newQuery
---
* Added a new query, `go/insecure-randomness-key-material`, which detects values from `math/rand` that are stored in or returned as key material (keys, secrets, tokens, nonces, salts), identified by the name of the variable, field or function. It also tracks taint through arithmetic such as `rand.Intn(100) + 1`. Results already reported by `go/insecure-randomness` are not repeated.
