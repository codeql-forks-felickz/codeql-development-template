# Hard-coded initialization vector

A zero-filled or explicitly zero-initialized IV is fixed rather than fresh. With block ciphers that require an IV, reuse can make encryption deterministic and reveal relationships between plaintexts.

Generate a new cryptographically random IV for each encryption, and store it with the ciphertext.

This query detects zero-filled byte arrays directly assigned to a symmetric algorithm's `IV` property. It does not model IV values passed through helper methods or derived from a password-based KDF. In particular, a constant KDF salt combined with a low or default iteration count remains unsupported because identifying the resulting IV use requires additional context-sensitive modeling.

## References

- CWE-329: [Generation of Predictable IV with CBC Mode](https://cwe.mitre.org/data/definitions/329.html)
