# Cleartext logging of cryptographic key material
Output written to the console or to a log is commonly retained in shared log storage, and is readable by operators, log aggregation services, and anyone else with access to those logs. If a cryptographic key is written to such output, an attacker who can read the logs can recover the key and use it to decrypt or forge the data that it protects.

This query finds key material that is generated at runtime (for example by filling a buffer with random bytes, or by calling `generate_key`), that is used as a cryptographic key, and that is also written to a log or to standard output or standard error, possibly after hex encoding. The standard `rust/cleartext-logging` query relies on variable names to recognize sensitive data, and does not recognize names such as `key_bytes`.


## Recommendation
Do not write cryptographic keys to logs or to the console, even in encoded form. If you need to identify a key in diagnostic output, log a non-secret identifier for the key instead.


## Example
In the following example, a freshly generated AES-256-GCM key is hex-encoded and printed:


```rust
use ring::aead::{UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};

fn make_key() -> UnboundKey {
    let mut key_bytes = vec![0; AES_256_GCM.key_len()];
    SystemRandom::new().fill(&mut key_bytes).unwrap();
    println!("key_bytes = {}", hex::encode(&key_bytes)); // BAD: the key is written to stdout
    UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap()
}

```
In the following corrected example, only the key length is printed:


```rust
use ring::aead::{UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};

fn make_key() -> UnboundKey {
    let mut key_bytes = vec![0; AES_256_GCM.key_len()];
    SystemRandom::new().fill(&mut key_bytes).unwrap();
    println!("generated a {}-byte key", key_bytes.len()); // GOOD: only the key length is written
    UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap()
}

```

## References
* MITRE: [CWE-532: Insertion of Sensitive Information into Log File](https://cwe.mitre.org/data/definitions/532.html).
* OWASP: [Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html).
* Common Weakness Enumeration: [CWE-312](https://cwe.mitre.org/data/definitions/312.html).
* Common Weakness Enumeration: [CWE-532](https://cwe.mitre.org/data/definitions/532.html).
