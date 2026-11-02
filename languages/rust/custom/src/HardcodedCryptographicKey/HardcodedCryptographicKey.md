# Hard-coded cryptographic key or passphrase
A cryptographic key or passphrase that is embedded in source code can be recovered by anyone with access to the source code or to the compiled binary. An attacker who recovers the key can decrypt data that it protects, or forge ciphertexts and authentication tags that the application will accept as genuine.

This query finds constant values (literals, constant arrays, and repeated-value arrays) that flow to the key or passphrase argument of a cryptographic API. It complements the standard `rust/hard-coded-cryptographic-value` query by recognizing additional APIs from the `age`, `orion` and `ring` crates, and keys that are wrapped with `GenericArray::from` or `secrecy::Secret::new` before use. Results that the standard query already reports are not repeated.


## Recommendation
Do not embed keys or passphrases in source code. Generate keys with a cryptographically secure random number generator, or load them at runtime from a protected secret store such as a key management service, and rotate any key that has been committed to source control.


## Example
In the following example, an AES key is a fixed array of zero bytes:


```rust
use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;

fn encrypt(block: &mut [u8; 16]) {
    let key = GenericArray::from([0u8; 16]); // BAD: the key is hard-coded
    let cipher = Aes128::new(&key);
    cipher.encrypt_block(GenericArray::from_mut_slice(block));
}

```
In the following corrected example, the key is supplied at runtime from a protected secret store:


```rust
use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;

fn encrypt(block: &mut [u8; 16], key_bytes: [u8; 16]) {
    // GOOD: the key is loaded at runtime from a protected secret store
    let key = GenericArray::from(key_bytes);
    let cipher = Aes128::new(&key);
    cipher.encrypt_block(GenericArray::from_mut_slice(block));
}

```

## References
* MITRE: [CWE-321: Use of Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html).
* OWASP: [Key Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html).
* Common Weakness Enumeration: [CWE-321](https://cwe.mitre.org/data/definitions/321.html).
* Common Weakness Enumeration: [CWE-798](https://cwe.mitre.org/data/definitions/798.html).
