# Static initialization vector for encryption

## Overview

Block cipher modes such as CBC, CTR and GCM require an initialization vector (IV) that is unpredictable (CBC) or never reused with the same key (CTR, GCM). When an `OpenSSL::Cipher` is used for encryption with a hard-coded IV, encryption becomes deterministic: identical plaintexts produce identical ciphertexts, and in stream-like modes such as CTR and GCM, reusing an IV can expose the plaintext or allow forgery.

This query flags hard-coded string values, including values assigned to constants that may be defined in another file, that flow to the `iv=` setter of an `OpenSSL::Cipher` instance that is not put into decryption mode.

## Recommendation

Generate a new IV for every encryption with `cipher.random_iv` or `SecureRandom.random_bytes(cipher.iv_len)`, and store or transmit it alongside the ciphertext. The IV does not need to be secret.

## Example

In the following example, the IV is a constant, so every token encrypted with this key is deterministic:

```ruby
APP_IV = "PPKLKAJDKGHALDJL482823458028"

def encrypt(key, value)
  cipher = OpenSSL::Cipher.new("aes-256-cbc")
  cipher.encrypt
  cipher.key = key
  cipher.iv = APP_IV[0..15] # BAD: hard-coded IV
  cipher.update(value) + cipher.final
end
```

The following example generates a fresh random IV for each encryption and returns it with the ciphertext:

```ruby
def encrypt(key, value)
  cipher = OpenSSL::Cipher.new("aes-256-cbc")
  cipher.encrypt
  cipher.key = key
  iv = cipher.random_iv # GOOD: random IV
  iv + cipher.update(value) + cipher.final
end
```

## References

- Ruby documentation: [OpenSSL::Cipher](https://docs.ruby-lang.org/en/master/OpenSSL/Cipher.html).
- Common Weakness Enumeration: [CWE-329](https://cwe.mitre.org/data/definitions/329.html).
- Common Weakness Enumeration: [CWE-1204](https://cwe.mitre.org/data/definitions/1204.html).
