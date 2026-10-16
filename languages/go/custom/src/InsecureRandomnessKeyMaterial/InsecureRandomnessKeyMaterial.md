# Use of insufficient randomness as key material

`math/rand` is a pseudo-random number generator that is not cryptographically secure. Its output can be predicted, and when the value range is small (for example `rand.Intn(100)`) it can simply be enumerated.

The standard `go/insecure-randomness` query only reports such values when they reach a `crypto/*` API or a password-generating function. This query also reports `math/rand` values that are stored in, or returned as, key material: a variable, struct field or function whose name indicates a key, secret, token, nonce or salt (for example `MessageKey`, `secretKey`, `SessionToken`, `generateApiToken`).

## Recommendation

Use `crypto/rand` to generate keys, secrets, tokens, nonces and salts, and use a sufficiently large value range.

## Example

The following handler generates a message encryption key with `math/rand`. The key is one of only 100 values and is predictable:

```go
func (s *server) GetKey(w http.ResponseWriter, r *http.Request) {
	if s.MessageKey.Value == 0 {
		s.MessageKey.Value = rand.Intn(100) + 1 // BAD
	}
	// ...
}
```

Use `crypto/rand` instead:

```go
func newMessageKey() ([]byte, error) {
	key := make([]byte, 32)
	_, err := cryptorand.Read(key) // GOOD
	return key, err
}
```

## References

- CWE-338: [Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)](https://cwe.mitre.org/data/definitions/338.html).
- Go documentation: [crypto/rand](https://pkg.go.dev/crypto/rand).
