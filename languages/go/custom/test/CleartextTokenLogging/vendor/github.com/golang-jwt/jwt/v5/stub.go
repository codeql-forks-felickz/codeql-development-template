// Package jwt is a minimal stub of github.com/golang-jwt/jwt/v5 for testing.
package jwt

type Claims interface{}

type MapClaims map[string]interface{}

type SigningMethod interface {
	Sign(signingString string, key interface{}) ([]byte, error)
	Alg() string
}

type signingMethodStub struct{}

func (m *signingMethodStub) Sign(signingString string, key interface{}) ([]byte, error) {
	return nil, nil
}

func (m *signingMethodStub) Alg() string { return "" }

var SigningMethodHS256 SigningMethod = &signingMethodStub{}

type Token struct {
	Raw    string
	Method SigningMethod
	Claims Claims
	Valid  bool
}

func NewWithClaims(method SigningMethod, claims Claims) *Token {
	return &Token{Method: method, Claims: claims}
}

func (t *Token) SignedString(key interface{}) (string, error) {
	return "", nil
}
