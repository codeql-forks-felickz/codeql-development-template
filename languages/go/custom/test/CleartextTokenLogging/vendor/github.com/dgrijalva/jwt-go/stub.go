// Package jwt is a minimal stub of github.com/dgrijalva/jwt-go for testing.
package jwt

type Claims interface {
	Valid() error
}

type StandardClaims struct {
	ExpiresAt int64
	Subject   string
}

func (c StandardClaims) Valid() error { return nil }

type SigningMethod interface {
	Sign(signingString string, key interface{}) (string, error)
	Alg() string
}

type signingMethodStub struct{}

func (m *signingMethodStub) Sign(signingString string, key interface{}) (string, error) {
	return "", nil
}

func (m *signingMethodStub) Alg() string { return "" }

var SigningMethodHS256 SigningMethod = &signingMethodStub{}

var SigningMethodNone SigningMethod = &signingMethodStub{}

const UnsafeAllowNoneSignatureType unsafeNoneMagicConstant = "none signing method allowed"

type unsafeNoneMagicConstant string

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
